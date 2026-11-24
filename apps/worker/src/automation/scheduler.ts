import { and, eq, inArray, lte } from "drizzle-orm";
import { DEFAULT_SCANNERS } from "@indicative/contracts";
import {
  auditEvents,
  projectRepositories,
  projects,
  scans,
  scanSchedules,
  securityPolicies,
  type Database
} from "@indicative/database";
import type { StructuredLogger } from "@indicative/security";
import { generateCorrelationId } from "@indicative/shared";
import type { ScanJobEnqueuer } from "../jobs/scanQueue.js";
import { computeNextCronRun } from "./cron.js";

export interface SchedulerTickResult {
  checked: number;
  triggeredScanIds: string[];
  skippedConcurrency: number;
  errors: number;
}

/**
 * Evaluates all enabled scan_schedules whose nextRunAt <= now, creates idempotent SCHEDULED scans
 * while honoring organization security_policies.maxConcurrentScans, and advances nextRunAt.
 */
export async function runDueScanSchedules(params: {
  db: Database;
  enqueuer: ScanJobEnqueuer;
  defaultMaxConcurrentScans?: number;
  logger?: StructuredLogger;
  now?: Date;
}): Promise<SchedulerTickResult> {
  const now = params.now ?? new Date();
  const dueSchedules = await params.db
    .select()
    .from(scanSchedules)
    .where(and(eq(scanSchedules.enabled, true), lte(scanSchedules.nextRunAt, now)));

  const result: SchedulerTickResult = {
    checked: dueSchedules.length,
    triggeredScanIds: [],
    skippedConcurrency: 0,
    errors: 0
  };

  for (const schedule of dueSchedules) {
    try {
      const [project] = await params.db
        .select()
        .from(projects)
        .where(
          and(
            eq(projects.id, schedule.projectId),
            eq(projects.organizationId, schedule.organizationId)
          )
        );
      const [repo] = await params.db
        .select()
        .from(projectRepositories)
        .where(
          and(
            eq(projectRepositories.projectId, schedule.projectId),
            eq(projectRepositories.organizationId, schedule.organizationId)
          )
        );

      if (!project || !repo) {
        await params.db
          .update(scanSchedules)
          .set({ enabled: false, updatedAt: new Date() })
          .where(eq(scanSchedules.id, schedule.id));
        continue;
      }

      const [policy] = await params.db
        .select()
        .from(securityPolicies)
        .where(eq(securityPolicies.organizationId, schedule.organizationId));

      const maxConcurrent = policy?.maxConcurrentScans ?? params.defaultMaxConcurrentScans ?? 3;
      const activeScans = await params.db
        .select({ id: scans.id })
        .from(scans)
        .where(
          and(
            eq(scans.organizationId, schedule.organizationId),
            inArray(scans.status, ["QUEUED", "INITIALIZING", "CLONING", "SCANNING", "ANALYZING"])
          )
        );

      if (activeScans.length >= maxConcurrent) {
        result.skippedConcurrency += 1;
        params.logger?.warn("Skipped scheduled scan due to org concurrency limit", {
          scheduleId: schedule.id,
          organizationId: schedule.organizationId,
          activeScans: activeScans.length,
          maxConcurrent
        });
        continue;
      }

      const slotKey = schedule.nextRunAt.toISOString().slice(0, 16);
      const idempotencyKey = `sched-${schedule.id}-${slotKey}`;

      // Guard against duplicate triggers across multiple worker instances
      const [existingScan] = await params.db
        .select({ id: scans.id })
        .from(scans)
        .where(
          and(
            eq(scans.projectId, schedule.projectId),
            eq(scans.idempotencyKey, idempotencyKey)
          )
        );

      const nextRunAt = computeNextCronRun(schedule.cronExpression, now);

      if (existingScan) {
        await params.db
          .update(scanSchedules)
          .set({ nextRunAt, updatedAt: new Date() })
          .where(eq(scanSchedules.id, schedule.id));
        continue;
      }

      const runAiAnalysis =
        Boolean(schedule.runAiAnalysis) && (policy ? policy.allowAiAnalysis : true);
      const requestedScanners =
        Array.isArray(schedule.scanners) && schedule.scanners.length > 0
          ? schedule.scanners
          : [...DEFAULT_SCANNERS];
      const correlationId = generateCorrelationId();

      const [createdScan] = await params.db
        .insert(scans)
        .values({
          organizationId: schedule.organizationId,
          projectId: schedule.projectId,
          repositoryId: repo.id,
          initiatedByUserId: schedule.createdByUserId,
          idempotencyKey,
          triggerSource: "SCHEDULED",
          triggerMetadata: {
            scheduleId: schedule.id,
            scheduleName: schedule.name,
            cadence: schedule.cadence,
            cronExpression: schedule.cronExpression
          },
          branch: schedule.branch || repo.defaultBranch,
          status: "QUEUED",
          requestedScanners,
          runAiAnalysis,
          isDemoScan: project.isDemo,
          correlationId
        })
        .returning();

      await params.db
        .update(scanSchedules)
        .set({
          lastRunAt: now,
          nextRunAt,
          lastScanId: createdScan!.id,
          updatedAt: new Date()
        })
        .where(eq(scanSchedules.id, schedule.id));

      await params.db.insert(auditEvents).values({
        organizationId: schedule.organizationId,
        actorUserId: schedule.createdByUserId,
        action: "SCHEDULED_SCAN_TRIGGERED",
        resourceType: "SCAN",
        resourceId: createdScan!.id,
        correlationId,
        metadata: {
          scheduleId: schedule.id,
          scheduleName: schedule.name,
          cadence: schedule.cadence,
          nextRunAt: nextRunAt.toISOString()
        }
      });

      await params.enqueuer.enqueue({
        scanId: createdScan!.id,
        organizationId: schedule.organizationId,
        projectId: schedule.projectId,
        correlationId
      });

      result.triggeredScanIds.push(createdScan!.id);
    } catch (err) {
      result.errors += 1;
      params.logger?.error("Failed to process due scan schedule", {
        scheduleId: schedule.id,
        error: (err as Error).message
      });
    }
  }

  return result;
}

export function startSchedulePoller(params: {
  db: Database;
  enqueuer: ScanJobEnqueuer;
  intervalMs: number;
  defaultMaxConcurrentScans?: number;
  logger?: StructuredLogger;
}): { stop(): void } {
  let running = false;

  const tick = async () => {
    if (running) return;
    running = true;
    try {
      const res = await runDueScanSchedules({
        db: params.db,
        enqueuer: params.enqueuer,
        defaultMaxConcurrentScans: params.defaultMaxConcurrentScans,
        logger: params.logger
      });
      if (res.triggeredScanIds.length > 0) {
        params.logger?.info("Scheduled scans enqueued", {
          count: res.triggeredScanIds.length,
          scanIds: res.triggeredScanIds
        });
      }
    } catch (err) {
      params.logger?.error("Schedule poller tick failed", {
        error: (err as Error).message
      });
    } finally {
      running = false;
    }
  };

  const timer = setInterval(() => {
    void tick();
  }, params.intervalMs);
  timer.unref?.();

  return {
    stop() {
      clearInterval(timer);
    }
  };
}

import type { FastifyInstance } from "fastify";
import { and, desc, eq } from "drizzle-orm";
import type { AppConfig } from "@indicative/config";
import {
  CreateNotificationChannelRequestSchema,
  CreateScanScheduleRequestSchema,
  DEFAULT_SCANNERS,
  UpdateNotificationChannelRequestSchema,
  UpdateScanScheduleRequestSchema
} from "@indicative/contracts";
import {
  auditEvents,
  notificationChannels,
  notificationDeliveries,
  projectRepositories,
  projects,
  scans,
  scanSchedules,
  webhookDeliveries,
  type Database
} from "@indicative/database";
import {
  encryptTenantSecret,
  validateGitHubRepositorySlug
} from "@indicative/security";
import {
  computeNextCronRun,
  resolveCronExpression,
  sendTestNotificationForChannel,
  validateNotificationOutboundUrl,
  type GitHubAppClient,
  type ScanJobEnqueuer
} from "@indicative/worker";
import { NotFoundError, ValidationError } from "@indicative/shared";
import type { AuthContext } from "../middleware/auth.js";

export interface AutomationRouteDeps {
  db: Database;
  config: AppConfig;
  enqueuer: ScanJobEnqueuer;
  githubAppClient?: GitHubAppClient;
  requireAuth: (req: any, reply: any) => Promise<void>;
  fetchImpl?: typeof fetch;
}

const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function assertUuid(value: string, label: string): string {
  if (!UUID_REGEX.test(value)) {
    throw new ValidationError(`Invalid ${label} identifier format (expected UUID).`);
  }
  return value;
}

function sanitizeChannelForApi(row: typeof notificationChannels.$inferSelect) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    projectId: row.projectId,
    name: row.name,
    channelType: row.channelType,
    enabled: row.enabled,
    events: row.events,
    minSeverity: row.minSeverity,
    onlyOnNewFindings: row.onlyOnNewFindings,
    config: row.configJson,
    hasCredentials: Boolean(row.encryptedCredentials),
    lastTriggeredAt: row.lastTriggeredAt,
    lastError: row.lastError,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt
  };
}

export function registerAutomationRoutes(
  app: FastifyInstance,
  deps: AutomationRouteDeps
): void {
  // ============================================================================
  // Scheduled / Recurring Scans
  // ============================================================================

  app.get("/api/v1/schedules", { preHandler: deps.requireAuth }, async (request) => {
    const auth = request.auth as AuthContext;
    const rows = await deps.db
      .select({
        schedule: scanSchedules,
        projectName: projects.name,
        repositoryFullName: projectRepositories.fullName
      })
      .from(scanSchedules)
      .innerJoin(projects, eq(scanSchedules.projectId, projects.id))
      .innerJoin(projectRepositories, eq(projectRepositories.projectId, projects.id))
      .where(eq(scanSchedules.organizationId, auth.organizationId))
      .orderBy(desc(scanSchedules.createdAt));

    return {
      schedules: rows.map((r) => ({
        ...r.schedule,
        projectName: r.projectName,
        repositoryFullName: r.repositoryFullName
      }))
    };
  });

  app.post("/api/v1/schedules", { preHandler: deps.requireAuth }, async (request, reply) => {
    const auth = request.auth as AuthContext;
    const parsed = CreateScanScheduleRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      throw new ValidationError("Invalid scan schedule payload.", parsed.error.flatten());
    }

    const [project] = await deps.db
      .select()
      .from(projects)
      .where(
        and(
          eq(projects.id, parsed.data.projectId),
          eq(projects.organizationId, auth.organizationId)
        )
      );
    if (!project) {
      throw new NotFoundError("Project not found in your organization.");
    }

    let cronExpression: string;
    let nextRunAt: Date;
    try {
      cronExpression = resolveCronExpression(parsed.data.cadence, parsed.data.cronExpression);
      nextRunAt = computeNextCronRun(cronExpression, new Date());
    } catch (err) {
      throw new ValidationError((err as Error).message);
    }

    const [created] = await deps.db
      .insert(scanSchedules)
      .values({
        organizationId: auth.organizationId,
        projectId: project.id,
        name: parsed.data.name,
        cadence: parsed.data.cadence,
        cronExpression,
        branch: parsed.data.branch ?? null,
        scanners: parsed.data.scanners ?? [...DEFAULT_SCANNERS],
        runAiAnalysis: parsed.data.runAiAnalysis,
        enabled: parsed.data.enabled,
        nextRunAt,
        createdByUserId: auth.userId
      })
      .returning();

    await deps.db.insert(auditEvents).values({
      organizationId: auth.organizationId,
      actorUserId: auth.userId,
      action: "SCAN_SCHEDULE_CREATED",
      resourceType: "SCAN_SCHEDULE",
      resourceId: created!.id,
      correlationId: request.correlationId,
      ipAddress: request.ip,
      metadata: {
        projectId: project.id,
        cadence: parsed.data.cadence,
        cronExpression,
        nextRunAt: nextRunAt.toISOString()
      }
    });

    return reply.status(201).send({ schedule: created });
  });

  app.patch<{ Params: { scheduleId: string } }>(
    "/api/v1/schedules/:scheduleId",
    { preHandler: deps.requireAuth },
    async (request) => {
      const auth = request.auth as AuthContext;
      const scheduleId = assertUuid(request.params.scheduleId, "scheduleId");
      const parsed = UpdateScanScheduleRequestSchema.safeParse(request.body);
      if (!parsed.success) {
        throw new ValidationError("Invalid schedule update payload.", parsed.error.flatten());
      }

      const [existing] = await deps.db
        .select()
        .from(scanSchedules)
        .where(
          and(
            eq(scanSchedules.id, scheduleId),
            eq(scanSchedules.organizationId, auth.organizationId)
          )
        );
      if (!existing) throw new NotFoundError("Scan schedule not found.");

      const nextCadence = parsed.data.cadence ?? (existing.cadence as "HOURLY" | "DAILY" | "WEEKLY" | "CUSTOM_CRON");
      let cronExpression = existing.cronExpression;
      let nextRunAt = existing.nextRunAt;
      if (parsed.data.cadence !== undefined || parsed.data.cronExpression !== undefined) {
        try {
          cronExpression = resolveCronExpression(
            nextCadence,
            parsed.data.cronExpression ??
              (parsed.data.cadence === "CUSTOM_CRON" ? existing.cronExpression : undefined)
          );
          nextRunAt = computeNextCronRun(cronExpression, new Date());
        } catch (err) {
          throw new ValidationError((err as Error).message);
        }
      }

      const [updated] = await deps.db
        .update(scanSchedules)
        .set({
          name: parsed.data.name ?? existing.name,
          cadence: nextCadence,
          cronExpression,
          branch: parsed.data.branch !== undefined ? parsed.data.branch : existing.branch,
          scanners: parsed.data.scanners ?? existing.scanners,
          runAiAnalysis:
            parsed.data.runAiAnalysis !== undefined
              ? parsed.data.runAiAnalysis
              : existing.runAiAnalysis,
          enabled: parsed.data.enabled !== undefined ? parsed.data.enabled : existing.enabled,
          nextRunAt,
          updatedAt: new Date()
        })
        .where(eq(scanSchedules.id, scheduleId))
        .returning();

      return { schedule: updated };
    }
  );

  app.delete<{ Params: { scheduleId: string } }>(
    "/api/v1/schedules/:scheduleId",
    { preHandler: deps.requireAuth },
    async (request) => {
      const auth = request.auth as AuthContext;
      const scheduleId = assertUuid(request.params.scheduleId, "scheduleId");
      const deleted = await deps.db
        .delete(scanSchedules)
        .where(
          and(
            eq(scanSchedules.id, scheduleId),
            eq(scanSchedules.organizationId, auth.organizationId)
          )
        )
        .returning();
      if (deleted.length === 0) throw new NotFoundError("Scan schedule not found.");
      return { ok: true, deletedId: scheduleId };
    }
  );

  app.post<{ Params: { scheduleId: string } }>(
    "/api/v1/schedules/:scheduleId/trigger",
    { preHandler: deps.requireAuth },
    async (request, reply) => {
      const auth = request.auth as AuthContext;
      const scheduleId = assertUuid(request.params.scheduleId, "scheduleId");
      const [schedule] = await deps.db
        .select()
        .from(scanSchedules)
        .where(
          and(
            eq(scanSchedules.id, scheduleId),
            eq(scanSchedules.organizationId, auth.organizationId)
          )
        );
      if (!schedule) throw new NotFoundError("Scan schedule not found.");

      const [project] = await deps.db
        .select()
        .from(projects)
        .where(eq(projects.id, schedule.projectId));
      const [repo] = await deps.db
        .select()
        .from(projectRepositories)
        .where(eq(projectRepositories.projectId, schedule.projectId));
      if (!project || !repo) throw new NotFoundError("Scheduled project repository not found.");

      const [createdScan] = await deps.db
        .insert(scans)
        .values({
          organizationId: auth.organizationId,
          projectId: project.id,
          repositoryId: repo.id,
          initiatedByUserId: auth.userId,
          triggerSource: "SCHEDULED",
          triggerMetadata: {
            scheduleId: schedule.id,
            scheduleName: schedule.name,
            manualTrigger: true
          },
          branch: schedule.branch || repo.defaultBranch,
          status: "QUEUED",
          requestedScanners:
            Array.isArray(schedule.scanners) && schedule.scanners.length > 0
              ? schedule.scanners
              : [...DEFAULT_SCANNERS],
          runAiAnalysis: schedule.runAiAnalysis,
          isDemoScan: project.isDemo,
          correlationId: request.correlationId
        })
        .returning();

      await deps.db
        .update(scanSchedules)
        .set({ lastRunAt: new Date(), lastScanId: createdScan!.id, updatedAt: new Date() })
        .where(eq(scanSchedules.id, schedule.id));

      await deps.enqueuer.enqueue({
        scanId: createdScan!.id,
        organizationId: auth.organizationId,
        projectId: project.id,
        correlationId: request.correlationId
      });

      return reply.status(202).send({ scan: createdScan });
    }
  );

  // ============================================================================
  // Notification Channels (Slack, Jira, GitHub Issues)
  // ============================================================================

  app.get("/api/v1/notifications/channels", { preHandler: deps.requireAuth }, async (request) => {
    const auth = request.auth as AuthContext;
    const rows = await deps.db
      .select()
      .from(notificationChannels)
      .where(eq(notificationChannels.organizationId, auth.organizationId))
      .orderBy(desc(notificationChannels.createdAt));

    return { channels: rows.map(sanitizeChannelForApi) };
  });

  app.post(
    "/api/v1/notifications/channels",
    { preHandler: deps.requireAuth },
    async (request, reply) => {
      const auth = request.auth as AuthContext;
      const parsed = CreateNotificationChannelRequestSchema.safeParse(request.body);
      if (!parsed.success) {
        throw new ValidationError("Invalid notification channel configuration.", parsed.error.flatten());
      }

      const data = parsed.data;
      if (data.projectId) {
        const [project] = await deps.db
          .select({ id: projects.id })
          .from(projects)
          .where(
            and(eq(projects.id, data.projectId), eq(projects.organizationId, auth.organizationId))
          );
        if (!project) throw new NotFoundError("Project not found in your organization.");
      }

      const allowHttpInTest = deps.config.NODE_ENV === "test";
      let publicConfig: Record<string, unknown>;
      let secretPayload: Record<string, unknown>;

      try {
        if (data.channelType === "SLACK") {
          const parsedUrl = validateNotificationOutboundUrl(
            "SLACK",
            data.config.webhookUrl,
            allowHttpInTest
          );
          publicConfig = {
            host: parsedUrl.hostname,
            channelLabel: data.config.channelLabel ?? "#security-alerts"
          };
          secretPayload = { webhookUrl: parsedUrl.toString() };
        } else if (data.channelType === "JIRA") {
          const parsedUrl = validateNotificationOutboundUrl(
            "JIRA",
            data.config.baseUrl,
            allowHttpInTest
          );
          publicConfig = {
            baseUrl: parsedUrl.origin,
            projectKey: data.config.projectKey,
            issueType: data.config.issueType,
            labels: data.config.labels
          };
          secretPayload = {
            email: data.config.email,
            apiToken: data.config.apiToken
          };
        } else {
          const slug = validateGitHubRepositorySlug(data.config.repositoryFullName).fullName;
          publicConfig = {
            repositoryFullName: slug,
            labels: data.config.labels
          };
          secretPayload = data.config.token ? { token: data.config.token } : {};
        }
      } catch (err) {
        throw new ValidationError((err as Error).message);
      }

      const encryptedCredentials =
        Object.keys(secretPayload).length > 0
          ? encryptTenantSecret(
              JSON.stringify(secretPayload),
              auth.organizationId,
              deps.config.SECRET_FINGERPRINT_KEY
            )
          : null;

      const [created] = await deps.db
        .insert(notificationChannels)
        .values({
          organizationId: auth.organizationId,
          projectId: data.projectId ?? null,
          name: data.name,
          channelType: data.channelType,
          enabled: data.enabled,
          events: data.events,
          minSeverity: data.minSeverity,
          onlyOnNewFindings: data.onlyOnNewFindings,
          configJson: publicConfig,
          encryptedCredentials
        })
        .returning();

      await deps.db.insert(auditEvents).values({
        organizationId: auth.organizationId,
        actorUserId: auth.userId,
        action: "NOTIFICATION_CHANNEL_CREATED",
        resourceType: "NOTIFICATION_CHANNEL",
        resourceId: created!.id,
        correlationId: request.correlationId,
        ipAddress: request.ip,
        metadata: {
          channelType: data.channelType,
          name: data.name,
          projectId: data.projectId ?? null,
          events: data.events
        }
      });

      return reply.status(201).send({ channel: sanitizeChannelForApi(created!) });
    }
  );

  app.patch<{ Params: { channelId: string } }>(
    "/api/v1/notifications/channels/:channelId",
    { preHandler: deps.requireAuth },
    async (request) => {
      const auth = request.auth as AuthContext;
      const channelId = assertUuid(request.params.channelId, "channelId");
      const parsed = UpdateNotificationChannelRequestSchema.safeParse(request.body);
      if (!parsed.success) {
        throw new ValidationError("Invalid notification channel update.", parsed.error.flatten());
      }

      const [existing] = await deps.db
        .select()
        .from(notificationChannels)
        .where(
          and(
            eq(notificationChannels.id, channelId),
            eq(notificationChannels.organizationId, auth.organizationId)
          )
        );
      if (!existing) throw new NotFoundError("Notification channel not found.");

      const [updated] = await deps.db
        .update(notificationChannels)
        .set({
          name: parsed.data.name ?? existing.name,
          enabled: parsed.data.enabled !== undefined ? parsed.data.enabled : existing.enabled,
          events: parsed.data.events ?? existing.events,
          minSeverity: parsed.data.minSeverity ?? existing.minSeverity,
          onlyOnNewFindings:
            parsed.data.onlyOnNewFindings !== undefined
              ? parsed.data.onlyOnNewFindings
              : existing.onlyOnNewFindings,
          updatedAt: new Date()
        })
        .where(eq(notificationChannels.id, channelId))
        .returning();

      return { channel: sanitizeChannelForApi(updated!) };
    }
  );

  app.delete<{ Params: { channelId: string } }>(
    "/api/v1/notifications/channels/:channelId",
    { preHandler: deps.requireAuth },
    async (request) => {
      const auth = request.auth as AuthContext;
      const channelId = assertUuid(request.params.channelId, "channelId");
      const deleted = await deps.db
        .delete(notificationChannels)
        .where(
          and(
            eq(notificationChannels.id, channelId),
            eq(notificationChannels.organizationId, auth.organizationId)
          )
        )
        .returning();
      if (deleted.length === 0) throw new NotFoundError("Notification channel not found.");
      return { ok: true, deletedId: channelId };
    }
  );

  app.post<{ Params: { channelId: string } }>(
    "/api/v1/notifications/channels/:channelId/test",
    { preHandler: deps.requireAuth },
    async (request) => {
      const auth = request.auth as AuthContext;
      const channelId = assertUuid(request.params.channelId, "channelId");
      const [channel] = await deps.db
        .select()
        .from(notificationChannels)
        .where(
          and(
            eq(notificationChannels.id, channelId),
            eq(notificationChannels.organizationId, auth.organizationId)
          )
        );
      if (!channel) throw new NotFoundError("Notification channel not found.");

      const result = await sendTestNotificationForChannel({
        db: deps.db,
        config: deps.config,
        channel,
        githubAppClient: deps.githubAppClient,
        fetchImpl: deps.fetchImpl
      });
      return { result };
    }
  );

  app.get("/api/v1/notifications/deliveries", { preHandler: deps.requireAuth }, async (request) => {
    const auth = request.auth as AuthContext;
    const rows = await deps.db
      .select()
      .from(notificationDeliveries)
      .where(eq(notificationDeliveries.organizationId, auth.organizationId))
      .orderBy(desc(notificationDeliveries.createdAt))
      .limit(50);

    return { deliveries: rows };
  });

  app.get("/api/v1/webhooks/deliveries", { preHandler: deps.requireAuth }, async (request) => {
    const auth = request.auth as AuthContext;
    const rows = await deps.db
      .select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.organizationId, auth.organizationId))
      .orderBy(desc(webhookDeliveries.receivedAt))
      .limit(50);

    return { deliveries: rows };
  });
}

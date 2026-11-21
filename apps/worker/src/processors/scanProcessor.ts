import { and, desc, eq, ne } from "drizzle-orm";
import type { AppConfig } from "@indicative/config";
import type {
  FindingStatus,
  ScanStatus,
  ScannerExecutionResult,
  ScannerLimitation,
  ScannerRunSummary,
  SecurityFinding
} from "@indicative/contracts";
import {
  auditEvents,
  findingAiAnalyses,
  findingEvidence,
  findingOccurrences,
  findings,
  findingStatusHistory,
  organizations,
  projectRepositories,
  projects,
  scanArtifacts,
  scannerRuns,
  scans,
  githubInstallations,
  type Database
} from "@indicative/database";
import {
  computeScanComparisonAndVerification,
  exportReportAsJson,
  exportReportAsSarif,
  normalizeAndDeduplicateFindings
} from "@indicative/findings";
import { AiSecurityAnalyst } from "@indicative/ai";
import type {
  IsolatedScannerRunner,
  RunnerExecutionResponse
} from "@indicative/scanner-runner";
import {
  createRedactingLogger,
  redactSecretsInText,
  type StructuredLogger
} from "@indicative/security";
import {
  defaultMetrics,
  type ArtifactStorageAdapter,
  type MetricsRegistry
} from "@indicative/shared";
import { GitHubAppClient } from "../ingestion/githubApp.js";
import { ingestRepositoryForScan } from "../ingestion/repositoryIngestor.js";

export interface ScanProcessorDependencies {
  db: Database;
  config: AppConfig;
  artifactStorage: ArtifactStorageAdapter;
  localRunner?: IsolatedScannerRunner;
  aiAnalyst?: AiSecurityAnalyst;
  githubAppClient?: GitHubAppClient;
  metrics?: MetricsRegistry;
  logger?: StructuredLogger;
}

async function invokeRemoteScannerRunner(params: {
  config: AppConfig;
  scanId: string;
  organizationId: string;
  projectId: string;
  workspacePath: string;
  scanners: string[];
}): Promise<RunnerExecutionResponse> {
  const res = await fetch(`${params.config.SCANNER_RUNNER_URL.replace(/\/+$/, "")}/internal/v1/execute`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Scanner-Runner-Secret": params.config.SCANNER_RUNNER_SHARED_SECRET
    },
    body: JSON.stringify({
      scanId: params.scanId,
      organizationId: params.organizationId,
      projectId: params.projectId,
      workspacePath: params.workspacePath,
      scanners: params.scanners
    })
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => "");
    throw new Error(
      `SCANNER_RUNNER_HTTP_ERROR (${res.status}): ${redactSecretsInText(errText.slice(0, 300))}`
    );
  }

  return (await res.json()) as RunnerExecutionResponse;
}

async function isScanCancelled(db: Database, scanId: string): Promise<boolean> {
  const [row] = await db
    .select({ status: scans.status })
    .from(scans)
    .where(eq(scans.id, scanId));
  return row?.status === "CANCELLED";
}

function determineFinalScanStatus(results: ScannerExecutionResult[]): ScanStatus {
  if (results.length === 0) return "FAILED";
  const allCancelled = results.every((r) => r.status === "CANCELLED");
  if (allCancelled) return "CANCELLED";

  const succeededCount = results.filter((r) => r.status === "SUCCESS").length;
  const failedOrErrored = results.some(
    (r) =>
      r.status === "FAILED" ||
      r.status === "TIMEOUT" ||
      r.status === "UNAVAILABLE" ||
      r.status === "PARTIAL"
  );

  if (succeededCount === 0) return "FAILED";
  if (failedOrErrored) return "COMPLETED_WITH_ERRORS";
  return "COMPLETED";
}

/**
 * Executes the complete asynchronous scan pipeline:
 * INITIALIZING -> CLONING -> SCANNING -> ANALYZING -> COMPLETED | COMPLETED_WITH_ERRORS | FAILED | CANCELLED
 */
export async function executeScanPipeline(
  scanId: string,
  deps: ScanProcessorDependencies
): Promise<{ scanId: string; status: ScanStatus; findingsCount: number }> {
  const startedAt = new Date();
  const metrics = deps.metrics ?? defaultMetrics;
  const log = (
    deps.logger ?? createRedactingLogger({ service: "worker", level: deps.config.LOG_LEVEL })
  ).child({ scanId });

  const [scanRow] = await deps.db.select().from(scans).where(eq(scans.id, scanId));
  if (!scanRow) {
    throw new Error(`SCAN_NOT_FOUND: Scan ${scanId} does not exist.`);
  }

  if (scanRow.status === "CANCELLED") {
    return { scanId, status: "CANCELLED", findingsCount: 0 };
  }

  const [projectRow] = await deps.db
    .select()
    .from(projects)
    .where(and(eq(projects.id, scanRow.projectId), eq(projects.organizationId, scanRow.organizationId)));

  const [repoRow] = await deps.db
    .select()
    .from(projectRepositories)
    .where(
      and(
        eq(projectRepositories.id, scanRow.repositoryId),
        eq(projectRepositories.organizationId, scanRow.organizationId)
      )
    );

  const [orgRow] = await deps.db
    .select()
    .from(organizations)
    .where(eq(organizations.id, scanRow.organizationId));

  if (!projectRow || !repoRow || !orgRow) {
    throw new Error(`SCAN_CONTEXT_MISSING: Project, repository, or organization missing for scan ${scanId}.`);
  }

  let cleanupWorkspace: (() => Promise<void>) | undefined;

  let peakRssBytes = process.memoryUsage().rss;
  let peakHeapUsedBytes = process.memoryUsage().heapUsed;
  const sampleMemory = () => {
    const mem = process.memoryUsage();
    if (mem.rss > peakRssBytes) peakRssBytes = mem.rss;
    if (mem.heapUsed > peakHeapUsedBytes) peakHeapUsedBytes = mem.heapUsed;
  };
  const stageTimings = {
    ingestMs: 0,
    scanMs: 0,
    parseNormalizeMs: 0,
    persistMs: 0,
    aiMs: 0,
    artifactMs: 0
  };

  try {
    // 1. INITIALIZING
    await deps.db
      .update(scans)
      .set({ status: "INITIALIZING", startedAt, updatedAt: new Date() })
      .where(eq(scans.id, scanId));

    // Resolve GitHub installation numeric ID if needed
    let ghInstallationNumber: number | undefined;
    if (repoRow.provider === "GITHUB" && repoRow.githubInstallationId) {
      const [inst] = await deps.db
        .select()
        .from(githubInstallations)
        .where(
          and(
            eq(githubInstallations.id, repoRow.githubInstallationId),
            eq(githubInstallations.organizationId, scanRow.organizationId)
          )
        );
      ghInstallationNumber = inst?.installationId;
    }

    // 2. CLONING / TRUSTED INGESTION
    if (await isScanCancelled(deps.db, scanId)) {
      return { scanId, status: "CANCELLED", findingsCount: 0 };
    }
    await deps.db
      .update(scans)
      .set({ status: "CLONING", updatedAt: new Date() })
      .where(eq(scans.id, scanId));

    const ingestStart = Date.now();
    const ingested = await ingestRepositoryForScan({
      scanId,
      provider: repoRow.provider === "LOCAL_FIXTURE" ? "LOCAL_FIXTURE" : "GITHUB",
      repositoryFullName: repoRow.fullName,
      branch: scanRow.branch || repoRow.defaultBranch,
      githubInstallationId: ghInstallationNumber,
      localFixturePath: repoRow.localFixturePath ?? undefined,
      workspacesRoot: deps.config.SCANNER_WORKSPACES_ROOT,
      timeoutMs: Math.min(deps.config.SCANNER_TIMEOUT_MS, 90_000),
      githubAppClient: deps.githubAppClient
    });
    stageTimings.ingestMs = Date.now() - ingestStart;
    metrics.observe("indicative_scan_stage_duration_ms", stageTimings.ingestMs, { stage: "ingest" });
    sampleMemory();
    cleanupWorkspace = ingested.cleanup;

    await deps.db
      .update(scans)
      .set({
        branch: ingested.branch,
        commitSha: ingested.commitSha,
        commitMessage: ingested.commitMessage,
        status: "SCANNING",
        updatedAt: new Date()
      })
      .where(eq(scans.id, scanId));

    if (await isScanCancelled(deps.db, scanId)) {
      return { scanId, status: "CANCELLED", findingsCount: 0 };
    }

    // 3. ISOLATED SCANNER EXECUTION
    const requestedScanners =
      Array.isArray(scanRow.requestedScanners) && scanRow.requestedScanners.length > 0
        ? scanRow.requestedScanners
        : ["semgrep", "trivy", "gitleaks"];

    const scanExecStart = Date.now();
    let runnerResp: RunnerExecutionResponse;
    if (deps.config.SCANNER_RUNNER_MODE === "http" && !deps.localRunner) {
      runnerResp = await invokeRemoteScannerRunner({
        config: deps.config,
        scanId,
        organizationId: scanRow.organizationId,
        projectId: scanRow.projectId,
        workspacePath: ingested.workspacePath,
        scanners: requestedScanners
      });
    } else if (deps.localRunner) {
      runnerResp = await deps.localRunner.executeScan({
        scanId,
        organizationId: scanRow.organizationId,
        projectId: scanRow.projectId,
        workspacePath: ingested.workspacePath,
        scanners: requestedScanners,
        secretFingerprintKey: deps.config.SECRET_FINGERPRINT_KEY
      });
    } else {
      throw new Error("SCANNER_RUNNER_UNCONFIGURED: Neither localRunner nor HTTP runner is configured.");
    }
    stageTimings.scanMs = Date.now() - scanExecStart;
    metrics.observe("indicative_scan_stage_duration_ms", stageTimings.scanMs, { stage: "scan" });
    sampleMemory();

    // Persist scanner_runs provenance records
    const persistedScannerRuns: ScannerRunSummary[] = [];
    for (const r of runnerResp.results) {
      metrics.observe("indicative_scanner_duration_ms", r.durationMs, {
        scanner: r.scanner,
        status: r.status
      });
      if (r.status !== "SUCCESS") {
        metrics.inc("indicative_scanner_failures_total", {
          scanner: r.scanner,
          error_class: r.errorClass
        });
      }

      const [insertedRun] = await deps.db
        .insert(scannerRuns)
        .values({
          organizationId: scanRow.organizationId,
          scanId,
          scanner: r.scanner,
          scannerVersion: r.scannerVersion,
          rulesetVersion: r.rulesetVersion,
          status: r.status,
          exitCode: r.exitCode,
          findingsCount: r.findings.length,
          errorClass: r.errorClass,
          errorMessage: r.errorMessage,
          limitations: r.limitations,
          resourceUsage: r.resourceUsage,
          durationMs: r.durationMs,
          startedAt: new Date(r.startedAt),
          completedAt: new Date(r.completedAt)
        })
        .returning();

      persistedScannerRuns.push({
        id: insertedRun!.id,
        scanner: r.scanner,
        scannerVersion: r.scannerVersion,
        rulesetVersion: r.rulesetVersion,
        status: r.status,
        exitCode: r.exitCode,
        findingsCount: r.findings.length,
        durationMs: r.durationMs,
        errorClass: r.errorClass,
        errorMessage: r.errorMessage,
        limitations: r.limitations,
        startedAt: r.startedAt,
        completedAt: r.completedAt
      });
    }

    // 4. ANALYZING — NORMALIZATION, DEDUPLICATION, COMPARISON & PERSISTENCE
    await deps.db
      .update(scans)
      .set({ status: "ANALYZING", updatedAt: new Date() })
      .where(eq(scans.id, scanId));

    const normalizeStart = Date.now();
    const allRawFindings = runnerResp.results.flatMap((r) => r.findings);
    const normalizedBundles = normalizeAndDeduplicateFindings({
      organizationId: scanRow.organizationId,
      projectId: scanRow.projectId,
      scanId,
      rawFindings: allRawFindings
    });
    stageTimings.parseNormalizeMs = Date.now() - normalizeStart;
    metrics.observe("indicative_scan_stage_duration_ms", stageTimings.parseNormalizeMs, {
      stage: "parse_normalize"
    });
    sampleMemory();

    const persistStart = Date.now();

    // Fetch previous completed scan and existing project findings for comparison/verification
    const previousScans = await deps.db
      .select({ id: scans.id })
      .from(scans)
      .where(
        and(
          eq(scans.organizationId, scanRow.organizationId),
          eq(scans.projectId, scanRow.projectId),
          ne(scans.id, scanId)
        )
      )
      .orderBy(desc(scans.createdAt))
      .limit(1);
    const previousScanId = previousScans[0]?.id ?? null;

    const existingRows = await deps.db
      .select()
      .from(findings)
      .where(
        and(
          eq(findings.organizationId, scanRow.organizationId),
          eq(findings.projectId, scanRow.projectId)
        )
      );

    const existingByFingerprint = new Map(existingRows.map((row) => [row.fingerprint, row]));
    const detectedFingerprints = new Set(normalizedBundles.map((b) => b.finding.fingerprint));

    const comparisonPlan = computeScanComparisonAndVerification({
      currentScanId: scanId,
      previousScanId,
      existingFindings: existingRows.map((row) => ({
        id: row.id,
        fingerprint: row.fingerprint,
        scanner: row.scanner,
        category: row.category,
        status: row.status as FindingStatus,
        exposureLocation: row.exposureLocation
      })),
      detectedFingerprints,
      scannerOutcomes: runnerResp.results.map((r) => ({
        scanner: r.scanner,
        status: r.status,
        hasScopeLimitations: r.limitations.some(
          (l) =>
            l.code === "NO_GIT_HISTORY" ||
            l.code === "SHALLOW_CLONE_HISTORY_TRUNCATED" ||
            l.code === "GIT_HISTORY_SCAN_FAILED"
        )
      }))
    });

    const recurringDecisionMap = new Map(
      comparisonPlan.recurringDecisions.map((d) => [d.findingId, d])
    );

    const persistedFindingsForReport: SecurityFinding[] = [];
    const newFindingIds: string[] = [];

    for (const bundle of normalizedBundles) {
      const f = bundle.finding;
      const existing = existingByFingerprint.get(f.fingerprint);
      let findingId: string;
      let effectiveStatus: FindingStatus = "OPEN";
      let firstSeenAt = new Date(f.firstSeenAt);

      if (!existing) {
        const [inserted] = await deps.db
          .insert(findings)
          .values({
            fingerprint: f.fingerprint,
            organizationId: scanRow.organizationId,
            projectId: scanRow.projectId,
            latestScanId: scanId,
            scanner: f.scanner,
            scannerVersion: f.scannerVersion,
            rulesetVersion: f.rulesetVersion,
            ruleId: f.ruleId,
            category: f.category,
            title: f.title,
            description: f.description,
            severity: f.severity,
            originalSeverity: f.originalSeverity,
            confidence: f.confidence,
            riskPriority: f.riskPriority,
            riskRationale: f.riskRationale,
            filePath: f.filePath,
            lineStart: f.lineStart,
            lineEnd: f.lineEnd,
            packageName: f.packageName,
            installedVersion: f.installedVersion,
            fixedVersion: f.fixedVersion,
            cve: f.cve,
            cvssScore: f.cvssScore,
            secretType: f.secretType,
            secretFingerprint: f.secretFingerprint,
            secretValidity: f.secretValidity,
            commitSha: f.commitSha,
            commitTimestamp: f.commitTimestamp ? new Date(f.commitTimestamp) : null,
            exposureLocation: f.exposureLocation,
            remediation: f.remediation,
            status: "OPEN",
            verificationState: "DETECTED",
            occurrenceCount: bundle.occurrences.length,
            firstSeenAt,
            lastSeenAt: new Date()
          })
          .returning();

        findingId = inserted!.id;
        newFindingIds.push(findingId);

        await deps.db.insert(findingStatusHistory).values({
          organizationId: scanRow.organizationId,
          findingId,
          fromStatus: null,
          toStatus: "OPEN",
          reason: `First detected in scan ${scanId} by ${f.scanner} (${f.scannerVersion}).`,
          changedBySystem: true,
          scanId
        });
      } else {
        findingId = existing.id;
        firstSeenAt = existing.firstSeenAt;
        const decision = recurringDecisionMap.get(findingId);
        effectiveStatus = decision?.nextStatus ?? (existing.status as FindingStatus);

        await deps.db
          .update(findings)
          .set({
            latestScanId: scanId,
            scannerVersion: f.scannerVersion,
            rulesetVersion: f.rulesetVersion,
            severity: f.severity,
            confidence: f.confidence,
            riskPriority: f.riskPriority,
            riskRationale: f.riskRationale,
            filePath: f.filePath,
            lineStart: f.lineStart,
            lineEnd: f.lineEnd,
            fixedVersion: f.fixedVersion,
            exposureLocation: f.exposureLocation ?? existing.exposureLocation,
            status: effectiveStatus,
            verificationState: "DETECTED",
            occurrenceCount: bundle.occurrences.length,
            lastSeenAt: new Date(),
            updatedAt: new Date()
          })
          .where(eq(findings.id, findingId));

        if (decision?.statusChanged) {
          await deps.db.insert(findingStatusHistory).values({
            organizationId: scanRow.organizationId,
            findingId,
            fromStatus: decision.previousStatus,
            toStatus: decision.nextStatus,
            reason: decision.reason,
            changedBySystem: true,
            scanId
          });
        }
      }

      // Record occurrences for this scan
      for (const occ of bundle.occurrences) {
        await deps.db.insert(findingOccurrences).values({
          organizationId: scanRow.organizationId,
          findingId,
          scanId,
          filePath: occ.filePath,
          lineStart: occ.lineStart,
          lineEnd: occ.lineEnd,
          commitSha: occ.commitSha,
          commitTimestamp: occ.commitTimestamp ? new Date(occ.commitTimestamp) : null,
          exposureLocation: occ.exposureLocation,
          redactedSnippet: occ.redactedSnippet
        });
      }

      // Record evidence for this scan
      for (const ev of f.evidence) {
        await deps.db.insert(findingEvidence).values({
          organizationId: scanRow.organizationId,
          findingId,
          scanId,
          evidenceType: ev.type,
          label: ev.label,
          content: ev.content,
          filePath: ev.filePath,
          lineStart: ev.lineStart,
          lineEnd: ev.lineEnd,
          commitSha: ev.commitSha,
          referenceUrl: ev.referenceUrl,
          metadata: ev.metadata ?? {}
        });
      }

      persistedFindingsForReport.push({
        ...f,
        id: findingId,
        status: effectiveStatus,
        verificationState: "DETECTED",
        firstSeenAt: firstSeenAt.toISOString(),
        lastSeenAt: new Date().toISOString()
      });
    }

    // Apply verification updates for previously open findings no longer detected
    for (const decision of comparisonPlan.missingDecisions) {
      await deps.db
        .update(findings)
        .set({
          status: decision.nextStatus,
          verificationState: decision.verificationState,
          updatedAt: new Date()
        })
        .where(eq(findings.id, decision.findingId));

      if (decision.statusChanged) {
        await deps.db.insert(findingStatusHistory).values({
          organizationId: scanRow.organizationId,
          findingId: decision.findingId,
          fromStatus: decision.previousStatus,
          toStatus: decision.nextStatus,
          reason: decision.reason,
          changedBySystem: true,
          scanId
        });
      }
    }

    comparisonPlan.comparison.newFindingIds = newFindingIds;
    stageTimings.persistMs = Date.now() - persistStart;
    metrics.observe("indicative_scan_stage_duration_ms", stageTimings.persistMs, {
      stage: "persist"
    });
    sampleMemory();

    // 5. OPTIONAL AI ANALYSIS (only if requested AND configured; limited to top 5 critical/high findings)
    const aiStart = Date.now();
    if (scanRow.runAiAnalysis && deps.aiAnalyst?.isEnabled) {
      const topFindings = persistedFindingsForReport
        .filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH")
        .slice(0, 5);

      for (const target of topFindings) {
        try {
          const aiRes = await deps.aiAnalyst.analyzeFinding({ finding: target });
          metrics.observe("indicative_ai_latency_ms", aiRes.latencyMs, {
            model: aiRes.model
          });
          if (aiRes.totalTokens) {
            metrics.inc("indicative_ai_tokens_total", { model: aiRes.model }, aiRes.totalTokens);
          }

          await deps.db.insert(findingAiAnalyses).values({
            organizationId: scanRow.organizationId,
            findingId: target.id,
            provider: aiRes.provider,
            model: aiRes.model,
            promptVersion: aiRes.promptVersion,
            analysisJson: aiRes.analysis as unknown as Record<string, unknown>,
            promptTokens: aiRes.promptTokens,
            completionTokens: aiRes.completionTokens,
            totalTokens: aiRes.totalTokens,
            latencyMs: aiRes.latencyMs
          });
        } catch (aiErr) {
          metrics.inc("indicative_ai_failures_total", { reason: "analysis_error" });
          log.warn("Optional AI analysis failed for finding; continuing deterministic scan", {
            findingId: target.id,
            error: (aiErr as Error).message
          });
        }
      }
    }
    stageTimings.aiMs = Date.now() - aiStart;
    metrics.observe("indicative_scan_stage_duration_ms", stageTimings.aiMs, { stage: "ai" });
    sampleMemory();

    // 6. FINALIZE SCAN STATUS & ARCHIVE REDACTED ARTIFACTS
    const artifactStart = Date.now();
    const finalStatus = determineFinalScanStatus(runnerResp.results);
    const completedAt = new Date();
    const durationMs = completedAt.getTime() - startedAt.getTime();

    const allLimitations: ScannerLimitation[] = runnerResp.limitations;

    // Store redacted JSON & SARIF reports in artifact storage with retention expiry
    const expiresAt = new Date(
      Date.now() + deps.config.ARTIFACT_RETENTION_DAYS * 24 * 60 * 60 * 1000
    );
    const reportCtx = {
      generatedAt: completedAt.toISOString(),
      organizationName: orgRow.name,
      projectName: projectRow.name,
      repositoryFullName: repoRow.fullName,
      isDemo: projectRow.isDemo,
      scan: {
        id: scanId,
        branch: ingested.branch,
        commitSha: ingested.commitSha,
        status: finalStatus,
        startedAt: startedAt.toISOString(),
        completedAt: completedAt.toISOString(),
        durationMs,
        limitations: allLimitations
      },
      scannerRuns: persistedScannerRuns,
      findings: persistedFindingsForReport
    };

    const jsonReport = exportReportAsJson(reportCtx);
    const sarifReport = exportReportAsSarif(reportCtx);

    const jsonStored = await deps.artifactStorage.putObject(
      `${scanRow.organizationId}/${scanRow.projectId}/${scanId}/report.json`,
      jsonReport,
      "application/json"
    );
    const sarifStored = await deps.artifactStorage.putObject(
      `${scanRow.organizationId}/${scanRow.projectId}/${scanId}/report.sarif.json`,
      sarifReport,
      "application/sarif+json"
    );

    await deps.db.insert(scanArtifacts).values([
      {
        organizationId: scanRow.organizationId,
        scanId,
        artifactType: "NORMALIZED_REPORT_JSON",
        storageKey: jsonStored.storageKey,
        contentType: jsonStored.contentType,
        sizeBytes: jsonStored.sizeBytes,
        sha256: jsonStored.sha256,
        redacted: true,
        expiresAt
      },
      {
        organizationId: scanRow.organizationId,
        scanId,
        artifactType: "SARIF",
        storageKey: sarifStored.storageKey,
        contentType: sarifStored.contentType,
        sizeBytes: sarifStored.sizeBytes,
        sha256: sarifStored.sha256,
        redacted: true,
        expiresAt
      }
    ]);

    stageTimings.artifactMs = Date.now() - artifactStart;
    metrics.observe("indicative_scan_stage_duration_ms", stageTimings.artifactMs, {
      stage: "artifact"
    });
    sampleMemory();

    const peakRssMb = Math.round((peakRssBytes / (1024 * 1024)) * 10) / 10;
    const peakHeapUsedMb = Math.round((peakHeapUsedBytes / (1024 * 1024)) * 10) / 10;
    metrics.setGauge("indicative_worker_peak_rss_bytes", peakRssBytes);
    metrics.setGauge("indicative_worker_heap_used_bytes", peakHeapUsedBytes);

    const summaryCounts = {
      total: persistedFindingsForReport.length,
      critical: persistedFindingsForReport.filter((f) => f.severity === "CRITICAL").length,
      high: persistedFindingsForReport.filter((f) => f.severity === "HIGH").length,
      medium: persistedFindingsForReport.filter((f) => f.severity === "MEDIUM").length,
      low: persistedFindingsForReport.filter((f) => f.severity === "LOW").length,
      info: persistedFindingsForReport.filter((f) => f.severity === "INFO").length,
      unknown: persistedFindingsForReport.filter((f) => f.severity === "UNKNOWN").length,
      newFindings: newFindingIds.length,
      recurringFindings: comparisonPlan.comparison.recurringFindingIds.length,
      notDetectedFindings: comparisonPlan.comparison.notDetectedFindingIds.length,
      reopenedFindings: comparisonPlan.comparison.reopenedFindingIds.length,
      ingestMs: stageTimings.ingestMs,
      scanMs: stageTimings.scanMs,
      parseNormalizeMs: stageTimings.parseNormalizeMs,
      persistMs: stageTimings.persistMs,
      aiMs: stageTimings.aiMs,
      artifactMs: stageTimings.artifactMs,
      peakRssMb,
      peakHeapUsedMb
    };

    await deps.db
      .update(scans)
      .set({
        status: finalStatus,
        summaryCounts,
        comparisonSummary: comparisonPlan.comparison as unknown as Record<string, unknown>,
        limitations: allLimitations,
        completedAt,
        durationMs,
        updatedAt: new Date()
      })
      .where(eq(scans.id, scanId));

    await deps.db.insert(auditEvents).values({
      organizationId: scanRow.organizationId,
      actorUserId: scanRow.initiatedByUserId,
      action: "SCAN_COMPLETED",
      resourceType: "SCAN",
      resourceId: scanId,
      correlationId: scanRow.correlationId,
      metadata: {
        status: finalStatus,
        findingsCount: persistedFindingsForReport.length,
        durationMs,
        stageTimings,
        peakRssMb,
        peakHeapUsedMb
      }
    });

    metrics.inc("indicative_scans_total", { status: finalStatus });
    metrics.observe("indicative_scan_duration_ms", durationMs, { status: finalStatus });

    log.info("Scan pipeline completed", {
      status: finalStatus,
      findingsCount: persistedFindingsForReport.length,
      durationMs,
      stageTimings,
      peakRssMb,
      peakHeapUsedMb
    });

    return {
      scanId,
      status: finalStatus,
      findingsCount: persistedFindingsForReport.length
    };
  } catch (err) {
    const errMessage = redactSecretsInText((err as Error).message);
    metrics.inc("indicative_scans_total", { status: "FAILED" });
    log.error("Scan pipeline failed", { error: errMessage });

    await deps.db
      .update(scans)
      .set({
        status: "FAILED",
        failureReason: errMessage,
        completedAt: new Date(),
        durationMs: Date.now() - startedAt.getTime(),
        updatedAt: new Date()
      })
      .where(eq(scans.id, scanId));

    return { scanId, status: "FAILED", findingsCount: 0 };
  } finally {
    if (cleanupWorkspace) {
      await cleanupWorkspace();
    }
  }
}

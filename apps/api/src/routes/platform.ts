import os from "node:os";
import path from "node:path";
import type { FastifyInstance } from "fastify";
import { and, desc, eq, gte, ilike, inArray, lte, or, sql } from "drizzle-orm";
import type { AppConfig } from "@indicative/config";
import {
  AiAdvisorQuestionRequestSchema,
  CreateProjectRequestSchema,
  CreateScanRequestSchema,
  DEFAULT_SCANNERS,
  FindingsFilterQuerySchema,
  FindingStatusTransitionRequestSchema,
  RegisterGitHubInstallationSchema,
  ReportFormatSchema,
  type FindingCategory,
  type FindingConfidence,
  type FindingSeverity,
  type FindingStatus,
  type RiskPriority,
  type ScannerRunSummary,
  type SecurityFinding,
  type VerificationState
} from "@indicative/contracts";
import {
  auditEvents,
  findingAiAnalyses,
  findingEvidence,
  findingOccurrences,
  findings,
  findingStatusHistory,
  githubInstallations,
  integrations,
  projectRepositories,
  projects,
  scanArtifacts,
  scannerMetadata,
  scannerRuns,
  scans,
  securityPolicies,
  type Database
} from "@indicative/database";
import {
  assertValidStatusTransition,
  streamReportAsCsv,
  streamReportAsJson,
  streamReportAsSarif,
  type ReportExportContext
} from "@indicative/findings";
import type { AiSecurityAnalyst } from "@indicative/ai";
import type { GitHubAppClient, ScanJobEnqueuer } from "@indicative/worker";
import {
  validateGitHubRepositorySlug,
  validateSafePathWithinRoot
} from "@indicative/security";
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  RateLimitError,
  ValidationError
} from "@indicative/shared";
import type { AuthContext } from "../middleware/auth.js";

export interface PlatformRouteDeps {
  db: Database;
  config: AppConfig;
  enqueuer: ScanJobEnqueuer;
  aiAnalyst: AiSecurityAnalyst;
  githubAppClient?: GitHubAppClient;
  requireAuth: (req: any, reply: any) => Promise<void>;
}

const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function assertUuidParam(value: string, label: string): string {
  if (!UUID_REGEX.test(value)) {
    throw new ValidationError(`Invalid ${label} identifier format (expected UUID).`);
  }
  return value;
}

function validateAllowedFixturePath(rawPath: string): string {
  const resolved = path.resolve(rawPath);
  const allowedRoots = [
    path.resolve(process.cwd(), "tests/fixtures"),
    path.resolve(os.tmpdir())
  ];
  for (const root of allowedRoots) {
    try {
      return validateSafePathWithinRoot(root, resolved);
    } catch {
      // try next approved root
    }
  }
  throw new ForbiddenError(
    "localFixturePath must reside inside the approved fixtures directory or temporary test directory."
  );
}

function slugify(input: string): string {
  return (
    input
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 64) || "project"
  );
}

function mapFindingRowToContract(
  row: typeof findings.$inferSelect,
  evidenceRows: Array<typeof findingEvidence.$inferSelect> = []
): SecurityFinding {
  return {
    id: row.id,
    fingerprint: row.fingerprint,
    organizationId: row.organizationId,
    projectId: row.projectId,
    scanId: row.latestScanId,
    scanner: row.scanner,
    scannerVersion: row.scannerVersion,
    rulesetVersion: row.rulesetVersion ?? undefined,
    ruleId: row.ruleId,
    category: row.category as FindingCategory,
    title: row.title,
    description: row.description,
    severity: row.severity as FindingSeverity,
    originalSeverity: row.originalSeverity ?? undefined,
    confidence: row.confidence as FindingConfidence,
    riskPriority: row.riskPriority as RiskPriority,
    riskRationale: Array.isArray(row.riskRationale) ? row.riskRationale : [],
    filePath: row.filePath ?? undefined,
    lineStart: row.lineStart ?? undefined,
    lineEnd: row.lineEnd ?? undefined,
    packageName: row.packageName ?? undefined,
    installedVersion: row.installedVersion ?? undefined,
    fixedVersion: row.fixedVersion ?? undefined,
    cve: row.cve ?? undefined,
    cvssScore: row.cvssScore ?? undefined,
    secretType: row.secretType ?? undefined,
    secretFingerprint: row.secretFingerprint ?? undefined,
    secretValidity: (row.secretValidity as "UNKNOWN" | "NOT_VERIFIED") ?? undefined,
    commitSha: row.commitSha ?? undefined,
    commitTimestamp: row.commitTimestamp?.toISOString(),
    exposureLocation: (row.exposureLocation as "WORKING_TREE" | "GIT_HISTORY" | "BOTH") ?? undefined,
    evidence: evidenceRows.map((e) => ({
      id: e.id,
      type: e.evidenceType as SecurityFinding["evidence"][number]["type"],
      label: e.label,
      content: e.content,
      filePath: e.filePath ?? undefined,
      lineStart: e.lineStart ?? undefined,
      lineEnd: e.lineEnd ?? undefined,
      commitSha: e.commitSha ?? undefined,
      referenceUrl: e.referenceUrl ?? undefined
    })),
    remediation: row.remediation ?? undefined,
    status: row.status as FindingStatus,
    verificationState: row.verificationState as VerificationState,
    occurrenceCount: row.occurrenceCount,
    firstSeenAt: row.firstSeenAt.toISOString(),
    lastSeenAt: row.lastSeenAt.toISOString()
  };
}

export function registerPlatformRoutes(app: FastifyInstance, deps: PlatformRouteDeps) {
  // ==========================================================================
  // Dashboard Summary
  // ==========================================================================
  app.get("/api/v1/dashboard", { preHandler: [deps.requireAuth] }, async (request) => {
    const auth = request.auth as AuthContext;

    const orgProjects = await deps.db
      .select()
      .from(projects)
      .where(eq(projects.organizationId, auth.organizationId));

    const orgFindings = await deps.db
      .select()
      .from(findings)
      .where(eq(findings.organizationId, auth.organizationId));

    const recentScans = await deps.db
      .select({
        id: scans.id,
        projectId: scans.projectId,
        projectName: projects.name,
        repositoryFullName: projectRepositories.fullName,
        branch: scans.branch,
        commitSha: scans.commitSha,
        status: scans.status,
        isDemoScan: scans.isDemoScan,
        summaryCounts: scans.summaryCounts,
        durationMs: scans.durationMs,
        createdAt: scans.createdAt,
        completedAt: scans.completedAt
      })
      .from(scans)
      .innerJoin(projects, eq(scans.projectId, projects.id))
      .innerJoin(projectRepositories, eq(scans.repositoryId, projectRepositories.id))
      .where(eq(scans.organizationId, auth.organizationId))
      .orderBy(desc(scans.createdAt))
      .limit(10);

    const recentActivity = await deps.db
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.organizationId, auth.organizationId))
      .orderBy(desc(auditEvents.createdAt))
      .limit(15);

    const openStatuses = new Set(["OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "REOPENED", "FIXED_PENDING_VERIFICATION"]);
    const openFindings = orgFindings.filter((f) => openStatuses.has(f.status));
    const resolvedFindings = orgFindings.filter(
      (f) =>
        f.status === "RESOLVED_VERIFIED" ||
        f.verificationState === "NOT_DETECTED_IN_LATEST_SCAN" ||
        f.verificationState === "VERIFICATION_SUCCESSFUL_WITHIN_SCANNED_SCOPE"
    );
    const inconclusiveFindings = orgFindings.filter(
      (f) => f.verificationState === "VERIFICATION_INCONCLUSIVE"
    );

    const allScannedProjects = await deps.db
      .select({ projectId: scans.projectId })
      .from(scans)
      .where(eq(scans.organizationId, auth.organizationId));
    const scannedRepoIds = new Set(allScannedProjects.map((s) => s.projectId));

    const severityBreakdown = {
      critical: openFindings.filter((f) => f.severity === "CRITICAL").length,
      high: openFindings.filter((f) => f.severity === "HIGH").length,
      medium: openFindings.filter((f) => f.severity === "MEDIUM").length,
      low: openFindings.filter((f) => f.severity === "LOW").length,
      info: openFindings.filter((f) => f.severity === "INFO").length,
      unknown: openFindings.filter((f) => f.severity === "UNKNOWN").length
    };

    const categoryBreakdown = {
      SAST: openFindings.filter((f) => f.category === "SAST").length,
      SCA: openFindings.filter((f) => f.category === "SCA").length,
      SECRET: openFindings.filter((f) => f.category === "SECRET").length,
      IAC: openFindings.filter((f) => f.category === "IAC").length,
      CICD: openFindings.filter((f) => f.category === "CICD").length,
      CLOUD_IDENTITY: openFindings.filter((f) => f.category === "CLOUD_IDENTITY").length
    };

    const scanners = await deps.db.select().from(scannerMetadata);

    const securityTrends = recentScans
      .slice()
      .reverse()
      .map((s) => ({
        scanId: s.id,
        projectName: s.projectName,
        timestamp: s.createdAt.toISOString(),
        status: s.status,
        total: Number(s.summaryCounts?.total ?? 0),
        critical: Number(s.summaryCounts?.critical ?? 0),
        high: Number(s.summaryCounts?.high ?? 0),
        medium: Number(s.summaryCounts?.medium ?? 0),
        low: Number(s.summaryCounts?.low ?? 0)
      }));

    return {
      totals: {
        projects: orgProjects.length,
        repositoriesScanned: scannedRepoIds.size,
        openFindings: openFindings.length,
        resolvedOrNotDetected: resolvedFindings.length,
        inconclusiveVerification: inconclusiveFindings.length,
        ...severityBreakdown
      },
      categoryBreakdown,
      scanners,
      recentScans,
      securityTrends,
      recentActivity
    };
  });

  // ==========================================================================
  // GitHub Integrations
  // ==========================================================================
  app.post(
    "/api/v1/integrations/github/installations",
    { preHandler: [deps.requireAuth] },
    async (request, reply) => {
      const auth = request.auth as AuthContext;
      const parsed = RegisterGitHubInstallationSchema.safeParse(request.body);
      if (!parsed.success) {
        throw new ValidationError("Invalid GitHub installation payload", parsed.error.issues);
      }

      const [integration] = await deps.db
        .insert(integrations)
        .values({
          organizationId: auth.organizationId,
          provider: "GITHUB_APP",
          status: "ACTIVE",
          configMetadata: { accountLogin: parsed.data.accountLogin }
        })
        .returning();

      const existing = await deps.db
        .select()
        .from(githubInstallations)
        .where(
          and(
            eq(githubInstallations.organizationId, auth.organizationId),
            eq(githubInstallations.installationId, parsed.data.installationId)
          )
        );

      let installation = existing[0];
      if (!installation) {
        [installation] = await deps.db
          .insert(githubInstallations)
          .values({
            organizationId: auth.organizationId,
            integrationId: integration!.id,
            installationId: parsed.data.installationId,
            accountLogin: parsed.data.accountLogin,
            accountType: parsed.data.accountType,
            permissions: { contents: "read", metadata: "read" },
            status: "ACTIVE"
          })
          .returning();
      }

      await deps.db.insert(auditEvents).values({
        organizationId: auth.organizationId,
        actorUserId: auth.userId,
        action: "GITHUB_INSTALLATION_REGISTERED",
        resourceType: "GITHUB_INSTALLATION",
        resourceId: installation!.id,
        correlationId: request.correlationId,
        ipAddress: request.ip,
        metadata: {
          installationId: parsed.data.installationId,
          accountLogin: parsed.data.accountLogin
        }
      });

      return reply.status(201).send({ installation });
    }
  );

  app.get(
    "/api/v1/integrations/github/installations",
    { preHandler: [deps.requireAuth] },
    async (request) => {
      const auth = request.auth as AuthContext;
      const list = await deps.db
        .select()
        .from(githubInstallations)
        .where(eq(githubInstallations.organizationId, auth.organizationId));
      return { installations: list };
    }
  );

  app.get(
    "/api/v1/integrations/github/repositories",
    { preHandler: [deps.requireAuth] },
    async (request) => {
      const auth = request.auth as AuthContext;
      const installations = await deps.db
        .select()
        .from(githubInstallations)
        .where(
          and(
            eq(githubInstallations.organizationId, auth.organizationId),
            eq(githubInstallations.status, "ACTIVE")
          )
        );

      if (installations.length === 0) {
        return { repositories: [], installationsCount: 0 };
      }

      if (!deps.githubAppClient) {
        return {
          repositories: [],
          installationsCount: installations.length,
          warning:
            "GitHub App credentials (GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY) are not configured on this server."
        };
      }

      const discovered: Array<{
        githubInstallationDbId: string;
        installationId: number;
        accountLogin: string;
        externalRepoId: string;
        fullName: string;
        defaultBranch: string;
        isPrivate: boolean;
        htmlUrl: string;
        description: string | null;
      }> = [];

      for (const inst of installations) {
        const repos = await deps.githubAppClient.listInstallationRepositories(
          inst.installationId
        );
        for (const repo of repos) {
          discovered.push({
            githubInstallationDbId: inst.id,
            installationId: inst.installationId,
            accountLogin: inst.accountLogin,
            ...repo
          });
        }
      }

      return { repositories: discovered, installationsCount: installations.length };
    }
  );

  // ==========================================================================
  // Projects
  // ==========================================================================
  app.post("/api/v1/projects", { preHandler: [deps.requireAuth] }, async (request, reply) => {
    const auth = request.auth as AuthContext;
    const parsed = CreateProjectRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      throw new ValidationError("Invalid project payload", parsed.error.issues);
    }

    const slug = validateGitHubRepositorySlug(parsed.data.repositoryFullName);
    const projectSlug = slugify(parsed.data.name);

    // Local fixture projects are strictly restricted to non-production DEMO_MODE and approved roots
    const isLocalFixture = Boolean(parsed.data.localFixturePath);
    let safeFixturePath: string | null = null;
    if (isLocalFixture) {
      if (deps.config.NODE_ENV === "production" || !deps.config.DEMO_MODE) {
        throw new ForbiddenError("Local fixture repositories are only allowed in development demo mode.");
      }
      safeFixturePath = validateAllowedFixturePath(parsed.data.localFixturePath!);
    }

    if (parsed.data.githubInstallationId) {
      const [inst] = await deps.db
        .select()
        .from(githubInstallations)
        .where(
          and(
            eq(githubInstallations.id, parsed.data.githubInstallationId),
            eq(githubInstallations.organizationId, auth.organizationId)
          )
        );
      if (!inst) {
        throw new NotFoundError("GitHub installation");
      }
    }

    const existingSlug = await deps.db
      .select()
      .from(projects)
      .where(
        and(eq(projects.organizationId, auth.organizationId), eq(projects.slug, projectSlug))
      );
    const finalSlug =
      existingSlug.length > 0 ? `${projectSlug}-${Date.now().toString(36)}` : projectSlug;

    const [createdProject] = await deps.db
      .insert(projects)
      .values({
        organizationId: auth.organizationId,
        name: parsed.data.name,
        slug: finalSlug,
        description: parsed.data.description ?? null,
        isDemo: isLocalFixture
      })
      .returning();

    const [createdRepo] = await deps.db
      .insert(projectRepositories)
      .values({
        organizationId: auth.organizationId,
        projectId: createdProject!.id,
        githubInstallationId: parsed.data.githubInstallationId ?? null,
        provider: isLocalFixture ? "LOCAL_FIXTURE" : "GITHUB",
        externalRepoId: parsed.data.externalRepoId ?? null,
        fullName: slug.fullName,
        defaultBranch: parsed.data.defaultBranch,
        isPrivate: parsed.data.isPrivate,
        localFixturePath: safeFixturePath
      })
      .returning();

    await deps.db.insert(auditEvents).values({
      organizationId: auth.organizationId,
      actorUserId: auth.userId,
      action: "PROJECT_CREATED",
      resourceType: "PROJECT",
      resourceId: createdProject!.id,
      correlationId: request.correlationId,
      ipAddress: request.ip,
      metadata: { repositoryFullName: slug.fullName, isDemo: isLocalFixture }
    });

    return reply.status(201).send({
      project: createdProject,
      repository: createdRepo
    });
  });

  app.get("/api/v1/projects", { preHandler: [deps.requireAuth] }, async (request) => {
    const auth = request.auth as AuthContext;
    const rows = await deps.db
      .select({
        project: projects,
        repository: projectRepositories
      })
      .from(projects)
      .leftJoin(projectRepositories, eq(projectRepositories.projectId, projects.id))
      .where(eq(projects.organizationId, auth.organizationId))
      .orderBy(desc(projects.createdAt));

    const result = await Promise.all(
      rows.map(async (r) => {
        const [latestScan] = await deps.db
          .select()
          .from(scans)
          .where(
            and(
              eq(scans.organizationId, auth.organizationId),
              eq(scans.projectId, r.project.id)
            )
          )
          .orderBy(desc(scans.createdAt))
          .limit(1);

        const openFindings = await deps.db
          .select({ severity: findings.severity })
          .from(findings)
          .where(
            and(
              eq(findings.organizationId, auth.organizationId),
              eq(findings.projectId, r.project.id),
              inArray(findings.status, [
                "OPEN",
                "ACKNOWLEDGED",
                "IN_PROGRESS",
                "REOPENED",
                "FIXED_PENDING_VERIFICATION"
              ])
            )
          );

        return {
          ...r.project,
          repository: r.repository,
          latestScan: latestScan ?? null,
          openFindingsSummary: {
            total: openFindings.length,
            critical: openFindings.filter((f) => f.severity === "CRITICAL").length,
            high: openFindings.filter((f) => f.severity === "HIGH").length,
            medium: openFindings.filter((f) => f.severity === "MEDIUM").length,
            low: openFindings.filter((f) => f.severity === "LOW").length
          }
        };
      })
    );

    return { projects: result };
  });

  app.get("/api/v1/projects/:projectId", { preHandler: [deps.requireAuth] }, async (request) => {
    const auth = request.auth as AuthContext;
    const projectId = assertUuidParam((request.params as { projectId: string }).projectId, "projectId");

    const [project] = await deps.db
      .select()
      .from(projects)
      .where(
        and(eq(projects.id, projectId), eq(projects.organizationId, auth.organizationId))
      );
    if (!project) throw new NotFoundError("Project");

    const [repository] = await deps.db
      .select()
      .from(projectRepositories)
      .where(
        and(
          eq(projectRepositories.projectId, projectId),
          eq(projectRepositories.organizationId, auth.organizationId)
        )
      );

    const projectScans = await deps.db
      .select()
      .from(scans)
      .where(
        and(eq(scans.projectId, projectId), eq(scans.organizationId, auth.organizationId))
      )
      .orderBy(desc(scans.createdAt))
      .limit(20);

    return { project, repository, recentScans: projectScans };
  });

  // ==========================================================================
  // Scans
  // ==========================================================================
  app.post(
    "/api/v1/projects/:projectId/scans",
    { preHandler: [deps.requireAuth] },
    async (request, reply) => {
      const auth = request.auth as AuthContext;
      const projectId = assertUuidParam((request.params as { projectId: string }).projectId, "projectId");

      const parsed = CreateScanRequestSchema.safeParse(request.body ?? {});
      if (!parsed.success) {
        throw new ValidationError("Invalid scan initiation request", parsed.error.issues);
      }

      const [project] = await deps.db
        .select()
        .from(projects)
        .where(
          and(eq(projects.id, projectId), eq(projects.organizationId, auth.organizationId))
        );
      if (!project) throw new NotFoundError("Project");

      const [repo] = await deps.db
        .select()
        .from(projectRepositories)
        .where(
          and(
            eq(projectRepositories.projectId, projectId),
            eq(projectRepositories.organizationId, auth.organizationId)
          )
        );
      if (!repo) throw new NotFoundError("Project repository");

      const headerIdempotency = request.headers["idempotency-key"];
      const idempotencyKey =
        parsed.data.idempotencyKey ||
        (typeof headerIdempotency === "string" && headerIdempotency.trim().length >= 8
          ? headerIdempotency.trim()
          : undefined);

      // Idempotent scan initiation: return existing scan if idempotencyKey matches
      if (idempotencyKey) {
        const [existing] = await deps.db
          .select()
          .from(scans)
          .where(
            and(
              eq(scans.organizationId, auth.organizationId),
              eq(scans.projectId, projectId),
              eq(scans.idempotencyKey, idempotencyKey)
            )
          );
        if (existing) {
          return reply.status(200).send({ scan: existing, deduplicated: true });
        }
      }

      // Enforce per-organization active concurrent scan limit (honoring security_policies when present)
      const [orgPolicy] = await deps.db
        .select()
        .from(securityPolicies)
        .where(eq(securityPolicies.organizationId, auth.organizationId));
      const maxConcurrent = Math.min(
        deps.config.MAX_CONCURRENT_SCANS_PER_ORG,
        orgPolicy?.maxConcurrentScans ?? deps.config.MAX_CONCURRENT_SCANS_PER_ORG
      );

      const activeScans = await deps.db
        .select({ id: scans.id })
        .from(scans)
        .where(
          and(
            eq(scans.organizationId, auth.organizationId),
            inArray(scans.status, ["QUEUED", "INITIALIZING", "CLONING", "SCANNING", "ANALYZING"])
          )
        );

      if (activeScans.length >= maxConcurrent) {
        throw new RateLimitError(
          `Organization already has ${activeScans.length} active scans (limit: ${maxConcurrent}).`
        );
      }

      const [createdScan] = await deps.db
        .insert(scans)
        .values({
          organizationId: auth.organizationId,
          projectId,
          repositoryId: repo.id,
          initiatedByUserId: auth.userId,
          idempotencyKey: idempotencyKey ?? null,
          triggerSource: project.isDemo ? "DEMO" : "MANUAL",
          branch: parsed.data.branch || repo.defaultBranch,
          status: "QUEUED",
          requestedScanners: parsed.data.scanners ?? [...DEFAULT_SCANNERS],
          runAiAnalysis:
            parsed.data.runAiAnalysis && (orgPolicy?.allowAiAnalysis ?? true),
          isDemoScan: project.isDemo,
          correlationId: request.correlationId
        })
        .returning();

      await deps.db.insert(auditEvents).values({
        organizationId: auth.organizationId,
        actorUserId: auth.userId,
        action: "SCAN_INITIATED",
        resourceType: "SCAN",
        resourceId: createdScan!.id,
        correlationId: request.correlationId,
        ipAddress: request.ip,
        metadata: {
          projectId,
          branch: createdScan!.branch,
          scanners: createdScan!.requestedScanners
        }
      });

      const { jobId } = await deps.enqueuer.enqueue({
        scanId: createdScan!.id,
        organizationId: auth.organizationId,
        projectId,
        correlationId: request.correlationId
      });

      return reply.status(202).send({ scan: createdScan, jobId });
    }
  );

  app.get(
    "/api/v1/projects/:projectId/scans",
    { preHandler: [deps.requireAuth] },
    async (request) => {
      const auth = request.auth as AuthContext;
      const { projectId } = request.params as { projectId: string };

      const [project] = await deps.db
        .select({ id: projects.id })
        .from(projects)
        .where(
          and(eq(projects.id, projectId), eq(projects.organizationId, auth.organizationId))
        );
      if (!project) throw new NotFoundError("Project");

      const list = await deps.db
        .select()
        .from(scans)
        .where(
          and(eq(scans.projectId, projectId), eq(scans.organizationId, auth.organizationId))
        )
        .orderBy(desc(scans.createdAt))
        .limit(50);

      return { scans: list };
    }
  );

  app.get("/api/v1/scans/:scanId", { preHandler: [deps.requireAuth] }, async (request) => {
    const auth = request.auth as AuthContext;
    const scanId = assertUuidParam((request.params as { scanId: string }).scanId, "scanId");

    const [scan] = await deps.db
      .select()
      .from(scans)
      .where(and(eq(scans.id, scanId), eq(scans.organizationId, auth.organizationId)));
    if (!scan) throw new NotFoundError("Scan");

    const [project] = await deps.db
      .select()
      .from(projects)
      .where(eq(projects.id, scan.projectId));
    const [repository] = await deps.db
      .select()
      .from(projectRepositories)
      .where(eq(projectRepositories.id, scan.repositoryId));

    const runs = await deps.db
      .select()
      .from(scannerRuns)
      .where(
        and(eq(scannerRuns.scanId, scanId), eq(scannerRuns.organizationId, auth.organizationId))
      );

    const artifacts = await deps.db
      .select()
      .from(scanArtifacts)
      .where(
        and(
          eq(scanArtifacts.scanId, scanId),
          eq(scanArtifacts.organizationId, auth.organizationId)
        )
      );

    return {
      scan,
      project,
      repository,
      scannerRuns: runs,
      artifacts
    };
  });

  app.post(
    "/api/v1/scans/:scanId/cancel",
    { preHandler: [deps.requireAuth] },
    async (request) => {
      const auth = request.auth as AuthContext;
      const { scanId } = request.params as { scanId: string };

      const [scan] = await deps.db
        .select()
        .from(scans)
        .where(and(eq(scans.id, scanId), eq(scans.organizationId, auth.organizationId)));
      if (!scan) throw new NotFoundError("Scan");

      if (["COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED", "CANCELLED"].includes(scan.status)) {
        throw new ConflictError(`Scan is already in terminal state "${scan.status}".`);
      }

      const [updated] = await deps.db
        .update(scans)
        .set({
          status: "CANCELLED",
          failureReason: "Cancelled by user.",
          completedAt: new Date(),
          updatedAt: new Date()
        })
        .where(and(eq(scans.id, scanId), eq(scans.organizationId, auth.organizationId)))
        .returning();

      await deps.enqueuer.cancel(scanId);

      await deps.db.insert(auditEvents).values({
        organizationId: auth.organizationId,
        actorUserId: auth.userId,
        action: "SCAN_CANCELLED",
        resourceType: "SCAN",
        resourceId: scanId,
        correlationId: request.correlationId,
        ipAddress: request.ip
      });

      return { scan: updated };
    }
  );

  // ==========================================================================
  // Findings
  // ==========================================================================
  async function queryFindings(
    auth: AuthContext,
    rawQuery: unknown,
    forcedProjectId?: string
  ) {
    const parsed = FindingsFilterQuerySchema.safeParse(rawQuery ?? {});
    if (!parsed.success) {
      throw new ValidationError("Invalid findings filter query", parsed.error.issues);
    }
    const q = parsed.data;
    const projectId = forcedProjectId ?? q.projectId;

    const conditions = [eq(findings.organizationId, auth.organizationId)];
    if (projectId) conditions.push(eq(findings.projectId, projectId));
    if (q.scanId) conditions.push(eq(findings.latestScanId, q.scanId));
    if (q.severity) conditions.push(eq(findings.severity, q.severity));
    if (q.riskPriority) conditions.push(eq(findings.riskPriority, q.riskPriority));
    if (q.category) conditions.push(eq(findings.category, q.category));
    if (q.scanner) conditions.push(eq(findings.scanner, q.scanner));
    if (q.status) conditions.push(eq(findings.status, q.status));
    if (q.confidence) conditions.push(eq(findings.confidence, q.confidence));
    if (q.fromDate) conditions.push(gte(findings.lastSeenAt, new Date(q.fromDate)));
    if (q.toDate) conditions.push(lte(findings.lastSeenAt, new Date(q.toDate)));
    if (q.search) {
      const pattern = `%${q.search}%`;
      conditions.push(
        or(
          ilike(findings.title, pattern),
          ilike(findings.description, pattern),
          ilike(findings.ruleId, pattern),
          ilike(findings.filePath, pattern),
          ilike(findings.packageName, pattern),
          ilike(findings.cve, pattern)
        )!
      );
    }

    const whereClause = and(...conditions);
    const offset = (q.page - 1) * q.pageSize;

    const rows = await deps.db
      .select()
      .from(findings)
      .where(whereClause)
      .orderBy(desc(findings.lastSeenAt))
      .limit(q.pageSize)
      .offset(offset);

    const [countRow] = await deps.db
      .select({ count: sql<number>`count(*)::int` })
      .from(findings)
      .where(whereClause);

    const total = Number(countRow?.count ?? 0);

    // Attach latest evidence items for each finding
    const findingIds = rows.map((r) => r.id);
    const evidenceRows =
      findingIds.length > 0
        ? await deps.db
            .select()
            .from(findingEvidence)
            .where(
              and(
                eq(findingEvidence.organizationId, auth.organizationId),
                inArray(findingEvidence.findingId, findingIds)
              )
            )
        : [];

    const evidenceByFinding = new Map<string, Array<typeof findingEvidence.$inferSelect>>();
    for (const ev of evidenceRows) {
      const arr = evidenceByFinding.get(ev.findingId) ?? [];
      arr.push(ev);
      evidenceByFinding.set(ev.findingId, arr);
    }

    return {
      findings: rows.map((r) => mapFindingRowToContract(r, evidenceByFinding.get(r.id) ?? [])),
      pagination: {
        page: q.page,
        pageSize: q.pageSize,
        total,
        totalPages: Math.max(1, Math.ceil(total / q.pageSize))
      }
    };
  }

  app.get("/api/v1/findings", { preHandler: [deps.requireAuth] }, async (request) => {
    return queryFindings(request.auth as AuthContext, request.query);
  });

  app.get(
    "/api/v1/projects/:projectId/findings",
    { preHandler: [deps.requireAuth] },
    async (request) => {
      const auth = request.auth as AuthContext;
      const { projectId } = request.params as { projectId: string };
      const [project] = await deps.db
        .select({ id: projects.id })
        .from(projects)
        .where(
          and(eq(projects.id, projectId), eq(projects.organizationId, auth.organizationId))
        );
      if (!project) throw new NotFoundError("Project");
      return queryFindings(auth, request.query, projectId);
    }
  );

  app.get("/api/v1/findings/:findingId", { preHandler: [deps.requireAuth] }, async (request) => {
    const auth = request.auth as AuthContext;
    const findingId = assertUuidParam(
      (request.params as { findingId: string }).findingId,
      "findingId"
    );

    const [row] = await deps.db
      .select()
      .from(findings)
      .where(
        and(eq(findings.id, findingId), eq(findings.organizationId, auth.organizationId))
      );
    if (!row) throw new NotFoundError("Finding");

    const [project] = await deps.db
      .select()
      .from(projects)
      .where(eq(projects.id, row.projectId));

    const evidenceRows = await deps.db
      .select()
      .from(findingEvidence)
      .where(
        and(
          eq(findingEvidence.findingId, findingId),
          eq(findingEvidence.organizationId, auth.organizationId)
        )
      )
      .orderBy(desc(findingEvidence.createdAt));

    const occurrenceRows = await deps.db
      .select()
      .from(findingOccurrences)
      .where(
        and(
          eq(findingOccurrences.findingId, findingId),
          eq(findingOccurrences.organizationId, auth.organizationId)
        )
      )
      .orderBy(desc(findingOccurrences.detectedAt));

    const historyRows = await deps.db
      .select()
      .from(findingStatusHistory)
      .where(
        and(
          eq(findingStatusHistory.findingId, findingId),
          eq(findingStatusHistory.organizationId, auth.organizationId)
        )
      )
      .orderBy(desc(findingStatusHistory.createdAt));

    const aiRows = await deps.db
      .select()
      .from(findingAiAnalyses)
      .where(
        and(
          eq(findingAiAnalyses.findingId, findingId),
          eq(findingAiAnalyses.organizationId, auth.organizationId)
        )
      )
      .orderBy(desc(findingAiAnalyses.createdAt));

    return {
      finding: mapFindingRowToContract(row, evidenceRows),
      project,
      occurrences: occurrenceRows,
      statusHistory: historyRows,
      aiAnalyses: aiRows
    };
  });

  app.patch(
    "/api/v1/findings/:findingId/status",
    { preHandler: [deps.requireAuth] },
    async (request) => {
      const auth = request.auth as AuthContext;
      const findingId = assertUuidParam(
        (request.params as { findingId: string }).findingId,
        "findingId"
      );

      const parsed = FindingStatusTransitionRequestSchema.safeParse(request.body);
      if (!parsed.success) {
        throw new ValidationError("Invalid status update payload", parsed.error.issues);
      }

      const [existing] = await deps.db
        .select()
        .from(findings)
        .where(
          and(eq(findings.id, findingId), eq(findings.organizationId, auth.organizationId))
        );
      if (!existing) throw new NotFoundError("Finding");

      try {
        assertValidStatusTransition(existing.status as FindingStatus, parsed.data.status);
      } catch (err) {
        throw new ValidationError((err as Error).message);
      }

      const [updated] = await deps.db
        .update(findings)
        .set({ status: parsed.data.status, updatedAt: new Date() })
        .where(
          and(eq(findings.id, findingId), eq(findings.organizationId, auth.organizationId))
        )
        .returning();

      const [historyEntry] = await deps.db
        .insert(findingStatusHistory)
        .values({
          organizationId: auth.organizationId,
          findingId,
          fromStatus: existing.status,
          toStatus: parsed.data.status,
          reason: parsed.data.reason,
          changedByUserId: auth.userId,
          changedBySystem: false
        })
        .returning();

      await deps.db.insert(auditEvents).values({
        organizationId: auth.organizationId,
        actorUserId: auth.userId,
        action: "FINDING_STATUS_UPDATED",
        resourceType: "FINDING",
        resourceId: findingId,
        correlationId: request.correlationId,
        ipAddress: request.ip,
        metadata: {
          fromStatus: existing.status,
          toStatus: parsed.data.status,
          reason: parsed.data.reason
        }
      });

      return { finding: mapFindingRowToContract(updated!), historyEntry };
    }
  );

  app.get(
    "/api/v1/findings/:findingId/history",
    { preHandler: [deps.requireAuth] },
    async (request) => {
      const auth = request.auth as AuthContext;
      const { findingId } = request.params as { findingId: string };

      const [existing] = await deps.db
        .select({ id: findings.id })
        .from(findings)
        .where(
          and(eq(findings.id, findingId), eq(findings.organizationId, auth.organizationId))
        );
      if (!existing) throw new NotFoundError("Finding");

      const statusHistory = await deps.db
        .select()
        .from(findingStatusHistory)
        .where(
          and(
            eq(findingStatusHistory.findingId, findingId),
            eq(findingStatusHistory.organizationId, auth.organizationId)
          )
        )
        .orderBy(desc(findingStatusHistory.createdAt));

      const occurrences = await deps.db
        .select()
        .from(findingOccurrences)
        .where(
          and(
            eq(findingOccurrences.findingId, findingId),
            eq(findingOccurrences.organizationId, auth.organizationId)
          )
        )
        .orderBy(desc(findingOccurrences.detectedAt));

      return { findingId, statusHistory, occurrences };
    }
  );

  // ==========================================================================
  // AI Contextual Analysis & Scoped AI Security Advisor
  // ==========================================================================
  app.post(
    "/api/v1/findings/:findingId/analyze",
    { preHandler: [deps.requireAuth] },
    async (request, reply) => {
      const auth = request.auth as AuthContext;
      const findingId = assertUuidParam(
        (request.params as { findingId: string }).findingId,
        "findingId"
      );

      const [orgPolicy] = await deps.db
        .select()
        .from(securityPolicies)
        .where(eq(securityPolicies.organizationId, auth.organizationId));
      if (orgPolicy && !orgPolicy.allowAiAnalysis) {
        throw new ForbiddenError("AI analysis is disabled by organization security policy.");
      }

      if (!deps.aiAnalyst.isEnabled) {
        return reply.status(503).send({
          error: {
            code: "AI_DISABLED",
            message:
              "AI Security Analyst is disabled because no LLM provider API key is configured. Deterministic findings remain fully available.",
            correlationId: request.correlationId
          }
        });
      }

      const [row] = await deps.db
        .select()
        .from(findings)
        .where(
          and(eq(findings.id, findingId), eq(findings.organizationId, auth.organizationId))
        );
      if (!row) throw new NotFoundError("Finding");

      const evidenceRows = await deps.db
        .select()
        .from(findingEvidence)
        .where(
          and(
            eq(findingEvidence.findingId, findingId),
            eq(findingEvidence.organizationId, auth.organizationId)
          )
        );

      const findingObj = mapFindingRowToContract(row, evidenceRows);
      const aiResult = await deps.aiAnalyst.analyzeFinding({ finding: findingObj });

      const [saved] = await deps.db
        .insert(findingAiAnalyses)
        .values({
          organizationId: auth.organizationId,
          findingId,
          provider: aiResult.provider,
          model: aiResult.model,
          promptVersion: aiResult.promptVersion,
          analysisJson: aiResult.analysis as unknown as Record<string, unknown>,
          promptTokens: aiResult.promptTokens,
          completionTokens: aiResult.completionTokens,
          totalTokens: aiResult.totalTokens,
          latencyMs: aiResult.latencyMs
        })
        .returning();

      await deps.db.insert(auditEvents).values({
        organizationId: auth.organizationId,
        actorUserId: auth.userId,
        action: "FINDING_AI_ANALYZED",
        resourceType: "FINDING",
        resourceId: findingId,
        correlationId: request.correlationId,
        ipAddress: request.ip,
        metadata: {
          model: aiResult.model,
          promptVersion: aiResult.promptVersion,
          totalTokens: aiResult.totalTokens ?? 0,
          injectionSignalsDetected: aiResult.injectionSignalsDetected.length
        }
      });

      return { analysis: saved };
    }
  );

  app.post(
    "/api/v1/advisor/ask",
    { preHandler: [deps.requireAuth] },
    async (request, reply) => {
      const auth = request.auth as AuthContext;
      const parsed = AiAdvisorQuestionRequestSchema.safeParse(request.body);
      if (!parsed.success) {
        throw new ValidationError("Invalid AI Advisor request", parsed.error.issues);
      }

      if (!deps.aiAnalyst.isEnabled) {
        return reply.status(503).send({
          error: {
            code: "AI_DISABLED",
            message:
              "AI Security Advisor is disabled because no LLM provider is configured. Configure AI_PROVIDER=openai-compatible and AI_API_KEY.",
            correlationId: request.correlationId
          }
        });
      }

      const [orgPolicy] = await deps.db
        .select()
        .from(securityPolicies)
        .where(eq(securityPolicies.organizationId, auth.organizationId));
      if (orgPolicy && !orgPolicy.allowAiAnalysis) {
        throw new ForbiddenError("AI Security Advisor is disabled by organization security policy.");
      }

      const { scope, projectId, scanId, findingId, question } = parsed.data;

      // Enforce strict tenant authorization on selected project
      const [project] = await deps.db
        .select()
        .from(projects)
        .where(
          and(eq(projects.id, projectId), eq(projects.organizationId, auth.organizationId))
        );
      if (!project) throw new NotFoundError("Project");

      const conditions = [
        eq(findings.organizationId, auth.organizationId),
        eq(findings.projectId, projectId)
      ];
      let scopeLabel = `Project "${project.name}"`;
      let scanMetaSummary: string | undefined;

      if (scope === "scan" && scanId) {
        const [scan] = await deps.db
          .select()
          .from(scans)
          .where(
            and(
              eq(scans.id, scanId),
              eq(scans.projectId, projectId),
              eq(scans.organizationId, auth.organizationId)
            )
          );
        if (!scan) throw new NotFoundError("Scan");
        conditions.push(eq(findings.latestScanId, scanId));
        scopeLabel = `Project "${project.name}" / Scan ${scan.id} (${scan.status}, branch=${scan.branch}, commit=${scan.commitSha ?? "unknown"})`;
        scanMetaSummary = JSON.stringify(scan.summaryCounts);
      } else if (scope === "finding" && findingId) {
        conditions.push(eq(findings.id, findingId));
        scopeLabel = `Project "${project.name}" / Finding ${findingId}`;
      }

      const scopedRows = await deps.db
        .select()
        .from(findings)
        .where(and(...conditions))
        .limit(30);

      if (scope === "finding" && scopedRows.length === 0) {
        throw new NotFoundError("Finding");
      }

      const result = await deps.aiAnalyst.answerScopedQuestion({
        question,
        scopeLabel,
        findings: scopedRows.map((r) => mapFindingRowToContract(r)),
        scanMetadataSummary: scanMetaSummary
      });

      await deps.db.insert(auditEvents).values({
        organizationId: auth.organizationId,
        actorUserId: auth.userId,
        action: "AI_ADVISOR_QUESTION",
        resourceType: scope.toUpperCase(),
        resourceId: findingId ?? scanId ?? projectId,
        correlationId: request.correlationId,
        ipAddress: request.ip,
        metadata: {
          scope,
          model: result.answer.model,
          totalTokens: result.totalTokens ?? 0
        }
      });

      return result.answer;
    }
  );

  // ==========================================================================
  // Reports & Exports (JSON / SARIF 2.1.0 / CSV)
  // ==========================================================================
  app.get(
    "/api/v1/projects/:projectId/reports",
    { preHandler: [deps.requireAuth] },
    async (request) => {
      const auth = request.auth as AuthContext;
      const { projectId } = request.params as { projectId: string };

      const [project] = await deps.db
        .select()
        .from(projects)
        .where(
          and(eq(projects.id, projectId), eq(projects.organizationId, auth.organizationId))
        );
      if (!project) throw new NotFoundError("Project");

      const projectScans = await deps.db
        .select()
        .from(scans)
        .where(
          and(eq(scans.projectId, projectId), eq(scans.organizationId, auth.organizationId))
        )
        .orderBy(desc(scans.createdAt))
        .limit(25);

      return {
        project,
        reports: projectScans.map((s) => ({
          scanId: s.id,
          status: s.status,
          branch: s.branch,
          commitSha: s.commitSha,
          createdAt: s.createdAt,
          completedAt: s.completedAt,
          summaryCounts: s.summaryCounts,
          downloadUrls: {
            json: `/api/v1/scans/${s.id}/report?format=json`,
            sarif: `/api/v1/scans/${s.id}/report?format=sarif`,
            csv: `/api/v1/scans/${s.id}/report?format=csv`
          }
        }))
      };
    }
  );

  app.get(
    "/api/v1/scans/:scanId/report",
    { preHandler: [deps.requireAuth] },
    async (request, reply) => {
      const auth = request.auth as AuthContext;
      const { scanId } = request.params as { scanId: string };
      const query = request.query as { format?: string };
      const formatParsed = ReportFormatSchema.safeParse((query.format ?? "json").toLowerCase());
      if (!formatParsed.success) {
        throw new ValidationError("format must be one of: json, sarif, csv");
      }
      const format = formatParsed.data;

      const [scan] = await deps.db
        .select()
        .from(scans)
        .where(and(eq(scans.id, scanId), eq(scans.organizationId, auth.organizationId)));
      if (!scan) throw new NotFoundError("Scan");

      const [project] = await deps.db
        .select()
        .from(projects)
        .where(eq(projects.id, scan.projectId));
      const [repository] = await deps.db
        .select()
        .from(projectRepositories)
        .where(eq(projectRepositories.id, scan.repositoryId));

      const runs = await deps.db
        .select()
        .from(scannerRuns)
        .where(
          and(eq(scannerRuns.scanId, scanId), eq(scannerRuns.organizationId, auth.organizationId))
        );

      // Find all findings observed during this scan via finding_occurrences or latestScanId
      const scanOccs = await deps.db
        .select({ findingId: findingOccurrences.findingId })
        .from(findingOccurrences)
        .where(
          and(
            eq(findingOccurrences.scanId, scanId),
            eq(findingOccurrences.organizationId, auth.organizationId)
          )
        );
      const occFindingIds = [...new Set(scanOccs.map((o) => o.findingId))];

      const scanFindingsRows =
        occFindingIds.length > 0
          ? await deps.db
              .select()
              .from(findings)
              .where(
                and(
                  eq(findings.organizationId, auth.organizationId),
                  inArray(findings.id, occFindingIds)
                )
              )
          : await deps.db
              .select()
              .from(findings)
              .where(
                and(
                  eq(findings.organizationId, auth.organizationId),
                  eq(findings.latestScanId, scanId)
                )
              );

      const fIds = scanFindingsRows.map((f) => f.id);
      const evRows =
        fIds.length > 0
          ? await deps.db
              .select()
              .from(findingEvidence)
              .where(
                and(
                  eq(findingEvidence.organizationId, auth.organizationId),
                  inArray(findingEvidence.findingId, fIds)
                )
              )
          : [];
      const evMap = new Map<string, Array<typeof findingEvidence.$inferSelect>>();
      for (const e of evRows) {
        const list = evMap.get(e.findingId) ?? [];
        list.push(e);
        evMap.set(e.findingId, list);
      }

      const exportCtx: ReportExportContext = {
        generatedAt: new Date().toISOString(),
        organizationName: auth.organizationName,
        projectName: project!.name,
        repositoryFullName: repository!.fullName,
        isDemo: project!.isDemo,
        scan: {
          id: scan.id,
          branch: scan.branch,
          commitSha: scan.commitSha,
          status: scan.status,
          startedAt: scan.startedAt?.toISOString() ?? null,
          completedAt: scan.completedAt?.toISOString() ?? null,
          durationMs: scan.durationMs ?? null,
          limitations: Array.isArray(scan.limitations) ? scan.limitations : []
        },
        scannerRuns: runs.map(
          (r): ScannerRunSummary => ({
            id: r.id,
            scanner: r.scanner,
            scannerVersion: r.scannerVersion,
            rulesetVersion: r.rulesetVersion ?? undefined,
            status: r.status as ScannerRunSummary["status"],
            exitCode: r.exitCode,
            findingsCount: r.findingsCount,
            durationMs: r.durationMs,
            errorClass: r.errorClass,
            errorMessage: r.errorMessage ?? undefined,
            limitations: Array.isArray(r.limitations) ? r.limitations : [],
            startedAt: r.startedAt.toISOString(),
            completedAt: r.completedAt?.toISOString()
          })
        ),
        findings: scanFindingsRows.map((r) => mapFindingRowToContract(r, evMap.get(r.id) ?? []))
      };

      await deps.db.insert(auditEvents).values({
        organizationId: auth.organizationId,
        actorUserId: auth.userId,
        action: "SCAN_REPORT_EXPORTED",
        resourceType: "SCAN",
        resourceId: scanId,
        correlationId: request.correlationId,
        ipAddress: request.ip,
        metadata: { format, findingsCount: exportCtx.findings.length }
      });

      if (format === "sarif") {
        const sarifStream = streamReportAsSarif(exportCtx);
        return reply
          .header("Content-Type", "application/sarif+json; charset=utf-8")
          .header(
            "Content-Disposition",
            `attachment; filename="indicative-scan-${scanId.slice(0, 8)}.sarif.json"`
          )
          .send(sarifStream);
      }

      if (format === "csv") {
        const csvStream = streamReportAsCsv(exportCtx);
        return reply
          .header("Content-Type", "text/csv; charset=utf-8")
          .header(
            "Content-Disposition",
            `attachment; filename="indicative-scan-${scanId.slice(0, 8)}.csv"`
          )
          .send(csvStream);
      }

      const jsonStream = streamReportAsJson(exportCtx);
      return reply
        .header("Content-Type", "application/json; charset=utf-8")
        .header(
          "Content-Disposition",
          `attachment; filename="indicative-scan-${scanId.slice(0, 8)}.json"`
        )
        .send(jsonStream);
    }
  );

  // ==========================================================================
  // CI/CD Workflow & OIDC Security Intelligence View
  // ==========================================================================
  async function buildWorkflowSecuritySummary(
    auth: AuthContext,
    projectId?: string
  ) {
    const conditions = [
      eq(findings.organizationId, auth.organizationId),
      eq(findings.category, "CICD")
    ];
    if (projectId) {
      conditions.push(eq(findings.projectId, projectId));
    }

    const cicdRows = await deps.db
      .select()
      .from(findings)
      .where(and(...conditions))
      .orderBy(desc(findings.lastSeenAt))
      .limit(200);

    const findingIds = cicdRows.map((r) => r.id);
    const evRows =
      findingIds.length > 0
        ? await deps.db
            .select()
            .from(findingEvidence)
            .where(
              and(
                eq(findingEvidence.organizationId, auth.organizationId),
                inArray(findingEvidence.findingId, findingIds)
              )
            )
        : [];

    const evByFinding = new Map<string, Array<typeof findingEvidence.$inferSelect>>();
    for (const ev of evRows) {
      const list = evByFinding.get(ev.findingId) ?? [];
      list.push(ev);
      evByFinding.set(ev.findingId, list);
    }

    const mappedFindings = cicdRows.map((r) =>
      mapFindingRowToContract(r, evByFinding.get(r.id) ?? [])
    );

    const byFile = new Map<
      string,
      {
        filePath: string;
        kind: "WORKFLOW" | "OIDC_TRUST_POLICY";
        projectId: string;
        findingsCount: number;
        criticalCount: number;
        highCount: number;
        rulesTriggered: string[];
        oidcRelated: boolean;
      }
    >();

    for (const f of mappedFindings) {
      const key = `${f.projectId}:${f.filePath ?? "repository"}`;
      const isOidc = f.ruleId.startsWith("GHA-OIDC");
      const entry = byFile.get(key) ?? {
        filePath: f.filePath ?? "repository",
        kind: isOidc && !(f.filePath ?? "").includes(".github/workflows")
          ? "OIDC_TRUST_POLICY"
          : "WORKFLOW",
        projectId: f.projectId,
        findingsCount: 0,
        criticalCount: 0,
        highCount: 0,
        rulesTriggered: [],
        oidcRelated: false
      };
      entry.findingsCount += 1;
      if (f.severity === "CRITICAL") entry.criticalCount += 1;
      if (f.severity === "HIGH") entry.highCount += 1;
      if (!entry.rulesTriggered.includes(f.ruleId)) {
        entry.rulesTriggered.push(f.ruleId);
      }
      if (isOidc || f.ruleId === "GHA-PERM-004") {
        entry.oidcRelated = true;
      }
      byFile.set(key, entry);
    }

    const oidcFindings = mappedFindings.filter(
      (f) => f.ruleId.startsWith("GHA-OIDC") || f.ruleId === "GHA-PERM-004"
    );

    return {
      evidenceBasis: "STATIC_CONFIG",
      disclaimer:
        "Workflow and OIDC federation security data reflects deterministic static analysis of repository files. Live cloud IAM permissions, SCPs, and GitHub repository settings are not verified statically.",
      summary: {
        totalCicdFindings: mappedFindings.length,
        critical: mappedFindings.filter((f) => f.severity === "CRITICAL").length,
        high: mappedFindings.filter((f) => f.severity === "HIGH").length,
        medium: mappedFindings.filter((f) => f.severity === "MEDIUM").length,
        oidcFindingsCount: oidcFindings.length,
        affectedFilesCount: byFile.size
      },
      assets: [...byFile.values()],
      findings: mappedFindings
    };
  }

  app.get("/api/v1/workflows", { preHandler: [deps.requireAuth] }, async (request) => {
    const auth = request.auth as AuthContext;
    const query = request.query as { projectId?: string };
    const projectId = query.projectId ? assertUuidParam(query.projectId, "projectId") : undefined;
    return buildWorkflowSecuritySummary(auth, projectId);
  });

  app.get(
    "/api/v1/projects/:projectId/workflows",
    { preHandler: [deps.requireAuth] },
    async (request) => {
      const auth = request.auth as AuthContext;
      const projectId = assertUuidParam(
        (request.params as { projectId: string }).projectId,
        "projectId"
      );
      const [project] = await deps.db
        .select({ id: projects.id })
        .from(projects)
        .where(and(eq(projects.id, projectId), eq(projects.organizationId, auth.organizationId)));
      if (!project) throw new NotFoundError("Project");
      return buildWorkflowSecuritySummary(auth, projectId);
    }
  );

  app.get("/api/v1/scanners", { preHandler: [deps.requireAuth] }, async () => {
    const rows = await deps.db.select().from(scannerMetadata);
    return { scanners: rows };
  });
}

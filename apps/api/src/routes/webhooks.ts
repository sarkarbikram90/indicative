import type { FastifyInstance } from "fastify";
import { and, eq, inArray } from "drizzle-orm";
import type { AppConfig } from "@indicative/config";
import { isGitHubWebhookConfigured } from "@indicative/config";
import { DEFAULT_SCANNERS, type ScanTriggerMetadata } from "@indicative/contracts";
import {
  auditEvents,
  githubInstallations,
  projectRepositories,
  projects,
  scans,
  securityPolicies,
  webhookDeliveries,
  type Database
} from "@indicative/database";
import {
  redactSecretsInText,
  validateGitHubRepositorySlug,
  verifyGitHubWebhookSignature,
  type StructuredLogger
} from "@indicative/security";
import type { GitHubAppClient, ScanJobEnqueuer } from "@indicative/worker";
import { generateCorrelationId } from "@indicative/shared";

export interface WebhookRouteDeps {
  db: Database;
  config: AppConfig;
  enqueuer: ScanJobEnqueuer;
  githubAppClient?: GitHubAppClient;
  logger?: StructuredLogger;
}

interface GitHubPushPayload {
  ref?: string;
  after?: string;
  deleted?: boolean;
  repository?: {
    full_name?: string;
    default_branch?: string;
  };
  installation?: {
    id?: number;
  };
}

interface GitHubPullRequestPayload {
  action?: string;
  number?: number;
  pull_request?: {
    number?: number;
    html_url?: string;
    head?: {
      ref?: string;
      sha?: string;
      repo?: {
        full_name?: string;
        fork?: boolean;
      } | null;
    };
    base?: {
      ref?: string;
      repo?: {
        full_name?: string;
      } | null;
    };
  };
  repository?: {
    full_name?: string;
    default_branch?: string;
  };
  installation?: {
    id?: number;
  };
}

const PR_SCAN_ACTIONS = new Set(["opened", "synchronize", "reopened"]);

export function registerWebhookRoutes(
  app: FastifyInstance,
  deps: WebhookRouteDeps
): void {
  // Encapsulate raw-body JSON parsing strictly to webhook routes so X-Hub-Signature-256
  // is verified over the exact wire bytes.
  void app.register(async (webhookApp) => {
    webhookApp.addContentTypeParser(
      "application/json",
      { parseAs: "buffer" },
      (_req, body, done) => {
        done(null, body);
      }
    );

    webhookApp.post("/api/v1/webhooks/github", async (request, reply) => {
      if (!isGitHubWebhookConfigured(deps.config)) {
        return reply.status(503).send({
          error: {
            code: "WEBHOOK_NOT_CONFIGURED",
            message: "GITHUB_APP_WEBHOOK_SECRET is not configured on this server.",
            correlationId: request.correlationId
          }
        });
      }

      const rawBody = Buffer.isBuffer(request.body)
        ? request.body
        : Buffer.from(
            typeof request.body === "string"
              ? request.body
              : JSON.stringify(request.body ?? {}),
            "utf8"
          );

      const signature = request.headers["x-hub-signature-256"];
      const signatureHeader = typeof signature === "string" ? signature : undefined;
      const eventHeader = request.headers["x-github-event"];
      const eventType = typeof eventHeader === "string" ? eventHeader.trim() : "unknown";
      const deliveryHeader = request.headers["x-github-delivery"];
      const deliveryId =
        typeof deliveryHeader === "string" && deliveryHeader.trim().length > 0
          ? deliveryHeader.trim().slice(0, 128)
          : `synthetic-${generateCorrelationId()}`;

      const sigValid = verifyGitHubWebhookSignature(
        rawBody,
        signatureHeader,
        deps.config.GITHUB_APP_WEBHOOK_SECRET
      );

      if (!sigValid) {
        await deps.db
          .insert(webhookDeliveries)
          .values({
            deliveryId: `invalid-${deliveryId}-${Date.now()}`,
            provider: "GITHUB",
            eventType,
            signatureValid: false,
            status: "REJECTED",
            summary: "Invalid or missing X-Hub-Signature-256 HMAC signature."
          })
          .onConflictDoNothing();

        return reply.status(401).send({
          error: {
            code: "INVALID_WEBHOOK_SIGNATURE",
            message: "Webhook signature verification failed.",
            correlationId: request.correlationId
          }
        });
      }

      // Replay protection: check if this X-GitHub-Delivery was already accepted/processed
      const [existingDelivery] = await deps.db
        .select()
        .from(webhookDeliveries)
        .where(
          and(
            eq(webhookDeliveries.provider, "GITHUB"),
            eq(webhookDeliveries.deliveryId, deliveryId)
          )
        );

      if (existingDelivery) {
        return reply.status(200).send({
          status: "duplicate_ignored",
          deliveryId,
          scanId: existingDelivery.scanId
        });
      }

      let payload: Record<string, unknown>;
      try {
        payload = JSON.parse(rawBody.toString("utf8")) as Record<string, unknown>;
      } catch {
        return reply.status(400).send({
          error: {
            code: "INVALID_WEBHOOK_PAYLOAD",
            message: "Webhook body is not valid JSON.",
            correlationId: request.correlationId
          }
        });
      }

      if (eventType === "ping") {
        await deps.db.insert(webhookDeliveries).values({
          deliveryId,
          provider: "GITHUB",
          eventType: "ping",
          signatureValid: true,
          status: "ACCEPTED",
          summary: "GitHub webhook ping verified."
        });
        return reply.status(200).send({ status: "pong", deliveryId });
      }

      if (eventType !== "push" && eventType !== "pull_request") {
        await deps.db.insert(webhookDeliveries).values({
          deliveryId,
          provider: "GITHUB",
          eventType,
          signatureValid: true,
          status: "IGNORED",
          summary: `Unsupported event type "${eventType}" ignored.`
        });
        return reply.status(202).send({ status: "ignored", eventType, deliveryId });
      }

      let rawRepoFullName: string | undefined;
      let branch = "main";
      let headSha: string | undefined;
      let action: string | undefined;
      let triggerSource: "WEBHOOK_PUSH" | "WEBHOOK_PR" = "WEBHOOK_PUSH";
      let installationId: number | undefined;
      let pullRequestNumber: number | undefined;
      let pullRequestUrl: string | undefined;
      let baseBranch: string | undefined;
      let isForkPr = false;

      if (eventType === "push") {
        const push = payload as GitHubPushPayload;
        rawRepoFullName = push.repository?.full_name;
        installationId = push.installation?.id;
        headSha = push.after;
        if (push.deleted || push.after === "0000000000000000000000000000000000000000") {
          await deps.db.insert(webhookDeliveries).values({
            deliveryId,
            provider: "GITHUB",
            eventType,
            repositoryFullName: rawRepoFullName,
            signatureValid: true,
            status: "IGNORED",
            summary: "Branch deletion push event ignored."
          });
          return reply.status(202).send({ status: "ignored", reason: "branch_deleted", deliveryId });
        }
        if (typeof push.ref === "string" && push.ref.startsWith("refs/heads/")) {
          branch = push.ref.slice("refs/heads/".length);
        } else if (push.repository?.default_branch) {
          branch = push.repository.default_branch;
        }
      } else {
        const pr = payload as GitHubPullRequestPayload;
        action = pr.action;
        rawRepoFullName = pr.repository?.full_name;
        installationId = pr.installation?.id;
        triggerSource = "WEBHOOK_PR";

        if (!action || !PR_SCAN_ACTIONS.has(action)) {
          await deps.db.insert(webhookDeliveries).values({
            deliveryId,
            provider: "GITHUB",
            eventType,
            action,
            repositoryFullName: rawRepoFullName,
            signatureValid: true,
            status: "IGNORED",
            summary: `Pull request action "${action ?? "unknown"}" ignored.`
          });
          return reply.status(202).send({ status: "ignored", action, deliveryId });
        }

        pullRequestNumber = pr.pull_request?.number ?? pr.number;
        pullRequestUrl = pr.pull_request?.html_url;
        headSha = pr.pull_request?.head?.sha;
        baseBranch = pr.pull_request?.base?.ref ?? pr.repository?.default_branch ?? "main";
        const headRepoFull = pr.pull_request?.head?.repo?.full_name;
        const baseRepoFull = pr.pull_request?.base?.repo?.full_name ?? rawRepoFullName;
        isForkPr = Boolean(
          pr.pull_request?.head?.repo?.fork ||
            (headRepoFull && baseRepoFull && headRepoFull.toLowerCase() !== baseRepoFull.toLowerCase())
        );
        // For fork PRs, scan the base branch or refuse unsafe untrusted ref checkout
        branch = isForkPr ? baseBranch : pr.pull_request?.head?.ref ?? baseBranch;
      }

      if (!rawRepoFullName) {
        return reply.status(400).send({
          error: {
            code: "INVALID_WEBHOOK_PAYLOAD",
            message: "Missing repository.full_name in GitHub webhook payload.",
            correlationId: request.correlationId
          }
        });
      }

      let validatedSlug: string;
      try {
        validatedSlug = validateGitHubRepositorySlug(rawRepoFullName).fullName;
      } catch {
        return reply.status(400).send({
          error: {
            code: "INVALID_REPOSITORY_SLUG",
            message: "Invalid repository slug in webhook payload.",
            correlationId: request.correlationId
          }
        });
      }

      // Match connected Indicative projects by repository slug (and installationId when available)
      const matchedRepos = await deps.db
        .select()
        .from(projectRepositories)
        .where(eq(projectRepositories.fullName, validatedSlug));

      if (matchedRepos.length === 0) {
        await deps.db.insert(webhookDeliveries).values({
          deliveryId,
          provider: "GITHUB",
          eventType,
          action,
          repositoryFullName: validatedSlug,
          signatureValid: true,
          status: "IGNORED",
          summary: `No Indicative project connected for repository ${validatedSlug}.`
        });
        return reply.status(202).send({
          status: "ignored",
          reason: "repository_not_connected",
          repository: validatedSlug,
          deliveryId
        });
      }

      let targetRepo = matchedRepos[0]!;
      if (installationId && matchedRepos.length > 1) {
        const installs = await deps.db
          .select()
          .from(githubInstallations)
          .where(eq(githubInstallations.installationId, installationId));
        const installIds = new Set(installs.map((i) => i.id));
        const exact = matchedRepos.find(
          (r) => r.githubInstallationId && installIds.has(r.githubInstallationId)
        );
        if (exact) targetRepo = exact;
      }

      // Resolve installation number from DB if not present on payload
      let resolvedInstallationId = installationId;
      if (!resolvedInstallationId && targetRepo.githubInstallationId) {
        const [inst] = await deps.db
          .select()
          .from(githubInstallations)
          .where(eq(githubInstallations.id, targetRepo.githubInstallationId));
        resolvedInstallationId = inst?.installationId;
      }

      const [project] = await deps.db
        .select()
        .from(projects)
        .where(
          and(
            eq(projects.id, targetRepo.projectId),
            eq(projects.organizationId, targetRepo.organizationId)
          )
        );

      if (!project) {
        return reply.status(202).send({ status: "ignored", reason: "project_missing", deliveryId });
      }

      // Enforce organization security_policies.maxConcurrentScans
      const [policy] = await deps.db
        .select()
        .from(securityPolicies)
        .where(eq(securityPolicies.organizationId, targetRepo.organizationId));
      const maxConcurrent = policy?.maxConcurrentScans ?? deps.config.MAX_CONCURRENT_SCANS_PER_ORG;

      const activeScans = await deps.db
        .select({ id: scans.id })
        .from(scans)
        .where(
          and(
            eq(scans.organizationId, targetRepo.organizationId),
            inArray(scans.status, ["QUEUED", "INITIALIZING", "CLONING", "SCANNING", "ANALYZING"])
          )
        );

      if (activeScans.length >= maxConcurrent) {
        await deps.db.insert(webhookDeliveries).values({
          deliveryId,
          provider: "GITHUB",
          eventType,
          action,
          repositoryFullName: validatedSlug,
          organizationId: targetRepo.organizationId,
          projectId: targetRepo.projectId,
          signatureValid: true,
          status: "IGNORED",
          summary: `Concurrency limit (${maxConcurrent}) reached for organization.`
        });
        return reply.status(429).send({
          error: {
            code: "CONCURRENT_SCAN_LIMIT",
            message: `Organization concurrent scan limit (${maxConcurrent}) reached.`,
            correlationId: request.correlationId
          }
        });
      }

      // Create initial GitHub Check Run (in_progress) when configured
      let checkRunId: number | undefined;
      if (
        deps.config.GITHUB_WEBHOOK_CREATE_CHECK_RUNS &&
        deps.githubAppClient &&
        resolvedInstallationId &&
        headSha
      ) {
        try {
          const checkRes = await deps.githubAppClient.upsertCheckRun({
            installationId: resolvedInstallationId,
            repositoryFullName: validatedSlug,
            payload: {
              name: "Indicative Security Intelligence",
              headSha,
              status: "in_progress",
              title: "Running deterministic security scan...",
              summary: `Indicative has queued SAST, SCA, IaC, Secret, and CI/CD & OIDC analysis for \`${branch}\`.`
            }
          });
          checkRunId = checkRes.checkRunId;
        } catch (err) {
          deps.logger?.warn("Initial GitHub Check Run creation failed; continuing webhook scan", {
            deliveryId,
            error: redactSecretsInText((err as Error).message)
          });
        }
      }

      const triggerMetadata: ScanTriggerMetadata = {
        webhookDeliveryId: deliveryId,
        githubEvent: eventType,
        githubInstallationId: resolvedInstallationId,
        pullRequestNumber,
        pullRequestUrl,
        baseBranch,
        headBranch: branch,
        headSha,
        isForkPr,
        checkRunId
      };

      const idempotencyKey = `gh-${eventType}-${deliveryId}`.slice(0, 128);
      const [createdScan] = await deps.db
        .insert(scans)
        .values({
          organizationId: targetRepo.organizationId,
          projectId: targetRepo.projectId,
          repositoryId: targetRepo.id,
          idempotencyKey,
          triggerSource,
          triggerMetadata: triggerMetadata as Record<string, unknown>,
          branch,
          commitSha: headSha ?? null,
          status: "QUEUED",
          requestedScanners: [...DEFAULT_SCANNERS],
          runAiAnalysis: false,
          isDemoScan: project.isDemo,
          correlationId: request.correlationId
        })
        .returning();

      await deps.db.insert(webhookDeliveries).values({
        deliveryId,
        provider: "GITHUB",
        eventType,
        action,
        repositoryFullName: validatedSlug,
        organizationId: targetRepo.organizationId,
        projectId: targetRepo.projectId,
        scanId: createdScan!.id,
        signatureValid: true,
        status: "ACCEPTED",
        summary: `Triggered ${triggerSource} scan on ${branch}${pullRequestNumber ? ` (PR #${pullRequestNumber})` : ""}.`
      });

      await deps.db.insert(auditEvents).values({
        organizationId: targetRepo.organizationId,
        action: "WEBHOOK_SCAN_TRIGGERED",
        resourceType: "SCAN",
        resourceId: createdScan!.id,
        correlationId: request.correlationId,
        ipAddress: request.ip,
        metadata: {
          deliveryId,
          eventType,
          action,
          repositoryFullName: validatedSlug,
          branch,
          pullRequestNumber,
          checkRunId
        }
      });

      await deps.enqueuer.enqueue({
        scanId: createdScan!.id,
        organizationId: targetRepo.organizationId,
        projectId: targetRepo.projectId,
        correlationId: request.correlationId
      });

      return reply.status(202).send({
        status: "accepted",
        deliveryId,
        scanId: createdScan!.id,
        projectId: targetRepo.projectId,
        triggerSource,
        checkRunId
      });
    });
  });
}

import crypto from "node:crypto";
import Fastify from "fastify";
import { z } from "zod";
import { loadConfig } from "@indicative/config";
import { createRedactingLogger } from "@indicative/security";
import { createDefaultScannerRegistry } from "./adapters/registry.js";
import { createResourceLimits, describeSandboxRuntime } from "./resource-limits/limits.js";
import { IsolatedScannerRunner } from "./execution/runner.js";

const executeBodySchema = z.object({
  scanId: z.string().uuid(),
  organizationId: z.string().uuid(),
  projectId: z.string().uuid(),
  workspacePath: z.string().min(1),
  scanners: z.array(z.enum(["semgrep", "trivy", "gitleaks"])).min(1)
});

function verifySharedSecret(provided: string | undefined, expected: string): boolean {
  if (!provided) return false;
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function buildScannerRunnerServer() {
  const config = loadConfig();
  const logger = createRedactingLogger({
    service: "scanner-runner",
    level: config.LOG_LEVEL
  });

  const registry = createDefaultScannerRegistry({
    semgrepBin: config.SEMGREP_BIN,
    semgrepRulesDir: config.SEMGREP_RULES_DIR,
    trivyBin: config.TRIVY_BIN,
    trivyCacheDir: config.TRIVY_CACHE_DIR,
    trivyOfflineMode: true,
    gitleaksBin: config.GITLEAKS_BIN
  });

  const limits = createResourceLimits({
    maxRepoSizeBytes: config.MAX_REPO_SIZE_MB * 1024 * 1024,
    maxFilesPerScan: config.MAX_FILES_PER_SCAN,
    maxReportBytes: config.SCANNER_MAX_REPORT_BYTES,
    scannerTimeoutMs: config.SCANNER_TIMEOUT_MS,
    maxScanDurationMs: config.MAX_SCAN_DURATION_MS,
    maxGitHistoryCommits: config.MAX_GIT_HISTORY_COMMITS,
    sandboxRuntime: config.SCANNER_SANDBOX_RUNTIME
  });

  const runtimeDescriptor = describeSandboxRuntime(config.SCANNER_SANDBOX_RUNTIME);

  const runner = new IsolatedScannerRunner({
    registry,
    workspacesRoot: config.SCANNER_WORKSPACES_ROOT,
    limits,
    logger
  });

  const app = Fastify({ logger: false });

  app.get("/health", async () => {
    const health = await runner.healthCheck();
    return {
      status: health.ok ? "ok" : "degraded",
      sandboxRuntime: runtimeDescriptor.runtime,
      productionMultiTenantReady: runtimeDescriptor.productionMultiTenantReady,
      isolationSummary: runtimeDescriptor.isolationSummary,
      scanners: health.scanners
    };
  });

  app.post("/internal/v1/execute", async (request, reply) => {
    const authHeader = request.headers["x-scanner-runner-secret"];
    const token = Array.isArray(authHeader) ? authHeader[0] : authHeader;
    if (!verifySharedSecret(token, config.SCANNER_RUNNER_SHARED_SECRET)) {
      return reply.status(401).send({ error: "UNAUTHORIZED_RUNNER_CALL" });
    }

    const parsed = executeBodySchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({
        error: "INVALID_EXECUTION_REQUEST",
        issues: parsed.error.issues
      });
    }

    try {
      const result = await runner.executeScan({
        ...parsed.data,
        secretFingerprintKey: config.SECRET_FINGERPRINT_KEY
      });
      return reply.status(200).send(result);
    } catch (err) {
      logger.error("Scanner runner execution error", {
        scanId: parsed.data.scanId,
        error: (err as Error).message
      });
      return reply.status(500).send({
        error: "RUNNER_EXECUTION_FAILED",
        message: (err as Error).message
      });
    }
  });

  return { app, config, runner, logger };
}

const isMain = process.argv[1]?.endsWith("server.ts") || process.argv[1]?.endsWith("server.js");
if (isMain) {
  const { app, config, logger } = buildScannerRunnerServer();
  app
    .listen({ host: config.SCANNER_RUNNER_HOST, port: config.SCANNER_RUNNER_PORT })
    .then(() => {
      logger.info("Isolated scanner-runner listening", {
        host: config.SCANNER_RUNNER_HOST,
        port: config.SCANNER_RUNNER_PORT
      });
    })
    .catch((err) => {
      logger.error("Failed to start scanner-runner", { error: (err as Error).message });
      process.exit(1);
    });
}

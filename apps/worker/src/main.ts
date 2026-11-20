import { loadConfig, isAiConfigured, isGitHubAppConfigured } from "@indicative/config";
import { createPostgresConnection, runMigrations } from "@indicative/database";
import {
  AiSecurityAnalyst,
  DisabledAiProvider,
  OpenAiCompatibleProvider
} from "@indicative/ai";
import {
  createDefaultScannerRegistry,
  createResourceLimits,
  IsolatedScannerRunner
} from "@indicative/scanner-runner";
import { createRedactingLogger } from "@indicative/security";
import { LocalArtifactStorage, S3ArtifactStorage } from "@indicative/shared";
import { GitHubAppClient } from "./ingestion/githubApp.js";
import { startBullMqWorker } from "./jobs/scanQueue.js";

async function main() {
  const config = loadConfig();
  const logger = createRedactingLogger({ service: "worker", level: config.LOG_LEVEL });
  const dbConn = await createPostgresConnection(config.DATABASE_URL);
  await runMigrations(dbConn);

  const artifactStorage =
    config.ARTIFACT_STORAGE_DRIVER === "s3"
      ? new S3ArtifactStorage({
          endpoint: config.S3_ENDPOINT,
          region: config.S3_REGION,
          bucket: config.S3_BUCKET,
          accessKeyId: config.S3_ACCESS_KEY_ID,
          secretAccessKey: config.S3_SECRET_ACCESS_KEY,
          forcePathStyle: config.S3_FORCE_PATH_STYLE
        })
      : new LocalArtifactStorage(config.ARTIFACT_LOCAL_DIR);

  const localRunner =
    config.SCANNER_RUNNER_MODE === "local"
      ? new IsolatedScannerRunner({
          registry: createDefaultScannerRegistry({
            semgrepBin: config.SEMGREP_BIN,
            semgrepRulesDir: config.SEMGREP_RULES_DIR,
            trivyBin: config.TRIVY_BIN,
            trivyCacheDir: config.TRIVY_CACHE_DIR,
            gitleaksBin: config.GITLEAKS_BIN
          }),
          workspacesRoot: config.SCANNER_WORKSPACES_ROOT,
          limits: createResourceLimits({
            maxRepoSizeBytes: config.MAX_REPO_SIZE_MB * 1024 * 1024,
            maxFilesPerScan: config.MAX_FILES_PER_SCAN,
            scannerTimeoutMs: config.SCANNER_TIMEOUT_MS,
            maxScanDurationMs: config.MAX_SCAN_DURATION_MS,
            maxGitHistoryCommits: config.MAX_GIT_HISTORY_COMMITS
          }),
          logger
        })
      : undefined;

  const aiProvider = isAiConfigured(config)
    ? new OpenAiCompatibleProvider({
        baseUrl: config.AI_API_BASE_URL,
        apiKey: config.AI_API_KEY,
        model: config.AI_MODEL,
        timeoutMs: config.AI_TIMEOUT_MS,
        maxRetries: config.AI_MAX_RETRIES
      })
    : new DisabledAiProvider();

  const aiAnalyst = new AiSecurityAnalyst({
    provider: aiProvider,
    maxContextChars: config.AI_MAX_CONTEXT_CHARS,
    maxTokens: config.AI_MAX_TOKENS
  });

  const githubAppClient = isGitHubAppConfigured(config)
    ? new GitHubAppClient({
        appId: config.GITHUB_APP_ID,
        privateKeyPem: config.GITHUB_APP_PRIVATE_KEY
      })
    : undefined;

  const { worker, close } = startBullMqWorker(config.REDIS_URL, config.WORKER_CONCURRENCY, {
    db: dbConn.db,
    config,
    artifactStorage,
    localRunner,
    aiAnalyst,
    githubAppClient,
    logger
  });

  worker.on("completed", (job) => {
    logger.info("BullMQ scan job completed", { jobId: job.id, scanId: job.data.scanId });
  });
  worker.on("failed", (job, err) => {
    logger.error("BullMQ scan job failed", {
      jobId: job?.id,
      scanId: job?.data?.scanId,
      error: err.message
    });
  });

  logger.info("Indicative worker started", {
    concurrency: config.WORKER_CONCURRENCY,
    runnerMode: config.SCANNER_RUNNER_MODE,
    aiEnabled: aiAnalyst.isEnabled
  });

  const shutdown = async () => {
    logger.info("Shutting down Indicative worker...");
    await close();
    await dbConn.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("Worker startup error:", err);
  process.exit(1);
});

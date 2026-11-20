import {
  isAiConfigured,
  isGitHubAppConfigured,
  loadConfig
} from "@indicative/config";
import {
  createEmbeddedPostgresConnection,
  createPostgresConnection,
  runMigrations,
  seedDatabase,
  type DatabaseConnection
} from "@indicative/database";
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
import {
  createBullMqEnqueuer,
  createInlineAsyncEnqueuer,
  GitHubAppClient,
  type ScanJobEnqueuer
} from "@indicative/worker";
import { createRedactingLogger } from "@indicative/security";
import { LocalArtifactStorage, S3ArtifactStorage } from "@indicative/shared";
import { buildApiServer } from "./server.js";

async function main() {
  const config = loadConfig();
  const logger = createRedactingLogger({ service: "api", level: config.LOG_LEVEL });

  let dbConn: DatabaseConnection;
  try {
    dbConn = await createPostgresConnection(config.DATABASE_URL);
    const health = await dbConn.healthCheck();
    if (!health.ok) {
      throw new Error(health.error ?? "PostgreSQL unreachable");
    }
  } catch (err) {
    if (config.NODE_ENV === "development" && config.DEMO_MODE) {
      logger.warn(
        "External PostgreSQL unreachable in development DEMO_MODE; falling back to embedded PGlite PostgreSQL instance.",
        { error: (err as Error).message }
      );
      dbConn = await createEmbeddedPostgresConnection(".indicative-tmp/pglite-dev");
    } else {
      throw err;
    }
  }

  await runMigrations(dbConn);
  if (config.NODE_ENV === "development" && config.DEMO_MODE) {
    await seedDatabase(dbConn);
  }

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

  let enqueuer: ScanJobEnqueuer;
  if (config.NODE_ENV === "development" && config.DEMO_MODE && dbConn.driver === "pglite") {
    const localRunner = new IsolatedScannerRunner({
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
    });

    enqueuer = createInlineAsyncEnqueuer(() => ({
      db: dbConn.db,
      config,
      artifactStorage,
      localRunner,
      aiAnalyst,
      githubAppClient,
      logger
    }));
  } else {
    enqueuer = createBullMqEnqueuer(config.REDIS_URL);
  }

  const app = await buildApiServer({
    config,
    dbConn,
    enqueuer,
    artifactStorage,
    aiAnalyst,
    githubAppClient,
    logger
  });

  await app.listen({ host: config.API_HOST, port: config.API_PORT });
  logger.info("Indicative API server listening", {
    host: config.API_HOST,
    port: config.API_PORT,
    docsUrl: `${config.API_PUBLIC_URL}/docs`,
    dbDriver: dbConn.driver,
    aiEnabled: aiAnalyst.isEnabled
  });

  const shutdown = async () => {
    logger.info("Shutting down Indicative API...");
    await app.close();
    await enqueuer.close();
    await dbConn.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("API startup failed:", err);
  process.exit(1);
});

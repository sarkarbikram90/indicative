import { z } from "zod";
import path from "node:path";

const booleanFromEnv = z
  .union([z.boolean(), z.string()])
  .transform((val) => {
    if (typeof val === "boolean") return val;
    return val.toLowerCase() === "true" || val === "1";
  });

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),
  DEMO_MODE: booleanFromEnv.default(false),

  API_HOST: z.string().default("0.0.0.0"),
  API_PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  API_PUBLIC_URL: z.string().url().default("http://localhost:4000"),
  WEB_PUBLIC_URL: z.string().url().default("http://localhost:3000"),

  DATABASE_URL: z
    .string()
    .min(1)
    .default("postgresql://indicative:indicative_dev_password@localhost:5432/indicative"),
  REDIS_URL: z.string().min(1).default("redis://localhost:6379"),

  ARTIFACT_STORAGE_DRIVER: z.enum(["s3", "local"]).default("local"),
  ARTIFACT_LOCAL_DIR: z.string().default(".local-artifacts"),
  S3_ENDPOINT: z.string().default("http://localhost:9000"),
  S3_REGION: z.string().default("us-east-1"),
  S3_BUCKET: z.string().default("indicative-artifacts"),
  S3_ACCESS_KEY_ID: z.string().default("indicative_minio"),
  S3_SECRET_ACCESS_KEY: z.string().default("indicative_minio_secret_dev"),
  S3_FORCE_PATH_STYLE: booleanFromEnv.default(true),
  ARTIFACT_RETENTION_DAYS: z.coerce.number().int().min(1).max(3650).default(30),

  SESSION_SECRET: z
    .string()
    .min(32, "SESSION_SECRET must be at least 32 characters")
    .default("dev-only-replace-with-64-char-random-hex-string-0123456789abcdef"),
  SECRET_FINGERPRINT_KEY: z
    .string()
    .min(32, "SECRET_FINGERPRINT_KEY must be at least 32 characters")
    .default("dev-only-replace-with-64-char-hmac-master-key-fedcba9876543210"),
  SCANNER_RUNNER_SHARED_SECRET: z
    .string()
    .min(16)
    .default("dev-only-scanner-runner-internal-token-change-in-prod"),

  GITHUB_OAUTH_CLIENT_ID: z.string().default(""),
  GITHUB_OAUTH_CLIENT_SECRET: z.string().default(""),
  GITHUB_OAUTH_CALLBACK_URL: z
    .string()
    .url()
    .default("http://localhost:4000/api/v1/auth/github/callback"),

  GITHUB_APP_ID: z.string().default(""),
  GITHUB_APP_SLUG: z.string().default("indicative-security"),
  GITHUB_APP_PRIVATE_KEY: z.string().default(""),
  GITHUB_APP_WEBHOOK_SECRET: z.string().default(""),
  GITHUB_WEBHOOK_POST_PR_COMMENTS: booleanFromEnv.default(true),
  GITHUB_WEBHOOK_CREATE_CHECK_RUNS: booleanFromEnv.default(true),

  ENABLE_SCHEDULER: booleanFromEnv.default(true),
  SCHEDULER_POLL_INTERVAL_MS: z.coerce.number().int().min(5000).max(3600000).default(60000),
  NOTIFICATION_TIMEOUT_MS: z.coerce.number().int().min(1000).max(60000).default(10000),

  SCANNER_RUNNER_MODE: z.enum(["http", "local"]).default("local"),
  SCANNER_SANDBOX_RUNTIME: z
    .enum(["local-process", "docker", "gvisor", "kata"])
    .default("local-process"),
  SCANNER_RUNNER_URL: z.string().url().default("http://localhost:4100"),
  SCANNER_RUNNER_HOST: z.string().default("0.0.0.0"),
  SCANNER_RUNNER_PORT: z.coerce.number().int().min(1).max(65535).default(4100),
  SCANNER_WORKSPACES_ROOT: z.string().default(path.resolve(process.cwd(), ".indicative-tmp")),
  SCANNER_MAX_REPORT_BYTES: z.coerce
    .number()
    .int()
    .min(1024 * 1024)
    .max(512 * 1024 * 1024)
    .default(64 * 1024 * 1024),

  SEMGREP_BIN: z.string().default("semgrep"),
  TRIVY_BIN: z.string().default("trivy"),
  GITLEAKS_BIN: z.string().default("gitleaks"),
  TRIVY_CACHE_DIR: z.string().default(path.resolve(process.cwd(), ".trivy-cache")),
  SEMGREP_RULES_DIR: z
    .string()
    .default(path.resolve(process.cwd(), "services/scanner-runner/rules/semgrep")),

  MAX_REPO_SIZE_MB: z.coerce.number().int().min(1).max(2048).default(250),
  MAX_FILES_PER_SCAN: z.coerce.number().int().min(10).max(200000).default(25000),
  MAX_SCAN_DURATION_MS: z.coerce.number().int().min(5000).max(1800000).default(300000),
  SCANNER_TIMEOUT_MS: z.coerce.number().int().min(1000).max(600000).default(120000),
  MAX_CONCURRENT_SCANS_PER_ORG: z.coerce.number().int().min(1).max(50).default(3),
  WORKER_CONCURRENCY: z.coerce.number().int().min(1).max(32).default(2),
  MAX_GIT_HISTORY_COMMITS: z.coerce.number().int().min(1).max(100000).default(5000),

  AI_PROVIDER: z.enum(["disabled", "openai-compatible"]).default("disabled"),
  AI_API_BASE_URL: z.string().url().default("https://api.openai.com/v1"),
  AI_API_KEY: z.string().default(""),
  AI_MODEL: z.string().default("gpt-4o-mini"),
  AI_MAX_CONTEXT_CHARS: z.coerce.number().int().min(500).max(100000).default(12000),
  AI_MAX_TOKENS: z.coerce.number().int().min(100).max(8000).default(1200),
  AI_TIMEOUT_MS: z.coerce.number().int().min(1000).max(120000).default(30000),
  AI_MAX_RETRIES: z.coerce.number().int().min(0).max(5).default(2)
});

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(env: Record<string, string | undefined> = process.env): AppConfig {
  const parsed = envSchema.parse(env);

  // Strict security guardrail: DEMO_MODE must NEVER run in production.
  if (parsed.NODE_ENV === "production" && parsed.DEMO_MODE) {
    throw new Error(
      "SECURITY_VIOLATION: DEMO_MODE cannot be enabled when NODE_ENV=production."
    );
  }

  // Strict security guardrail: default dev keys must not be used in production.
  if (parsed.NODE_ENV === "production") {
    if (parsed.SESSION_SECRET.startsWith("dev-only-")) {
      throw new Error("SECURITY_VIOLATION: SESSION_SECRET must be overridden in production.");
    }
    if (parsed.SECRET_FINGERPRINT_KEY.startsWith("dev-only-")) {
      throw new Error(
        "SECURITY_VIOLATION: SECRET_FINGERPRINT_KEY must be overridden in production."
      );
    }
    if (parsed.SCANNER_RUNNER_SHARED_SECRET.startsWith("dev-only-")) {
      throw new Error(
        "SECURITY_VIOLATION: SCANNER_RUNNER_SHARED_SECRET must be overridden in production."
      );
    }
  }

  return parsed;
}

export function isAiConfigured(config: AppConfig): boolean {
  return config.AI_PROVIDER === "openai-compatible" && config.AI_API_KEY.trim().length > 0;
}

export function isGitHubOAuthConfigured(config: AppConfig): boolean {
  return (
    config.GITHUB_OAUTH_CLIENT_ID.trim().length > 0 &&
    config.GITHUB_OAUTH_CLIENT_SECRET.trim().length > 0
  );
}

export function isGitHubAppConfigured(config: AppConfig): boolean {
  return (
    config.GITHUB_APP_ID.trim().length > 0 && config.GITHUB_APP_PRIVATE_KEY.trim().length > 0
  );
}

export function isGitHubWebhookConfigured(config: AppConfig): boolean {
  return config.GITHUB_APP_WEBHOOK_SECRET.trim().length >= 16;
}

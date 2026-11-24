import Fastify, { type FastifyInstance } from "fastify";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import type { AppConfig } from "@indicative/config";
import type { DatabaseConnection } from "@indicative/database";
import { AiSecurityAnalyst } from "@indicative/ai";
import type { GitHubAppClient, ScanJobEnqueuer } from "@indicative/worker";
import {
  createRedactingLogger,
  redactSecretsInText,
  type StructuredLogger
} from "@indicative/security";
import {
  AppError,
  defaultMetrics,
  generateCorrelationId,
  type ArtifactStorageAdapter,
  type MetricsRegistry
} from "@indicative/shared";
import { createAuthMiddleware } from "./middleware/auth.js";
import { registerAuthRoutes } from "./routes/auth.js";
import { registerPlatformRoutes } from "./routes/platform.js";
import { registerWebhookRoutes } from "./routes/webhooks.js";
import { registerAutomationRoutes } from "./routes/automation.js";

export interface BuildApiServerOptions {
  config: AppConfig;
  dbConn: DatabaseConnection;
  enqueuer: ScanJobEnqueuer;
  artifactStorage: ArtifactStorageAdapter;
  aiAnalyst: AiSecurityAnalyst;
  githubAppClient?: GitHubAppClient;
  metrics?: MetricsRegistry;
  logger?: StructuredLogger;
  fetchImpl?: typeof fetch;
}

export async function buildApiServer(
  options: BuildApiServerOptions
): Promise<FastifyInstance> {
  const { config, dbConn } = options;
  const metrics = options.metrics ?? defaultMetrics;
  const logger =
    options.logger ??
    createRedactingLogger({ service: "api", level: config.LOG_LEVEL });

  const app = Fastify({
    logger: false,
    trustProxy: true,
    bodyLimit: 1024 * 1024 // 1 MB max API payload
  });

  await app.register(helmet, {
    contentSecurityPolicy: false // Swagger UI requires inline scripts on /docs
  });

  const allowedCorsOrigins =
    config.NODE_ENV === "production"
      ? [config.WEB_PUBLIC_URL]
      : [config.WEB_PUBLIC_URL, "http://localhost:3000", "http://127.0.0.1:3000"];

  await app.register(cors, {
    origin: allowedCorsOrigins,
    credentials: true,
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"]
  });

  await app.register(cookie, {
    secret: config.SESSION_SECRET
  });

  await app.register(rateLimit, {
    max: config.NODE_ENV === "test" ? 10_000 : 200,
    timeWindow: "1 minute"
  });

  await app.register(swagger, {
    openapi: {
      openapi: "3.1.0",
      info: {
        title: "Indicative Security Intelligence API",
        description:
          "REST API for repository integration, asynchronous multi-engine security scanning (Semgrep, Trivy, Gitleaks), canonical findings lifecycle, AI Security Analyst, and redacted report exports.",
        version: "0.1.0"
      },
      servers: [{ url: config.API_PUBLIC_URL }]
    }
  });

  await app.register(swaggerUi, {
    routePrefix: "/docs",
    uiConfig: {
      docExpansion: "list",
      deepLinking: false
    }
  });

  // Correlation IDs & request metrics
  app.addHook("onRequest", async (request, reply) => {
    const incoming = request.headers["x-correlation-id"];
    request.correlationId =
      typeof incoming === "string" && incoming.trim().length > 0
        ? incoming.trim().slice(0, 64)
        : generateCorrelationId();
    reply.header("X-Correlation-Id", request.correlationId);
  });

  app.addHook("onResponse", async (request, reply) => {
    metrics.inc("indicative_http_requests_total", {
      method: request.method,
      status: String(reply.statusCode)
    });
    logger.info("HTTP request handled", {
      correlationId: request.correlationId,
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode
    });
  });

  // Consistent, non-leaking error handler
  app.setErrorHandler((err, request, reply) => {
    const correlationId = request.correlationId ?? generateCorrelationId();
    if (err instanceof AppError) {
      return reply.status(err.statusCode).send({
        error: {
          code: err.code,
          message: redactSecretsInText(err.message),
          correlationId,
          ...(err.details ? { details: err.details } : {})
        }
      });
    }

    const statusCode =
      typeof (err as { statusCode?: number }).statusCode === "number"
        ? (err as { statusCode: number }).statusCode
        : 500;

    logger.error("Unhandled API error", {
      correlationId,
      statusCode,
      error: (err as Error).message
    });

    return reply.status(statusCode).send({
      error: {
        code: statusCode === 429 ? "RATE_LIMITED" : "INTERNAL_ERROR",
        message:
          statusCode >= 500
            ? "An unexpected internal error occurred."
            : redactSecretsInText((err as Error).message),
        correlationId
      }
    });
  });

  // Health & Observability endpoints
  app.get("/health", async () => {
    const dbHealth = await dbConn.healthCheck();
    const storageHealth = await options.artifactStorage.healthCheck();
    const queueDepth = await options.enqueuer.getQueueDepth().catch(() => -1);
    return {
      status: dbHealth.ok && storageHealth.ok ? "ok" : "degraded",
      timestamp: new Date().toISOString(),
      database: dbHealth,
      artifactStorage: storageHealth,
      queue: { depth: queueDepth },
      aiEnabled: options.aiAnalyst.isEnabled,
      demoMode: config.DEMO_MODE && config.NODE_ENV !== "production"
    };
  });

  app.get("/metrics", async (_request, reply) => {
    return reply
      .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
      .send(metrics.toPrometheusText());
  });

  const requireAuth = createAuthMiddleware(dbConn.db, config);

  registerAuthRoutes(app, {
    db: dbConn.db,
    config,
    requireAuth,
    fetchImpl: options.fetchImpl
  });

  registerPlatformRoutes(app, {
    db: dbConn.db,
    config,
    enqueuer: options.enqueuer,
    aiAnalyst: options.aiAnalyst,
    githubAppClient: options.githubAppClient,
    requireAuth
  });

  registerWebhookRoutes(app, {
    db: dbConn.db,
    config,
    enqueuer: options.enqueuer,
    githubAppClient: options.githubAppClient,
    logger
  });

  registerAutomationRoutes(app, {
    db: dbConn.db,
    config,
    enqueuer: options.enqueuer,
    githubAppClient: options.githubAppClient,
    requireAuth,
    fetchImpl: options.fetchImpl
  });

  return app;
}

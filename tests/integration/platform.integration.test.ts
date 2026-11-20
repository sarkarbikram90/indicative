import { describe, it, expect, beforeAll, afterAll } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { loadConfig } from "@indicative/config";
import {
  createEmbeddedPostgresConnection,
  runMigrations,
  seedDatabase,
  type DatabaseConnection
} from "@indicative/database";
import { AiSecurityAnalyst, DisabledAiProvider } from "@indicative/ai";
import { LocalArtifactStorage } from "@indicative/shared";
import {
  createInlineAsyncEnqueuer,
  GitHubAppClient
} from "@indicative/worker";
import { buildApiServer } from "../../apps/api/src/server.js";

describe("Integration: GitHub App, OAuth CSRF, API, DB Persistence, Idempotency & Exports", () => {
  let dbConn: DatabaseConnection;
  let tmpDir: string;
  let api: Awaited<ReturnType<typeof buildApiServer>>;
  let ghPrivateKeyPem: string;
  const mintedFakeInstallToken = [
    "ghs_",
    "MockedInstallationAccessTokenNeverExposeToUI999"
  ].join("");

  beforeAll(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "ind-int-"));
    const { privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" }
    });
    ghPrivateKeyPem = privateKey;

    dbConn = await createEmbeddedPostgresConnection();
    await runMigrations(dbConn);
    await seedDatabase(dbConn, path.resolve(process.cwd(), "tests/fixtures/clean-app"));

    const config = loadConfig({
      NODE_ENV: "test",
      DEMO_MODE: "true",
      SCANNER_WORKSPACES_ROOT: path.join(tmpDir, "workspaces"),
      ARTIFACT_STORAGE_DRIVER: "local",
      ARTIFACT_LOCAL_DIR: path.join(tmpDir, "artifacts"),
      GITHUB_OAUTH_CLIENT_ID: "mock-client-id",
      GITHUB_OAUTH_CLIENT_SECRET: "mock-client-secret",
      GITHUB_APP_ID: "987654",
      GITHUB_APP_PRIVATE_KEY: ghPrivateKeyPem
    });

    const artifactStorage = new LocalArtifactStorage(path.join(tmpDir, "artifacts"));
    const aiAnalyst = new AiSecurityAnalyst({ provider: new DisabledAiProvider() });

    const githubAppClient = new GitHubAppClient({
      appId: "987654",
      privateKeyPem: ghPrivateKeyPem,
      fetchImpl: (async (input: string | URL) => {
        const url = String(input);
        if (url.includes("/access_tokens")) {
          return new Response(
            JSON.stringify({
              token: mintedFakeInstallToken,
              expires_at: new Date(Date.now() + 3600_000).toISOString()
            }),
            { status: 201, headers: { "Content-Type": "application/json" } }
          );
        }
        if (url.includes("/installation/repositories")) {
          return new Response(
            JSON.stringify({
              repositories: [
                {
                  id: 1001,
                  full_name: "acme-sec/payments-service",
                  default_branch: "main",
                  private: true,
                  html_url: "https://github.com/acme-sec/payments-service",
                  description: "Payments microservice"
                }
              ]
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        return new Response("Not Found", { status: 404 });
      }) as typeof fetch
    });

    const enqueuer = createInlineAsyncEnqueuer(() => ({
      db: dbConn.db,
      config,
      artifactStorage,
      aiAnalyst,
      githubAppClient
    }));

    api = await buildApiServer({
      config,
      dbConn,
      enqueuer,
      artifactStorage,
      aiAnalyst,
      githubAppClient
    });
  });

  afterAll(async () => {
    await api.close();
    await dbConn.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("exposes /health, /metrics, and OpenAPI /docs/json", async () => {
    const health = await api.inject({ method: "GET", url: "/health" });
    expect(health.statusCode).toBe(200);
    expect(health.json().status).toBe("ok");
    expect(health.headers["x-correlation-id"]).toMatch(/^cor_/);

    const metrics = await api.inject({ method: "GET", url: "/metrics" });
    expect(metrics.statusCode).toBe(200);
    expect(metrics.body).toContain("indicative_http_requests_total");

    const docs = await api.inject({ method: "GET", url: "/docs/json" });
    expect(docs.statusCode).toBe(200);
    expect(docs.json().openapi).toMatch(/^3\./);
  });

  it("rejects GitHub OAuth callback with missing or mismatched CSRF state", async () => {
    const res = await api.inject({
      method: "GET",
      url: "/api/v1/auth/github/callback?code=abc&state=forged"
    });
    expect(res.statusCode).toBe(403);
  });

  it("registers GitHub App installation, discovers repos, and NEVER exposes installation tokens", async () => {
    const login = await api.inject({ method: "POST", url: "/api/v1/auth/demo" });
    expect(login.statusCode).toBe(200);
    const { token } = login.json() as { token: string };

    const reg = await api.inject({
      method: "POST",
      url: "/api/v1/integrations/github/installations",
      headers: { Authorization: `Bearer ${token}` },
      payload: {
        installationId: 424242,
        accountLogin: "acme-sec",
        accountType: "Organization"
      }
    });
    expect(reg.statusCode).toBe(201);
    const instDbId = reg.json().installation.id as string;

    const discovery = await api.inject({
      method: "GET",
      url: "/api/v1/integrations/github/repositories",
      headers: { Authorization: `Bearer ${token}` }
    });
    expect(discovery.statusCode).toBe(200);
    expect(discovery.body).not.toContain(mintedFakeInstallToken);
    expect(discovery.json().repositories).toHaveLength(1);
    expect(discovery.json().repositories[0].fullName).toBe("acme-sec/payments-service");

    // Link project
    const createProj = await api.inject({
      method: "POST",
      url: "/api/v1/projects",
      headers: { Authorization: `Bearer ${token}` },
      payload: {
        name: "Payments Service",
        repositoryFullName: "acme-sec/payments-service",
        defaultBranch: "main",
        githubInstallationId: instDbId
      }
    });
    expect(createProj.statusCode).toBe(201);
    const projectId = createProj.json().project.id as string;

    // Verify idempotency key deduplicates scan creation
    const idemKey = "scan-idempotency-request-0001";
    const scan1 = await api.inject({
      method: "POST",
      url: `/api/v1/projects/${projectId}/scans`,
      headers: {
        Authorization: `Bearer ${token}`,
        "Idempotency-Key": idemKey
      },
      payload: {}
    });
    expect(scan1.statusCode).toBe(202);
    const scan1Id = scan1.json().scan.id as string;

    const scan1Dup = await api.inject({
      method: "POST",
      url: `/api/v1/projects/${projectId}/scans`,
      headers: {
        Authorization: `Bearer ${token}`,
        "Idempotency-Key": idemKey
      },
      payload: {}
    });
    expect(scan1Dup.statusCode).toBe(200);
    expect(scan1Dup.json().deduplicated).toBe(true);
    expect(scan1Dup.json().scan.id).toBe(scan1Id);
  });
});

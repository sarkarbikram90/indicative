import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { loadConfig } from "@indicative/config";
import {
  createEmbeddedPostgresConnection,
  organizationMembers,
  organizations,
  runMigrations,
  users,
  type DatabaseConnection
} from "@indicative/database";
import { AiSecurityAnalyst, DisabledAiProvider } from "@indicative/ai";
import {
  createDefaultScannerRegistry,
  createResourceLimits,
  IsolatedScannerRunner
} from "@indicative/scanner-runner";
import {
  LocalArtifactStorage
} from "@indicative/shared";
import { createInlineAsyncEnqueuer } from "@indicative/worker";
import { buildApiServer } from "../../apps/api/src/server.js";
import { createUserSession, SESSION_COOKIE_NAME } from "../../apps/api/src/index.js";

describe("Security Controls: Tenant Isolation, Auth/CSRF, Production Guardrails & Runner Hardening", () => {
  let dbConn: DatabaseConnection;
  let tmpDir: string;
  let api: Awaited<ReturnType<typeof buildApiServer>>;
  let orgAToken: string;
  let orgBToken: string;
  let orgACsrf: string;

  beforeAll(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "ind-sec-test-"));
    dbConn = await createEmbeddedPostgresConnection();
    await runMigrations(dbConn);

    const config = loadConfig({
      NODE_ENV: "test",
      DEMO_MODE: "true",
      SCANNER_WORKSPACES_ROOT: path.join(tmpDir, "workspaces"),
      ARTIFACT_STORAGE_DRIVER: "local",
      ARTIFACT_LOCAL_DIR: path.join(tmpDir, "artifacts")
    });

    // Create two completely separate tenants (Org A and Org B)
    const [userA] = await dbConn.db
      .insert(users)
      .values({ email: "alice@org-a.example", name: "Alice" })
      .returning();
    const [orgA] = await dbConn.db
      .insert(organizations)
      .values({ name: "Org A", slug: "org-a" })
      .returning();
    await dbConn.db
      .insert(organizationMembers)
      .values({ organizationId: orgA!.id, userId: userA!.id, role: "OWNER" });

    const [userB] = await dbConn.db
      .insert(users)
      .values({ email: "bob@org-b.example", name: "Bob" })
      .returning();
    const [orgB] = await dbConn.db
      .insert(organizations)
      .values({ name: "Org B", slug: "org-b" })
      .returning();
    await dbConn.db
      .insert(organizationMembers)
      .values({ organizationId: orgB!.id, userId: userB!.id, role: "OWNER" });

    const sessA = await createUserSession({
      db: dbConn.db,
      config,
      userId: userA!.id,
      organizationId: orgA!.id
    });
    const sessB = await createUserSession({
      db: dbConn.db,
      config,
      userId: userB!.id,
      organizationId: orgB!.id
    });
    orgAToken = sessA.rawToken;
    orgACsrf = sessA.csrfToken;
    orgBToken = sessB.rawToken;

    const artifactStorage = new LocalArtifactStorage(path.join(tmpDir, "artifacts"));
    const aiAnalyst = new AiSecurityAnalyst({ provider: new DisabledAiProvider() });
    const enqueuer = createInlineAsyncEnqueuer(() => ({
      db: dbConn.db,
      config,
      artifactStorage,
      aiAnalyst
    }));

    api = await buildApiServer({
      config,
      dbConn,
      enqueuer,
      artifactStorage,
      aiAnalyst
    });
  });

  afterAll(async () => {
    await api.close();
    await dbConn.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("refuses to boot in production when DEMO_MODE=true or default dev keys are set", () => {
    expect(() =>
      loadConfig({
        NODE_ENV: "production",
        DEMO_MODE: "true",
        SESSION_SECRET: "prod-random-secret-0123456789abcdef0123456789abcdef",
        SECRET_FINGERPRINT_KEY: "prod-random-hmac-key-0123456789abcdef0123456789abcdef",
        SCANNER_RUNNER_SHARED_SECRET: "prod-random-runner-secret-0123456789"
      })
    ).toThrow(/SECURITY_VIOLATION: DEMO_MODE/);

    expect(() =>
      loadConfig({
        NODE_ENV: "production",
        DEMO_MODE: "false"
      })
    ).toThrow(/SECURITY_VIOLATION: SESSION_SECRET/);
  });

  it("enforces authentication and cookie CSRF protection", async () => {
    const unauth = await api.inject({ method: "GET", url: "/api/v1/projects" });
    expect(unauth.statusCode).toBe(401);

    // Cookie-authenticated POST without CSRF token MUST fail with 403
    const noCsrf = await api.inject({
      method: "POST",
      url: "/api/v1/projects",
      cookies: { [SESSION_COOKIE_NAME]: orgAToken },
      payload: { name: "No CSRF", repositoryFullName: "org-a/repo-1" }
    });
    expect(noCsrf.statusCode).toBe(403);

    // Cookie-authenticated POST with valid CSRF token succeeds
    const withCsrf = await api.inject({
      method: "POST",
      url: "/api/v1/projects",
      cookies: { [SESSION_COOKIE_NAME]: orgAToken },
      headers: { "X-CSRF-Token": orgACsrf },
      payload: { name: "Org A Private App", repositoryFullName: "org-a/private-app" }
    });
    expect(withCsrf.statusCode).toBe(201);
  });

  it("enforces strict cross-tenant isolation across projects, scans, findings, and AI advisor", async () => {
    const createA = await api.inject({
      method: "POST",
      url: "/api/v1/projects",
      headers: { Authorization: `Bearer ${orgAToken}` },
      payload: {
        name: "Org A Secret Project",
        repositoryFullName: "org-a/secret-repo"
      }
    });
    expect(createA.statusCode).toBe(201);
    const projectAId = createA.json().project.id as string;

    // Org B tries to read Org A's project -> 404
    const readByB = await api.inject({
      method: "GET",
      url: `/api/v1/projects/${projectAId}`,
      headers: { Authorization: `Bearer ${orgBToken}` }
    });
    expect(readByB.statusCode).toBe(404);

    // Org B tries to initiate scan on Org A's project -> 404
    const scanByB = await api.inject({
      method: "POST",
      url: `/api/v1/projects/${projectAId}/scans`,
      headers: { Authorization: `Bearer ${orgBToken}` },
      payload: {}
    });
    expect(scanByB.statusCode).toBe(404);

    // Org B tries to read Org A's project findings -> 404
    const findingsByB = await api.inject({
      method: "GET",
      url: `/api/v1/projects/${projectAId}/findings`,
      headers: { Authorization: `Bearer ${orgBToken}` }
    });
    expect(findingsByB.statusCode).toBe(404);

    // Org B lists projects -> must NOT contain Org A's project
    const listB = await api.inject({
      method: "GET",
      url: "/api/v1/projects",
      headers: { Authorization: `Bearer ${orgBToken}` }
    });
    expect(listB.statusCode).toBe(200);
    expect(listB.json().projects).toHaveLength(0);
  });

  it("rejects workspaces exceeding file count / size limits and rejects path traversal in scanner-runner", async () => {
    const wsRoot = path.join(tmpDir, "runner-workspaces");
    const overLimitRepo = path.join(wsRoot, "too-many-files");
    await fs.mkdir(overLimitRepo, { recursive: true });
    for (let i = 0; i < 15; i++) {
      await fs.writeFile(path.join(overLimitRepo, `f${i}.txt`), "x", "utf8");
    }

    const runner = new IsolatedScannerRunner({
      registry: createDefaultScannerRegistry({
        semgrepBin: "semgrep",
        semgrepRulesDir: path.resolve(process.cwd(), "services/scanner-runner/rules/semgrep"),
        trivyBin: "trivy",
        trivyCacheDir: path.resolve(process.cwd(), ".trivy-cache"),
        gitleaksBin: "gitleaks"
      }),
      workspacesRoot: wsRoot,
      limits: createResourceLimits({ maxFilesPerScan: 10 })
    });

    const testFingerprintKey = "unit-test-only-hmac-key-aaaaaaaaaaaaaaaaaaaa";

    // Traversal outside workspacesRoot MUST throw
    await expect(
      runner.executeScan({
        scanId: "11111111-1111-1111-1111-111111111111",
        organizationId: "22222222-2222-2222-2222-222222222222",
        projectId: "33333333-3333-3333-3333-333333333333",
        workspacePath: path.resolve(wsRoot, ".."),
        scanners: ["gitleaks"],
        secretFingerprintKey: testFingerprintKey
      })
    ).rejects.toThrow(/SECURITY_PATH_TRAVERSAL/);

    // Exceeding file limit MUST fail transparently with RESOURCE_LIMIT (not silent clean scan)
    const res = await runner.executeScan({
      scanId: "11111111-1111-1111-1111-111111111112",
      organizationId: "22222222-2222-2222-2222-222222222222",
      projectId: "33333333-3333-3333-3333-333333333333",
      workspacePath: overLimitRepo,
      scanners: ["semgrep", "trivy", "gitleaks"],
      secretFingerprintKey: testFingerprintKey
    });
    expect(res.limitations.some((l) => l.code === "MAX_FILES_EXCEEDED")).toBe(true);
    expect(res.results.every((r) => r.status === "FAILED" && r.errorClass === "RESOURCE_LIMIT")).toBe(
      true
    );
  });

  it("refuses to store artifacts containing unredacted plaintext secrets", async () => {
    const storage = new LocalArtifactStorage(path.join(tmpDir, "sec-artifacts"));
    const dummyGh = ["ghp_", "9xK4mN7pQ2rS5tU8vW1yZ3aB6cD0eF4gH7jK"].join("");
    await expect(
      storage.putObject("leak.json", JSON.stringify({ secret: dummyGh }), "application/json")
    ).rejects.toThrow(/SECURITY_VIOLATION/);
  });
});

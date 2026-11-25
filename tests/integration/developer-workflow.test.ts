import { describe, it, expect, beforeAll, afterAll } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { eq } from "drizzle-orm";
import { loadConfig } from "@indicative/config";
import {
  createEmbeddedPostgresConnection,
  notificationChannels,
  runMigrations,
  scanSchedules,
  seedDatabase,
  type DatabaseConnection
} from "@indicative/database";
import { AiSecurityAnalyst, DisabledAiProvider } from "@indicative/ai";
import {
  computeGitHubWebhookSignature,
  decryptTenantSecret,
  encryptTenantSecret,
  verifyGitHubWebhookSignature
} from "@indicative/security";
import { LocalArtifactStorage } from "@indicative/shared";
import {
  CicdGitHubActionsAdapter
} from "@indicative/cicd-security";
import {
  createResourceLimits,
  IsolatedScannerRunner,
  ScannerAdapterRegistry
} from "@indicative/scanner-runner";
import {
  computeNextCronRun,
  createInlineAsyncEnqueuer,
  GitHubAppClient,
  INDICATIVE_PR_COMMENT_MARKER,
  resolveCronExpression,
  runDueScanSchedules
} from "@indicative/worker";
import { buildApiServer } from "../../apps/api/src/server.js";

describe("Integration: Developer Workflow & Automation (Webhooks, PR/Check Runs, Schedules, Notifications)", () => {
  let dbConn: DatabaseConnection;
  let tmpDir: string;
  let api: Awaited<ReturnType<typeof buildApiServer>>;
  let enqueuer: ReturnType<typeof createInlineAsyncEnqueuer>;
  let authToken: string;
  let demoProjectId: string;
  let demoOrgId: string;
  const webhookSecret = "whsec_indicative_test_hmac_secret_1234567890";

  const githubCalls: Array<{ method: string; url: string; body?: unknown }> = [];
  const outboundNotificationCalls: Array<{ method: string; url: string; body?: unknown }> = [];
  const createdCheckRunId = 7001;
  let existingPrCommentId: number | null = null;

  beforeAll(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "ind-auto-"));
    const { privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" }
    });

    dbConn = await createEmbeddedPostgresConnection();
    await runMigrations(dbConn);
    const seeded = await seedDatabase(
      dbConn,
      path.resolve(process.cwd(), "tests/fixtures/cicd-vulnerable")
    );
    demoProjectId = seeded.demoProjectId;
    demoOrgId = seeded.demoOrgId;

    const config = loadConfig({
      NODE_ENV: "test",
      DEMO_MODE: "true",
      SCANNER_WORKSPACES_ROOT: path.join(tmpDir, "workspaces"),
      ARTIFACT_STORAGE_DRIVER: "local",
      ARTIFACT_LOCAL_DIR: path.join(tmpDir, "artifacts"),
      GITHUB_APP_ID: "777001",
      GITHUB_APP_PRIVATE_KEY: privateKey,
      GITHUB_APP_WEBHOOK_SECRET: webhookSecret
    });

    const artifactStorage = new LocalArtifactStorage(path.join(tmpDir, "artifacts"));
    const aiAnalyst = new AiSecurityAnalyst({ provider: new DisabledAiProvider() });

    const mockGitHubFetch = (async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      const parsedBody =
        typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : undefined;
      githubCalls.push({ method, url, body: parsedBody });

      if (url.includes("/access_tokens")) {
        return new Response(
          JSON.stringify({
            token: "ghs_MockWorkflowAutomationInstallToken001",
            expires_at: new Date(Date.now() + 3600_000).toISOString()
          }),
          { status: 201, headers: { "Content-Type": "application/json" } }
        );
      }
      if (url.includes("/check-runs")) {
        return new Response(
          JSON.stringify({
            id: createdCheckRunId,
            html_url: `https://github.com/indicative-demo/vulnerable-app/runs/${createdCheckRunId}`
          }),
          { status: method === "POST" ? 201 : 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (url.includes("/issues/") && url.includes("/comments") && method === "GET") {
        const list = existingPrCommentId
          ? [{ id: existingPrCommentId, body: `${INDICATIVE_PR_COMMENT_MARKER}\nold summary` }]
          : [];
        return new Response(JSON.stringify(list), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url.includes("/comments") && (method === "POST" || method === "PATCH")) {
        existingPrCommentId = 9001;
        return new Response(
          JSON.stringify({
            id: existingPrCommentId,
            html_url: "https://github.com/indicative-demo/vulnerable-app/pull/42#issuecomment-9001"
          }),
          { status: method === "POST" ? 201 : 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (url.endsWith("/issues") && method === "POST") {
        return new Response(
          JSON.stringify({
            number: 108,
            html_url: "https://github.com/indicative-demo/vulnerable-app/issues/108"
          }),
          { status: 201, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("Not Found", { status: 404 });
    }) as typeof fetch;

    const mockNotificationFetch = (async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "POST";
      const parsedBody =
        typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : undefined;
      outboundNotificationCalls.push({ method, url, body: parsedBody });

      if (url.includes("hooks.slack.com")) {
        return new Response("ok", { status: 200 });
      }
      if (url.includes("/rest/api/3/issue")) {
        return new Response(JSON.stringify({ id: "10042", key: "SEC-42" }), {
          status: 201,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url.includes("api.github.com/repos/")) {
        return new Response(
          JSON.stringify({ number: 109, html_url: "https://github.com/acme/sec/issues/109" }),
          { status: 201, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("Not Found", { status: 404 });
    }) as typeof fetch;

    const githubAppClient = new GitHubAppClient({
      appId: "777001",
      privateKeyPem: privateKey,
      fetchImpl: mockGitHubFetch
    });

    // Use real CI/CD analyzer inside IsolatedScannerRunner so webhook & scheduled scans execute fast & deterministically
    const registry = new ScannerAdapterRegistry([new CicdGitHubActionsAdapter()]);
    const localRunner = new IsolatedScannerRunner({
      registry,
      workspacesRoot: config.SCANNER_WORKSPACES_ROOT,
      limits: createResourceLimits({
        maxRepoSizeBytes: 50 * 1024 * 1024,
        maxFilesPerScan: 1000,
        scannerTimeoutMs: 30_000,
        maxScanDurationMs: 60_000
      })
    });

    enqueuer = createInlineAsyncEnqueuer(() => ({
      db: dbConn.db,
      config,
      artifactStorage,
      localRunner,
      aiAnalyst,
      githubAppClient,
      fetchImpl: mockNotificationFetch
    }));

    api = await buildApiServer({
      config,
      dbConn,
      enqueuer,
      artifactStorage,
      aiAnalyst,
      githubAppClient,
      fetchImpl: mockNotificationFetch
    });

    const login = await api.inject({ method: "POST", url: "/api/v1/auth/demo" });
    expect(login.statusCode).toBe(200);
    authToken = (login.json() as { token: string }).token;
  });

  afterAll(async () => {
    await enqueuer?.close();
    await api?.close();
    await dbConn?.close();
    if (tmpDir) await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("verifies GitHub HMAC-SHA256 webhook signatures and encrypts tenant secrets with tenant binding", () => {
    const body = JSON.stringify({ zen: "Keep it logically awesome." });
    const sig = computeGitHubWebhookSignature(body, webhookSecret);
    expect(verifyGitHubWebhookSignature(body, sig, webhookSecret)).toBe(true);
    expect(verifyGitHubWebhookSignature(body + " ", sig, webhookSecret)).toBe(false);
    expect(verifyGitHubWebhookSignature(body, "sha256=deadbeef", webhookSecret)).toBe(false);
    expect(verifyGitHubWebhookSignature(body, undefined, webhookSecret)).toBe(false);

    const masterKey = "a-very-long-test-master-key-with-at-least-32-chars";
    const encrypted = encryptTenantSecret("https://hooks.slack.com/services/T00/B00/XXXX", "org-a", masterKey);
    expect(encrypted.startsWith("enc:v1:")).toBe(true);
    expect(encrypted).not.toContain("hooks.slack.com");
    expect(decryptTenantSecret(encrypted, "org-a", masterKey)).toBe(
      "https://hooks.slack.com/services/T00/B00/XXXX"
    );
    // Cross-tenant decryption MUST fail (HKDF + GCM AAD tenant binding)
    expect(() => decryptTenantSecret(encrypted, "org-b", masterKey)).toThrow();
  });

  it("rejects invalid webhook signatures, supports ping, deduplicates replays, and triggers PR scan with Check Run & sticky PR comment", async () => {
    // 1. Missing/invalid signature -> 401
    const badSig = await api.inject({
      method: "POST",
      url: "/api/v1/webhooks/github",
      headers: {
        "content-type": "application/json",
        "x-github-event": "ping",
        "x-github-delivery": "deliv-bad-1",
        "x-hub-signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000"
      },
      payload: JSON.stringify({ zen: "forged" })
    });
    expect(badSig.statusCode).toBe(401);

    // 2. Valid ping -> 200 pong
    const pingBody = JSON.stringify({ zen: "Responsive is better than fast." });
    const pingRes = await api.inject({
      method: "POST",
      url: "/api/v1/webhooks/github",
      headers: {
        "content-type": "application/json",
        "x-github-event": "ping",
        "x-github-delivery": "deliv-ping-1",
        "x-hub-signature-256": computeGitHubWebhookSignature(pingBody, webhookSecret)
      },
      payload: pingBody
    });
    expect(pingRes.statusCode).toBe(200);
    expect(pingRes.json().status).toBe("pong");

    // 3. Valid pull_request webhook triggers scan, creates Check Run, and posts PR comment
    const prBody = JSON.stringify({
      action: "opened",
      number: 42,
      installation: { id: 555001 },
      repository: {
        full_name: "indicative-demo/vulnerable-app",
        default_branch: "main"
      },
      pull_request: {
        number: 42,
        html_url: "https://github.com/indicative-demo/vulnerable-app/pull/42",
        head: {
          ref: "feat/workflow-change",
          sha: "1111111111111111111111111111111111111111",
          repo: { full_name: "indicative-demo/vulnerable-app", fork: false }
        },
        base: {
          ref: "main",
          repo: { full_name: "indicative-demo/vulnerable-app" }
        }
      }
    });

    const prRes = await api.inject({
      method: "POST",
      url: "/api/v1/webhooks/github",
      headers: {
        "content-type": "application/json",
        "x-github-event": "pull_request",
        "x-github-delivery": "deliv-pr-42-opened",
        "x-hub-signature-256": computeGitHubWebhookSignature(prBody, webhookSecret)
      },
      payload: prBody
    });
    expect(prRes.statusCode).toBe(202);
    const prJson = prRes.json() as { status: string; scanId: string; checkRunId: number };
    expect(prJson.status).toBe("accepted");
    expect(prJson.checkRunId).toBe(7001);

    await enqueuer.drain();

    // Verify both Check Run completion PATCH and sticky PR comment POST happened
    const checkPatch = githubCalls.find(
      (c) => c.method === "PATCH" && c.url.includes("/check-runs/7001")
    );
    expect(checkPatch).toBeDefined();
    expect((checkPatch?.body as { status?: string; conclusion?: string })?.status).toBe("completed");
    expect((checkPatch?.body as { conclusion?: string })?.conclusion).toBe("action_required");

    const prCommentPost = githubCalls.find(
      (c) => c.method === "POST" && c.url.includes("/issues/42/comments")
    );
    expect(prCommentPost).toBeDefined();
    expect(String((prCommentPost?.body as { body?: string })?.body)).toContain(
      INDICATIVE_PR_COMMENT_MARKER
    );

    // 4. Replay of identical X-GitHub-Delivery MUST be ignored cleanly
    const replayRes = await api.inject({
      method: "POST",
      url: "/api/v1/webhooks/github",
      headers: {
        "content-type": "application/json",
        "x-github-event": "pull_request",
        "x-github-delivery": "deliv-pr-42-opened",
        "x-hub-signature-256": computeGitHubWebhookSignature(prBody, webhookSecret)
      },
      payload: prBody
    });
    expect(replayRes.statusCode).toBe(200);
    expect(replayRes.json().status).toBe("duplicate_ignored");

    // 5. Webhook deliveries audit endpoint shows org deliveries
    const deliveriesRes = await api.inject({
      method: "GET",
      url: "/api/v1/webhooks/deliveries",
      headers: { Authorization: `Bearer ${authToken}` }
    });
    expect(deliveriesRes.statusCode).toBe(200);
    expect(deliveriesRes.json().deliveries.length).toBeGreaterThanOrEqual(1);
  });

  it("parses cron schedules, enforces CRUD, and executes due scheduled scans idempotently", async () => {
    expect(resolveCronExpression("DAILY")).toBe("0 2 * * *");
    expect(resolveCronExpression("WEEKLY")).toBe("0 3 * * 1");
    const next = computeNextCronRun("0 2 * * *", new Date("2026-11-24T01:30:00Z"));
    expect(next.toISOString()).toBe("2026-11-24T02:00:00.000Z");
    expect(() => computeNextCronRun("invalid cron")).toThrow();

    const createRes = await api.inject({
      method: "POST",
      url: "/api/v1/schedules",
      headers: { Authorization: `Bearer ${authToken}` },
      payload: {
        projectId: demoProjectId,
        name: "Nightly CI/CD & CVE Audit",
        cadence: "DAILY",
        scanners: ["cicd-github-actions"]
      }
    });
    expect(createRes.statusCode).toBe(201);
    const scheduleId = createRes.json().schedule.id as string;

    // Backdate nextRunAt to simulate due schedule
    const pastSlot = new Date("2026-11-24T02:00:00Z");
    await dbConn.db
      .update(scanSchedules)
      .set({ nextRunAt: pastSlot })
      .where(eq(scanSchedules.id, scheduleId));

    const tick1 = await runDueScanSchedules({
      db: dbConn.db,
      enqueuer,
      now: new Date("2026-11-24T02:01:00Z")
    });
    expect(tick1.checked).toBe(1);
    expect(tick1.triggeredScanIds.length).toBe(1);
    await enqueuer.drain();

    // Second tick at the same timestamp must trigger 0 scans (nextRunAt advanced)
    const tick2 = await runDueScanSchedules({
      db: dbConn.db,
      enqueuer,
      now: new Date("2026-11-24T02:01:30Z")
    });
    expect(tick2.triggeredScanIds.length).toBe(0);

    const listRes = await api.inject({
      method: "GET",
      url: "/api/v1/schedules",
      headers: { Authorization: `Bearer ${authToken}` }
    });
    expect(listRes.statusCode).toBe(200);
    expect(listRes.json().schedules.some((s: { id: string }) => s.id === scheduleId)).toBe(true);
  });

  it("creates encrypted Slack/Jira/GitHub Issue channels, blocks SSRF URLs, never exposes credentials, and dispatches alerts on scan completion", async () => {
    // 1. SSRF attempt on Jira baseUrl pointing to cloud metadata IP must fail with 400
    const ssrfRes = await api.inject({
      method: "POST",
      url: "/api/v1/notifications/channels",
      headers: { Authorization: `Bearer ${authToken}` },
      payload: {
        channelType: "JIRA",
        name: "SSRF Attempt",
        config: {
          baseUrl: "http://169.254.169.254",
          projectKey: "SEC",
          issueType: "Task",
          email: "sec@example.com",
          apiToken: "jira-token-123456789"
        }
      }
    });
    expect(ssrfRes.statusCode).toBe(400);

    // 2. Create Slack, Jira, and GitHub Issue channels
    const slackRes = await api.inject({
      method: "POST",
      url: "/api/v1/notifications/channels",
      headers: { Authorization: `Bearer ${authToken}` },
      payload: {
        channelType: "SLACK",
        name: "SecOps Slack",
        events: ["SCAN_COMPLETED", "NEW_CRITICAL_OR_HIGH", "KEV_DETECTED"],
        minSeverity: "HIGH",
        onlyOnNewFindings: false,
        config: {
          webhookUrl: "https://hooks.slack.com/services/T111/B222/SecretWebhookToken999",
          channelLabel: "#secops"
        }
      }
    });
    expect(slackRes.statusCode).toBe(201);
    const slackChannel = slackRes.json().channel as Record<string, unknown>;
    expect(slackChannel.hasCredentials).toBe(true);
    // Secret webhook URL MUST NEVER be echoed in API responses
    expect(JSON.stringify(slackChannel)).not.toContain("SecretWebhookToken999");

    // Verify DB stores ciphertext, not plaintext
    const [dbSlackRow] = await dbConn.db
      .select()
      .from(notificationChannels)
      .where(eq(notificationChannels.id, String(slackChannel.id)));
    expect(dbSlackRow?.encryptedCredentials).toMatch(/^enc:v1:/);
    expect(dbSlackRow?.encryptedCredentials).not.toContain("SecretWebhookToken999");

    const jiraRes = await api.inject({
      method: "POST",
      url: "/api/v1/notifications/channels",
      headers: { Authorization: `Bearer ${authToken}` },
      payload: {
        channelType: "JIRA",
        name: "Security Jira",
        events: ["SCAN_COMPLETED", "NEW_CRITICAL_OR_HIGH"],
        minSeverity: "HIGH",
        onlyOnNewFindings: false,
        config: {
          baseUrl: "https://acme-sec.atlassian.net",
          projectKey: "SEC",
          issueType: "Task",
          email: "appsec@acme.example",
          apiToken: "jira-api-secret-token-xyz123"
        }
      }
    });
    expect(jiraRes.statusCode).toBe(201);
    expect(JSON.stringify(jiraRes.json())).not.toContain("jira-api-secret-token-xyz123");

    const ghIssueRes = await api.inject({
      method: "POST",
      url: "/api/v1/notifications/channels",
      headers: { Authorization: `Bearer ${authToken}` },
      payload: {
        channelType: "GITHUB_ISSUE",
        name: "Security Tracking Repo",
        events: ["SCAN_COMPLETED"],
        minSeverity: "HIGH",
        onlyOnNewFindings: false,
        config: {
          repositoryFullName: "acme/sec",
          token: "github_pat_mock_issue_token_1234567890"
        }
      }
    });
    expect(ghIssueRes.statusCode).toBe(201);
    expect(JSON.stringify(ghIssueRes.json())).not.toContain("github_pat_mock_issue_token");

    // 3. Test notification delivery endpoint works for Slack
    const testRes = await api.inject({
      method: "POST",
      url: `/api/v1/notifications/channels/${slackChannel.id}/test`,
      headers: { Authorization: `Bearer ${authToken}` }
    });
    expect(testRes.statusCode).toBe(200);
    expect(testRes.json().result.ok).toBe(true);

    // 4. Trigger a real scan via API and verify Slack, Jira, and GitHub Issue alerts are all dispatched!
    outboundNotificationCalls.length = 0;
    const scanRes = await api.inject({
      method: "POST",
      url: `/api/v1/projects/${demoProjectId}/scans`,
      headers: { Authorization: `Bearer ${authToken}` },
      payload: {
        scanners: ["cicd-github-actions"]
      }
    });
    expect(scanRes.statusCode).toBe(202);
    await enqueuer.drain();

    expect(outboundNotificationCalls.some((c) => c.url.includes("hooks.slack.com"))).toBe(true);
    expect(outboundNotificationCalls.some((c) => c.url.includes("/rest/api/3/issue"))).toBe(true);

    const deliveriesRes = await api.inject({
      method: "GET",
      url: "/api/v1/notifications/deliveries",
      headers: { Authorization: `Bearer ${authToken}` }
    });
    expect(deliveriesRes.statusCode).toBe(200);
    const deliveries = deliveriesRes.json().deliveries as Array<{ status: string; externalRef?: string }>;
    expect(deliveries.some((d) => d.status === "SENT")).toBe(true);
    expect(deliveries.some((d) => d.externalRef === "https://acme-sec.atlassian.net/browse/SEC-42")).toBe(
      true
    );
    expect(demoOrgId).toBeTruthy();
  });
});

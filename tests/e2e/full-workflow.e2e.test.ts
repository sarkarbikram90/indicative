import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { loadConfig } from "@indicative/config";
import {
  createEmbeddedPostgresConnection,
  findings as findingsTable,
  runMigrations,
  seedDatabase,
  type DatabaseConnection
} from "@indicative/database";
import { AiSecurityAnalyst, type AiProvider } from "@indicative/ai";
import {
  createDefaultScannerRegistry,
  createResourceLimits,
  IsolatedScannerRunner
} from "@indicative/scanner-runner";
import { createRedactingLogger } from "@indicative/security";
import { LocalArtifactStorage } from "@indicative/shared";
import { createInlineAsyncEnqueuer } from "@indicative/worker";
import { buildApiServer } from "../../apps/api/src/server.js";
import {
  materializeVulnerableGitRepo,
  type MaterializedCorpusRepo
} from "../fixtures/corpusBuilder.js";

describe("End-to-End: Complete Indicative Workflow with REAL Semgrep, Trivy, and Gitleaks", () => {
  let tmpDir: string;
  let corpusRepo: MaterializedCorpusRepo;
  let dbConn: DatabaseConnection;
  let api: Awaited<ReturnType<typeof buildApiServer>>;
  let enqueuer: ReturnType<typeof createInlineAsyncEnqueuer>;
  const capturedLogs: string[] = [];
  const capturedAiPrompts: string[] = [];

  beforeAll(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "ind-e2e-"));
    corpusRepo = await materializeVulnerableGitRepo(tmpDir);

    dbConn = await createEmbeddedPostgresConnection();
    await runMigrations(dbConn);
    await seedDatabase(dbConn, corpusRepo.repoPath);

    const config = loadConfig({
      NODE_ENV: "test",
      DEMO_MODE: "true",
      SCANNER_RUNNER_MODE: "local",
      SCANNER_WORKSPACES_ROOT: path.join(tmpDir, "workspaces"),
      ARTIFACT_STORAGE_DRIVER: "local",
      ARTIFACT_LOCAL_DIR: path.join(tmpDir, "artifacts"),
      SEMGREP_RULES_DIR: path.resolve(process.cwd(), "services/scanner-runner/rules/semgrep"),
      TRIVY_CACHE_DIR: path.resolve(process.cwd(), ".trivy-cache"),
      AI_PROVIDER: "openai-compatible",
      AI_API_KEY: "test-mock-key"
    });

    const logger = createRedactingLogger({
      service: "e2e",
      sink: (line) => capturedLogs.push(line)
    });

    const localRunner = new IsolatedScannerRunner({
      registry: createDefaultScannerRegistry({
        semgrepBin: config.SEMGREP_BIN,
        semgrepRulesDir: config.SEMGREP_RULES_DIR,
        trivyBin: config.TRIVY_BIN,
        trivyCacheDir: config.TRIVY_CACHE_DIR,
        trivyOfflineMode: true,
        gitleaksBin: config.GITLEAKS_BIN
      }),
      workspacesRoot: config.SCANNER_WORKSPACES_ROOT,
      limits: createResourceLimits(),
      logger
    });

    const artifactStorage = new LocalArtifactStorage(config.ARTIFACT_LOCAL_DIR);

    const mockAiProvider: AiProvider = {
      name: "openai-compatible",
      model: "gpt-4o-mini-e2e",
      enabled: true,
      async complete(req) {
        capturedAiPrompts.push(req.messages.map((m) => m.content).join("\n"));
        return {
          content: JSON.stringify({
            summary: "Detected vulnerability verified via deterministic scanner output.",
            whyItMatters: "Allows unauthorized query manipulation or credential misuse.",
            rootCause: "Untrusted input interpolated into sink without parameterization.",
            attackScenario: "An attacker passes crafted input to alter query semantics.",
            recommendedRemediation: "Use parameterized prepared statements and rotate exposed keys.",
            secureCodePattern: "db.query('SELECT id FROM users WHERE id = $1', [userId])",
            verificationSteps: [
              "Apply fix and commit to repository",
              "Initiate follow-up Indicative scan to verify finding is no longer detected"
            ],
            missingInformation: ["Runtime deployment topology and network exposure."],
            uncertaintyNotes: "Static scan alone does not confirm internet reachability."
          }),
          model: "gpt-4o-mini-e2e",
          provider: "openai-compatible",
          promptTokens: 320,
          completionTokens: 180,
          totalTokens: 500,
          latencyMs: 18
        };
      }
    };

    const aiAnalyst = new AiSecurityAnalyst({ provider: mockAiProvider });

    enqueuer = createInlineAsyncEnqueuer(() => ({
      db: dbConn.db,
      config,
      artifactStorage,
      localRunner,
      aiAnalyst,
      logger
    }));

    api = await buildApiServer({
      config,
      dbConn,
      enqueuer,
      artifactStorage,
      aiAnalyst,
      logger
    });
  });

  afterAll(async () => {
    await api.close();
    await dbConn.close();
    await corpusRepo.cleanup();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("executes full 13-step E2E scan, redaction, AI analysis, remediation commit, and re-scan verification", async () => {
    // 1. Authenticate user
    const login = await api.inject({ method: "POST", url: "/api/v1/auth/demo" });
    expect(login.statusCode).toBe(200);
    const token = login.json().token as string;
    const authHeaders = { Authorization: `Bearer ${token}` };

    // 2-3. Verify repository appears in Indicative
    const projectsRes = await api.inject({
      method: "GET",
      url: "/api/v1/projects",
      headers: authHeaders
    });
    expect(projectsRes.statusCode).toBe(200);
    const projectId = projectsRes.json().projects[0].id as string;

    // 4-6. Initiate Scan #1 and wait for real Semgrep + Trivy + Gitleaks background execution
    const scan1Init = await api.inject({
      method: "POST",
      url: `/api/v1/projects/${projectId}/scans`,
      headers: authHeaders,
      payload: { runAiAnalysis: false }
    });
    expect(scan1Init.statusCode).toBe(202);
    const scan1Id = scan1Init.json().scan.id as string;

    await enqueuer.drain();

    const scan1Detail = await api.inject({
      method: "GET",
      url: `/api/v1/scans/${scan1Id}`,
      headers: authHeaders
    });
    expect(scan1Detail.statusCode).toBe(200);
    const scan1Body = scan1Detail.json();
    expect(scan1Body.scan.status).toBe("COMPLETED");
    expect(scan1Body.scan.commitSha).toMatch(/^[0-9a-f]{40}$/);
    expect(scan1Body.scannerRuns).toHaveLength(3);
    for (const run of scan1Body.scannerRuns) {
      expect(run.status).toBe("SUCCESS");
    }

    // Verify stage-level latency & peak RSS telemetry recorded for objective profiling (ADR-014)
    expect(typeof scan1Body.scan.summaryCounts.ingestMs).toBe("number");
    expect(typeof scan1Body.scan.summaryCounts.scanMs).toBe("number");
    expect(typeof scan1Body.scan.summaryCounts.parseNormalizeMs).toBe("number");
    expect(typeof scan1Body.scan.summaryCounts.persistMs).toBe("number");
    expect(typeof scan1Body.scan.summaryCounts.artifactMs).toBe("number");
    expect(scan1Body.scan.summaryCounts.peakRssMb).toBeGreaterThan(0);

    const metricsRes = await api.inject({ method: "GET", url: "/metrics" });
    expect(metricsRes.statusCode).toBe(200);
    expect(metricsRes.body).toContain("indicative_scan_stage_duration_ms");
    expect(metricsRes.body).toContain("indicative_worker_peak_rss_bytes");

    // 7-8. Verify normalized findings across all 4 categories (SAST, SCA, SECRET, IAC)
    const findingsRes = await api.inject({
      method: "GET",
      url: `/api/v1/projects/${projectId}/findings?pageSize=100`,
      headers: authHeaders
    });
    expect(findingsRes.statusCode).toBe(200);
    const allFindings = findingsRes.json().findings as Array<any>;

    const categories = new Set(allFindings.map((f) => f.category));
    expect(categories.has("SAST")).toBe(true);
    expect(categories.has("SCA")).toBe(true);
    expect(categories.has("SECRET")).toBe(true);
    expect(categories.has("IAC")).toBe(true);

    // Verify historical removed secret (GitHub PAT) WAS detected in Git history!
    const histSecret = allFindings.find(
      (f) => f.category === "SECRET" && f.ruleId === "github-pat"
    );
    expect(histSecret).toBeDefined();
    expect(histSecret.exposureLocation).toBe("GIT_HISTORY");
    expect(histSecret.secretValidity).toBe("NOT_VERIFIED");
    expect(histSecret.secretFingerprint).toMatch(/^hmac-sha256:v1:/);

    // Verify duplicate AWS dummy key across current.env & backup.env was correlated into ONE canonical finding!
    const awsSecret = allFindings.find(
      (f) => f.category === "SECRET" && f.ruleId === "aws-access-token"
    );
    expect(awsSecret).toBeDefined();
    expect(awsSecret.occurrenceCount).toBeGreaterThanOrEqual(2);

    // 9-10. Open a SAST finding and generate AI contextual analysis
    const sqliFinding = allFindings.find(
      (f) => f.ruleId === "indicative.js.sql-injection.template-query"
    );
    expect(sqliFinding).toBeDefined();

    const detailRes = await api.inject({
      method: "GET",
      url: `/api/v1/findings/${sqliFinding.id}`,
      headers: authHeaders
    });
    expect(detailRes.statusCode).toBe(200);

    const aiRes = await api.inject({
      method: "POST",
      url: `/api/v1/findings/${sqliFinding.id}/analyze`,
      headers: authHeaders
    });
    expect(aiRes.statusCode).toBe(200);
    expect(aiRes.json().analysis.model).toBe("gpt-4o-mini-e2e");

    // Also run AI analysis on the AWS secret finding to verify secrets NEVER reach AI prompts!
    const aiSecretRes = await api.inject({
      method: "POST",
      url: `/api/v1/findings/${awsSecret.id}/analyze`,
      headers: authHeaders
    });
    expect(aiSecretRes.statusCode).toBe(200);

    // Verify JSON, SARIF, and CSV exports succeed and contain ZERO plaintext secrets
    const [jsonExp, sarifExp, csvExp] = await Promise.all([
      api.inject({
        method: "GET",
        url: `/api/v1/scans/${scan1Id}/report?format=json`,
        headers: authHeaders
      }),
      api.inject({
        method: "GET",
        url: `/api/v1/scans/${scan1Id}/report?format=sarif`,
        headers: authHeaders
      }),
      api.inject({
        method: "GET",
        url: `/api/v1/scans/${scan1Id}/report?format=csv`,
        headers: authHeaders
      })
    ]);
    expect(jsonExp.statusCode).toBe(200);
    expect(sarifExp.statusCode).toBe(200);
    expect(csvExp.statusCode).toBe(200);
    expect(sarifExp.json().version).toBe("2.1.0");

    // CRITICAL CRITERION 5: Verify ZERO plaintext secrets in DB, API responses, reports, logs, or AI prompts!
    const rawDbRows = await dbConn.db.select().from(findingsTable);
    const allSurfaces = [
      findingsRes.body,
      detailRes.body,
      jsonExp.body,
      sarifExp.body,
      csvExp.body,
      capturedLogs.join("\n"),
      capturedAiPrompts.join("\n"),
      JSON.stringify(rawDbRows)
    ].join("\n");

    expect(allSurfaces).not.toContain(corpusRepo.secrets.dummyAwsKey);
    expect(allSurfaces).not.toContain(corpusRepo.secrets.dummyGithubPat);
    expect(allSurfaces).not.toContain(corpusRepo.secrets.dummyDbPassword);
    expect(allSurfaces).not.toContain(corpusRepo.secrets.dummyPrivateKeyLine);

    // 11-13. Transition SQLi finding to FIXED_PENDING_VERIFICATION, apply real remediation commit, and re-scan!
    const markFixed = await api.inject({
      method: "PATCH",
      url: `/api/v1/findings/${sqliFinding.id}/status`,
      headers: authHeaders,
      payload: {
        status: "FIXED_PENDING_VERIFICATION",
        reason: "Replaced template SQL query with parameterized query in src/vulnerable.ts."
      }
    });
    expect(markFixed.statusCode).toBe(200);

    const newCommitSha = await corpusRepo.applyRemediationCommit();

    const scan2Init = await api.inject({
      method: "POST",
      url: `/api/v1/projects/${projectId}/scans`,
      headers: authHeaders,
      payload: {}
    });
    expect(scan2Init.statusCode).toBe(202);
    const scan2Id = scan2Init.json().scan.id as string;
    await enqueuer.drain();

    const scan2Detail = await api.inject({
      method: "GET",
      url: `/api/v1/scans/${scan2Id}`,
      headers: authHeaders
    });
    expect(scan2Detail.statusCode).toBe(200);
    const scan2Json = scan2Detail.json();
    expect(scan2Json.scan.status).toBe("COMPLETED");
    expect(scan2Json.scan.commitSha).toBe(newCommitSha);
    expect(scan2Json.scan.comparisonSummary.notDetectedFindingIds).toContain(sqliFinding.id);

    // Verify SQLi finding is now RESOLVED_VERIFIED with VERIFICATION_SUCCESSFUL_WITHIN_SCANNED_SCOPE
    const verifiedFindingRes = await api.inject({
      method: "GET",
      url: `/api/v1/findings/${sqliFinding.id}`,
      headers: authHeaders
    });
    const verified = verifiedFindingRes.json();
    expect(verified.finding.status).toBe("RESOLVED_VERIFIED");
    expect(verified.finding.verificationState).toBe(
      "VERIFICATION_SUCCESSFUL_WITHIN_SCANNED_SCOPE"
    );
    expect(verified.statusHistory.length).toBeGreaterThanOrEqual(3);

    // Verify Dashboard reflects both open and resolved findings
    const dash = await api.inject({
      method: "GET",
      url: "/api/v1/dashboard",
      headers: authHeaders
    });
    expect(dash.statusCode).toBe(200);
    expect(dash.json().totals.openFindings).toBeGreaterThan(0);
    expect(dash.json().totals.resolvedOrNotDetected).toBeGreaterThan(0);
  });
});

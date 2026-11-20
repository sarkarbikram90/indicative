import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  assertApprovedBinary,
  buildSanitizedScannerEnv,
  GitleaksScannerAdapter,
  parseAndRedactGitleaksOutput,
  parseSemgrepOutput,
  parseTrivyOutput,
  SemgrepScannerAdapter,
  TrivyScannerAdapter
} from "./index.js";

describe("@indicative/scanners — unit & independent real scanner verification", () => {
  const masterKey = "unit-test-master-secret-fingerprint-key-0123456789abcdef";

  it("blocks unapproved binaries and strips control-plane secrets from scanner env", () => {
    expect(() => assertApprovedBinary("bash")).toThrow(/SECURITY_DISALLOWED_BINARY/);
    expect(() => assertApprovedBinary("powershell.exe")).toThrow(/SECURITY_DISALLOWED_BINARY/);
    expect(() => assertApprovedBinary("semgrep")).not.toThrow();

    process.env.GITHUB_APP_PRIVATE_KEY = "super-sensitive-private-key";
    process.env.AI_API_KEY = "sk-should-never-leak-to-scanner";
    const env = buildSanitizedScannerEnv();
    expect(env.GITHUB_APP_PRIVATE_KEY).toBeUndefined();
    expect(env.AI_API_KEY).toBeUndefined();
    expect(env.SEMGREP_SEND_METRICS).toBe("off");
    delete process.env.GITHUB_APP_PRIVATE_KEY;
    delete process.env.AI_API_KEY;
  });

  it("handles malformed JSON safely across all scanner parsers", () => {
    expect(() =>
      parseSemgrepOutput("{not-json", "/tmp", "1.186.0", "v1")
    ).toThrow();
    expect(() => parseTrivyOutput("invalid", "/tmp", "0.76.2")).toThrow();
    expect(() =>
      parseAndRedactGitleaksOutput("{}", {
        workspacePath: "/tmp",
        scannerVersion: "8.30.1",
        organizationId: "org-1",
        secretFingerprintKey: masterKey,
        exposureLocation: "WORKING_TREE"
      })
    ).toThrow();
  });

  it("immediately redacts raw Gitleaks secrets and computes keyed HMAC fingerprints", () => {
    const dummySecret = ["ghp_", "9xK4mN7pQ2rS5tU8vW1yZ3aB6cD0eF4gH7jK"].join("");
    const sample = JSON.stringify([
      {
        RuleID: "github-pat",
        Description: "GitHub Personal Access Token",
        StartLine: 3,
        EndLine: 3,
        Match: `GITHUB_TOKEN=${dummySecret}`,
        Secret: dummySecret,
        File: "config/secrets.env",
        Commit: "1111222233334444",
        Date: "2026-01-01T00:00:00Z",
        Entropy: 4.5
      }
    ]);

    const parsed = parseAndRedactGitleaksOutput(sample, {
      workspacePath: "/workspace",
      scannerVersion: "8.30.1",
      organizationId: "org-1",
      secretFingerprintKey: masterKey,
      exposureLocation: "GIT_HISTORY"
    });

    expect(parsed).toHaveLength(1);
    expect(parsed[0]!.secretFingerprint).toMatch(/^hmac-sha256:v1:/);
    expect(JSON.stringify(parsed[0])).not.toContain(dummySecret);
  });

  it("demonstrates REAL Semgrep, Trivy, and Gitleaks independently against fixtures (Phase 3 Gate)", async () => {
    const rulesDir = path.resolve(process.cwd(), "services/scanner-runner/rules/semgrep");
    const trivyCacheDir = path.resolve(process.cwd(), ".trivy-cache");
    const fixtureDir = path.resolve(process.cwd(), "tests/fixtures/vulnerable-app");

    const semgrep = new SemgrepScannerAdapter({ binaryPath: "semgrep", rulesDir });
    const trivy = new TrivyScannerAdapter({
      binaryPath: "trivy",
      cacheDir: trivyCacheDir,
      offlineMode: true
    });
    const gitleaks = new GitleaksScannerAdapter({ binaryPath: "gitleaks" });

    // 1. Health checks
    const [sHealth, tHealth, gHealth] = await Promise.all([
      semgrep.healthCheck(),
      trivy.healthCheck(),
      gitleaks.healthCheck()
    ]);

    expect(sHealth.available).toBe(true);
    expect(tHealth.available).toBe(true);
    expect(gHealth.available).toBe(true);

    // 2. Real Semgrep execution on an isolated temp copy of vulnerable-app
    const tmpSemgrepWs = await fs.mkdtemp(path.join(os.tmpdir(), "ind-sg-unit-"));
    try {
      await fs.cp(fixtureDir, tmpSemgrepWs, { recursive: true });
      const semgrepRes = await semgrep.execute({
        scanId: "unit-semgrep-1",
        organizationId: "org-1",
        projectId: "proj-1",
        workspacePath: tmpSemgrepWs,
        hasGitHistory: false,
        isShallowClone: false,
        maxGitHistoryCommits: 100,
        timeoutMs: 60_000,
        secretFingerprintKey: masterKey
      });
      expect(semgrepRes.status).toBe("SUCCESS");
      expect(semgrepRes.findings.length).toBeGreaterThanOrEqual(10);
      expect(
        semgrepRes.findings.some((f) => f.ruleId === "indicative.js.sql-injection.template-query")
      ).toBe(true);
    } finally {
      await fs.rm(tmpSemgrepWs, { recursive: true, force: true });
    }

    // 3. Real Trivy offline execution on vulnerable-app (SCA + IaC)
    const trivyRes = await trivy.execute({
      scanId: "unit-trivy-1",
      organizationId: "org-1",
      projectId: "proj-1",
      workspacePath: fixtureDir,
      hasGitHistory: false,
      isShallowClone: false,
      maxGitHistoryCommits: 100,
      timeoutMs: 60_000,
      secretFingerprintKey: masterKey
    });
    expect(trivyRes.status).toBe("SUCCESS");
    expect(trivyRes.findings.some((f) => f.category === "SCA" && f.packageName === "lodash")).toBe(
      true
    );
    expect(trivyRes.findings.some((f) => f.category === "IAC")).toBe(true);

    // 4. Real Gitleaks execution on a temporary file with dummy AWS key
    const tmpSecretDir = await fs.mkdtemp(path.join(os.tmpdir(), "ind-gl-test-"));
    const dummyAws = ["AKIA", "QYLPMN5HHHFPZAM2"].join("");
    try {
      await fs.writeFile(
        path.join(tmpSecretDir, ".env"),
        `AWS_ACCESS_KEY_ID=${dummyAws}\n`,
        "utf8"
      );
      const glRes = await gitleaks.execute({
        scanId: "unit-gl-1",
        organizationId: "org-1",
        projectId: "proj-1",
        workspacePath: tmpSecretDir,
        hasGitHistory: false,
        isShallowClone: false,
        maxGitHistoryCommits: 100,
        timeoutMs: 30_000,
        secretFingerprintKey: masterKey
      });
      expect(glRes.status).toBe("SUCCESS");
      expect(glRes.findings.length).toBeGreaterThanOrEqual(1);
      expect(glRes.limitations.some((l) => l.code === "NO_GIT_HISTORY")).toBe(true);
      expect(JSON.stringify(glRes)).not.toContain(dummyAws);
    } finally {
      await fs.rm(tmpSecretDir, { recursive: true, force: true });
    }
  });
});

import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  analyzeStructuredOidcPolicies,
  analyzeWorkspaceCicdSecurity,
  CicdGitHubActionsAdapter,
  evaluateCicdPolicy,
  formatGitHubAnnotations,
  formatPullRequestMarkdownSummary,
  isActionPinnedToSha,
  isSubjectOverlyBroad,
  parseGitHubWorkflowYaml
} from "./index.js";

describe("@indicative/cicd-security", () => {
  it("parses valid GitHub Actions workflows with line numbers and distinguishes pinned vs mutable actions", () => {
    expect(isActionPinnedToSha("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")).toBe(true);
    expect(isActionPinnedToSha("./.github/actions/local-build")).toBe(true);
    expect(isActionPinnedToSha("docker://alpine@sha256:" + "a".repeat(64))).toBe(true);
    expect(isActionPinnedToSha("actions/checkout@v4")).toBe(false);
    expect(isActionPinnedToSha("org/action@main")).toBe(false);

    const parsed = parseGitHubWorkflowYaml(
      ".github/workflows/ci.yml",
      [
        "name: CI",
        "on: [push, pull_request]",
        "permissions:",
        "  contents: read",
        "jobs:",
        "  build:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - run: npm ci"
      ].join("\n")
    );

    expect(parsed.error).toBeUndefined();
    expect(parsed.workflow?.name).toBe("CI");
    expect(parsed.workflow?.triggers.map((t) => t.event)).toEqual(["push", "pull_request"]);
    expect(parsed.workflow?.permissions?.scopes.contents).toBe("read");
    expect(parsed.workflow?.jobs).toHaveLength(1);
    expect(parsed.workflow?.thirdPartyActions[0]?.pinnedToSha).toBe(false);
    expect(parsed.workflow?.thirdPartyActions[0]?.lineStart).toBe(9);
  });

  it("defends against YAML alias expansion bombs (CICD-T1) and reports malformed workflows as PARTIAL (CICD-T6)", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "ind-cicd-adv-"));
    try {
      const wfDir = path.join(tmpDir, ".github", "workflows");
      await fs.mkdir(wfDir, { recursive: true });

      // Malformed YAML workflow
      await fs.writeFile(
        path.join(wfDir, "broken.yml"),
        "name: Broken\non:\n  push: [\nunclosed",
        "utf8"
      );

      // Alias expansion bomb (> 32 aliases)
      const aliases = Array.from({ length: 40 }, () => "*a").join(", ");
      await fs.writeFile(
        path.join(wfDir, "bomb.yml"),
        `name: Bomb\non: push\nx-a: &a [1, 2, 3]\nx-b: [${aliases}]\njobs: {}\n`,
        "utf8"
      );

      const adapter = new CicdGitHubActionsAdapter();
      const res = await adapter.execute({
        scanId: "11111111-1111-1111-1111-111111111111",
        organizationId: "22222222-2222-2222-2222-222222222222",
        projectId: "33333333-3333-3333-3333-333333333333",
        workspacePath: tmpDir,
        hasGitHistory: false,
        isShallowClone: false,
        maxGitHistoryCommits: 100,
        timeoutMs: 10_000,
        secretFingerprintKey: "test-key-0123456789abcdef0123456789abcdef"
      });

      expect(res.status).toBe("PARTIAL");
      expect(res.errorClass).toBe("MALFORMED_OUTPUT");
      expect(res.limitations.some((l) => l.code === "WORKFLOW_YAML_PARSE_ERROR")).toBe(true);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("detects overly broad OIDC subjects and parses CloudFormation/IAM JSON OIDC trust policies", () => {
    expect(isSubjectOverlyBroad("repo:acme/*")).toBe(true);
    expect(isSubjectOverlyBroad("repo:acme/app:*")).toBe(true);
    expect(isSubjectOverlyBroad("*")).toBe(true);
    expect(isSubjectOverlyBroad("repo:acme/app:environment:production")).toBe(false);
    expect(isSubjectOverlyBroad("repo:acme/app:ref:refs/heads/main")).toBe(false);

    const iamJson = JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Principal: {
            Federated: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
          },
          Action: "sts:AssumeRoleWithWebIdentity",
          Condition: {
            StringLike: {
              "token.actions.githubusercontent.com:sub": "repo:acme/*"
            }
          }
        }
      ]
    });

    const policies = analyzeStructuredOidcPolicies("iam/trust-policy.json", iamJson);
    expect(policies).toHaveLength(1);
    expect(policies[0]!.hasWildcardSubject).toBe(true);
    expect(policies[0]!.hasMissingOrWildcardAudience).toBe(true);
  });

  it("escapes GitHub Actions annotations safely against workflow-command injection (CICD-T5) and redacts embedded secrets (CICD-T4)", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "ind-cicd-inj-"));
    try {
      const wfDir = path.join(tmpDir, ".github", "workflows");
      await fs.mkdir(wfDir, { recursive: true });
      const dummyPat = ["ghp_", "9xK4mN7pQ2rS5tU8vW1yZ3aB6cD0eF4gH7jK"].join("");

      await fs.writeFile(
        path.join(wfDir, "leaky.yml"),
        [
          `name: "Leaky\\n::add-mask::injected"`,
          "on: pull_request_target",
          "permissions: write-all",
          "jobs:",
          "  leak:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          `      - run: echo "${dummyPat}" && echo "\${{ github.event.pull_request.title }}"`
        ].join("\n"),
        "utf8"
      );

      const report = await analyzeWorkspaceCicdSecurity(tmpDir);
      expect(report.findings.length).toBeGreaterThan(0);

      // Zero plaintext secret leakage across entire report
      expect(JSON.stringify(report.findings)).not.toContain(dummyPat);

      // Annotations must escape newlines and % signs so workflow commands cannot be injected
      const annotations = formatGitHubAnnotations(report.findings);
      for (const line of annotations.split("\n")) {
        expect(line.startsWith("::")).toBe(true);
        expect(line).not.toContain("\r");
      }

      // Default policy is non-blocking warning mode; explicit failure mode blocks on CRITICAL/HIGH
      const warnEval = evaluateCicdPolicy(report.findings, {
        mode: "warning",
        failOnSeverities: ["CRITICAL", "HIGH"]
      });
      expect(warnEval.exitCode).toBe(0);
      expect(warnEval.passed).toBe(true);

      const failEval = evaluateCicdPolicy(report.findings, {
        mode: "failure",
        failOnSeverities: ["CRITICAL", "HIGH"]
      });
      expect(failEval.exitCode).toBe(1);
      expect(failEval.passed).toBe(false);

      const md = formatPullRequestMarkdownSummary(report);
      expect(md).toContain("Indicative CI/CD & OIDC Security Summary");
      expect(md).toContain("STATIC_CONFIG");
      expect(md).not.toContain(dummyPat);

      // SARIF 2.1.0 output must be valid, include rules + results, and never leak plaintext secrets
      const { formatCicdReportAsSarif } = await import("./policy.js");
      const sarifRaw = formatCicdReportAsSarif(report);
      expect(sarifRaw).not.toContain(dummyPat);
      const sarif = JSON.parse(sarifRaw) as {
        version: string;
        runs: Array<{
          tool: { driver: { rules: Array<{ id: string }> } };
          results: Array<{ ruleId: string; partialFingerprints: { primaryLocationLineHash: string } }>;
        }>;
      };
      expect(sarif.version).toBe("2.1.0");
      expect(sarif.runs[0]!.tool.driver.rules.length).toBeGreaterThan(0);
      expect(sarif.runs[0]!.results.length).toBe(report.findings.length);
      expect(sarif.runs[0]!.results[0]!.partialFingerprints.primaryLocationLineHash).toMatch(/^[0-9a-f]{64}$/);

      // CLI helper writes SARIF, summary, and GitHub outputs cleanly
      const { runCicdCli } = await import("./cli.js");
      const sarifOut = path.join(tmpDir, "out.sarif");
      const summaryOut = path.join(tmpDir, "summary.md");
      const ghOut = path.join(tmpDir, "gh-output.txt");
      const code = await runCicdCli({
        targetPath: tmpDir,
        format: "markdown",
        policyMode: "failure",
        ignorePaths: [],
        outputFile: path.join(tmpDir, "report.md"),
        sarifFile: sarifOut,
        summaryFile: summaryOut,
        githubOutputFile: ghOut
      });
      expect(code).toBe(1);
      const writtenSarif = JSON.parse(await fs.readFile(sarifOut, "utf8")) as { version: string };
      expect(writtenSarif.version).toBe("2.1.0");
      const writtenGhOut = await fs.readFile(ghOut, "utf8");
      expect(writtenGhOut).toContain("policy-passed=false");
      expect(writtenGhOut).toContain(`findings-count=${report.findings.length}`);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("supports .indicative.yml rule overrides, audited suppressions, inline directives, expiration enforcement, and baseline ratchet mode", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "indicative-cicd-config-"));
    try {
      await fs.mkdir(path.join(tmpDir, ".github", "workflows"), { recursive: true });
      await fs.writeFile(
        path.join(tmpDir, ".github", "workflows", "ci.yml"),
        [
          "name: CI",
          "on: [push]",
          "permissions:",
          "  contents: write",
          "jobs:",
          "  build:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      # indicative-ignore: GHA-ACT-001 reason=\"internal verified mirror\" expires=2099-01-01",
          "      - uses: actions/checkout@v4",
          "      - run: npm install",
          "  deploy:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      # indicative-ignore: GHA-ACT-001 reason=\"expired exception\" expires=2020-01-01",
          "      - uses: actions/setup-node@v4"
        ].join("\n"),
        "utf8"
      );

      await fs.writeFile(
        path.join(tmpDir, ".indicative.yml"),
        [
          "version: 1",
          "policy: failure",
          "rules:",
          "  GHA-INT-002: off",
          "  GHA-PERM-003: low",
          "suppressions:",
          "  - ruleId: GHA-ACT-003",
          "    path: .github/workflows/ci.yml",
          "    reason: \"Temporary build step requires git push credentials\"",
          "    expires: \"2099-12-31\"",
          "  - ruleId: GHA-ACT-001",
          "    path: .github/workflows/ci.yml",
          "    reason: \"Old expired config suppression\"",
          "    expires: \"2021-01-01\""
        ].join("\n"),
        "utf8"
      );

      const report = await analyzeWorkspaceCicdSecurity(tmpDir, {
        nowDateIso: "2026-11-25"
      });

      expect(report.configPath).toBe(".indicative.yml");
      // GHA-INT-002 disabled via config rules, GHA-ACT-003 suppressed via config, first GHA-ACT-001 suppressed inline
      expect(report.suppressedFindings.map((s) => s.ruleId)).toEqual(
        expect.arrayContaining(["GHA-INT-002", "GHA-ACT-003", "GHA-ACT-001"])
      );
      // Expired inline + expired config suppression MUST be rejected and surfaced
      expect(report.expiredSuppressions.length).toBeGreaterThanOrEqual(2);
      expect(report.limitations.some((l) => l.code === "EXPIRED_SUPPRESSION")).toBe(true);
      // GHA-PERM-003 downgraded to LOW via config rules (originalSeverity preserved)
      const perm003 = report.findings.find((f) => f.ruleId === "GHA-PERM-003");
      expect(perm003?.severity).toBe("LOW");
      expect(perm003?.originalSeverity).toBe("HIGH");
      // Second GHA-ACT-001 (expired inline suppression) remains active HIGH and triggers failure policy from .indicative.yml
      expect(report.findings.some((f) => f.ruleId === "GHA-ACT-001")).toBe(true);
      expect(report.policyEvaluation.mode).toBe("failure");
      expect(report.policyEvaluation.passed).toBe(false);

      // Baseline / differential ratchet mode: write baseline, then re-run -> 0 new findings -> passes!
      const { writeBaselineFile } = await import("./baseline.js");
      const baselineFile = path.join(tmpDir, ".indicative-baseline.json");
      await writeBaselineFile(baselineFile, report.findings, report.scanner);

      const ratcheted = await analyzeWorkspaceCicdSecurity(tmpDir, {
        baselinePath: baselineFile,
        nowDateIso: "2026-11-25"
      });
      expect(ratcheted.baselineDiff?.newFindingsCount).toBe(0);
      expect(ratcheted.baselineDiff?.existingBaselineFindingsCount).toBe(report.findings.length);
      expect(ratcheted.policyEvaluation.passed).toBe(true);
      expect(ratcheted.policyEvaluation.exitCode).toBe(0);

      // Introduce one NEW high-severity finding -> baseline ratchet catches ONLY the new finding and fails!
      await fs.writeFile(
        path.join(tmpDir, ".github", "workflows", "new-risk.yml"),
        [
          "name: New Risk",
          "on: [push]",
          "permissions: write-all",
          "jobs:",
          "  x:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      - run: echo ok"
        ].join("\n"),
        "utf8"
      );

      const withNewFinding = await analyzeWorkspaceCicdSecurity(tmpDir, {
        baselinePath: baselineFile,
        nowDateIso: "2026-11-25"
      });
      expect(withNewFinding.baselineDiff?.newFindingsCount).toBe(1);
      expect(withNewFinding.newFindings?.[0]?.ruleId).toBe("GHA-PERM-002");
      expect(withNewFinding.policyEvaluation.passed).toBe(false);
      expect(withNewFinding.policyEvaluation.blockingFindingsCount).toBe(1);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});

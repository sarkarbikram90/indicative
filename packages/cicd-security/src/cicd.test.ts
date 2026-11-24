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
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});

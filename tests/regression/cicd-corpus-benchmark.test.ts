import { describe, it, expect } from "vitest";
import path from "node:path";
import { analyzeWorkspaceCicdSecurity } from "@indicative/cicd-security";
import {
  exportReportAsCsv,
  exportReportAsJson,
  exportReportAsSarif,
  normalizeAndDeduplicateFindings
} from "@indicative/findings";

describe("CI/CD & OIDC Security Regression Corpus — Precision, Recall & False-Positive Baseline", () => {
  const vulnerableDir = path.resolve(process.cwd(), "tests/fixtures/cicd-vulnerable");
  const hardenedDir = path.resolve(process.cwd(), "tests/fixtures/cicd-hardened");

  it("achieves 100% recall on expected vulnerable CI/CD + OIDC rules and 0 false positives on hardened workflows", async () => {
    const [vulnReport, hardenedReport] = await Promise.all([
      analyzeWorkspaceCicdSecurity(vulnerableDir),
      analyzeWorkspaceCicdSecurity(hardenedDir)
    ]);

    expect(vulnReport.limitations).toHaveLength(0);
    expect(hardenedReport.limitations).toHaveLength(0);

    const expectedRules = [
      "GHA-PERM-002", // permissions: write-all
      "GHA-PERM-003", // root contents: write across multiple jobs / untrusted trigger
      "GHA-PERM-004", // root id-token: write across multiple jobs
      "GHA-TRIG-001", // pull_request_target + untrusted PR head checkout
      "GHA-TRIG-002", // workflow_run downloading upstream artifact
      "GHA-INJ-001", // untrusted pull_request.title interpolated directly in run:
      "GHA-ACT-001", // unpinned third-party actions (@v4)
      "GHA-ACT-002", // unpinned external reusable workflow (@main)
      "GHA-ACT-003", // actions/checkout without persist-credentials: false
      "GHA-SEC-001", // echo secrets.DEPLOY_TOKEN + secrets: inherit
      "GHA-SEC-002", // static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
      "GHA-INT-001", // curl | bash
      "GHA-INT-002", // mutable npm install
      "GHA-OIDC-001", // wildcard sub (AWS, Azure) + missing condition (GCP)
      "GHA-OIDC-002", // missing/wildcard aud
      "GHA-OIDC-003" // cross-file correlation: workflow OIDC + permissive trust policy
    ];

    const detectedRuleIds = new Set(vulnReport.findings.map((f) => f.ruleId));
    const missedRules = expectedRules.filter((r) => !detectedRuleIds.has(r));
    const truePositives = expectedRules.length - missedRules.length;
    const falsePositivesOnHardened = hardenedReport.findings.length;

    const recall = truePositives / expectedRules.length;
    const precision = truePositives / (truePositives + falsePositivesOnHardened);

    // Normalize through canonical pipeline & verify SARIF/JSON/CSV generation
    const normalized = normalizeAndDeduplicateFindings({
      organizationId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb1",
      projectId: "cccccccc-cccc-cccc-cccc-ccccccccccc9",
      scanId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa9",
      rawFindings: vulnReport.findings
    });

    const oidcCorrelated = normalized.find((b) => b.finding.ruleId === "GHA-OIDC-003");
    expect(oidcCorrelated?.finding.riskPriority).toBe("IMMEDIATE");
    expect(
      oidcCorrelated?.finding.riskRationale.some((r) => r.includes("STATIC_CONFIG"))
    ).toBe(true);

    const exportCtx = {
      generatedAt: new Date().toISOString(),
      organizationName: "Regression Org",
      projectName: "CI/CD Vulnerable Fixture",
      repositoryFullName: "acme-corp/cicd-vulnerable",
      isDemo: true,
      scan: {
        id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa9",
        branch: "main",
        commitSha: "deadbeef1234",
        status: "COMPLETED",
        limitations: []
      },
      scannerRuns: [
        {
          id: "run-cicd-1",
          scanner: vulnReport.scanner,
          scannerVersion: vulnReport.scannerVersion,
          rulesetVersion: vulnReport.rulesetVersion,
          status: "SUCCESS" as const,
          exitCode: 0,
          findingsCount: vulnReport.findings.length,
          durationMs: 15,
          errorClass: "NONE",
          limitations: [],
          startedAt: new Date().toISOString()
        }
      ],
      findings: normalized.map((n) => n.finding)
    };

    const sarif = JSON.parse(exportReportAsSarif(exportCtx));
    const json = JSON.parse(exportReportAsJson(exportCtx));
    const csv = exportReportAsCsv(exportCtx);

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.length).toBe(normalized.length);
    expect(json.summary.byCategory.CICD).toBe(normalized.length);
    expect(csv).toContain("GHA-OIDC-003");

    console.log(
      JSON.stringify(
        {
          benchmark: "indicative-cicd-oidc-regression-corpus",
          workflowsAnalyzed: vulnReport.workflows.length + hardenedReport.workflows.length,
          oidcPoliciesAnalyzed:
            vulnReport.oidcTrustPolicies.length + hardenedReport.oidcTrustPolicies.length,
          expectedRuleFamilies: expectedRules.length,
          truePositives,
          missedRules,
          vulnerableTotalFindings: vulnReport.findings.length,
          hardenedFalsePositives: falsePositivesOnHardened,
          precision: Number(precision.toFixed(4)),
          recall: Number(recall.toFixed(4))
        },
        null,
        2
      )
    );

    expect(missedRules).toEqual([]);
    expect(falsePositivesOnHardened).toBe(0);
    expect(recall).toBe(1);
    expect(precision).toBe(1);
  });
});

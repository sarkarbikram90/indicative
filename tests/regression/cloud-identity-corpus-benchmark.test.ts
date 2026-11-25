import path from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeWorkspaceCloudIdentity } from "@indicative/cloud-identity";

const VULNERABLE_CORPUS = path.resolve(
  process.cwd(),
  "tests/fixtures/cloud-identity-vulnerable"
);
const HARDENED_CORPUS = path.resolve(
  process.cwd(),
  "tests/fixtures/cloud-identity-hardened"
);

const EXPECTED_RULE_IDS = [
  "IAM-ADMIN-001",
  "IAM-PERM-001",
  "IAM-PERM-002",
  "IAM-DATA-001",
  "IAM-ESC-001",
  "IAM-ESC-002",
  "IAM-BOUND-001",
  "IAM-CORR-001"
] as const;

describe("Cloud Identity & AWS IAM Regression Corpus Benchmark", () => {
  it("achieves 100% recall across all 8 AWS IAM & workflow-correlation rules on vulnerable corpus and 0 false positives on hardened corpus", async () => {
    const vulnReport = await analyzeWorkspaceCloudIdentity(VULNERABLE_CORPUS, {
      mode: "failure",
      failOnSeverities: ["CRITICAL", "HIGH"]
    });
    const detectedVulnRules = new Set(vulnReport.findings.map((f) => f.ruleId));

    const missed = EXPECTED_RULE_IDS.filter((r) => !detectedVulnRules.has(r));
    expect(missed).toEqual([]);
    expect(vulnReport.correlatedChains.length).toBeGreaterThanOrEqual(1);
    expect(vulnReport.correlatedChains[0]!.linkConfidence).toBe("EXACT_ROLE_MATCH");
    expect(vulnReport.policyEvaluation.passed).toBe(false);

    const hardenedReport = await analyzeWorkspaceCloudIdentity(HARDENED_CORPUS, {
      mode: "failure",
      failOnSeverities: ["CRITICAL", "HIGH"]
    });
    expect(hardenedReport.findings).toEqual([]);
    expect(hardenedReport.correlatedChains).toEqual([]);
    expect(hardenedReport.policyEvaluation.passed).toBe(true);
  });
});

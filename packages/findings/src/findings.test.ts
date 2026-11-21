import { describe, it, expect } from "vitest";
import type { RawScannerFinding } from "@indicative/contracts";
import { computeSecretFingerprint } from "@indicative/security";
import {
  assertValidStatusTransition,
  computeCanonicalFingerprint,
  computeScanComparisonAndVerification,
  exportReportAsCsv,
  exportReportAsJson,
  exportReportAsSarif,
  isValidStatusTransition,
  normalizeAndDeduplicateFindings,
  streamReportAsCsv,
  streamReportAsJson,
  streamReportAsSarif
} from "./index.js";

describe("@indicative/findings", () => {
  const masterKey = "unit-test-master-secret-fingerprint-key-0123456789abcdef";

  it("correlates the same leaked credential across multiple files and git history into one canonical finding", () => {
    const dummySecret = ["AKIA", "7F9K2M4P8Q3R6T1V9X2Z"].join("");
    const hmacFp = computeSecretFingerprint(dummySecret, masterKey, "org-1");

    const rawFindings: RawScannerFinding[] = [
      {
        scanner: "gitleaks",
        scannerVersion: "8.30.1",
        ruleId: "aws-access-token",
        category: "SECRET",
        title: "Exposed AWS Access Key in config/current.env",
        description: "Detected in working tree",
        severity: "CRITICAL",
        confidence: "HIGH",
        filePath: "config/current.env",
        lineStart: 2,
        secretType: "aws-access-token",
        secretFingerprint: hmacFp,
        redactedMatch: "[REDACTED:aws-access-token:AKIA****2Z]",
        exposureLocation: "WORKING_TREE",
        references: []
      },
      {
        scanner: "gitleaks",
        scannerVersion: "8.30.1",
        ruleId: "aws-access-token",
        category: "SECRET",
        title: "Exposed AWS Access Key in config/backup.env",
        description: "Detected in git history",
        severity: "CRITICAL",
        confidence: "HIGH",
        filePath: "config/backup.env",
        lineStart: 1,
        commitSha: "abcdef1234567890",
        secretType: "aws-access-token",
        secretFingerprint: hmacFp,
        redactedMatch: "[REDACTED:aws-access-token:AKIA****2Z]",
        exposureLocation: "GIT_HISTORY",
        references: []
      }
    ];

    const normalized = normalizeAndDeduplicateFindings({
      organizationId: "org-1",
      projectId: "proj-1",
      scanId: "scan-1",
      rawFindings
    });

    expect(normalized).toHaveLength(1);
    const bundle = normalized[0]!;
    expect(bundle.occurrences).toHaveLength(2);
    expect(bundle.finding.occurrenceCount).toBe(2);
    expect(bundle.finding.exposureLocation).toBe("BOTH");
    expect(bundle.finding.secretValidity).toBe("NOT_VERIFIED");
    expect(bundle.finding.riskPriority).toBe("IMMEDIATE");
    expect(JSON.stringify(bundle)).not.toContain(dummySecret);
  });

  it("generates distinct deterministic fingerprints per category and never relies on title alone", () => {
    const f1: RawScannerFinding = {
      scanner: "semgrep",
      scannerVersion: "1.186.0",
      ruleId: "indicative.js.sql-injection.template-query",
      category: "SAST",
      title: "Title A",
      description: "SQLi",
      severity: "HIGH",
      confidence: "HIGH",
      filePath: "src/db.ts",
      lineStart: 10,
      codeSnippet: "db.query(`SELECT * FROM users WHERE id = ${id}`)",
      references: []
    };
    const f2: RawScannerFinding = { ...f1, title: "Completely Different Title" };
    const f3: RawScannerFinding = { ...f1, filePath: "src/other.ts" };

    expect(computeCanonicalFingerprint("proj-1", f1)).toBe(
      computeCanonicalFingerprint("proj-1", f2)
    );
    expect(computeCanonicalFingerprint("proj-1", f1)).not.toBe(
      computeCanonicalFingerprint("proj-1", f3)
    );
  });

  it("enforces valid finding lifecycle transitions", () => {
    expect(isValidStatusTransition("OPEN", "ACKNOWLEDGED")).toBe(true);
    expect(isValidStatusTransition("IN_PROGRESS", "FIXED_PENDING_VERIFICATION")).toBe(true);
    expect(isValidStatusTransition("OPEN", "RESOLVED_VERIFIED")).toBe(false);
    expect(() => assertValidStatusTransition("OPEN", "RESOLVED_VERIFIED")).toThrow(
      /INVALID_STATUS_TRANSITION/
    );
  });

  it("marks verification INCONCLUSIVE when responsible scanner failed or had truncated scope", () => {
    const plan = computeScanComparisonAndVerification({
      currentScanId: "scan-2",
      previousScanId: "scan-1",
      existingFindings: [
        {
          id: "f-sast",
          fingerprint: "fp:sast:1",
          scanner: "semgrep",
          category: "SAST",
          status: "FIXED_PENDING_VERIFICATION"
        },
        {
          id: "f-secret",
          fingerprint: "fp:secret:1",
          scanner: "gitleaks",
          category: "SECRET",
          status: "FIXED_PENDING_VERIFICATION"
        }
      ],
      detectedFingerprints: new Set(),
      scannerOutcomes: [
        { scanner: "semgrep", status: "FAILED", hasScopeLimitations: false },
        { scanner: "gitleaks", status: "SUCCESS", hasScopeLimitations: true }
      ]
    });

    expect(plan.comparison.inconclusiveFindingIds).toEqual(["f-sast", "f-secret"]);
    expect(plan.comparison.notDetectedFindingIds).toEqual([]);
    expect(plan.missingDecisions.every((d) => d.verificationState === "VERIFICATION_INCONCLUSIVE")).toBe(true);
    expect(plan.missingDecisions.every((d) => d.statusChanged === false)).toBe(true);
  });

  it("verifies resolution on clean re-scan and reopens findings that reappear", () => {
    const plan = computeScanComparisonAndVerification({
      currentScanId: "scan-2",
      previousScanId: "scan-1",
      existingFindings: [
        {
          id: "f-fixed",
          fingerprint: "fp:sast:fixed",
          scanner: "semgrep",
          category: "SAST",
          status: "FIXED_PENDING_VERIFICATION"
        },
        {
          id: "f-regression",
          fingerprint: "fp:sast:reappeared",
          scanner: "semgrep",
          category: "SAST",
          status: "RESOLVED_VERIFIED"
        }
      ],
      detectedFingerprints: new Set(["fp:sast:reappeared"]),
      scannerOutcomes: [{ scanner: "semgrep", status: "SUCCESS", hasScopeLimitations: false }]
    });

    expect(plan.comparison.notDetectedFindingIds).toEqual(["f-fixed"]);
    expect(plan.comparison.reopenedFindingIds).toEqual(["f-regression"]);
    expect(plan.missingDecisions[0]?.nextStatus).toBe("RESOLVED_VERIFIED");
    expect(plan.missingDecisions[0]?.verificationState).toBe(
      "VERIFICATION_SUCCESSFUL_WITHIN_SCANNED_SCOPE"
    );
    expect(plan.recurringDecisions[0]?.nextStatus).toBe("REOPENED");
  });

  it("exports redacted JSON, SARIF 2.1.0, and CSV with scanner provenance", async () => {
    const normalized = normalizeAndDeduplicateFindings({
      organizationId: "org-1",
      projectId: "proj-1",
      scanId: "scan-1",
      rawFindings: [
        {
          scanner: "trivy",
          scannerVersion: "0.76.2",
          ruleId: "CVE-2020-8203",
          category: "SCA",
          title: "Prototype pollution in lodash",
          description: "Lodash vulnerability",
          severity: "HIGH",
          originalSeverity: "HIGH",
          confidence: "HIGH",
          filePath: "package-lock.json",
          packageName: "lodash",
          installedVersion: "4.17.15",
          fixedVersion: "4.17.19",
          cve: "CVE-2020-8203",
          cvssScore: 7.4,
          references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-8203"]
        }
      ]
    });

    const ctx = {
      generatedAt: new Date().toISOString(),
      organizationName: "Test Org",
      projectName: "Test App",
      repositoryFullName: "org/test-app",
      isDemo: false,
      scan: {
        id: "scan-1",
        branch: "main",
        commitSha: "1234567890abcdef",
        status: "COMPLETED",
        limitations: []
      },
      scannerRuns: [
        {
          id: "run-1",
          scanner: "trivy",
          scannerVersion: "0.76.2",
          status: "SUCCESS" as const,
          exitCode: 0,
          findingsCount: 1,
          durationMs: 420,
          errorClass: "NONE",
          limitations: [],
          startedAt: new Date().toISOString()
        }
      ],
      findings: normalized.map((n) => n.finding)
    };

    const json = JSON.parse(exportReportAsJson(ctx));
    expect(json.scannerProvenance[0].version).toBe("0.76.2");
    expect(json.findings).toHaveLength(1);

    const sarif = JSON.parse(exportReportAsSarif(ctx));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results[0].ruleId).toBe("CVE-2020-8203");

    const csv = exportReportAsCsv(ctx);
    expect(csv).toContain("CVE-2020-8203");
    expect(csv).toContain("lodash");

    // Verify streaming JSON, SARIF, and CSV exporters produce valid equivalent output
    const readStream = async (stream: NodeJS.ReadableStream) => {
      let out = "";
      for await (const chunk of stream) out += chunk.toString();
      return out;
    };

    const streamedJson = JSON.parse(await readStream(streamReportAsJson(ctx)));
    expect(streamedJson.findings).toHaveLength(1);
    expect(streamedJson.scannerProvenance[0].version).toBe("0.76.2");

    const streamedSarif = JSON.parse(await readStream(streamReportAsSarif(ctx)));
    expect(streamedSarif.version).toBe("2.1.0");
    expect(streamedSarif.runs[0].results[0].ruleId).toBe("CVE-2020-8203");

    const streamedCsv = await readStream(streamReportAsCsv(ctx));
    expect(streamedCsv).toContain("CVE-2020-8203");
    expect(streamedCsv).toContain("lodash");
  });
});

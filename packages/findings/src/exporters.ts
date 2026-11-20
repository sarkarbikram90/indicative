import type { ScannerRunSummary, SecurityFinding } from "@indicative/contracts";
import {
  containsPotentialPlaintextSecret,
  redactSecretsInText
} from "@indicative/security";

export interface ReportExportContext {
  generatedAt: string;
  organizationName: string;
  projectName: string;
  repositoryFullName: string;
  isDemo: boolean;
  scan: {
    id: string;
    branch: string;
    commitSha?: string | null;
    status: string;
    startedAt?: string | null;
    completedAt?: string | null;
    durationMs?: number | null;
    limitations: Array<{ code: string; message: string; scopeAffected?: string }>;
  };
  scannerRuns: ScannerRunSummary[];
  findings: SecurityFinding[];
}

function assertReportRedacted(serialized: string, format: string): string {
  if (containsPotentialPlaintextSecret(serialized)) {
    throw new Error(
      `SECURITY_VIOLATION: Exported ${format} report failed plaintext secret redaction check.`
    );
  }
  return serialized;
}

export function exportReportAsJson(ctx: ReportExportContext): string {
  const payload = {
    schemaVersion: "indicative.report.v1",
    generatedAt: ctx.generatedAt,
    organization: ctx.organizationName,
    project: {
      name: ctx.projectName,
      repository: ctx.repositoryFullName,
      isDemo: ctx.isDemo
    },
    scan: ctx.scan,
    scannerProvenance: ctx.scannerRuns.map((r) => ({
      scanner: r.scanner,
      version: r.scannerVersion,
      rulesetVersion: r.rulesetVersion,
      status: r.status,
      exitCode: r.exitCode,
      findingsCount: r.findingsCount,
      durationMs: r.durationMs,
      errorClass: r.errorClass,
      limitations: r.limitations
    })),
    summary: {
      totalFindings: ctx.findings.length,
      bySeverity: ctx.findings.reduce<Record<string, number>>((acc, f) => {
        acc[f.severity] = (acc[f.severity] ?? 0) + 1;
        return acc;
      }, {}),
      byCategory: ctx.findings.reduce<Record<string, number>>((acc, f) => {
        acc[f.category] = (acc[f.category] ?? 0) + 1;
        return acc;
      }, {})
    },
    findings: ctx.findings.map((f) => ({
      id: f.id,
      fingerprint: f.fingerprint,
      scanner: f.scanner,
      scannerVersion: f.scannerVersion,
      rulesetVersion: f.rulesetVersion,
      ruleId: f.ruleId,
      category: f.category,
      title: redactSecretsInText(f.title),
      description: redactSecretsInText(f.description),
      severity: f.severity,
      originalSeverity: f.originalSeverity,
      confidence: f.confidence,
      riskPriority: f.riskPriority,
      riskRationale: f.riskRationale,
      filePath: f.filePath,
      lineStart: f.lineStart,
      lineEnd: f.lineEnd,
      packageName: f.packageName,
      installedVersion: f.installedVersion,
      fixedVersion: f.fixedVersion,
      cve: f.cve,
      cvssScore: f.cvssScore,
      secretType: f.secretType,
      secretFingerprint: f.secretFingerprint,
      secretValidity: f.secretValidity,
      exposureLocation: f.exposureLocation,
      commitSha: f.commitSha,
      status: f.status,
      verificationState: f.verificationState,
      occurrenceCount: f.occurrenceCount,
      firstSeenAt: f.firstSeenAt,
      lastSeenAt: f.lastSeenAt,
      remediation: f.remediation ? redactSecretsInText(f.remediation) : undefined,
      evidence: f.evidence.map((e) => ({
        ...e,
        content: redactSecretsInText(e.content)
      }))
    }))
  };

  return assertReportRedacted(JSON.stringify(payload, null, 2), "JSON");
}

function mapSeverityToSarifLevel(severity: string): "error" | "warning" | "note" {
  if (severity === "CRITICAL" || severity === "HIGH") return "error";
  if (severity === "MEDIUM") return "warning";
  return "note";
}

export function exportReportAsSarif(ctx: ReportExportContext): string {
  const rulesByKey = new Map<
    string,
    {
      id: string;
      name: string;
      shortDescription: { text: string };
      fullDescription: { text: string };
      properties: Record<string, unknown>;
    }
  >();

  for (const f of ctx.findings) {
    const key = `${f.scanner}:${f.ruleId}`;
    if (!rulesByKey.has(key)) {
      rulesByKey.set(key, {
        id: f.ruleId,
        name: f.ruleId,
        shortDescription: { text: redactSecretsInText(f.title) },
        fullDescription: { text: redactSecretsInText(f.description) },
        properties: {
          scanner: f.scanner,
          scannerVersion: f.scannerVersion,
          category: f.category,
          severity: f.severity
        }
      });
    }
  }

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Indicative",
            version: "0.1.0",
            informationUri: "https://github.com/sarkarbikram90/indicative",
            rules: [...rulesByKey.values()]
          }
        },
        invocations: [
          {
            executionSuccessful: ctx.scan.status !== "FAILED",
            startTimeUtc: ctx.scan.startedAt ?? ctx.generatedAt,
            endTimeUtc: ctx.scan.completedAt ?? ctx.generatedAt,
            properties: {
              scanId: ctx.scan.id,
              repository: ctx.repositoryFullName,
              branch: ctx.scan.branch,
              commitSha: ctx.scan.commitSha ?? undefined,
              scannerRuns: ctx.scannerRuns.map((r) => ({
                scanner: r.scanner,
                version: r.scannerVersion,
                status: r.status,
                findingsCount: r.findingsCount
              }))
            }
          }
        ],
        results: ctx.findings.map((f) => ({
          ruleId: f.ruleId,
          level: mapSeverityToSarifLevel(f.severity),
          message: {
            text: redactSecretsInText(`${f.title} — ${f.description}`)
          },
          partialFingerprints: {
            indicativeCanonicalFingerprint: f.fingerprint,
            ...(f.secretFingerprint ? { secretHmacFingerprint: f.secretFingerprint } : {})
          },
          locations: f.filePath
            ? [
                {
                  physicalLocation: {
                    artifactLocation: { uri: f.filePath },
                    ...(f.lineStart
                      ? {
                          region: {
                            startLine: f.lineStart,
                            ...(f.lineEnd ? { endLine: f.lineEnd } : {})
                          }
                        }
                      : {})
                  }
                }
              ]
            : [],
          properties: {
            scanner: f.scanner,
            scannerVersion: f.scannerVersion,
            category: f.category,
            severity: f.severity,
            originalSeverity: f.originalSeverity,
            confidence: f.confidence,
            riskPriority: f.riskPriority,
            status: f.status,
            verificationState: f.verificationState,
            secretValidity: f.secretValidity,
            packageName: f.packageName,
            installedVersion: f.installedVersion,
            fixedVersion: f.fixedVersion,
            cve: f.cve
          }
        }))
      }
    ]
  };

  return assertReportRedacted(JSON.stringify(sarif, null, 2), "SARIF");
}

function csvEscape(val: unknown): string {
  const str = val === null || val === undefined ? "" : redactSecretsInText(String(val));
  // Neutralize CSV formula injection (=, +, -, @) when opened in spreadsheets
  const safe = /^[=+\-@]/.test(str) ? `'${str}` : str;
  if (/[",\r\n]/.test(safe)) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
}

export function exportReportAsCsv(ctx: ReportExportContext): string {
  const headers = [
    "id",
    "fingerprint",
    "scanner",
    "scannerVersion",
    "ruleId",
    "category",
    "severity",
    "originalSeverity",
    "confidence",
    "riskPriority",
    "status",
    "verificationState",
    "title",
    "filePath",
    "lineStart",
    "packageName",
    "installedVersion",
    "fixedVersion",
    "cve",
    "secretType",
    "secretValidity",
    "exposureLocation",
    "commitSha",
    "occurrenceCount",
    "firstSeenAt",
    "lastSeenAt",
    "remediation"
  ];

  const rows = [headers.join(",")];
  for (const f of ctx.findings) {
    rows.push(
      [
        f.id,
        f.fingerprint,
        f.scanner,
        f.scannerVersion,
        f.ruleId,
        f.category,
        f.severity,
        f.originalSeverity ?? "",
        f.confidence,
        f.riskPriority,
        f.status,
        f.verificationState ?? "",
        f.title,
        f.filePath ?? "",
        f.lineStart ?? "",
        f.packageName ?? "",
        f.installedVersion ?? "",
        f.fixedVersion ?? "",
        f.cve ?? "",
        f.secretType ?? "",
        f.secretValidity ?? "",
        f.exposureLocation ?? "",
        f.commitSha ?? "",
        f.occurrenceCount,
        f.firstSeenAt,
        f.lastSeenAt,
        f.remediation ?? ""
      ]
        .map(csvEscape)
        .join(",")
    );
  }

  return assertReportRedacted(`${rows.join("\n")}\n`, "CSV");
}

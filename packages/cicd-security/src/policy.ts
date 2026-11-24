import crypto from "node:crypto";
import type { FindingSeverity, RawScannerFinding } from "@indicative/contracts";
import {
  containsPotentialPlaintextSecret,
  redactSecretsInText
} from "@indicative/security";
import type {
  CicdAnalysisReport,
  CicdPolicyConfig,
  CicdPolicyEvaluation
} from "./types.js";

export const DEFAULT_CICD_POLICY: CicdPolicyConfig = {
  mode: "warning",
  failOnSeverities: ["CRITICAL", "HIGH"]
};

/**
 * Evaluates CI/CD findings against a user-configured policy.
 * Never blocks a pipeline unless mode === "failure" is explicitly configured.
 */
export function evaluateCicdPolicy(
  findings: RawScannerFinding[],
  policy: CicdPolicyConfig = DEFAULT_CICD_POLICY
): CicdPolicyEvaluation {
  const failSet = new Set<FindingSeverity>(policy.failOnSeverities);
  const matching = findings.filter((f) => failSet.has(f.severity));

  if (policy.mode === "informational") {
    return {
      mode: "informational",
      passed: true,
      exitCode: 0,
      blockingFindingsCount: 0,
      warningFindingsCount: findings.length,
      summary: `Informational mode: ${findings.length} CI/CD findings reported; pipeline not blocked.`
    };
  }

  if (policy.mode === "warning") {
    return {
      mode: "warning",
      passed: true,
      exitCode: 0,
      blockingFindingsCount: 0,
      warningFindingsCount: matching.length,
      summary: `Warning mode: ${findings.length} CI/CD findings (${matching.length} at ${policy.failOnSeverities.join("/")}); pipeline not blocked.`
    };
  }

  const passed = matching.length === 0;
  return {
    mode: "failure",
    passed,
    exitCode: passed ? 0 : 1,
    blockingFindingsCount: matching.length,
    warningFindingsCount: findings.length - matching.length,
    summary: passed
      ? `Policy passed: 0 blocking CI/CD findings at ${policy.failOnSeverities.join("/")}.`
      : `Policy failed: ${matching.length} blocking CI/CD finding(s) at ${policy.failOnSeverities.join("/")}.`
  };
}

function escapeWorkflowCommandData(value: string): string {
  return redactSecretsInText(value)
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A");
}

function escapeWorkflowCommandProperty(value: string): string {
  return escapeWorkflowCommandData(value)
    .replace(/:/g, "%3A")
    .replace(/,/g, "%2C");
}

/**
 * Emits GitHub Actions workflow command annotations safely escaped against
 * command/newline injection (CICD-T5).
 */
export function formatGitHubAnnotations(findings: RawScannerFinding[]): string {
  return findings
    .map((f) => {
      const level =
        f.severity === "CRITICAL" || f.severity === "HIGH"
          ? "error"
          : f.severity === "MEDIUM"
            ? "warning"
            : "notice";
      const props: string[] = [];
      if (f.filePath) {
        props.push(`file=${escapeWorkflowCommandProperty(f.filePath)}`);
      }
      if (f.lineStart) {
        props.push(`line=${f.lineStart}`);
      }
      if (f.lineEnd && f.lineEnd >= (f.lineStart ?? 0)) {
        props.push(`endLine=${f.lineEnd}`);
      }
      props.push(`title=${escapeWorkflowCommandProperty(`[${f.ruleId}] ${f.severity}`)}`);
      const msg = escapeWorkflowCommandData(f.title);
      return `::${level} ${props.join(",")}::${msg}`;
    })
    .join("\n");
}

/**
 * Renders a concise, evidence-backed Markdown summary suitable for Pull Request comments
 * or GitHub Job Summaries (`$GITHUB_STEP_SUMMARY`).
 */
export function formatPullRequestMarkdownSummary(report: CicdAnalysisReport): string {
  const lines: string[] = [];
  lines.push("## Indicative CI/CD & OIDC Security Summary");
  lines.push("");
  lines.push(
    `- **Engine:** \`${report.scanner}\` v${report.scannerVersion} (\`${report.rulesetVersion}\`)`
  );
  lines.push(
    `- **Scope Analyzed:** ${report.workflows.length} GitHub Actions workflow(s), ${report.oidcTrustPolicies.length} static cloud OIDC trust policy(ies)`
  );
  lines.push(
    `- **Policy Decision:** \`${report.policyEvaluation.mode.toUpperCase()}\` — ${report.policyEvaluation.summary}`
  );
  lines.push("");

  if (report.limitations.length > 0) {
    lines.push("### Coverage Limitations");
    for (const l of report.limitations) {
      lines.push(`- \`${l.code}\`: ${redactSecretsInText(l.message)}`);
    }
    lines.push("");
  }

  if (report.findings.length === 0) {
    lines.push("No CI/CD workflow or static OIDC trust weaknesses detected within scanned scope.");
  } else {
    lines.push(`### Findings (${report.findings.length})`);
    lines.push("");
    lines.push("| Severity | Rule | Location | Summary |");
    lines.push("|---|---|---|---|");
    for (const f of report.findings) {
      const loc = f.filePath ? `\`${f.filePath}${f.lineStart ? `:${f.lineStart}` : ""}\`` : "—";
      const safeTitle = redactSecretsInText(f.title).replace(/\|/g, "\\|");
      lines.push(`| **${f.severity}** | \`${f.ruleId}\` | ${loc} | ${safeTitle} |`);
    }
  }

  lines.push("");
  lines.push(
    "> **Evidence Boundary:** All findings reflect deterministic static configuration analysis (`STATIC_CONFIG`). Live cloud IAM permissions, SCPs, and GitHub repository settings are not verified statically."
  );
  return lines.join("\n");
}

function mapSeverityToSarifLevel(severity: FindingSeverity): "error" | "warning" | "note" {
  if (severity === "CRITICAL" || severity === "HIGH") return "error";
  if (severity === "MEDIUM") return "warning";
  return "note";
}

function mapSeverityToSecuritySeverityScore(severity: FindingSeverity): string {
  switch (severity) {
    case "CRITICAL":
      return "9.5";
    case "HIGH":
      return "7.8";
    case "MEDIUM":
      return "5.5";
    case "LOW":
      return "3.0";
    default:
      return "1.0";
  }
}

/**
 * Formats a CI/CD & OIDC analysis report as GitHub Code Scanning compatible SARIF 2.1.0.
 * Enforces fail-closed plaintext secret redaction before returning serialized output.
 */
export function formatCicdReportAsSarif(report: CicdAnalysisReport): string {
  const rulesById = new Map<string, Record<string, unknown>>();
  for (const f of report.findings) {
    if (!rulesById.has(f.ruleId)) {
      rulesById.set(f.ruleId, {
        id: f.ruleId,
        name: f.ruleId,
        shortDescription: { text: redactSecretsInText(f.title) },
        fullDescription: { text: redactSecretsInText(f.description) },
        help: {
          text: redactSecretsInText(
            f.remediationHint ??
              "Review this workflow or cloud OIDC trust policy and apply least-privilege controls."
          )
        },
        helpUri: "https://github.com/sarkarbikram90/indicative/tree/main/rules/cicd/github-actions",
        defaultConfiguration: {
          level: mapSeverityToSarifLevel(f.severity)
        },
        properties: {
          tags: ["security", "ci-cd", "github-actions", "oidc"],
          precision: f.confidence === "HIGH" ? "very-high" : f.confidence === "MEDIUM" ? "high" : "medium",
          "security-severity": mapSeverityToSecuritySeverityScore(f.severity)
        }
      });
    }
  }

  const results = report.findings.map((f) => {
    const normalizedPath = f.filePath ? f.filePath.replace(/\\/g, "/").replace(/^\.\//, "") : undefined;
    const fingerprint = crypto
      .createHash("sha256")
      .update(`${f.ruleId}|${normalizedPath ?? ""}|${f.lineStart ?? 0}|${f.title}`)
      .digest("hex");

    return {
      ruleId: f.ruleId,
      level: mapSeverityToSarifLevel(f.severity),
      message: {
        text: redactSecretsInText(
          `${f.title} — ${f.description}${f.remediationHint ? ` Remediation: ${f.remediationHint}` : ""}`
        )
      },
      partialFingerprints: {
        primaryLocationLineHash: fingerprint
      },
      locations: normalizedPath
        ? [
            {
              physicalLocation: {
                artifactLocation: { uri: normalizedPath },
                ...(f.lineStart
                  ? {
                      region: {
                        startLine: f.lineStart,
                        ...(f.lineEnd && f.lineEnd >= f.lineStart ? { endLine: f.lineEnd } : {})
                      }
                    }
                  : {})
              }
            }
          ]
        : [],
      properties: {
        scanner: report.scanner,
        scannerVersion: report.scannerVersion,
        rulesetVersion: report.rulesetVersion,
        severity: f.severity,
        confidence: f.confidence,
        category: f.category,
        evidenceBasis: "STATIC_CONFIG"
      }
    };
  });

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Indicative CI/CD & OIDC Security",
            version: report.scannerVersion,
            semanticVersion: report.scannerVersion,
            informationUri: "https://github.com/sarkarbikram90/indicative",
            rules: [...rulesById.values()]
          }
        },
        invocations: [
          {
            executionSuccessful: true,
            properties: {
              rulesetVersion: report.rulesetVersion,
              workflowsScanned: report.workflows.length,
              oidcPoliciesScanned: report.oidcTrustPolicies.length,
              policyMode: report.policyEvaluation.mode,
              policyPassed: report.policyEvaluation.passed,
              limitations: report.limitations
            }
          }
        ],
        results
      }
    ]
  };

  const serialized = JSON.stringify(sarif, null, 2);
  if (containsPotentialPlaintextSecret(serialized)) {
    throw new Error("SECURITY_VIOLATION: Exported CI/CD SARIF failed plaintext secret redaction check.");
  }
  return serialized;
}

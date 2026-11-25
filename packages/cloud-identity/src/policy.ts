import crypto from "node:crypto";
import type { FindingSeverity, RawScannerFinding } from "@indicative/contracts";
import { evaluateCicdPolicy } from "@indicative/cicd-security";
import {
  containsPotentialPlaintextSecret,
  redactSecretsInText
} from "@indicative/security";
import type {
  CloudIdentityAnalysisReport,
  CloudIdentityPolicyConfig
} from "./types.js";

export const DEFAULT_CLOUD_IDENTITY_POLICY: CloudIdentityPolicyConfig = {
  mode: "warning",
  failOnSeverities: ["CRITICAL", "HIGH"]
};

export function evaluateCloudIdentityPolicy(
  findings: RawScannerFinding[],
  policy: CloudIdentityPolicyConfig = DEFAULT_CLOUD_IDENTITY_POLICY
) {
  const result = evaluateCicdPolicy(findings, {
    mode: policy.mode ?? "warning",
    failOnSeverities: policy.failOnSeverities ?? ["CRITICAL", "HIGH"]
  });
  return {
    ...result,
    summary: result.summary.replace(/CI\/CD finding/g, "Cloud Identity finding")
  };
}

export function formatCloudIdentityMarkdownSummary(
  report: CloudIdentityAnalysisReport
): string {
  const lines: string[] = [];
  lines.push("## Indicative Cloud Identity & AWS IAM Risk Summary");
  lines.push("");
  lines.push(
    `- **Engine:** \`${report.scanner}\` v${report.scannerVersion} (\`${report.rulesetVersion}\`)`
  );
  lines.push(
    `- **Scope Analyzed:** ${report.workflows.length} workflow(s), ${report.workflowIdentityRefs.length} workflow cloud-identity reference(s), ${report.iamRoles.length} AWS IAM role(s), ${report.standalonePolicies.length} standalone IAM policy(ies)`
  );
  lines.push(
    `- **Correlated CI/CD → Cloud Attack Chains:** ${report.correlatedChains.length}`
  );
  lines.push(
    `- **Policy Decision:** \`${report.policyEvaluation.mode.toUpperCase()}\` — ${report.policyEvaluation.summary}`
  );
  lines.push("");

  if (report.correlatedChains.length > 0) {
    lines.push(`### Evidence-Backed CI/CD → Cloud Identity Chains (${report.correlatedChains.length})`);
    lines.push("");
    for (const chain of report.correlatedChains) {
      lines.push(
        `#### [${chain.severity}] \`${chain.workflowFilePath}\` (\`${chain.jobId}\`) → AWS Role \`${chain.roleName}\` (\`${chain.capabilityTier}\` · \`${chain.linkConfidence}\`)`
      );
      for (const hop of chain.hops) {
        const loc = hop.filePath
          ? ` (\`${hop.filePath}${hop.lineStart ? `:${hop.lineStart}` : ""}\`)`
          : "";
        lines.push(
          `  ${hop.hopNumber}. **[${hop.evidenceBasis}]** ${hop.label}${loc} — ${redactSecretsInText(hop.detail)}`
        );
      }
      lines.push(`  - **Unknown Controls:** ${chain.unknownControls.join(", ")}`);
      lines.push(`  - **Primary Breakpoint:** ${chain.remediationBreakpoints[0] ?? "Apply least privilege."}`);
      lines.push("");
    }
  }

  if (report.findings.length === 0) {
    lines.push("No static AWS IAM policy or correlated CI/CD-to-cloud identity weaknesses detected within scanned scope.");
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
    "> **Evidence Boundary:** All findings reflect deterministic static IaC & workflow analysis (`STATIC_CONFIG`). Live AWS IAM drift, Account SCPs, KMS/resource policies, and GitHub branch/environment approval gates are not verified statically."
  );

  return lines.join("\n");
}

function mapSeverityToSarifLevel(severity: FindingSeverity): "error" | "warning" | "note" {
  if (severity === "CRITICAL" || severity === "HIGH") return "error";
  if (severity === "MEDIUM") return "warning";
  return "note";
}

export function formatCloudIdentityReportAsSarif(
  report: CloudIdentityAnalysisReport
): string {
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
              "Apply least-privilege AWS IAM permissions and strict OIDC trust boundaries."
          )
        },
        helpUri: "https://github.com/sarkarbikram90/indicative/tree/main/rules/cloud-identity/aws-iam",
        defaultConfiguration: { level: mapSeverityToSarifLevel(f.severity) },
        properties: {
          tags: ["security", "cloud-identity", "aws-iam", "oidc"]
        }
      });
    }
  }

  const results = report.findings.map((f) => {
    const normalizedPath = f.filePath
      ? f.filePath.replace(/\\/g, "/").replace(/^\.\//, "")
      : undefined;
    const fingerprint = crypto
      .createHash("sha256")
      .update(`${f.ruleId}|${normalizedPath ?? ""}|${f.lineStart ?? 0}|${f.title}`)
      .digest("hex");

    return {
      ruleId: f.ruleId,
      level: mapSeverityToSarifLevel(f.severity),
      message: { text: redactSecretsInText(`${f.title} — ${f.description}`) },
      partialFingerprints: { primaryLocationLineHash: fingerprint },
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
        category: f.category,
        evidenceBasis: "STATIC_CONFIG"
      }
    };
  });

  const serialized = JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Indicative Cloud Identity & AWS IAM Security",
              version: report.scannerVersion,
              informationUri: "https://github.com/sarkarbikram90/indicative",
              rules: [...rulesById.values()]
            }
          },
          results
        }
      ]
    },
    null,
    2
  );

  if (containsPotentialPlaintextSecret(serialized)) {
    throw new Error(
      "SECURITY_VIOLATION: Exported Cloud Identity SARIF failed plaintext secret redaction check."
    );
  }
  return serialized;
}

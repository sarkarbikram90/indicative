import type { FindingSeverity, RawScannerFinding } from "@indicative/contracts";
import { redactSecretsInText } from "@indicative/security";
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

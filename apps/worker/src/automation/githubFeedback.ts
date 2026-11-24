import type {
  ScanComparison,
  ScanStatus,
  ScanTriggerMetadata,
  ScannerLimitation,
  SecurityFinding
} from "@indicative/contracts";
import { redactSecretsInText, type StructuredLogger } from "@indicative/security";
import type { GitHubAppClient, GitHubCheckRunAnnotation } from "../ingestion/githubApp.js";

export const INDICATIVE_PR_COMMENT_MARKER = "<!-- indicative-security-summary -->";

export interface GitHubFeedbackContext {
  webPublicUrl: string;
  scanId: string;
  repositoryFullName: string;
  branch: string;
  commitSha?: string | null;
  status: ScanStatus;
  findings: SecurityFinding[];
  comparison: ScanComparison;
  limitations: ScannerLimitation[];
  triggerMetadata: ScanTriggerMetadata;
}

export function buildGitHubPullRequestSummaryMarkdown(ctx: GitHubFeedbackContext): string {
  const critical = ctx.findings.filter((f) => f.severity === "CRITICAL").length;
  const high = ctx.findings.filter((f) => f.severity === "HIGH").length;
  const medium = ctx.findings.filter((f) => f.severity === "MEDIUM").length;
  const low = ctx.findings.filter((f) => f.severity === "LOW").length;
  const newIds = new Set(ctx.comparison.newFindingIds);
  const scanUrl = `${ctx.webPublicUrl.replace(/\/+$/, "")}/scans/${ctx.scanId}`;

  const statusBadge =
    ctx.status === "FAILED"
      ? "FAILED"
      : critical > 0 || high > 0
        ? "ACTION REQUIRED"
        : ctx.status === "COMPLETED_WITH_ERRORS"
          ? "COMPLETED WITH ERRORS"
          : "PASSED";

  const lines: string[] = [
    `## Indicative Security Scan — ${statusBadge}`,
    "",
    `- **Repository:** \`${ctx.repositoryFullName}\` (\`${ctx.branch}\`${ctx.commitSha ? ` @ \`${ctx.commitSha.slice(0, 10)}\`` : ""})`,
    `- **Scan Status:** \`${ctx.status}\` ([View full report](${scanUrl}))`,
    `- **Findings:** **${ctx.findings.length}** total (**${critical}** Critical, **${high}** High, **${medium}** Medium, **${low}** Low)`,
    `- **Delta:** **${ctx.comparison.newFindingIds.length}** new · **${ctx.comparison.recurringFindingIds.length}** recurring · **${ctx.comparison.notDetectedFindingIds.length}** no longer detected · **${ctx.comparison.reopenedFindingIds.length}** reopened`,
    ""
  ];

  if (ctx.limitations.length > 0) {
    lines.push("### Coverage Limitations");
    for (const l of ctx.limitations.slice(0, 8)) {
      lines.push(`- \`${l.code}\`: ${redactSecretsInText(l.message)}`);
    }
    lines.push("");
  }

  const prioritized = [...ctx.findings]
    .sort((a, b) => {
      const aNew = newIds.has(a.id) ? 1 : 0;
      const bNew = newIds.has(b.id) ? 1 : 0;
      if (aNew !== bNew) return bNew - aNew;
      const order: Record<string, number> = {
        CRITICAL: 5,
        HIGH: 4,
        MEDIUM: 3,
        LOW: 2,
        INFO: 1,
        UNKNOWN: 0
      };
      return (order[b.severity] ?? 0) - (order[a.severity] ?? 0);
    })
    .slice(0, 15);

  if (prioritized.length === 0) {
    lines.push("No security findings were detected in the scanned scope.");
  } else {
    lines.push("### Top Findings");
    lines.push("");
    lines.push("| Status | Severity | Category | Rule | Location | Summary |");
    lines.push("|---|---|---|---|---|---|");
    for (const f of prioritized) {
      const badge = newIds.has(f.id) ? "NEW" : "EXISTING";
      const loc = f.filePath ? `\`${f.filePath}${f.lineStart ? `:${f.lineStart}` : ""}\`` : "—";
      const title = redactSecretsInText(f.title).replace(/\|/g, "\\|").slice(0, 120);
      lines.push(`| ${badge} | **${f.severity}** | \`${f.category}\` | \`${f.ruleId}\` | ${loc} | ${title} |`);
    }
    if (ctx.findings.length > prioritized.length) {
      lines.push("");
      lines.push(`_Showing top ${prioritized.length} of ${ctx.findings.length} findings. [Open Indicative](${scanUrl}) for full evidence and remediation details._`);
    }
  }

  lines.push("");
  lines.push(
    "> **Evidence & Secret Safety:** Secret values are never persisted or posted in plaintext (`secretValidity: NOT_VERIFIED`). CI/CD & OIDC findings reflect static configuration analysis (`STATIC_CONFIG`)."
  );
  return lines.join("\n");
}

export function buildGitHubCheckRunAnnotations(
  findings: SecurityFinding[]
): GitHubCheckRunAnnotation[] {
  const annotations: GitHubCheckRunAnnotation[] = [];
  for (const f of findings) {
    if (!f.filePath || !f.lineStart || f.lineStart < 1) continue;
    const level: GitHubCheckRunAnnotation["annotation_level"] =
      f.severity === "CRITICAL" || f.severity === "HIGH"
        ? "failure"
        : f.severity === "MEDIUM"
          ? "warning"
          : "notice";
    annotations.push({
      path: f.filePath.replace(/\\/g, "/").replace(/^\.\//, ""),
      start_line: f.lineStart,
      end_line: Math.max(f.lineStart, f.lineEnd ?? f.lineStart),
      annotation_level: level,
      title: `[${f.category}] ${f.ruleId} (${f.severity})`,
      message: redactSecretsInText(
        `${f.title}${f.remediation ? ` — Remediation: ${f.remediation}` : ""}`
      ).slice(0, 900)
    });
    if (annotations.length >= 50) break;
  }
  return annotations;
}

export function computeCheckRunConclusion(
  status: ScanStatus,
  findings: SecurityFinding[]
): "success" | "neutral" | "failure" | "action_required" {
  if (status === "FAILED") return "failure";
  const hasCriticalOrHigh = findings.some(
    (f) => f.severity === "CRITICAL" || f.severity === "HIGH"
  );
  if (hasCriticalOrHigh) return "action_required";
  if (status === "COMPLETED_WITH_ERRORS") return "neutral";
  return "success";
}

export async function publishGitHubScanFeedback(params: {
  ctx: GitHubFeedbackContext;
  githubAppClient?: GitHubAppClient;
  postPrComments: boolean;
  createCheckRuns: boolean;
  logger?: StructuredLogger;
}): Promise<{ checkRunId?: number; commentId?: number }> {
  const { ctx, githubAppClient, logger } = params;
  const installationId = ctx.triggerMetadata.githubInstallationId;
  if (!githubAppClient || !installationId) {
    return {};
  }

  const result: { checkRunId?: number; commentId?: number } = {};
  const summaryMarkdown = buildGitHubPullRequestSummaryMarkdown(ctx);
  const headSha = ctx.triggerMetadata.headSha ?? ctx.commitSha ?? undefined;
  const scanUrl = `${ctx.webPublicUrl.replace(/\/+$/, "")}/scans/${ctx.scanId}`;

  if (params.createCheckRuns && headSha) {
    try {
      const conclusion = computeCheckRunConclusion(ctx.status, ctx.findings);
      const criticalOrHigh = ctx.findings.filter(
        (f) => f.severity === "CRITICAL" || f.severity === "HIGH"
      ).length;
      const checkRes = await githubAppClient.upsertCheckRun({
        installationId,
        repositoryFullName: ctx.repositoryFullName,
        checkRunId: ctx.triggerMetadata.checkRunId,
        payload: {
          name: "Indicative Security Intelligence",
          headSha,
          status: "completed",
          conclusion,
          detailsUrl: scanUrl,
          externalId: ctx.scanId,
          title:
            criticalOrHigh > 0
              ? `${criticalOrHigh} Critical/High finding(s) detected (${ctx.findings.length} total)`
              : `Scan ${ctx.status}: ${ctx.findings.length} finding(s)`,
          summary: summaryMarkdown,
          annotations: buildGitHubCheckRunAnnotations(ctx.findings)
        }
      });
      result.checkRunId = checkRes.checkRunId;
    } catch (err) {
      logger?.warn("Failed to publish GitHub Check Run; deterministic scan unaffected", {
        scanId: ctx.scanId,
        error: (err as Error).message
      });
    }
  }

  if (
    params.postPrComments &&
    ctx.triggerMetadata.pullRequestNumber &&
    !ctx.triggerMetadata.isForkPr
  ) {
    try {
      const commentRes = await githubAppClient.upsertPullRequestComment({
        installationId,
        repositoryFullName: ctx.repositoryFullName,
        pullNumber: ctx.triggerMetadata.pullRequestNumber,
        marker: INDICATIVE_PR_COMMENT_MARKER,
        bodyMarkdown: summaryMarkdown
      });
      result.commentId = commentRes.commentId;
    } catch (err) {
      logger?.warn("Failed to publish GitHub PR comment; deterministic scan unaffected", {
        scanId: ctx.scanId,
        error: (err as Error).message
      });
    }
  }

  return result;
}

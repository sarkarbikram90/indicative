import { and, eq, isNull, or } from "drizzle-orm";
import type { AppConfig } from "@indicative/config";
import {
  SEVERITY_RANK,
  type NotificationChannelType,
  type NotificationEventType,
  type ScanComparison,
  type ScanStatus,
  type SecurityFinding
} from "@indicative/contracts";
import {
  notificationChannels,
  notificationDeliveries,
  type Database
} from "@indicative/database";
import {
  containsPotentialPlaintextSecret,
  decryptTenantSecret,
  redactSecretsInText,
  validateAllowedOutboundUrl,
  validateGitHubRepositorySlug,
  type StructuredLogger
} from "@indicative/security";
import type { GitHubAppClient } from "../ingestion/githubApp.js";

const SLACK_ALLOWED_HOSTS = ["hooks.slack.com", "hooks.gov.slack.com"];

export interface StoredSlackCredentials {
  webhookUrl: string;
}

export interface StoredJiraCredentials {
  email: string;
  apiToken: string;
}

export interface StoredGitHubIssueCredentials {
  token?: string;
}

export function validateNotificationOutboundUrl(
  channelType: NotificationChannelType,
  rawUrl: string,
  allowHttpInTest = false
): URL {
  if (channelType === "SLACK") {
    return validateAllowedOutboundUrl(rawUrl, {
      allowedHosts: allowHttpInTest ? [] : SLACK_ALLOWED_HOSTS,
      allowHttpInTest
    });
  }
  if (channelType === "JIRA") {
    return validateAllowedOutboundUrl(rawUrl, {
      allowedHosts: [],
      allowHttpInTest
    });
  }
  return validateAllowedOutboundUrl(rawUrl, {
    allowedHosts: allowHttpInTest ? [] : ["api.github.com"],
    allowHttpInTest
  });
}

function assertPayloadRedacted(serialized: string, channelType: string): void {
  if (containsPotentialPlaintextSecret(serialized)) {
    throw new Error(
      `SECURITY_VIOLATION: Outbound ${channelType} notification payload failed secret redaction check.`
    );
  }
}

function isKevFinding(f: SecurityFinding): boolean {
  return (
    f.riskRationale.some((r) => r.toUpperCase().includes("CISA KEV") || r.toUpperCase().includes("KNOWN EXPLOITED")) ||
    f.evidence.some((e) => e.label.toUpperCase().includes("KEV"))
  );
}

export interface NotificationDispatchContext {
  db: Database;
  config: AppConfig;
  organizationId: string;
  projectId: string;
  projectName: string;
  repositoryFullName: string;
  scanId: string;
  branch: string;
  commitSha?: string | null;
  status: ScanStatus;
  findings: SecurityFinding[];
  comparison?: ScanComparison;
  failureReason?: string;
  githubInstallationId?: number;
  githubAppClient?: GitHubAppClient;
  fetchImpl?: typeof fetch;
  logger?: StructuredLogger;
}

function determineMatchedEvent(params: {
  channelEvents: string[];
  minSeverity: string;
  onlyOnNewFindings: boolean;
  status: ScanStatus;
  findings: SecurityFinding[];
  newFindingIds: Set<string>;
}): { event: NotificationEventType | null; qualifyingFindings: SecurityFinding[] } {
  const minRank = SEVERITY_RANK[params.minSeverity as keyof typeof SEVERITY_RANK] ?? 4;

  if (params.status === "FAILED" && params.channelEvents.includes("SCAN_FAILED")) {
    return { event: "SCAN_FAILED", qualifyingFindings: [] };
  }

  const candidateFindings = params.findings.filter((f) => {
    const rank = SEVERITY_RANK[f.severity] ?? 0;
    if (rank < minRank) return false;
    if (params.onlyOnNewFindings && params.newFindingIds.size > 0 && !params.newFindingIds.has(f.id)) {
      return false;
    }
    return true;
  });

  const kevFindings = candidateFindings.filter(isKevFinding);
  if (kevFindings.length > 0 && params.channelEvents.includes("KEV_DETECTED")) {
    return { event: "KEV_DETECTED", qualifyingFindings: kevFindings };
  }

  const highOrCrit = candidateFindings.filter(
    (f) => f.severity === "CRITICAL" || f.severity === "HIGH"
  );
  if (
    highOrCrit.length > 0 &&
    params.channelEvents.includes("NEW_CRITICAL_OR_HIGH") &&
    (!params.onlyOnNewFindings || highOrCrit.some((f) => params.newFindingIds.has(f.id)))
  ) {
    return { event: "NEW_CRITICAL_OR_HIGH", qualifyingFindings: highOrCrit };
  }

  if (params.channelEvents.includes("SCAN_COMPLETED")) {
    return { event: "SCAN_COMPLETED", qualifyingFindings: candidateFindings };
  }

  return { event: null, qualifyingFindings: [] };
}

async function deliverSlack(params: {
  webhookUrl: string;
  event: NotificationEventType;
  ctx: NotificationDispatchContext;
  qualifyingFindings: SecurityFinding[];
  fetchFn: typeof fetch;
  timeoutMs: number;
  allowHttpInTest: boolean;
}): Promise<{ httpStatus: number; externalRef?: string }> {
  const safeUrl = validateNotificationOutboundUrl("SLACK", params.webhookUrl, params.allowHttpInTest);
  const scanUrl = `${params.ctx.config.WEB_PUBLIC_URL.replace(/\/+$/, "")}/scans/${params.ctx.scanId}`;
  const critical = params.ctx.findings.filter((f) => f.severity === "CRITICAL").length;
  const high = params.ctx.findings.filter((f) => f.severity === "HIGH").length;

  const headerText =
    params.event === "SCAN_FAILED"
      ? `Indicative Scan Failed: ${params.ctx.repositoryFullName}`
      : params.event === "KEV_DETECTED"
        ? `CISA KEV Alert: ${params.ctx.repositoryFullName}`
        : `Indicative Security Alert: ${params.ctx.repositoryFullName}`;

  const topLines = params.qualifyingFindings.slice(0, 5).map((f) => {
    const loc = f.filePath ? ` (${f.filePath}${f.lineStart ? `:${f.lineStart}` : ""})` : "";
    return `• *[${f.severity}]* \`${f.ruleId}\` — ${redactSecretsInText(f.title).slice(0, 120)}${loc}`;
  });

  const payload = {
    text: redactSecretsInText(
      `${headerText} (${params.ctx.branch}) — ${params.ctx.findings.length} total findings (${critical} Critical, ${high} High)`
    ),
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: headerText.slice(0, 150) }
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Project:*\n${redactSecretsInText(params.ctx.projectName)}` },
          { type: "mrkdwn", text: `*Repository:*\n\`${params.ctx.repositoryFullName}\` (\`${params.ctx.branch}\`)` },
          { type: "mrkdwn", text: `*Event:*\n\`${params.event}\`` },
          {
            type: "mrkdwn",
            text: `*Summary:*\n${params.ctx.findings.length} total (${critical} Critical, ${high} High)`
          }
        ]
      },
      ...(topLines.length > 0
        ? [
            {
              type: "section",
              text: { type: "mrkdwn", text: `*Highlighted Findings:*\n${topLines.join("\n")}` }
            }
          ]
        : params.ctx.failureReason
          ? [
              {
                type: "section",
                text: {
                  type: "mrkdwn",
                  text: `*Failure Reason:*\n${redactSecretsInText(params.ctx.failureReason).slice(0, 400)}`
                }
              }
            ]
          : []),
      {
        type: "context",
        elements: [{ type: "mrkdwn", text: `<${scanUrl}|Open Indicative Scan Report>` }]
      }
    ]
  };

  const serialized = JSON.stringify(payload);
  assertPayloadRedacted(serialized, "SLACK");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), params.timeoutMs);
  try {
    const res = await params.fetchFn(safeUrl.toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: serialized,
      signal: controller.signal
    });
    if (!res.ok) {
      throw new Error(`SLACK_WEBHOOK_ERROR: HTTP ${res.status}`);
    }
    return { httpStatus: res.status };
  } finally {
    clearTimeout(timer);
  }
}

async function deliverJira(params: {
  baseUrl: string;
  projectKey: string;
  issueType: string;
  labels: string[];
  creds: StoredJiraCredentials;
  event: NotificationEventType;
  ctx: NotificationDispatchContext;
  qualifyingFindings: SecurityFinding[];
  fetchFn: typeof fetch;
  timeoutMs: number;
  allowHttpInTest: boolean;
}): Promise<{ httpStatus: number; externalRef?: string }> {
  const cleanBase = params.baseUrl.replace(/\/+$/, "");
  const issueUrl = validateNotificationOutboundUrl(
    "JIRA",
    `${cleanBase}/rest/api/3/issue`,
    params.allowHttpInTest
  );
  const scanUrl = `${params.ctx.config.WEB_PUBLIC_URL.replace(/\/+$/, "")}/scans/${params.ctx.scanId}`;

  const summary = redactSecretsInText(
    `[Indicative][${params.event}] ${params.ctx.repositoryFullName}: ${params.qualifyingFindings.length || params.ctx.findings.length} security finding(s)`
  ).slice(0, 240);

  const findingBulletText = params.qualifyingFindings
    .slice(0, 10)
    .map(
      (f) =>
        `- [${f.severity}] ${f.ruleId} (${f.category}): ${redactSecretsInText(f.title)}${f.filePath ? ` at ${f.filePath}${f.lineStart ? `:${f.lineStart}` : ""}` : ""}`
    )
    .join("\n");

  const descriptionText = redactSecretsInText(
    [
      `Repository: ${params.ctx.repositoryFullName} (branch: ${params.ctx.branch})`,
      `Scan ID: ${params.ctx.scanId}`,
      `Report URL: ${scanUrl}`,
      `Total findings: ${params.ctx.findings.length}`,
      "",
      findingBulletText || params.ctx.failureReason || "Review full details in Indicative."
    ].join("\n")
  );

  const payload = {
    fields: {
      project: { key: params.projectKey },
      issuetype: { name: params.issueType },
      summary,
      labels: [...new Set([...params.labels, "indicative-security"])],
      description: {
        type: "doc",
        version: 1,
        content: [
          {
            type: "paragraph",
            content: [{ type: "text", text: descriptionText }]
          }
        ]
      }
    }
  };

  const serialized = JSON.stringify(payload);
  assertPayloadRedacted(serialized, "JIRA");

  const basicAuth = Buffer.from(`${params.creds.email}:${params.creds.apiToken}`, "utf8").toString(
    "base64"
  );
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), params.timeoutMs);
  try {
    const res = await params.fetchFn(issueUrl.toString(), {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Basic ${basicAuth}`
      },
      body: serialized,
      signal: controller.signal
    });
    if (!res.ok) {
      throw new Error(`JIRA_API_ERROR: HTTP ${res.status}`);
    }
    const data = (await res.json().catch(() => ({}))) as { key?: string; id?: string };
    return {
      httpStatus: res.status,
      externalRef: data.key ? `${cleanBase}/browse/${data.key}` : data.id
    };
  } finally {
    clearTimeout(timer);
  }
}

async function deliverGitHubIssue(params: {
  repositoryFullName: string;
  labels: string[];
  creds: StoredGitHubIssueCredentials;
  event: NotificationEventType;
  ctx: NotificationDispatchContext;
  qualifyingFindings: SecurityFinding[];
  fetchFn: typeof fetch;
  timeoutMs: number;
  allowHttpInTest: boolean;
}): Promise<{ httpStatus: number; externalRef?: string }> {
  const { owner, repo, fullName } = validateGitHubRepositorySlug(params.repositoryFullName);
  const scanUrl = `${params.ctx.config.WEB_PUBLIC_URL.replace(/\/+$/, "")}/scans/${params.ctx.scanId}`;
  const title = redactSecretsInText(
    `[Indicative][${params.event}] ${params.qualifyingFindings.length || params.ctx.findings.length} security finding(s) in ${params.ctx.repositoryFullName}`
  ).slice(0, 240);

  const lines = [
    `## Indicative Automated Security Alert (\`${params.event}\`)`,
    "",
    `- **Repository:** \`${params.ctx.repositoryFullName}\` (\`${params.ctx.branch}\`)`,
    `- **Scan:** [\`${params.ctx.scanId}\`](${scanUrl})`,
    `- **Total Findings:** ${params.ctx.findings.length}`,
    ""
  ];
  if (params.qualifyingFindings.length > 0) {
    lines.push("### Qualifying Findings");
    for (const f of params.qualifyingFindings.slice(0, 15)) {
      const loc = f.filePath ? ` \`${f.filePath}${f.lineStart ? `:${f.lineStart}` : ""}\`` : "";
      lines.push(`- **[${f.severity}]** \`${f.ruleId}\` (${f.category}): ${redactSecretsInText(f.title)}${loc}`);
    }
  } else if (params.ctx.failureReason) {
    lines.push(`**Failure Reason:** ${redactSecretsInText(params.ctx.failureReason)}`);
  }
  lines.push("");
  lines.push("_Generated by Indicative Security Intelligence. Plaintext secrets are strictly redacted._");

  const bodyMarkdown = lines.join("\n");
  assertPayloadRedacted(bodyMarkdown, "GITHUB_ISSUE");

  if (params.ctx.githubAppClient && (params.ctx.githubInstallationId || params.creds.token)) {
    const created = await params.ctx.githubAppClient.createRepositoryIssue({
      installationId: params.ctx.githubInstallationId,
      token: params.creds.token,
      repositoryFullName: fullName,
      title,
      bodyMarkdown,
      labels: params.labels
    });
    return { httpStatus: 201, externalRef: created.htmlUrl };
  }

  if (!params.creds.token) {
    throw new Error(
      "GITHUB_ISSUE_UNCONFIGURED: Neither GitHub App installation nor channel token is available."
    );
  }

  const issueUrl = validateNotificationOutboundUrl(
    "GITHUB_ISSUE",
    `https://api.github.com/repos/${owner}/${repo}/issues`,
    params.allowHttpInTest
  );
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), params.timeoutMs);
  try {
    const res = await params.fetchFn(issueUrl.toString(), {
      method: "POST",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${params.creds.token}`,
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Indicative-Security-Platform/0.2"
      },
      body: JSON.stringify({
        title,
        body: bodyMarkdown,
        labels: [...new Set([...params.labels, "indicative-security"])]
      }),
      signal: controller.signal
    });
    if (!res.ok) {
      throw new Error(`GITHUB_ISSUE_API_ERROR: HTTP ${res.status}`);
    }
    const created = (await res.json().catch(() => ({}))) as { html_url?: string };
    return { httpStatus: res.status, externalRef: created.html_url };
  } finally {
    clearTimeout(timer);
  }
}

export async function dispatchScanNotifications(
  ctx: NotificationDispatchContext
): Promise<{ sent: number; failed: number; skipped: number }> {
  const channels = await ctx.db
    .select()
    .from(notificationChannels)
    .where(
      and(
        eq(notificationChannels.organizationId, ctx.organizationId),
        eq(notificationChannels.enabled, true),
        or(
          isNull(notificationChannels.projectId),
          eq(notificationChannels.projectId, ctx.projectId)
        )
      )
    );

  const summary = { sent: 0, failed: 0, skipped: 0 };
  if (channels.length === 0) return summary;

  const newFindingIds = new Set(ctx.comparison?.newFindingIds ?? []);
  const fetchFn = ctx.fetchImpl ?? fetch;
  const allowHttpInTest = ctx.config.NODE_ENV === "test";

  for (const channel of channels) {
    const events = Array.isArray(channel.events) ? channel.events : [];
    const { event, qualifyingFindings } = determineMatchedEvent({
      channelEvents: events,
      minSeverity: channel.minSeverity,
      onlyOnNewFindings: channel.onlyOnNewFindings,
      status: ctx.status,
      findings: ctx.findings,
      newFindingIds
    });

    if (!event) {
      summary.skipped += 1;
      continue;
    }

    try {
      const decryptedRaw = channel.encryptedCredentials
        ? decryptTenantSecret(
            channel.encryptedCredentials,
            ctx.organizationId,
            ctx.config.SECRET_FINGERPRINT_KEY
          )
        : "{}";
      const creds = JSON.parse(decryptedRaw) as Record<string, unknown>;
      const cfg = (channel.configJson ?? {}) as Record<string, unknown>;

      let deliveryRes: { httpStatus: number; externalRef?: string };
      if (channel.channelType === "SLACK") {
        deliveryRes = await deliverSlack({
          webhookUrl: String(creds.webhookUrl ?? ""),
          event,
          ctx,
          qualifyingFindings,
          fetchFn,
          timeoutMs: ctx.config.NOTIFICATION_TIMEOUT_MS,
          allowHttpInTest
        });
      } else if (channel.channelType === "JIRA") {
        deliveryRes = await deliverJira({
          baseUrl: String(cfg.baseUrl ?? ""),
          projectKey: String(cfg.projectKey ?? ""),
          issueType: String(cfg.issueType ?? "Task"),
          labels: Array.isArray(cfg.labels) ? cfg.labels.map(String) : ["indicative-security"],
          creds: {
            email: String(creds.email ?? ""),
            apiToken: String(creds.apiToken ?? "")
          },
          event,
          ctx,
          qualifyingFindings,
          fetchFn,
          timeoutMs: ctx.config.NOTIFICATION_TIMEOUT_MS,
          allowHttpInTest
        });
      } else if (channel.channelType === "GITHUB_ISSUE") {
        deliveryRes = await deliverGitHubIssue({
          repositoryFullName: String(cfg.repositoryFullName ?? ctx.repositoryFullName),
          labels: Array.isArray(cfg.labels) ? cfg.labels.map(String) : ["indicative-security"],
          creds: { token: typeof creds.token === "string" ? creds.token : undefined },
          event,
          ctx,
          qualifyingFindings,
          fetchFn,
          timeoutMs: ctx.config.NOTIFICATION_TIMEOUT_MS,
          allowHttpInTest
        });
      } else {
        summary.skipped += 1;
        continue;
      }

      await ctx.db.insert(notificationDeliveries).values({
        organizationId: ctx.organizationId,
        channelId: channel.id,
        scanId: ctx.scanId,
        eventType: event,
        status: "SENT",
        httpStatus: deliveryRes.httpStatus,
        externalRef: deliveryRes.externalRef
      });

      await ctx.db
        .update(notificationChannels)
        .set({ lastTriggeredAt: new Date(), lastError: null, updatedAt: new Date() })
        .where(eq(notificationChannels.id, channel.id));

      summary.sent += 1;
    } catch (err) {
      const safeErr = redactSecretsInText((err as Error).message).slice(0, 400);
      summary.failed += 1;
      await ctx.db.insert(notificationDeliveries).values({
        organizationId: ctx.organizationId,
        channelId: channel.id,
        scanId: ctx.scanId,
        eventType: event,
        status: "FAILED",
        errorMessage: safeErr
      });
      await ctx.db
        .update(notificationChannels)
        .set({ lastError: safeErr, updatedAt: new Date() })
        .where(eq(notificationChannels.id, channel.id));
      ctx.logger?.warn("Notification delivery failed; deterministic scan unaffected", {
        channelId: channel.id,
        channelType: channel.channelType,
        scanId: ctx.scanId,
        error: safeErr
      });
    }
  }

  return summary;
}

export async function sendTestNotificationForChannel(params: {
  db: Database;
  config: AppConfig;
  channel: typeof notificationChannels.$inferSelect;
  githubAppClient?: GitHubAppClient;
  fetchImpl?: typeof fetch;
}): Promise<{ ok: boolean; httpStatus?: number; externalRef?: string; error?: string }> {
  const fetchFn = params.fetchImpl ?? fetch;
  const allowHttpInTest = params.config.NODE_ENV === "test";
  const dummyCtx: NotificationDispatchContext = {
    db: params.db,
    config: params.config,
    organizationId: params.channel.organizationId,
    projectId: params.channel.projectId ?? "00000000-0000-0000-0000-000000000000",
    projectName: "Indicative Connectivity Check",
    repositoryFullName:
      typeof (params.channel.configJson as Record<string, unknown>)?.repositoryFullName === "string"
        ? String((params.channel.configJson as Record<string, unknown>).repositoryFullName)
        : "indicative/connectivity-check",
    scanId: "00000000-0000-0000-0000-000000000000",
    branch: "main",
    status: "COMPLETED",
    findings: [],
    githubAppClient: params.githubAppClient,
    fetchImpl: fetchFn
  };

  try {
    const decryptedRaw = params.channel.encryptedCredentials
      ? decryptTenantSecret(
          params.channel.encryptedCredentials,
          params.channel.organizationId,
          params.config.SECRET_FINGERPRINT_KEY
        )
      : "{}";
    const creds = JSON.parse(decryptedRaw) as Record<string, unknown>;
    const cfg = (params.channel.configJson ?? {}) as Record<string, unknown>;

    let deliveryRes: { httpStatus: number; externalRef?: string };
    if (params.channel.channelType === "SLACK") {
      deliveryRes = await deliverSlack({
        webhookUrl: String(creds.webhookUrl ?? ""),
        event: "SCAN_COMPLETED",
        ctx: dummyCtx,
        qualifyingFindings: [],
        fetchFn,
        timeoutMs: params.config.NOTIFICATION_TIMEOUT_MS,
        allowHttpInTest
      });
    } else if (params.channel.channelType === "JIRA") {
      deliveryRes = await deliverJira({
        baseUrl: String(cfg.baseUrl ?? ""),
        projectKey: String(cfg.projectKey ?? ""),
        issueType: String(cfg.issueType ?? "Task"),
        labels: Array.isArray(cfg.labels) ? cfg.labels.map(String) : ["indicative-security"],
        creds: {
          email: String(creds.email ?? ""),
          apiToken: String(creds.apiToken ?? "")
        },
        event: "SCAN_COMPLETED",
        ctx: dummyCtx,
        qualifyingFindings: [],
        fetchFn,
        timeoutMs: params.config.NOTIFICATION_TIMEOUT_MS,
        allowHttpInTest
      });
    } else {
      deliveryRes = await deliverGitHubIssue({
        repositoryFullName: String(cfg.repositoryFullName ?? dummyCtx.repositoryFullName),
        labels: Array.isArray(cfg.labels) ? cfg.labels.map(String) : ["indicative-security"],
        creds: { token: typeof creds.token === "string" ? creds.token : undefined },
        event: "SCAN_COMPLETED",
        ctx: dummyCtx,
        qualifyingFindings: [],
        fetchFn,
        timeoutMs: params.config.NOTIFICATION_TIMEOUT_MS,
        allowHttpInTest
      });
    }

    await params.db.insert(notificationDeliveries).values({
      organizationId: params.channel.organizationId,
      channelId: params.channel.id,
      eventType: "SCAN_COMPLETED",
      status: "SENT",
      httpStatus: deliveryRes.httpStatus,
      externalRef: deliveryRes.externalRef
    });
    await params.db
      .update(notificationChannels)
      .set({ lastTriggeredAt: new Date(), lastError: null, updatedAt: new Date() })
      .where(eq(notificationChannels.id, params.channel.id));

    return { ok: true, httpStatus: deliveryRes.httpStatus, externalRef: deliveryRes.externalRef };
  } catch (err) {
    const safeErr = redactSecretsInText((err as Error).message).slice(0, 400);
    await params.db.insert(notificationDeliveries).values({
      organizationId: params.channel.organizationId,
      channelId: params.channel.id,
      eventType: "SCAN_COMPLETED",
      status: "FAILED",
      errorMessage: safeErr
    });
    await params.db
      .update(notificationChannels)
      .set({ lastError: safeErr, updatedAt: new Date() })
      .where(eq(notificationChannels.id, params.channel.id));
    return { ok: false, error: safeErr };
  }
}

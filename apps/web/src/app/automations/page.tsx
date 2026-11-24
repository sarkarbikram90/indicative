"use client";

import React, { useEffect, useState } from "react";
import { AppShell } from "@/components/Shell";
import { apiFetch, getApiBaseUrl } from "@/lib/api";
import { BellRing, CalendarClock, Copy, Check, Play, Trash2, Webhook, Terminal } from "lucide-react";

interface ProjectItem {
  id: string;
  name: string;
  repository?: { fullName: string; defaultBranch: string };
}

interface ScheduleItem {
  id: string;
  projectId: string;
  projectName: string;
  repositoryFullName: string;
  name: string;
  cadence: "HOURLY" | "DAILY" | "WEEKLY" | "CUSTOM_CRON";
  cronExpression: string;
  branch: string | null;
  enabled: boolean;
  lastRunAt: string | null;
  nextRunAt: string;
}

interface NotificationChannelItem {
  id: string;
  name: string;
  channelType: "SLACK" | "JIRA" | "GITHUB_ISSUE";
  enabled: boolean;
  events: string[];
  minSeverity: string;
  onlyOnNewFindings: boolean;
  config: Record<string, unknown>;
  hasCredentials: boolean;
  lastTriggeredAt: string | null;
  lastError: string | null;
}

interface WebhookDeliveryItem {
  id: string;
  deliveryId: string;
  eventType: string;
  action: string | null;
  repositoryFullName: string | null;
  status: string;
  summary: string | null;
  receivedAt: string;
}

const GITHUB_ACTION_SNIPPET = `name: Indicative Security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  cicd-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
      - uses: sarkarbikram90/indicative@main
        with:
          policy: warning
          upload-sarif: true`;

export default function AutomationsPage() {
  const [projects, setProjects] = useState<ProjectItem[]>([]);
  const [schedules, setSchedules] = useState<ScheduleItem[]>([]);
  const [channels, setChannels] = useState<NotificationChannelItem[]>([]);
  const [webhooks, setWebhooks] = useState<WebhookDeliveryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  // Schedule form
  const [schedProjectId, setSchedProjectId] = useState("");
  const [schedName, setSchedName] = useState("Nightly Security Audit");
  const [schedCadence, setSchedCadence] = useState<"DAILY" | "WEEKLY" | "HOURLY" | "CUSTOM_CRON">("DAILY");
  const [schedCron, setSchedCron] = useState("0 2 * * *");

  // Channel form
  const [chanType, setChanType] = useState<"SLACK" | "JIRA" | "GITHUB_ISSUE">("SLACK");
  const [chanName, setChanName] = useState("Security Alerts");
  const [slackUrl, setSlackUrl] = useState("");
  const [jiraBaseUrl, setJiraBaseUrl] = useState("");
  const [jiraProjectKey, setJiraProjectKey] = useState("SEC");
  const [jiraEmail, setJiraEmail] = useState("");
  const [jiraToken, setJiraToken] = useState("");
  const [ghRepo, setGhRepo] = useState("");
  const [ghToken, setGhToken] = useState("");

  async function refreshAll() {
    setLoading(true);
    setError(null);
    try {
      const [projRes, schedRes, chanRes, hookRes] = await Promise.all([
        apiFetch<{ projects: ProjectItem[] }>("/api/v1/projects"),
        apiFetch<{ schedules: ScheduleItem[] }>("/api/v1/schedules"),
        apiFetch<{ channels: NotificationChannelItem[] }>("/api/v1/notifications/channels"),
        apiFetch<{ deliveries: WebhookDeliveryItem[] }>("/api/v1/webhooks/deliveries")
      ]);
      setProjects(projRes.projects);
      if (!schedProjectId && projRes.projects[0]) {
        setSchedProjectId(projRes.projects[0].id);
      }
      setSchedules(schedRes.schedules);
      setChannels(chanRes.channels);
      setWebhooks(hookRes.deliveries);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refreshAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleCreateSchedule(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    try {
      await apiFetch("/api/v1/schedules", {
        method: "POST",
        body: JSON.stringify({
          projectId: schedProjectId,
          name: schedName,
          cadence: schedCadence,
          ...(schedCadence === "CUSTOM_CRON" ? { cronExpression: schedCron } : {})
        })
      });
      setMessage("Recurring scan schedule created.");
      await refreshAll();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleTriggerSchedule(id: string) {
    setError(null);
    try {
      await apiFetch(`/api/v1/schedules/${id}/trigger`, { method: "POST" });
      setMessage("Scheduled scan triggered and queued.");
      await refreshAll();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleDeleteSchedule(id: string) {
    setError(null);
    try {
      await apiFetch(`/api/v1/schedules/${id}`, { method: "DELETE" });
      await refreshAll();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleCreateChannel(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    try {
      const config =
        chanType === "SLACK"
          ? { webhookUrl: slackUrl }
          : chanType === "JIRA"
            ? {
                baseUrl: jiraBaseUrl,
                projectKey: jiraProjectKey,
                issueType: "Task",
                email: jiraEmail,
                apiToken: jiraToken
              }
            : {
                repositoryFullName: ghRepo,
                ...(ghToken ? { token: ghToken } : {})
              };
      await apiFetch("/api/v1/notifications/channels", {
        method: "POST",
        body: JSON.stringify({
          channelType: chanType,
          name: chanName,
          events: ["NEW_CRITICAL_OR_HIGH", "KEV_DETECTED", "SCAN_FAILED"],
          minSeverity: "HIGH",
          onlyOnNewFindings: true,
          config
        })
      });
      setSlackUrl("");
      setJiraToken("");
      setGhToken("");
      setMessage(`Notification channel "${chanName}" created (credentials encrypted at rest).`);
      await refreshAll();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleDeleteChannel(id: string) {
    setError(null);
    try {
      await apiFetch(`/api/v1/notifications/channels/${id}`, { method: "DELETE" });
      await refreshAll();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleTestChannel(id: string) {
    setError(null);
    setMessage(null);
    try {
      const res = await apiFetch<{ result: { ok: boolean; error?: string } }>(
        `/api/v1/notifications/channels/${id}/test`,
        { method: "POST" }
      );
      if (res.result.ok) {
        setMessage("Test notification delivered successfully.");
      } else {
        setError(`Test delivery failed: ${res.result.error ?? "unknown error"}`);
      }
      await refreshAll();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  function copySnippet() {
    void navigator.clipboard.writeText(GITHUB_ACTION_SNIPPET);
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2000);
  }

  return (
    <AppShell>
      {() => (
        <div className="space-y-8">
          <div>
            <h1 className="text-2xl font-semibold text-white">Developer Workflow & Automations</h1>
            <p className="mt-1 text-sm text-slate-400">
              Automate PR/push scans via verified GitHub Webhooks, schedule recurring CVE/KEV audits,
              route alerts to Slack/Jira/GitHub Issues, or embed Indicative in GitHub Actions with SARIF upload.
            </p>
          </div>

          {error && (
            <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200">
              {error}
            </div>
          )}
          {message && (
            <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
              {message}
            </div>
          )}

          {/* Reusable GitHub Action + Webhook Endpoint */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <section className="rounded-xl border border-slate-800 bg-[#0d1320] p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-sky-400" />
                  Reusable GitHub Action (SARIF Code Scanning)
                </h2>
                <button
                  type="button"
                  onClick={copySnippet}
                  className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200"
                >
                  {copiedSnippet ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedSnippet ? "Copied" : "Copy YAML"}
                </button>
              </div>
              <pre className="text-xs bg-slate-950/80 border border-slate-800 rounded-lg p-3 overflow-x-auto text-slate-300">
                {GITHUB_ACTION_SNIPPET}
              </pre>
            </section>

            <section className="rounded-xl border border-slate-800 bg-[#0d1320] p-5 space-y-3">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Webhook className="w-4 h-4 text-sky-400" />
                GitHub App Webhook Receiver (HMAC-SHA256)
              </h2>
              <p className="text-xs text-slate-400">
                Configure your GitHub App webhook URL below with <code className="text-sky-300">GITHUB_APP_WEBHOOK_SECRET</code>.
                Indicative verifies <code className="text-sky-300">X-Hub-Signature-256</code> in constant time, deduplicates{" "}
                <code className="text-sky-300">X-GitHub-Delivery</code> replays, runs automated <code className="text-slate-200">push</code> /{" "}
                <code className="text-slate-200">pull_request</code> scans, and posts sticky PR summaries + Check Runs.
              </p>
              <div className="rounded-lg bg-slate-950/80 border border-slate-800 px-3 py-2 text-xs font-mono text-sky-300 break-all">
                POST {getApiBaseUrl()}/api/v1/webhooks/github
              </div>
              <div className="text-xs text-slate-400">
                Recent deliveries ({webhooks.length}):
                {webhooks.length === 0 ? (
                  <span className="ml-1 text-slate-500">No webhook deliveries recorded yet.</span>
                ) : (
                  <ul className="mt-2 space-y-1 max-h-28 overflow-y-auto">
                    {webhooks.slice(0, 5).map((w) => (
                      <li key={w.id} className="flex items-center justify-between text-[11px] bg-slate-900/70 px-2 py-1 rounded">
                        <span className="truncate text-slate-200">
                          {w.eventType}{w.action ? `.${w.action}` : ""} · {w.repositoryFullName ?? "—"}
                        </span>
                        <span className="text-sky-300 font-mono">{w.status}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </section>
          </div>

          {/* Scheduled Scans */}
          <section className="rounded-xl border border-slate-800 bg-[#0d1320] p-5 space-y-4">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <CalendarClock className="w-4 h-4 text-sky-400" />
              Scheduled / Recurring Scans
            </h2>

            <form onSubmit={handleCreateSchedule} className="grid grid-cols-1 md:grid-cols-5 gap-3 items-end">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Project</label>
                <select
                  value={schedProjectId}
                  onChange={(e) => setSchedProjectId(e.target.value)}
                  required
                  className="w-full rounded-md bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white"
                >
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Schedule Name</label>
                <input
                  value={schedName}
                  onChange={(e) => setSchedName(e.target.value)}
                  required
                  className="w-full rounded-md bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Cadence (UTC)</label>
                <select
                  value={schedCadence}
                  onChange={(e) => setSchedCadence(e.target.value as typeof schedCadence)}
                  className="w-full rounded-md bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white"
                >
                  <option value="DAILY">Daily (02:00 UTC)</option>
                  <option value="WEEKLY">Weekly (Mon 03:00 UTC)</option>
                  <option value="HOURLY">Hourly</option>
                  <option value="CUSTOM_CRON">Custom Cron</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Cron Expression</label>
                <input
                  value={schedCron}
                  onChange={(e) => setSchedCron(e.target.value)}
                  disabled={schedCadence !== "CUSTOM_CRON"}
                  className="w-full rounded-md bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white disabled:opacity-50 font-mono"
                />
              </div>
              <button
                type="submit"
                disabled={!schedProjectId}
                className="rounded-md bg-sky-600 hover:bg-sky-500 text-white text-sm font-medium px-4 py-2 disabled:opacity-50"
              >
                Add Schedule
              </button>
            </form>

            {loading ? (
              <div className="text-xs text-slate-500">Loading schedules...</div>
            ) : schedules.length === 0 ? (
              <div className="text-xs text-slate-500">No recurring scan schedules configured yet.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2 pr-3">Name</th>
                      <th className="py-2 pr-3">Repository</th>
                      <th className="py-2 pr-3">Cron (UTC)</th>
                      <th className="py-2 pr-3">Next Run</th>
                      <th className="py-2 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {schedules.map((s) => (
                      <tr key={s.id}>
                        <td className="py-2.5 pr-3 font-medium text-slate-100">{s.name}</td>
                        <td className="py-2.5 pr-3 text-slate-300 font-mono">{s.repositoryFullName}</td>
                        <td className="py-2.5 pr-3 text-sky-300 font-mono">{s.cronExpression}</td>
                        <td className="py-2.5 pr-3 text-slate-400">{new Date(s.nextRunAt).toLocaleString()}</td>
                        <td className="py-2.5 text-right space-x-2">
                          <button
                            type="button"
                            onClick={() => handleTriggerSchedule(s.id)}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200"
                          >
                            <Play className="w-3 h-3" /> Run now
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDeleteSchedule(s.id)}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded bg-red-500/15 hover:bg-red-500/25 text-red-300"
                          >
                            <Trash2 className="w-3 h-3" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {/* Notification Channels */}
          <section className="rounded-xl border border-slate-800 bg-[#0d1320] p-5 space-y-4">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <BellRing className="w-4 h-4 text-sky-400" />
              Notification & Issue Channels (Slack, Jira, GitHub Issues)
            </h2>

            <form onSubmit={handleCreateChannel} className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Provider</label>
                <select
                  value={chanType}
                  onChange={(e) => setChanType(e.target.value as typeof chanType)}
                  className="w-full rounded-md bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white"
                >
                  <option value="SLACK">Slack Incoming Webhook</option>
                  <option value="JIRA">Jira Cloud Issue</option>
                  <option value="GITHUB_ISSUE">GitHub Repository Issue</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Channel Name</label>
                <input
                  value={chanName}
                  onChange={(e) => setChanName(e.target.value)}
                  required
                  className="w-full rounded-md bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white"
                />
              </div>

              {chanType === "SLACK" && (
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Slack Webhook URL (HTTPS)</label>
                  <input
                    type="password"
                    value={slackUrl}
                    onChange={(e) => setSlackUrl(e.target.value)}
                    placeholder="https://hooks.slack.com/services/..."
                    required
                    className="w-full rounded-md bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white"
                  />
                </div>
              )}

              {chanType === "JIRA" && (
                <>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Jira Base URL</label>
                    <input
                      value={jiraBaseUrl}
                      onChange={(e) => setJiraBaseUrl(e.target.value)}
                      placeholder="https://yourorg.atlassian.net"
                      required
                      className="w-full rounded-md bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Project Key</label>
                    <input
                      value={jiraProjectKey}
                      onChange={(e) => setJiraProjectKey(e.target.value.toUpperCase())}
                      required
                      className="w-full rounded-md bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Jira Account Email</label>
                    <input
                      type="email"
                      value={jiraEmail}
                      onChange={(e) => setJiraEmail(e.target.value)}
                      required
                      className="w-full rounded-md bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Jira API Token</label>
                    <input
                      type="password"
                      value={jiraToken}
                      onChange={(e) => setJiraToken(e.target.value)}
                      required
                      className="w-full rounded-md bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white"
                    />
                  </div>
                </>
              )}

              {chanType === "GITHUB_ISSUE" && (
                <>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Target Repository (owner/repo)</label>
                    <input
                      value={ghRepo}
                      onChange={(e) => setGhRepo(e.target.value)}
                      placeholder="org/security-tracking"
                      required
                      className="w-full rounded-md bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">GitHub Token (optional if App linked)</label>
                    <input
                      type="password"
                      value={ghToken}
                      onChange={(e) => setGhToken(e.target.value)}
                      className="w-full rounded-md bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-white"
                    />
                  </div>
                </>
              )}

              <button
                type="submit"
                className="rounded-md bg-sky-600 hover:bg-sky-500 text-white text-sm font-medium px-4 py-2"
              >
                Add Channel
              </button>
            </form>

            {channels.length === 0 ? (
              <div className="text-xs text-slate-500">No notification channels configured yet.</div>
            ) : (
              <div className="space-y-2">
                {channels.map((ch) => (
                  <div
                    key={ch.id}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-950/60 px-4 py-3 text-xs"
                  >
                    <div>
                      <div className="font-medium text-white">
                        {ch.name}{" "}
                        <span className="ml-1.5 px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 font-mono text-[10px]">
                          {ch.channelType}
                        </span>
                      </div>
                      <div className="text-slate-400 mt-0.5">
                        Events: {ch.events.join(", ")} · Min severity: {ch.minSeverity}
                        {ch.lastError && <span className="ml-2 text-red-400">Last error: {ch.lastError}</span>}
                      </div>
                    </div>
                    <div className="space-x-2">
                      <button
                        type="button"
                        onClick={() => handleTestChannel(ch.id)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200"
                      >
                        Send Test
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDeleteChannel(ch.id)}
                        className="px-2 py-1 rounded bg-red-500/15 hover:bg-red-500/25 text-red-300"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      )}
    </AppShell>
  );
}

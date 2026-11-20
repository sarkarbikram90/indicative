"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Sparkles, ShieldAlert, History, ArrowLeft, Bot } from "lucide-react";
import { AppShell } from "@/components/Shell";
import { CategoryBadge, SeverityBadge, StatusBadge } from "@/components/Badges";
import { apiFetch, type AuthMeResponse } from "@/lib/api";

interface FindingDetailResponse {
  finding: {
    id: string;
    fingerprint: string;
    projectId: string;
    scanId: string;
    scanner: string;
    scannerVersion: string;
    rulesetVersion?: string;
    ruleId: string;
    category: string;
    title: string;
    description: string;
    severity: string;
    originalSeverity?: string;
    confidence: string;
    riskPriority: string;
    riskRationale: string[];
    filePath?: string;
    lineStart?: number;
    lineEnd?: number;
    packageName?: string;
    installedVersion?: string;
    fixedVersion?: string;
    cve?: string;
    cvssScore?: number;
    secretType?: string;
    secretFingerprint?: string;
    secretValidity?: string;
    exposureLocation?: string;
    remediation?: string;
    status: string;
    verificationState?: string;
    occurrenceCount: number;
    firstSeenAt: string;
    lastSeenAt: string;
    evidence: Array<{
      id: string;
      type: string;
      label: string;
      content: string;
      filePath?: string;
      lineStart?: number;
      commitSha?: string;
      referenceUrl?: string;
    }>;
  };
  project: { id: string; name: string };
  occurrences: Array<{
    id: string;
    scanId: string;
    filePath: string | null;
    lineStart: number | null;
    commitSha: string | null;
    exposureLocation: string | null;
    redactedSnippet: string | null;
    detectedAt: string;
  }>;
  statusHistory: Array<{
    id: string;
    fromStatus: string | null;
    toStatus: string;
    reason: string;
    changedBySystem: boolean;
    createdAt: string;
  }>;
  aiAnalyses: Array<{
    id: string;
    provider: string;
    model: string;
    promptVersion: string;
    latencyMs: number;
    totalTokens: number | null;
    createdAt: string;
    analysisJson: {
      summary: string;
      whyItMatters: string;
      rootCause: string;
      attackScenario: string;
      recommendedRemediation: string;
      secureCodePattern?: string;
      patchSuggestion?: string;
      verificationSteps: string[];
      missingInformation?: string[];
      uncertaintyNotes?: string;
      disclaimer: string;
    };
  }>;
}

const TRANSITION_OPTIONS: Record<string, string[]> = {
  OPEN: [
    "ACKNOWLEDGED",
    "IN_PROGRESS",
    "FIXED_PENDING_VERIFICATION",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK"
  ],
  ACKNOWLEDGED: [
    "IN_PROGRESS",
    "FIXED_PENDING_VERIFICATION",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
    "OPEN"
  ],
  IN_PROGRESS: [
    "FIXED_PENDING_VERIFICATION",
    "ACKNOWLEDGED",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK"
  ],
  FIXED_PENDING_VERIFICATION: ["IN_PROGRESS"],
  RESOLVED_VERIFIED: ["REOPENED"],
  FALSE_POSITIVE: ["OPEN", "REOPENED"],
  ACCEPTED_RISK: ["OPEN", "REOPENED"],
  REOPENED: [
    "ACKNOWLEDGED",
    "IN_PROGRESS",
    "FIXED_PENDING_VERIFICATION",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK"
  ]
};

function FindingDetailView({ session }: { session: AuthMeResponse }) {
  const params = useParams<{ findingId: string }>();
  const findingId = params.findingId;
  const [data, setData] = useState<FindingDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusTarget, setStatusTarget] = useState("");
  const [statusReason, setStatusReason] = useState("");
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [analyzingAi, setAnalyzingAi] = useState(false);

  async function load() {
    try {
      const res = await apiFetch<FindingDetailResponse>(`/api/v1/findings/${findingId}`);
      setData(res);
      const nextOpts = TRANSITION_OPTIONS[res.finding.status] ?? [];
      setStatusTarget(nextOpts[0] ?? "");
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    load();
  }, [findingId]);

  async function handleStatusUpdate(e: React.FormEvent) {
    e.preventDefault();
    if (!statusTarget || !statusReason.trim()) return;
    setUpdatingStatus(true);
    setError(null);
    try {
      await apiFetch(`/api/v1/findings/${findingId}/status`, {
        method: "PATCH",
        body: JSON.stringify({ status: statusTarget, reason: statusReason.trim() })
      });
      setStatusReason("");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUpdatingStatus(false);
    }
  }

  async function handleRunAi() {
    setAnalyzingAi(true);
    setError(null);
    try {
      await apiFetch(`/api/v1/findings/${findingId}/analyze`, { method: "POST" });
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setAnalyzingAi(false);
    }
  }

  if (error && !data) {
    return (
      <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/40 text-red-300 text-sm">
        {error}
      </div>
    );
  }
  if (!data) return <div className="text-sm text-slate-400">Loading finding details...</div>;

  const { finding, project, occurrences, statusHistory, aiAnalyses } = data;
  const allowedNext = TRANSITION_OPTIONS[finding.status] ?? [];
  const latestAi = aiAnalyses[0];

  return (
    <div className="space-y-6">
      <Link
        href="/findings"
        className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-white"
      >
        <ArrowLeft className="w-3.5 h-3.5" /> Back to Findings
      </Link>

      {/* Header */}
      <div className="p-6 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <CategoryBadge category={finding.category} />
              <StatusBadge status={finding.status} />
              <span className="text-xs font-mono text-slate-400">
                Risk Priority: <strong className="text-white">{finding.riskPriority}</strong>
              </span>
            </div>
            <h1 className="text-xl font-bold text-white">{finding.title}</h1>
            <div className="text-xs font-mono text-slate-400">
              {project.name} &bull; {finding.scanner} {finding.scannerVersion}
              {finding.rulesetVersion ? ` (${finding.rulesetVersion})` : ""} &bull; rule:{" "}
              {finding.ruleId}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Link
              href={`/advisor?projectId=${finding.projectId}&findingId=${finding.id}`}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700"
            >
              <Bot className="w-3.5 h-3.5 text-sky-400" /> Ask AI Advisor
            </Link>
            <button
              type="button"
              disabled={analyzingAi || !session.capabilities.aiConfigured}
              onClick={handleRunAi}
              title={
                session.capabilities.aiConfigured
                  ? "Generate contextual AI analysis"
                  : "Configure AI_PROVIDER and AI_API_KEY to enable AI analysis"
              }
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-40 text-xs font-semibold text-slate-950 cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5" />
              {analyzingAi ? "Analyzing..." : "Generate AI Analysis"}
            </button>
          </div>
        </div>

        <p className="text-sm text-slate-300 leading-relaxed">{finding.description}</p>

        {finding.category === "SECRET" && (
          <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/40 text-xs text-red-200 space-y-1">
            <div className="font-semibold flex items-center gap-1.5 text-red-300">
              <ShieldAlert className="w-4 h-4" />
              Exposed Credential Advisory — Validity: {finding.secretValidity ?? "NOT_VERIFIED"}
            </div>
            <p>
              Secret detection does not verify whether this credential is currently active or
              revoked. Removing the secret from repository files does not make it safe — the
              credential owner must immediately revoke and rotate it.
            </p>
            {finding.secretFingerprint && (
              <div className="font-mono text-[11px] text-red-300/80">
                Tenant-Keyed HMAC Fingerprint: {finding.secretFingerprint}
              </div>
            )}
          </div>
        )}
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/40 text-red-300 text-xs">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 space-y-6">
          {/* Qualitative Prioritization Rationale */}
          <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-3">
            <h2 className="text-sm font-semibold text-white">
              Evidence-Backed Risk Rationale (Deterministic)
            </h2>
            <ul className="list-disc pl-5 space-y-1 text-xs text-slate-300">
              {finding.riskRationale.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>

          {/* Evidence & Redacted Source Excerpts */}
          <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
            <h2 className="text-sm font-semibold text-white">
              Scanner Evidence &amp; Redacted Excerpts ({finding.evidence.length})
            </h2>
            {finding.evidence.length === 0 ? (
              <p className="text-xs text-slate-500">No additional evidence captured.</p>
            ) : (
              <div className="space-y-3">
                {finding.evidence.map((ev) => (
                  <div
                    key={ev.id}
                    className="p-3.5 rounded-lg bg-[#0d1320] border border-slate-800 space-y-2"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-slate-200">{ev.label}</span>
                      <span className="font-mono text-[10px] text-slate-400">{ev.type}</span>
                    </div>
                    <pre className="text-xs text-sky-200 bg-black/40 p-3 rounded overflow-x-auto whitespace-pre-wrap">
                      {ev.content}
                    </pre>
                    {ev.referenceUrl && (
                      <a
                        href={ev.referenceUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs text-sky-400 hover:underline inline-block"
                      >
                        {ev.referenceUrl}
                      </a>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Deterministic Remediation */}
          {finding.remediation && (
            <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-2">
              <h2 className="text-sm font-semibold text-white">Recommended Remediation</h2>
              <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">
                {finding.remediation}
              </p>
            </div>
          )}

          {/* AI Contextual Analysis (clearly labeled as advisory) */}
          <div className="p-5 rounded-xl bg-[#111827] border border-sky-500/30 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-sky-400" />
                AI Contextual Security Analysis
              </h2>
              <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/40">
                AI-Generated Advisory (Not Verified Evidence)
              </span>
            </div>

            {!latestAi ? (
              <p className="text-xs text-slate-400">
                {session.capabilities.aiConfigured
                  ? 'No AI analysis generated yet for this finding. Click "Generate AI Analysis" above to analyze redacted finding context.'
                  : "AI provider is not configured (AI_PROVIDER=disabled). Deterministic scanner findings and remediation guidance remain fully functional."}
              </p>
            ) : (
              <div className="space-y-4 text-xs text-slate-300">
                <div className="text-[11px] font-mono text-slate-400">
                  Model: {latestAi.model} &bull; Prompt: {latestAi.promptVersion} &bull; Latency:{" "}
                  {latestAi.latencyMs}ms
                  {latestAi.totalTokens ? ` • Tokens: ${latestAi.totalTokens}` : ""}
                </div>
                <div>
                  <div className="font-semibold text-white mb-1">Summary &amp; Why It Matters</div>
                  <p>{latestAi.analysisJson.summary}</p>
                  <p className="mt-1 text-slate-400">{latestAi.analysisJson.whyItMatters}</p>
                </div>
                <div>
                  <div className="font-semibold text-white mb-1">Root Cause &amp; Attack Scenario</div>
                  <p>{latestAi.analysisJson.rootCause}</p>
                  <p className="mt-1 text-slate-400">{latestAi.analysisJson.attackScenario}</p>
                </div>
                <div>
                  <div className="font-semibold text-white mb-1">Recommended Fix</div>
                  <p>{latestAi.analysisJson.recommendedRemediation}</p>
                  {latestAi.analysisJson.secureCodePattern && (
                    <pre className="mt-2 p-3 rounded bg-black/40 text-emerald-300 overflow-x-auto">
                      {latestAi.analysisJson.secureCodePattern}
                    </pre>
                  )}
                </div>
                <div>
                  <div className="font-semibold text-white mb-1">Verification Steps</div>
                  <ul className="list-disc pl-5 space-y-1">
                    {latestAi.analysisJson.verificationSteps.map((s, idx) => (
                      <li key={idx}>{s}</li>
                    ))}
                  </ul>
                </div>
                {latestAi.analysisJson.uncertaintyNotes && (
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
                    <strong>Uncertainty / Missing Context:</strong>{" "}
                    {latestAi.analysisJson.uncertaintyNotes}
                  </div>
                )}
                <div className="text-[11px] text-slate-500 italic">
                  {latestAi.analysisJson.disclaimer}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right sidebar: Metadata, Lifecycle, Occurrences, Audit History */}
        <div className="lg:col-span-4 space-y-6">
          <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-2.5 text-xs">
            <h2 className="text-sm font-semibold text-white mb-2">Metadata &amp; Provenance</h2>
            <div className="flex justify-between">
              <span className="text-slate-400">Original Severity</span>
              <span className="font-mono text-slate-200">{finding.originalSeverity ?? "—"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Confidence</span>
              <span className="font-mono text-slate-200">{finding.confidence}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Verification</span>
              <span className="font-mono text-sky-300">
                {(finding.verificationState ?? "DETECTED").replace(/_/g, " ")}
              </span>
            </div>
            {finding.filePath && (
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">Location</span>
                <span className="font-mono text-slate-200 truncate">
                  {finding.filePath}
                  {finding.lineStart ? `:${finding.lineStart}` : ""}
                </span>
              </div>
            )}
            {finding.packageName && (
              <>
                <div className="flex justify-between">
                  <span className="text-slate-400">Package</span>
                  <span className="font-mono text-slate-200">
                    {finding.packageName}@{finding.installedVersion}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Fixed Version</span>
                  <span className="font-mono text-emerald-300">
                    {finding.fixedVersion ?? "None reported"}
                  </span>
                </div>
              </>
            )}
            {finding.cve && (
              <div className="flex justify-between">
                <span className="text-slate-400">CVE</span>
                <span className="font-mono text-rose-300">{finding.cve}</span>
              </div>
            )}
            <div className="flex justify-between">
              <span className="text-slate-400">First Seen</span>
              <span className="font-mono text-slate-300">
                {new Date(finding.firstSeenAt).toLocaleDateString()}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Last Seen</span>
              <span className="font-mono text-slate-300">
                {new Date(finding.lastSeenAt).toLocaleDateString()}
              </span>
            </div>
          </div>

          {/* Audited Lifecycle Transition */}
          <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-3">
            <h2 className="text-sm font-semibold text-white">Update Finding Status (Audited)</h2>
            {allowedNext.length === 0 ? (
              <p className="text-xs text-slate-500">No manual transitions available.</p>
            ) : (
              <form onSubmit={handleStatusUpdate} className="space-y-3">
                <select
                  value={statusTarget}
                  onChange={(e) => setStatusTarget(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-xs text-white"
                >
                  {allowedNext.map((s) => (
                    <option key={s} value={s}>
                      {s.replace(/_/g, " ")}
                    </option>
                  ))}
                </select>
                <textarea
                  required
                  minLength={3}
                  rows={2}
                  placeholder="Provide audit justification (e.g., Parameterized SQL query in commit abc123, ready for verification re-scan)..."
                  value={statusReason}
                  onChange={(e) => setStatusReason(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-xs text-white"
                />
                <button
                  type="submit"
                  disabled={updatingStatus}
                  className="w-full py-2 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-xs font-semibold text-slate-950 cursor-pointer"
                >
                  {updatingStatus ? "Recording transition..." : "Apply Audited Status Transition"}
                </button>
              </form>
            )}
          </div>

          {/* Occurrence & Commit History */}
          <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-3">
            <h2 className="text-sm font-semibold text-white">
              Detection Occurrences ({occurrences.length})
            </h2>
            <div className="space-y-2 max-h-56 overflow-y-auto text-xs">
              {occurrences.map((occ) => (
                <div
                  key={occ.id}
                  className="p-2.5 rounded bg-[#0d1320] border border-slate-800 font-mono text-[11px] space-y-0.5"
                >
                  <div className="text-slate-200">
                    {occ.filePath ?? "repository"}
                    {occ.lineStart ? `:${occ.lineStart}` : ""}
                  </div>
                  {occ.commitSha && (
                    <div className="text-amber-300">commit: {occ.commitSha.slice(0, 10)}</div>
                  )}
                  <div className="text-slate-500">
                    {occ.exposureLocation ?? "SCAN"} &bull;{" "}
                    {new Date(occ.detectedAt).toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Audit & Status History */}
          <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-3">
            <h2 className="text-sm font-semibold text-white flex items-center gap-1.5">
              <History className="w-4 h-4 text-slate-400" /> Status &amp; Audit History
            </h2>
            <div className="space-y-3 text-xs">
              {statusHistory.map((h) => (
                <div key={h.id} className="border-l-2 border-slate-700 pl-3 space-y-0.5">
                  <div className="font-mono text-[11px] text-sky-300">
                    {h.fromStatus ? `${h.fromStatus} -> ${h.toStatus}` : h.toStatus}
                  </div>
                  <div className="text-slate-300">{h.reason}</div>
                  <div className="text-[10px] text-slate-500">
                    {h.changedBySystem ? "Automated verification" : "User decision"} &bull;{" "}
                    {new Date(h.createdAt).toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function FindingDetailPage() {
  return <AppShell>{(session) => <FindingDetailView session={session} />}</AppShell>;
}

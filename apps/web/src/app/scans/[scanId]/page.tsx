"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Download, RefreshCw, XCircle, AlertTriangle } from "lucide-react";
import { AppShell } from "@/components/Shell";
import { StatusBadge } from "@/components/Badges";
import { apiFetch, getApiBaseUrl } from "@/lib/api";

interface ScanDetailResponse {
  scan: {
    id: string;
    projectId: string;
    branch: string;
    commitSha: string | null;
    commitMessage: string | null;
    status: string;
    isDemoScan: boolean;
    startedAt: string | null;
    completedAt: string | null;
    durationMs: number | null;
    failureReason: string | null;
    summaryCounts: Record<string, number>;
    comparisonSummary: {
      previousScanId: string | null;
      newFindingIds: string[];
      recurringFindingIds: string[];
      notDetectedFindingIds: string[];
      reopenedFindingIds: string[];
      inconclusiveFindingIds: string[];
      summary: string;
    } | null;
    limitations: Array<{ code: string; message: string; scopeAffected?: string }>;
  };
  project: { id: string; name: string };
  repository: { fullName: string };
  scannerRuns: Array<{
    id: string;
    scanner: string;
    scannerVersion: string;
    rulesetVersion: string | null;
    status: string;
    exitCode: number | null;
    findingsCount: number;
    durationMs: number;
    errorClass: string;
    errorMessage: string | null;
    limitations: Array<{ code: string; message: string }>;
  }>;
}

function ScanDetailView() {
  const params = useParams<{ scanId: string }>();
  const scanId = params.scanId;
  const [data, setData] = useState<ScanDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadScan() {
    try {
      const res = await apiFetch<ScanDetailResponse>(`/api/v1/scans/${scanId}`);
      setData(res);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    loadScan();
  }, [scanId]);

  // Auto-refresh while scan is actively running
  useEffect(() => {
    if (!data) return;
    const active = ["QUEUED", "INITIALIZING", "CLONING", "SCANNING", "ANALYZING"].includes(
      data.scan.status
    );
    if (!active) return;
    const t = setInterval(loadScan, 2500);
    return () => clearInterval(t);
  }, [data?.scan.status]);

  async function handleCancel() {
    try {
      await apiFetch(`/api/v1/scans/${scanId}/cancel`, { method: "POST" });
      await loadScan();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  if (error) {
    return (
      <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/40 text-red-300 text-sm">
        {error}
      </div>
    );
  }
  if (!data) return <div className="text-sm text-slate-400">Loading scan details...</div>;

  const { scan, project, repository, scannerRuns } = data;
  const isActive = ["QUEUED", "INITIALIZING", "CLONING", "SCANNING", "ANALYZING"].includes(
    scan.status
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white">{project.name} — Scan</h1>
            <StatusBadge status={scan.status} />
            {scan.isDemoScan && (
              <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/40">
                DEMO FIXTURE SCAN
              </span>
            )}
          </div>
          <div className="mt-1 text-xs font-mono text-slate-400">
            {repository.fullName} &bull; branch: {scan.branch} &bull; commit:{" "}
            {scan.commitSha ? scan.commitSha.slice(0, 12) : "pending"}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={loadScan}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700 cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
          {isActive && (
            <button
              type="button"
              onClick={handleCancel}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/15 hover:bg-red-500/25 text-xs text-red-300 border border-red-500/40 cursor-pointer"
            >
              <XCircle className="w-3.5 h-3.5" /> Cancel Scan
            </button>
          )}
          {(["json", "sarif", "csv"] as const).map((fmt) => (
            <a
              key={fmt}
              href={`${getApiBaseUrl()}/api/v1/scans/${scan.id}/report?format=${fmt}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-sky-300 border border-slate-700 uppercase font-mono"
            >
              <Download className="w-3.5 h-3.5" /> {fmt}
            </a>
          ))}
        </div>
      </div>

      {scan.failureReason && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/40 text-red-200 text-xs">
          <strong>Failure Reason:</strong> {scan.failureReason}
        </div>
      )}

      {scan.limitations.length > 0 && (
        <div className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/40 space-y-1">
          <div className="flex items-center gap-2 text-xs font-semibold text-amber-300">
            <AlertTriangle className="w-4 h-4" />
            Scan Coverage Limitations Reported
          </div>
          {scan.limitations.map((l, idx) => (
            <div key={idx} className="text-xs text-amber-200/90">
              <span className="font-mono">[{l.code}]</span> {l.message}
            </div>
          ))}
        </div>
      )}

      {/* Metadata cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="text-xs text-slate-400">Total Findings</div>
          <div className="text-2xl font-bold text-white mt-1">
            {scan.summaryCounts?.total ?? 0}
          </div>
        </div>
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="text-xs text-slate-400">Duration</div>
          <div className="text-2xl font-bold text-white mt-1 font-mono">
            {scan.durationMs ? `${(scan.durationMs / 1000).toFixed(1)}s` : "—"}
          </div>
        </div>
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="text-xs text-slate-400">Started</div>
          <div className="text-xs text-slate-200 mt-2 font-mono">
            {scan.startedAt ? new Date(scan.startedAt).toLocaleString() : "Queued"}
          </div>
        </div>
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="text-xs text-slate-400">Completed</div>
          <div className="text-xs text-slate-200 mt-2 font-mono">
            {scan.completedAt ? new Date(scan.completedAt).toLocaleString() : "In progress"}
          </div>
        </div>
      </div>

      {/* Scan comparison / verification summary */}
      {scan.comparisonSummary && (
        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">
              Scan Comparison &amp; Verification Summary
            </h2>
            <Link
              href={`/findings?projectId=${scan.projectId}`}
              className="text-xs text-sky-400 hover:underline"
            >
              Inspect Project Findings &rarr;
            </Link>
          </div>
          <p className="text-xs text-slate-300">{scan.comparisonSummary.summary}</p>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
            <div className="p-2.5 rounded bg-[#0d1320] border border-slate-800">
              <div className="text-slate-400">New</div>
              <div className="text-lg font-bold text-rose-300">
                {scan.comparisonSummary.newFindingIds.length}
              </div>
            </div>
            <div className="p-2.5 rounded bg-[#0d1320] border border-slate-800">
              <div className="text-slate-400">Recurring</div>
              <div className="text-lg font-bold text-slate-200">
                {scan.comparisonSummary.recurringFindingIds.length}
              </div>
            </div>
            <div className="p-2.5 rounded bg-[#0d1320] border border-slate-800">
              <div className="text-slate-400">Not Detected</div>
              <div className="text-lg font-bold text-emerald-400">
                {scan.comparisonSummary.notDetectedFindingIds.length}
              </div>
            </div>
            <div className="p-2.5 rounded bg-[#0d1320] border border-slate-800">
              <div className="text-slate-400">Reopened</div>
              <div className="text-lg font-bold text-red-400">
                {scan.comparisonSummary.reopenedFindingIds.length}
              </div>
            </div>
            <div className="p-2.5 rounded bg-[#0d1320] border border-slate-800">
              <div className="text-slate-400">Inconclusive</div>
              <div className="text-lg font-bold text-amber-300">
                {scan.comparisonSummary.inconclusiveFindingIds.length}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Scanner Provenance & Execution Statuses */}
      <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
        <h2 className="text-sm font-semibold text-white">Scanner Engine Execution Provenance</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2 pr-4">Scanner</th>
                <th className="py-2 pr-4">Version</th>
                <th className="py-2 pr-4">Ruleset</th>
                <th className="py-2 pr-4">Status</th>
                <th className="py-2 pr-4">Exit Code</th>
                <th className="py-2 pr-4">Findings</th>
                <th className="py-2 pr-4">Duration</th>
                <th className="py-2">Errors / Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {scannerRuns.map((run) => (
                <tr key={run.id}>
                  <td className="py-3 pr-4 font-mono font-semibold text-white">{run.scanner}</td>
                  <td className="py-3 pr-4 font-mono text-slate-300">{run.scannerVersion}</td>
                  <td className="py-3 pr-4 font-mono text-slate-400">
                    {run.rulesetVersion ?? "—"}
                  </td>
                  <td className="py-3 pr-4">
                    <StatusBadge status={run.status} />
                  </td>
                  <td className="py-3 pr-4 font-mono text-slate-300">
                    {run.exitCode ?? "—"}
                  </td>
                  <td className="py-3 pr-4 font-mono text-white">{run.findingsCount}</td>
                  <td className="py-3 pr-4 font-mono text-slate-400">
                    {(run.durationMs / 1000).toFixed(2)}s
                  </td>
                  <td className="py-3 text-slate-400">
                    {run.errorMessage ? (
                      <span className="text-red-300">{run.errorMessage}</span>
                    ) : run.limitations.length > 0 ? (
                      <span className="text-amber-300">
                        {run.limitations.map((l) => l.code).join(", ")}
                      </span>
                    ) : (
                      "Clean execution"
                    )}
                  </td>
                </tr>
              ))}
              {scannerRuns.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-4 text-slate-500">
                    Waiting for scanner execution records...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default function ScanDetailPage() {
  return <AppShell>{() => <ScanDetailView />}</AppShell>;
}

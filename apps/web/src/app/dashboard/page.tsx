"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { AppShell } from "@/components/Shell";
import { StatusBadge } from "@/components/Badges";
import { apiFetch } from "@/lib/api";

interface DashboardData {
  totals: {
    projects: number;
    repositoriesScanned: number;
    openFindings: number;
    resolvedOrNotDetected: number;
    inconclusiveVerification?: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    unknown: number;
  };
  categoryBreakdown: {
    SAST: number;
    SCA: number;
    SECRET: number;
    IAC: number;
    CICD?: number;
  };
  recentScans: Array<{
    id: string;
    projectId: string;
    projectName: string;
    repositoryFullName: string;
    branch: string;
    commitSha: string | null;
    status: string;
    isDemoScan: boolean;
    summaryCounts: Record<string, number>;
    durationMs: number | null;
    createdAt: string;
  }>;
  securityTrends: Array<{
    scanId: string;
    projectName: string;
    timestamp: string;
    status: string;
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
  recentActivity: Array<{
    id: string;
    action: string;
    resourceType: string;
    resourceId: string | null;
    createdAt: string;
  }>;
}

function DashboardView() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<DashboardData>("/api/v1/dashboard")
      .then(setData)
      .catch((err) => setError((err as Error).message));
  }, []);

  if (error) {
    return (
      <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/40 text-red-300 text-sm">
        Failed to load dashboard: {error}
      </div>
    );
  }

  if (!data) {
    return <div className="text-sm text-slate-400">Loading security overview...</div>;
  }

  const maxTrendTotal = Math.max(1, ...data.securityTrends.map((t) => t.total));

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Overview</h1>
          <p className="text-sm text-slate-400 mt-1">
            Deterministic scanner counts separated from qualitative risk assessments — no
            synthetic aggregate scores.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/projects"
            className="px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-sm transition-colors"
          >
            Run New Scan
          </Link>
          <Link
            href="/findings"
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-100 text-sm font-medium border border-slate-700"
          >
            Inspect Findings
          </Link>
        </div>
      </div>

      {/* Primary KPI row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800">
          <div className="text-xs uppercase tracking-wider text-slate-400">Total Projects</div>
          <div className="mt-2 text-3xl font-bold text-white">{data.totals.projects}</div>
          <div className="mt-1 text-xs text-slate-500">
            {data.totals.repositoriesScanned} repositories scanned
          </div>
        </div>
        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800">
          <div className="text-xs uppercase tracking-wider text-slate-400">Open Findings</div>
          <div className="mt-2 text-3xl font-bold text-white">{data.totals.openFindings}</div>
          <div className="mt-1 text-xs text-slate-500">Active across all scanners</div>
        </div>
        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800">
          <div className="text-xs uppercase tracking-wider text-slate-400">
            Resolved / Not Detected
          </div>
          <div className="mt-2 text-3xl font-bold text-emerald-400">
            {data.totals.resolvedOrNotDetected}
          </div>
          <div className="mt-1 text-xs text-slate-500">Verified within scanned scope</div>
        </div>
        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800">
          <div className="text-xs uppercase tracking-wider text-slate-400">
            Critical &amp; High Open
          </div>
          <div className="mt-2 text-3xl font-bold text-red-400">
            {data.totals.critical + data.totals.high}
          </div>
          <div className="mt-1 text-xs text-slate-500">
            {data.totals.critical} Critical &bull; {data.totals.high} High
          </div>
        </div>
      </div>

      {/* Severity + Category Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
          <h2 className="text-sm font-semibold text-white">Open Findings by Severity</h2>
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: "Critical", val: data.totals.critical, color: "text-red-400" },
              { label: "High", val: data.totals.high, color: "text-orange-400" },
              { label: "Medium", val: data.totals.medium, color: "text-amber-300" },
              { label: "Low", val: data.totals.low, color: "text-sky-400" }
            ].map((item) => (
              <div
                key={item.label}
                className="p-3 rounded-lg bg-[#0d1320] border border-slate-800/80 text-center"
              >
                <div className={`text-2xl font-bold ${item.color}`}>{item.val}</div>
                <div className="text-xs text-slate-400 mt-1">{item.label}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
          <h2 className="text-sm font-semibold text-white">Open Findings by Category</h2>
          <div className="grid grid-cols-5 gap-3">
            {(["SAST", "SCA", "SECRET", "IAC", "CICD"] as const).map((cat) => (
              <div
                key={cat}
                className="p-3 rounded-lg bg-[#0d1320] border border-slate-800/80 text-center"
              >
                <div className="text-2xl font-bold text-slate-100">
                  {data.categoryBreakdown[cat] ?? 0}
                </div>
                <div className="text-xs font-mono text-slate-400 mt-1">{cat}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Security Trends */}
      <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">Scan Findings Trend</h2>
          <span className="text-xs text-slate-500">Latest {data.securityTrends.length} scans</span>
        </div>
        {data.securityTrends.length === 0 ? (
          <p className="text-xs text-slate-400">
            No scans executed yet. Initiate a scan from Projects to populate trend history.
          </p>
        ) : (
          <div className="flex items-end gap-3 h-36 pt-4">
            {data.securityTrends.map((pt) => {
              const heightPct = Math.max(8, Math.round((pt.total / maxTrendTotal) * 100));
              return (
                <Link
                  key={pt.scanId}
                  href={`/scans/${pt.scanId}`}
                  className="flex-1 flex flex-col items-center gap-2 group"
                >
                  <div className="text-[11px] font-mono text-slate-300">{pt.total}</div>
                  <div
                    className="w-full max-w-12 rounded-t bg-sky-500/70 group-hover:bg-sky-400 transition-colors"
                    style={{ height: `${heightPct}%` }}
                  />
                  <div className="text-[10px] text-slate-500 truncate max-w-20">
                    {new Date(pt.timestamp).toLocaleDateString()}
                  </div>
                </Link>
              );
            })}
          </div>
        )}
      </div>

      {/* Recent Scans & Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
          <h2 className="text-sm font-semibold text-white">Recent Scans</h2>
          {data.recentScans.length === 0 ? (
            <p className="text-xs text-slate-400">No scans recorded yet.</p>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {data.recentScans.map((scan) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="py-3 flex items-center justify-between gap-4 hover:bg-slate-800/30 px-2 rounded transition-colors"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-white truncate">
                        {scan.projectName}
                      </span>
                      {scan.isDemoScan && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
                          DEMO
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-400 font-mono mt-0.5">
                      {scan.repositoryFullName} &bull; {scan.branch}
                      {scan.commitSha ? ` @ ${scan.commitSha.slice(0, 8)}` : ""}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-xs text-slate-400 font-mono">
                      {scan.summaryCounts?.total ?? 0} findings
                    </span>
                    <StatusBadge status={scan.status} />
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        <div className="lg:col-span-5 p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
          <h2 className="text-sm font-semibold text-white">Recent Audit Activity</h2>
          {data.recentActivity.length === 0 ? (
            <p className="text-xs text-slate-400">No audit events recorded yet.</p>
          ) : (
            <div className="space-y-3">
              {data.recentActivity.map((ev) => (
                <div
                  key={ev.id}
                  className="text-xs flex items-center justify-between gap-3 border-b border-slate-800/60 pb-2"
                >
                  <div>
                    <span className="font-mono text-sky-300">{ev.action}</span>
                    <span className="text-slate-500 ml-2">{ev.resourceType}</span>
                  </div>
                  <span className="text-slate-500 shrink-0">
                    {new Date(ev.createdAt).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  return <AppShell>{() => <DashboardView />}</AppShell>;
}

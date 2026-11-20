"use client";

import React from "react";

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-300 border-red-500/40",
  HIGH: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  MEDIUM: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  LOW: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  INFO: "bg-slate-500/15 text-slate-300 border-slate-500/40",
  UNKNOWN: "bg-zinc-500/15 text-zinc-300 border-zinc-500/40"
};

const STATUS_STYLES: Record<string, string> = {
  OPEN: "bg-rose-500/15 text-rose-300 border-rose-500/35",
  REOPENED: "bg-red-500/20 text-red-200 border-red-400/50",
  ACKNOWLEDGED: "bg-indigo-500/15 text-indigo-300 border-indigo-500/35",
  IN_PROGRESS: "bg-cyan-500/15 text-cyan-300 border-cyan-500/35",
  FIXED_PENDING_VERIFICATION: "bg-amber-500/15 text-amber-200 border-amber-500/40",
  RESOLVED_VERIFIED: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  FALSE_POSITIVE: "bg-slate-500/20 text-slate-300 border-slate-500/40",
  ACCEPTED_RISK: "bg-purple-500/15 text-purple-300 border-purple-500/40",
  COMPLETED: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  COMPLETED_WITH_ERRORS: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  FAILED: "bg-red-500/15 text-red-300 border-red-500/40",
  CANCELLED: "bg-slate-500/20 text-slate-300 border-slate-500/40",
  QUEUED: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  SCANNING: "bg-cyan-500/15 text-cyan-200 border-cyan-500/40",
  ANALYZING: "bg-indigo-500/15 text-indigo-200 border-indigo-500/40",
  SUCCESS: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  TIMEOUT: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  PARTIAL: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  UNAVAILABLE: "bg-zinc-500/20 text-zinc-300 border-zinc-500/40"
};

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.UNKNOWN;
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border tracking-wide ${cls}`}
    >
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_STYLES[status] ?? "bg-slate-500/15 text-slate-300 border-slate-500/35";
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${cls}`}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}

export function CategoryBadge({ category }: { category: string }) {
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-200 border border-slate-700">
      {category}
    </span>
  );
}

"use client";

import React, { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { AppShell } from "@/components/Shell";
import { CategoryBadge, SeverityBadge, StatusBadge } from "@/components/Badges";
import { apiFetch } from "@/lib/api";

interface FindingListItem {
  id: string;
  title: string;
  description: string;
  severity: string;
  originalSeverity?: string;
  confidence: string;
  riskPriority: string;
  category: string;
  scanner: string;
  ruleId: string;
  filePath?: string;
  lineStart?: number;
  packageName?: string;
  installedVersion?: string;
  fixedVersion?: string;
  cve?: string;
  secretType?: string;
  secretValidity?: string;
  status: string;
  verificationState?: string;
  occurrenceCount: number;
  firstSeenAt: string;
  lastSeenAt: string;
}

interface ProjectOption {
  id: string;
  name: string;
}

function FindingsContent() {
  const searchParams = useSearchParams();
  const [projects, setProjects] = useState<ProjectOption[]>([]);
  const [findings, setFindings] = useState<FindingListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [projectId, setProjectId] = useState(searchParams.get("projectId") || "");
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [scanner, setScanner] = useState("");
  const [status, setStatus] = useState("");
  const [confidence, setConfidence] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    apiFetch<{ projects: ProjectOption[] }>("/api/v1/projects")
      .then((res) => setProjects(res.projects))
      .catch(() => {});
  }, []);

  useEffect(() => {
    setLoading(true);
    setError(null);
    const q = new URLSearchParams({ page: String(page), pageSize: "25" });
    if (projectId) q.set("projectId", projectId);
    if (severity) q.set("severity", severity);
    if (category) q.set("category", category);
    if (scanner) q.set("scanner", scanner);
    if (status) q.set("status", status);
    if (confidence) q.set("confidence", confidence);
    if (search.trim()) q.set("search", search.trim());

    apiFetch<{
      findings: FindingListItem[];
      pagination: { total: number; totalPages: number };
    }>(`/api/v1/findings?${q.toString()}`)
      .then((res) => {
        setFindings(res.findings);
        setTotal(res.pagination.total);
      })
      .catch((err) => setError((err as Error).message))
      .finally(() => setLoading(false));
  }, [projectId, severity, category, scanner, status, confidence, search, page]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Security Findings</h1>
        <p className="text-sm text-slate-400 mt-1">
          Canonical, deduplicated findings normalized across Semgrep, Trivy, and Gitleaks. All
          credentials remain strictly redacted.
        </p>
      </div>

      {/* Filters */}
      <div className="p-4 rounded-xl bg-[#111827] border border-slate-800 grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 text-xs">
        <input
          type="text"
          placeholder="Search title, rule, file, CVE..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
          className="col-span-2 px-3 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-white"
        />
        <select
          value={projectId}
          onChange={(e) => {
            setProjectId(e.target.value);
            setPage(1);
          }}
          className="px-2.5 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-slate-200"
        >
          <option value="">All Projects</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        <select
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setPage(1);
          }}
          className="px-2.5 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-slate-200"
        >
          <option value="">All Severities</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          value={category}
          onChange={(e) => {
            setCategory(e.target.value);
            setPage(1);
          }}
          className="px-2.5 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-slate-200"
        >
          <option value="">All Categories</option>
          {["SAST", "SCA", "SECRET", "IAC"].map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select
          value={scanner}
          onChange={(e) => {
            setScanner(e.target.value);
            setPage(1);
          }}
          className="px-2.5 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-slate-200"
        >
          <option value="">All Scanners</option>
          {["semgrep", "trivy", "gitleaks"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
          className="px-2.5 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-slate-200"
        >
          <option value="">All Statuses</option>
          {[
            "OPEN",
            "ACKNOWLEDGED",
            "IN_PROGRESS",
            "FIXED_PENDING_VERIFICATION",
            "RESOLVED_VERIFIED",
            "REOPENED",
            "FALSE_POSITIVE",
            "ACCEPTED_RISK"
          ].map((st) => (
            <option key={st} value={st}>
              {st.replace(/_/g, " ")}
            </option>
          ))}
        </select>
        <select
          value={confidence}
          onChange={(e) => {
            setConfidence(e.target.value);
            setPage(1);
          }}
          className="px-2.5 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-slate-200"
        >
          <option value="">All Confidence</option>
          {["HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/40 text-red-300 text-xs">
          {error}
        </div>
      )}

      {/* Results table */}
      <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span>
            Showing {findings.length} of {total} findings
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="px-2.5 py-1 rounded bg-slate-800 disabled:opacity-40 cursor-pointer"
            >
              Prev
            </button>
            <span className="font-mono">Page {page}</span>
            <button
              type="button"
              disabled={findings.length < 25}
              onClick={() => setPage((p) => p + 1)}
              className="px-2.5 py-1 rounded bg-slate-800 disabled:opacity-40 cursor-pointer"
            >
              Next
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0d1320] text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Severity / Priority</th>
                <th className="py-3 px-4">Finding</th>
                <th className="py-3 px-4">Category / Engine</th>
                <th className="py-3 px-4">Location / Target</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-6 px-4 text-slate-400">
                    Loading findings...
                  </td>
                </tr>
              ) : findings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 px-4 text-slate-500 text-center">
                    No findings match the current filter criteria.
                  </td>
                </tr>
              ) : (
                findings.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 whitespace-nowrap space-y-1">
                      <div>
                        <SeverityBadge severity={f.severity} />
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono">
                        Risk: {f.riskPriority} &bull; Conf: {f.confidence}
                      </div>
                    </td>
                    <td className="py-3 px-4 max-w-md">
                      <Link
                        href={`/findings/${f.id}`}
                        className="font-semibold text-white hover:text-sky-300 transition-colors block"
                      >
                        {f.title}
                      </Link>
                      <div className="text-[11px] text-slate-400 font-mono mt-0.5 truncate">
                        {f.ruleId}
                        {f.cve ? ` • ${f.cve}` : ""}
                        {f.secretType ? ` • ${f.secretType} (${f.secretValidity})` : ""}
                      </div>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap space-y-1">
                      <div>
                        <CategoryBadge category={f.category} />
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono">{f.scanner}</div>
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-300">
                      {f.filePath ? (
                        <span>
                          {f.filePath}
                          {f.lineStart ? `:${f.lineStart}` : ""}
                        </span>
                      ) : f.packageName ? (
                        <span>
                          {f.packageName}@{f.installedVersion}
                        </span>
                      ) : (
                        "—"
                      )}
                      {f.occurrenceCount > 1 && (
                        <div className="text-[10px] text-amber-300 mt-0.5">
                          {f.occurrenceCount} correlated occurrences
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap space-y-1">
                      <div>
                        <StatusBadge status={f.status} />
                      </div>
                      {f.verificationState && (
                        <div className="text-[10px] text-slate-500 font-mono">
                          {f.verificationState.replace(/_/g, " ")}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap text-slate-400 font-mono text-[11px]">
                      {new Date(f.lastSeenAt).toLocaleString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default function FindingsPage() {
  return (
    <AppShell>
      {() => (
        <Suspense fallback={<div className="text-xs text-slate-400">Loading findings...</div>}>
          <FindingsContent />
        </Suspense>
      )}
    </AppShell>
  );
}

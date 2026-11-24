"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { ShieldAlert, Workflow, KeyRound } from "lucide-react";
import { AppShell } from "@/components/Shell";
import { SeverityBadge, StatusBadge } from "@/components/Badges";
import { apiFetch } from "@/lib/api";

interface WorkflowSecurityResponse {
  evidenceBasis: string;
  disclaimer: string;
  summary: {
    totalCicdFindings: number;
    critical: number;
    high: number;
    medium: number;
    oidcFindingsCount: number;
    affectedFilesCount: number;
  };
  assets: Array<{
    filePath: string;
    kind: "WORKFLOW" | "OIDC_TRUST_POLICY";
    projectId: string;
    findingsCount: number;
    criticalCount: number;
    highCount: number;
    rulesTriggered: string[];
    oidcRelated: boolean;
  }>;
  findings: Array<{
    id: string;
    ruleId: string;
    title: string;
    severity: string;
    confidence: string;
    riskPriority: string;
    filePath?: string;
    lineStart?: number;
    status: string;
    lastSeenAt: string;
  }>;
}

interface ProjectOption {
  id: string;
  name: string;
}

function WorkflowsView() {
  const [projects, setProjects] = useState<ProjectOption[]>([]);
  const [projectId, setProjectId] = useState("");
  const [data, setData] = useState<WorkflowSecurityResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<{ projects: ProjectOption[] }>("/api/v1/projects")
      .then((res) => setProjects(res.projects))
      .catch(() => {});
  }, []);

  useEffect(() => {
    setLoading(true);
    setError(null);
    const url = projectId
      ? `/api/v1/projects/${projectId}/workflows`
      : "/api/v1/workflows";
    apiFetch<WorkflowSecurityResponse>(url)
      .then(setData)
      .catch((err) => setError((err as Error).message))
      .finally(() => setLoading(false));
  }, [projectId]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <Workflow className="w-6 h-6 text-sky-400" />
            CI/CD &amp; OIDC Federation Security
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Deterministic static analysis of GitHub Actions workflows, GITHUB_TOKEN permissions,
            supply-chain pinning, and cloud OIDC trust policies (AWS / Azure / GCP).
          </p>
        </div>

        <select
          value={projectId}
          onChange={(e) => setProjectId(e.target.value)}
          className="px-3 py-2 rounded-lg bg-[#111827] border border-slate-700 text-xs text-slate-200"
        >
          <option value="">All Projects</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </div>

      {data && (
        <div className="p-3.5 rounded-lg bg-sky-500/10 border border-sky-500/30 text-xs text-sky-200 flex items-start gap-2.5">
          <ShieldAlert className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-mono font-semibold text-sky-300">
              [{data.evidenceBasis}]
            </span>{" "}
            {data.disclaimer}
          </div>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/40 text-red-300 text-sm">
          {error}
        </div>
      )}

      {loading || !data ? (
        <div className="text-sm text-slate-400">Loading CI/CD security intelligence...</div>
      ) : (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-5 rounded-xl bg-[#111827] border border-slate-800">
              <div className="text-xs uppercase tracking-wider text-slate-400">
                CI/CD Findings
              </div>
              <div className="mt-2 text-3xl font-bold text-white">
                {data.summary.totalCicdFindings}
              </div>
              <div className="mt-1 text-xs text-slate-500">
                Across {data.summary.affectedFilesCount} workflow / IaC files
              </div>
            </div>
            <div className="p-5 rounded-xl bg-[#111827] border border-slate-800">
              <div className="text-xs uppercase tracking-wider text-slate-400">
                Critical &amp; High
              </div>
              <div className="mt-2 text-3xl font-bold text-red-400">
                {data.summary.critical + data.summary.high}
              </div>
              <div className="mt-1 text-xs text-slate-500">
                {data.summary.critical} Critical &bull; {data.summary.high} High
              </div>
            </div>
            <div className="p-5 rounded-xl bg-[#111827] border border-slate-800">
              <div className="text-xs uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <KeyRound className="w-3.5 h-3.5 text-amber-400" />
                OIDC Trust Risks
              </div>
              <div className="mt-2 text-3xl font-bold text-amber-300">
                {data.summary.oidcFindingsCount}
              </div>
              <div className="mt-1 text-xs text-slate-500">
                Workflow OIDC &amp; cloud trust policies
              </div>
            </div>
            <div className="p-5 rounded-xl bg-[#111827] border border-slate-800">
              <div className="text-xs uppercase tracking-wider text-slate-400">
                Medium Findings
              </div>
              <div className="mt-2 text-3xl font-bold text-sky-300">
                {data.summary.medium}
              </div>
              <div className="mt-1 text-xs text-slate-500">
                Pinning, lockfile &amp; token hardening
              </div>
            </div>
          </div>

          {/* Affected Workflows & OIDC Trust Policies */}
          <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
            <h2 className="text-sm font-semibold text-white">
              Workflows &amp; Static OIDC Trust Policies ({data.assets.length})
            </h2>
            {data.assets.length === 0 ? (
              <p className="text-xs text-slate-400">
                No CI/CD workflow or OIDC trust findings recorded yet. Run a scan on a project
                containing <code>.github/workflows/*.yml</code> or cloud OIDC IaC files.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2 pr-4">File Path</th>
                      <th className="py-2 pr-4">Asset Kind</th>
                      <th className="py-2 pr-4">Rules Triggered</th>
                      <th className="py-2 pr-4">OIDC</th>
                      <th className="py-2">Findings</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {data.assets.map((asset) => (
                      <tr key={`${asset.projectId}:${asset.filePath}`}>
                        <td className="py-3 pr-4 font-mono text-slate-200">{asset.filePath}</td>
                        <td className="py-3 pr-4">
                          <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 font-mono text-[11px] text-slate-300">
                            {asset.kind.replace(/_/g, " ")}
                          </span>
                        </td>
                        <td className="py-3 pr-4 font-mono text-[11px] text-sky-300">
                          {asset.rulesTriggered.join(", ")}
                        </td>
                        <td className="py-3 pr-4">
                          {asset.oidcRelated ? (
                            <span className="px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/40 text-[10px] font-semibold">
                              OIDC TRUST
                            </span>
                          ) : (
                            <span className="text-slate-500">—</span>
                          )}
                        </td>
                        <td className="py-3 font-mono text-white">
                          {asset.findingsCount}{" "}
                          <span className="text-slate-400">
                            ({asset.criticalCount}C / {asset.highCount}H)
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Prioritized CI/CD Findings */}
          <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
            <h2 className="text-sm font-semibold text-white">
              Prioritized CI/CD &amp; OIDC Findings ({data.findings.length})
            </h2>
            {data.findings.length === 0 ? (
              <p className="text-xs text-slate-400">No findings in current scope.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2 pr-4">Severity / Priority</th>
                      <th className="py-2 pr-4">Finding</th>
                      <th className="py-2 pr-4">Location</th>
                      <th className="py-2">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {data.findings.map((f) => (
                      <tr key={f.id} className="hover:bg-slate-800/30">
                        <td className="py-3 pr-4 whitespace-nowrap space-y-1">
                          <div>
                            <SeverityBadge severity={f.severity} />
                          </div>
                          <div className="text-[10px] font-mono text-slate-400">
                            Risk: {f.riskPriority}
                          </div>
                        </td>
                        <td className="py-3 pr-4 max-w-lg">
                          <Link
                            href={`/findings/${f.id}`}
                            className="font-semibold text-white hover:text-sky-300 block"
                          >
                            {f.title}
                          </Link>
                          <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                            {f.ruleId} &bull; Confidence: {f.confidence}
                          </div>
                        </td>
                        <td className="py-3 pr-4 font-mono text-[11px] text-slate-300">
                          {f.filePath ?? "—"}
                          {f.lineStart ? `:${f.lineStart}` : ""}
                        </td>
                        <td className="py-3 whitespace-nowrap">
                          <StatusBadge status={f.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export default function WorkflowsPage() {
  return <AppShell>{() => <WorkflowsView />}</AppShell>;
}

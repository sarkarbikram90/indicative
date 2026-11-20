"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Play, GitBranch, Plus, ExternalLink } from "lucide-react";
import { AppShell } from "@/components/Shell";
import { StatusBadge } from "@/components/Badges";
import { apiFetch, type AuthMeResponse } from "@/lib/api";

interface ProjectItem {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  isDemo: boolean;
  repository: {
    id: string;
    provider: string;
    fullName: string;
    defaultBranch: string;
    isPrivate: boolean;
  } | null;
  latestScan: {
    id: string;
    status: string;
    branch: string;
    commitSha: string | null;
    createdAt: string;
  } | null;
  openFindingsSummary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

interface DiscoveredRepo {
  githubInstallationDbId: string;
  installationId: number;
  fullName: string;
  defaultBranch: string;
  isPrivate: boolean;
  externalRepoId: string;
  description: string | null;
}

function ProjectsView({ session }: { session: AuthMeResponse }) {
  const router = useRouter();
  const [projects, setProjects] = useState<ProjectItem[]>([]);
  const [discoveredRepos, setDiscoveredRepos] = useState<DiscoveredRepo[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanningId, setScanningId] = useState<string | null>(null);
  const [runAi, setRunAi] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Register GitHub App Installation form
  const [installIdInput, setInstallIdInput] = useState("");
  const [accountLoginInput, setAccountLoginInput] = useState("");

  // Create project form
  const [projName, setProjName] = useState("");
  const [repoSlug, setRepoSlug] = useState("");
  const [branch, setBranch] = useState("main");

  async function refresh() {
    setLoading(true);
    try {
      const [projRes, repoRes] = await Promise.all([
        apiFetch<{ projects: ProjectItem[] }>("/api/v1/projects"),
        apiFetch<{ repositories: DiscoveredRepo[] }>(
          "/api/v1/integrations/github/repositories"
        ).catch(() => ({ repositories: [] }))
      ]);
      setProjects(projRes.projects);
      setDiscoveredRepos(repoRes.repositories);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function handleInitiateScan(projectId: string) {
    setScanningId(projectId);
    setError(null);
    setMessage(null);
    try {
      const res = await apiFetch<{ scan: { id: string } }>(
        `/api/v1/projects/${projectId}/scans`,
        {
          method: "POST",
          body: JSON.stringify({
            runAiAnalysis: runAi && session.capabilities.aiConfigured
          })
        }
      );
      router.push(`/scans/${res.scan.id}`);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setScanningId(null);
    }
  }

  async function handleRegisterInstallation(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    try {
      await apiFetch("/api/v1/integrations/github/installations", {
        method: "POST",
        body: JSON.stringify({
          installationId: Number(installIdInput),
          accountLogin: accountLoginInput
        })
      });
      setInstallIdInput("");
      setAccountLoginInput("");
      setMessage("GitHub App installation registered. Discovering repositories...");
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleCreateProject(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    try {
      await apiFetch("/api/v1/projects", {
        method: "POST",
        body: JSON.stringify({
          name: projName,
          repositoryFullName: repoSlug,
          defaultBranch: branch
        })
      });
      setProjName("");
      setRepoSlug("");
      setMessage("Project created.");
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleConnectDiscovered(repo: DiscoveredRepo) {
    setError(null);
    try {
      await apiFetch("/api/v1/projects", {
        method: "POST",
        body: JSON.stringify({
          name: repo.fullName.split("/")[1] || repo.fullName,
          repositoryFullName: repo.fullName,
          defaultBranch: repo.defaultBranch,
          isPrivate: repo.isPrivate,
          externalRepoId: repo.externalRepoId,
          githubInstallationId: repo.githubInstallationDbId
        })
      });
      setMessage(`Connected ${repo.fullName}`);
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Projects &amp; GitHub Repositories
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Connect GitHub App repositories and initiate asynchronous Semgrep, Trivy, and Gitleaks
            security scans.
          </p>
        </div>
        {session.capabilities.aiConfigured && (
          <label className="flex items-center gap-2 text-xs text-slate-300 bg-[#111827] px-3 py-2 rounded-lg border border-slate-800 cursor-pointer">
            <input
              type="checkbox"
              checked={runAi}
              onChange={(e) => setRunAi(e.target.checked)}
              className="rounded"
            />
            Run AI contextual analysis on top Critical/High findings
          </label>
        )}
      </div>

      {message && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 text-xs">
          {message}
        </div>
      )}
      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/40 text-red-300 text-xs">
          {error}
        </div>
      )}

      {/* Existing Projects */}
      <div className="space-y-4">
        <h2 className="text-sm font-semibold text-white">Connected Projects ({projects.length})</h2>
        {loading ? (
          <div className="text-xs text-slate-400">Loading projects...</div>
        ) : projects.length === 0 ? (
          <div className="p-6 rounded-xl bg-[#111827] border border-slate-800 text-sm text-slate-400">
            No projects connected yet.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {projects.map((p) => (
              <div
                key={p.id}
                className="p-5 rounded-xl bg-[#111827] border border-slate-800 flex flex-col justify-between gap-4"
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <h3 className="font-semibold text-white truncate">{p.name}</h3>
                      {p.isDemo && (
                        <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/40">
                          DEMO FIXTURE
                        </span>
                      )}
                    </div>
                    {p.latestScan && <StatusBadge status={p.latestScan.status} />}
                  </div>

                  {p.repository && (
                    <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                      <GitBranch className="w-3.5 h-3.5 text-slate-500" />
                      <span>{p.repository.fullName}</span>
                      <span>({p.repository.defaultBranch})</span>
                    </div>
                  )}

                  {p.description && (
                    <p className="text-xs text-slate-400 leading-relaxed">{p.description}</p>
                  )}

                  <div className="flex items-center gap-3 pt-2 text-xs">
                    <span className="text-red-400 font-semibold">
                      {p.openFindingsSummary.critical} Critical
                    </span>
                    <span className="text-orange-400 font-semibold">
                      {p.openFindingsSummary.high} High
                    </span>
                    <span className="text-amber-300">{p.openFindingsSummary.medium} Med</span>
                    <span className="text-sky-400">{p.openFindingsSummary.low} Low</span>
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-slate-800/80">
                  <div className="flex items-center gap-2">
                    <Link
                      href={`/findings?projectId=${p.id}`}
                      className="text-xs px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
                    >
                      View Findings
                    </Link>
                    {p.latestScan && (
                      <Link
                        href={`/scans/${p.latestScan.id}`}
                        className="text-xs px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
                      >
                        Latest Scan
                      </Link>
                    )}
                  </div>
                  <button
                    type="button"
                    disabled={scanningId === p.id}
                    onClick={() => handleInitiateScan(p.id)}
                    className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded bg-sky-500 hover:bg-sky-400 disabled:opacity-60 text-slate-950 cursor-pointer"
                  >
                    <Play className="w-3.5 h-3.5" />
                    {scanningId === p.id ? "Queuing..." : "Run Security Scan"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* GitHub App Authorization & Repository Connection */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">GitHub App Integration</h2>
            <a
              href={session.capabilities.githubAppInstallUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-sky-400 hover:text-sky-300"
            >
              Install GitHub App <ExternalLink className="w-3 h-3" />
            </a>
          </div>
          <p className="text-xs text-slate-400">
            Indicative requests read-only repository contents and metadata permissions using
            short-lived installation tokens minted exclusively on the backend worker.
          </p>
          <form onSubmit={handleRegisterInstallation} className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <input
                type="number"
                required
                placeholder="Installation ID (e.g. 123456)"
                value={installIdInput}
                onChange={(e) => setInstallIdInput(e.target.value)}
                className="px-3 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-xs text-white"
              />
              <input
                type="text"
                required
                placeholder="GitHub Account / Org Login"
                value={accountLoginInput}
                onChange={(e) => setAccountLoginInput(e.target.value)}
                className="px-3 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-xs text-white"
              />
            </div>
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-white cursor-pointer"
            >
              Link GitHub App Installation
            </button>
          </form>

          {discoveredRepos.length > 0 && (
            <div className="pt-3 border-t border-slate-800 space-y-2">
              <div className="text-xs font-semibold text-slate-300">
                Authorized Repositories ({discoveredRepos.length})
              </div>
              {discoveredRepos.map((repo) => (
                <div
                  key={repo.externalRepoId}
                  className="flex items-center justify-between p-2 rounded bg-[#0d1320] border border-slate-800 text-xs"
                >
                  <span className="font-mono text-slate-200">{repo.fullName}</span>
                  <button
                    type="button"
                    onClick={() => handleConnectDiscovered(repo)}
                    className="px-2.5 py-1 rounded bg-sky-500/20 text-sky-300 hover:bg-sky-500/30 border border-sky-500/30 cursor-pointer"
                  >
                    Connect
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Plus className="w-4 h-4 text-sky-400" />
            Create Project Manually
          </h2>
          <form onSubmit={handleCreateProject} className="space-y-3">
            <input
              type="text"
              required
              placeholder="Project Name (e.g. Payments API)"
              value={projName}
              onChange={(e) => setProjName(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-xs text-white"
            />
            <div className="grid grid-cols-3 gap-3">
              <input
                type="text"
                required
                placeholder="owner/repository"
                value={repoSlug}
                onChange={(e) => setRepoSlug(e.target.value)}
                className="col-span-2 px-3 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-xs text-white font-mono"
              />
              <input
                type="text"
                required
                placeholder="Branch"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                className="px-3 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-xs text-white font-mono"
              />
            </div>
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs cursor-pointer"
            >
              Create Project
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

export default function ProjectsPage() {
  return <AppShell>{(session) => <ProjectsView session={session} />}</AppShell>;
}

"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck, Lock, GitBranch, Sparkles, CheckCircle2, ArrowRight } from "lucide-react";
import { apiFetch, fetchSession, getApiBaseUrl, setCsrfToken } from "@/lib/api";

interface PublicAuthConfig {
  demoMode: boolean;
  githubOAuthConfigured: boolean;
  githubAppConfigured: boolean;
  githubAppInstallUrl: string;
  aiConfigured: boolean;
}

export default function LandingPage() {
  const router = useRouter();
  const [authConfig, setAuthConfig] = useState<PublicAuthConfig | null>(null);
  const [signingIn, setSigningIn] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchSession().then((me) => {
      if (me) router.replace("/dashboard");
    });
    apiFetch<PublicAuthConfig>("/api/v1/auth/config")
      .then(setAuthConfig)
      .catch(() => setAuthConfig(null));
  }, [router]);

  async function handleDemoLogin() {
    setSigningIn(true);
    setError(null);
    try {
      const res = await apiFetch<{ csrfToken: string }>("/api/v1/auth/demo", {
        method: "POST"
      });
      setCsrfToken(res.csrfToken);
      router.push("/dashboard");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSigningIn(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col justify-between">
      <header className="border-b border-slate-800/80 px-8 py-4 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-sky-500/15 border border-sky-500/40 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-sky-400" />
          </div>
          <span className="font-semibold text-lg tracking-tight">Indicative</span>
          <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
            MVP
          </span>
        </div>
        <div className="text-xs text-slate-400 font-mono">
          Detect &rarr; Understand &rarr; Prioritize &rarr; Recommend &rarr; Verify
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-16 grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
        <div className="lg:col-span-7 space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-500/10 border border-sky-500/30 text-sky-300 text-xs font-medium">
            Deterministic Multi-Engine Scanning + Redacted AI Contextual Analysis
          </div>
          <h1 className="text-4xl font-bold tracking-tight text-white leading-tight">
            Evidence-backed security intelligence for your GitHub repositories.
          </h1>
          <p className="text-slate-300 text-base leading-relaxed">
            Indicative combines pinned <strong>Semgrep</strong> (SAST),{" "}
            <strong>Trivy</strong> (SCA &amp; IaC), and <strong>Gitleaks</strong> (current files
            &amp; Git history) with canonical deduplication, tenant-keyed HMAC secret
            correlation, and optional AI remediation analysis — without ever storing or leaking
            plaintext credentials.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
            <div className="p-4 rounded-lg bg-[#111827] border border-slate-800">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <Lock className="w-4 h-4 text-emerald-400" />
                Zero Plaintext Secrets
              </div>
              <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
                Detected credentials are masked and keyed via HKDF+HMAC-SHA256 before
                persistence, reporting, or AI requests.
              </p>
            </div>
            <div className="p-4 rounded-lg bg-[#111827] border border-slate-800">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <CheckCircle2 className="w-4 h-4 text-sky-400" />
                Honest Re-Scan Verification
              </div>
              <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
                Compares scans across commits and never treats scanner failures or shallow clones
                as verified fixes.
              </p>
            </div>
          </div>
        </div>

        <div className="lg:col-span-5">
          <div className="p-6 rounded-xl bg-[#111827] border border-slate-800 shadow-2xl space-y-5">
            <div>
              <h2 className="text-lg font-semibold text-white">Sign in to Indicative</h2>
              <p className="text-xs text-slate-400 mt-1">
                Authenticate with GitHub OAuth and authorize read-only repository access through
                the Indicative GitHub App.
              </p>
            </div>

            {error && (
              <div className="p-3 rounded-md bg-red-500/10 border border-red-500/40 text-red-300 text-xs">
                {error}
              </div>
            )}

            <div className="space-y-3">
              {authConfig?.githubOAuthConfigured ? (
                <a
                  href={`${getApiBaseUrl()}/api/v1/auth/github/start`}
                  className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-white text-slate-950 font-semibold text-sm hover:bg-slate-200 transition-colors"
                >
                  <GitBranch className="w-4 h-4" />
                  Continue with GitHub OAuth
                </a>
              ) : (
                <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-400">
                  GitHub OAuth is not configured in this environment. Set{" "}
                  <code className="text-slate-200">GITHUB_OAUTH_CLIENT_ID</code> and{" "}
                  <code className="text-slate-200">GITHUB_OAUTH_CLIENT_SECRET</code> in{" "}
                  <code className="text-slate-200">.env</code> to enable GitHub login.
                </div>
              )}

              {authConfig?.demoMode && (
                <button
                  type="button"
                  disabled={signingIn}
                  onClick={handleDemoLogin}
                  className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-60 text-slate-950 font-semibold text-sm transition-colors cursor-pointer"
                >
                  <Sparkles className="w-4 h-4" />
                  {signingIn ? "Creating dev session..." : "Enter Development Demo Workspace"}
                  <ArrowRight className="w-4 h-4" />
                </button>
              )}
            </div>

            <div className="pt-4 border-t border-slate-800/80 text-[11px] text-slate-500 space-y-1">
              <p>
                Demo mode runs real Semgrep, Trivy, and Gitleaks scans against controlled local
                fixture repositories and is strictly disabled in production.
              </p>
              <p>
                Indicative is a working product brand name; trademark and domain availability are
                not represented as verified.
              </p>
            </div>
          </div>
        </div>
      </main>

      <footer className="border-t border-slate-800/70 px-8 py-4 text-xs text-slate-500 flex items-center justify-between">
        <span>Indicative Security Intelligence Platform (Apache-2.0)</span>
        <span>Semgrep CE &bull; Trivy &bull; Gitleaks v8</span>
      </footer>
    </div>
  );
}

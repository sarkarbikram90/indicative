"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  ShieldCheck,
  LayoutDashboard,
  FolderGit2,
  AlertTriangle,
  Workflow,
  BellRing,
  Bot,
  LogOut,
  FileCode2
} from "lucide-react";
import { apiFetch, fetchSession, setCsrfToken, type AuthMeResponse } from "@/lib/api";

const NAV_ITEMS = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/projects", label: "Projects", icon: FolderGit2 },
  { href: "/findings", label: "Findings", icon: AlertTriangle },
  { href: "/workflows", label: "CI/CD & OIDC", icon: Workflow },
  { href: "/automations", label: "Automations", icon: BellRing },
  { href: "/advisor", label: "AI Advisor", icon: Bot }
];

export function AppShell({
  children
}: {
  children: (session: AuthMeResponse) => React.ReactNode;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const [session, setSession] = useState<AuthMeResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    fetchSession().then((me) => {
      if (!active) return;
      if (!me) {
        router.replace("/");
      } else {
        setSession(me);
      }
      setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [router]);

  async function handleLogout() {
    try {
      await apiFetch("/api/v1/auth/logout", { method: "POST" });
    } catch {
      // ignore
    } finally {
      setCsrfToken(null);
      router.replace("/");
    }
  }

  if (loading || !session) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#090d16] text-slate-400 text-sm">
        Verifying authenticated workspace session...
      </div>
    );
  }

  return (
    <div className="min-h-screen flex bg-[#090d16] text-slate-100">
      <aside className="w-64 shrink-0 border-r border-slate-800/90 bg-[#0d1320] flex flex-col justify-between">
        <div>
          <div className="p-5 border-b border-slate-800/80">
            <Link href="/dashboard" className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-sky-500/15 border border-sky-500/40 flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-sky-400" />
              </div>
              <div>
                <div className="font-semibold text-base tracking-tight text-white">
                  Indicative
                </div>
                <div className="text-[11px] text-slate-400">
                  Security Intelligence
                </div>
              </div>
            </Link>
          </div>

          <div className="px-4 py-3 border-b border-slate-800/60">
            <div className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">
              Organization
            </div>
            <div className="mt-1 text-sm font-medium text-slate-200 truncate">
              {session.organization.name}
            </div>
            {session.user.isDemoUser && (
              <span className="mt-1.5 inline-block text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/40">
                Development Demo Workspace
              </span>
            )}
          </div>

          <nav className="p-3 space-y-1">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    active
                      ? "bg-sky-500/15 text-sky-300 border border-sky-500/30"
                      : "text-slate-300 hover:bg-slate-800/60 hover:text-white border border-transparent"
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </div>

        <div className="p-4 border-t border-slate-800/80 space-y-3">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="flex items-center gap-1.5">
              <FileCode2 className="w-3.5 h-3.5" />
              AI Analyst
            </span>
            <span
              className={
                session.capabilities.aiConfigured ? "text-emerald-400" : "text-slate-500"
              }
            >
              {session.capabilities.aiConfigured ? "Enabled" : "Disabled"}
            </span>
          </div>
          <div className="flex items-center justify-between pt-2 border-t border-slate-800/60">
            <div className="min-w-0">
              <div className="text-xs font-medium text-slate-200 truncate">
                {session.user.name}
              </div>
              <div className="text-[11px] text-slate-500 truncate">{session.user.email}</div>
            </div>
            <button
              type="button"
              onClick={handleLogout}
              title="Sign out"
              className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-100"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      <main className="flex-1 min-w-0 overflow-x-hidden">
        <div className="max-w-7xl mx-auto px-6 py-8">{children(session)}</div>
      </main>
    </div>
  );
}

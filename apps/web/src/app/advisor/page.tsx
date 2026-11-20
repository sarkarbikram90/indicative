"use client";

import React, { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Bot, Send } from "lucide-react";
import { AppShell } from "@/components/Shell";
import { apiFetch, type AuthMeResponse } from "@/lib/api";

interface ProjectOpt {
  id: string;
  name: string;
}

interface ChatTurn {
  question: string;
  answer: string;
  caveats: string[];
  model: string;
  disclaimer: string;
}

const SUGGESTED_QUESTIONS = [
  "Why is this vulnerability dangerous?",
  "Which findings should I remediate first and why?",
  "How can I remediate this issue safely?",
  "What additional evidence would confirm real-world risk?",
  "Did the latest scan detect this vulnerability again?"
];

function AdvisorContent({ session }: { session: AuthMeResponse }) {
  const searchParams = useSearchParams();
  const [projects, setProjects] = useState<ProjectOpt[]>([]);
  const [projectId, setProjectId] = useState(searchParams.get("projectId") || "");
  const [findingId, setFindingId] = useState(searchParams.get("findingId") || "");
  const [scope, setScope] = useState<"project" | "finding">(
    searchParams.get("findingId") ? "finding" : "project"
  );
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<{ projects: ProjectOpt[] }>("/api/v1/projects")
      .then((res) => {
        setProjects(res.projects);
        if (!projectId && res.projects[0]) {
          setProjectId(res.projects[0].id);
        }
      })
      .catch(() => {});
  }, []);

  async function ask(qText: string) {
    if (!projectId || !qText.trim()) return;
    setSending(true);
    setError(null);
    try {
      const res = await apiFetch<{
        answer: string;
        caveats: string[];
        model: string;
        disclaimer: string;
      }>("/api/v1/advisor/ask", {
        method: "POST",
        body: JSON.stringify({
          scope,
          projectId,
          ...(scope === "finding" && findingId ? { findingId } : {}),
          question: qText.trim()
        })
      });
      setTurns((prev) => [
        ...prev,
        {
          question: qText.trim(),
          answer: res.answer,
          caveats: res.caveats,
          model: res.model,
          disclaimer: res.disclaimer
        }
      ]);
      setQuestion("");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Bot className="w-6 h-6 text-sky-400" /> AI Security Advisor
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Scoped strictly to your organization&apos;s authorized projects and redacted findings.
          Never sends plaintext secrets or executes repository instructions.
        </p>
      </div>

      {!session.capabilities.aiConfigured && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/40 text-xs text-amber-200">
          AI Security Advisor is currently disabled because no LLM API key is configured (
          <code className="font-mono">AI_PROVIDER=disabled</code>). Set{" "}
          <code className="font-mono">AI_PROVIDER=openai-compatible</code> and{" "}
          <code className="font-mono">AI_API_KEY</code> in your environment to enable interactive
          advisory responses. Deterministic scanning and findings remain fully operational.
        </div>
      )}

      {/* Scope selector */}
      <div className="p-4 rounded-xl bg-[#111827] border border-slate-800 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
        <select
          value={projectId}
          onChange={(e) => setProjectId(e.target.value)}
          className="px-3 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-white"
        >
          <option value="">Select Project...</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        <select
          value={scope}
          onChange={(e) => setScope(e.target.value as "project" | "finding")}
          className="px-3 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-white"
        >
          <option value="project">Scope: Selected Project</option>
          <option value="finding">Scope: Specific Finding ID</option>
        </select>
        {scope === "finding" && (
          <input
            type="text"
            placeholder="Finding UUID"
            value={findingId}
            onChange={(e) => setFindingId(e.target.value)}
            className="px-3 py-2 rounded-lg bg-[#0d1320] border border-slate-700 text-white font-mono"
          />
        )}
      </div>

      {/* Suggested questions */}
      <div className="flex flex-wrap gap-2">
        {SUGGESTED_QUESTIONS.map((q) => (
          <button
            key={q}
            type="button"
            disabled={!session.capabilities.aiConfigured || sending}
            onClick={() => ask(q)}
            className="text-xs px-3 py-1.5 rounded-full bg-slate-800/90 hover:bg-slate-700 disabled:opacity-40 text-slate-300 border border-slate-700 cursor-pointer"
          >
            {q}
          </button>
        ))}
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/40 text-red-300 text-xs">
          {error}
        </div>
      )}

      {/* Conversation */}
      <div className="space-y-4">
        {turns.map((t, i) => (
          <div
            key={i}
            className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-3 text-xs"
          >
            <div className="font-semibold text-sky-300">You: {t.question}</div>
            <div className="text-slate-200 whitespace-pre-wrap leading-relaxed">{t.answer}</div>
            {t.caveats.length > 0 && (
              <ul className="list-disc pl-5 text-slate-400 space-y-0.5">
                {t.caveats.map((c, j) => (
                  <li key={j}>{c}</li>
                ))}
              </ul>
            )}
            <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-500 flex justify-between">
              <span>{t.disclaimer}</span>
              <span className="font-mono">{t.model}</span>
            </div>
          </div>
        ))}
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          ask(question);
        }}
        className="flex gap-3"
      >
        <input
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="Ask about vulnerabilities, remediation priorities, or verification status..."
          disabled={!session.capabilities.aiConfigured || sending}
          className="flex-1 px-4 py-2.5 rounded-lg bg-[#111827] border border-slate-700 text-sm text-white disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={!session.capabilities.aiConfigured || sending || !question.trim()}
          className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-40 text-slate-950 font-semibold text-sm cursor-pointer"
        >
          <Send className="w-4 h-4" /> Ask
        </button>
      </form>
    </div>
  );
}

export default function AdvisorPage() {
  return (
    <AppShell>
      {(session) => (
        <Suspense fallback={<div className="text-xs text-slate-400">Loading advisor...</div>}>
          <AdvisorContent session={session} />
        </Suspense>
      )}
    </AppShell>
  );
}

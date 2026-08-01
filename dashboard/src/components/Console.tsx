"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  AgentEvent,
  Finding,
  Health,
  decideHuman,
  eventsUrl,
  getHealth,
  getReport,
  getSandbox,
  getScan,
  startSandbox,
  startScan,
  stopSandbox,
} from "@/lib/api";

const KIND_STYLE: Record<string, string> = {
  narrative: "text-teal",
  thought: "text-mute",
  decision: "text-sky",
  action: "text-mist",
  action_result: "text-mist",
  finding: "text-amber",
  guardrail: "text-rose",
  human_gate: "text-amber",
  run_started: "text-teal",
  run_finished: "text-teal",
  run_blocked: "text-rose",
  error: "text-rose",
};

export default function Console() {
  const [target, setTarget] = useState("http://127.0.0.1:3001");
  const [mode, setMode] = useState<"passive" | "assisted">("passive");
  const [health, setHealth] = useState<Health | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [status, setStatus] = useState<string>("idle");
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [steps, setSteps] = useState(0);
  const [reportMd, setReportMd] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sandboxBusy, setSandboxBusy] = useState(false);
  const [sandboxMsg, setSandboxMsg] = useState("");
  const feedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch(() =>
        setHealth({
          ok: false,
          allowlist: [],
          llm: false,
          supabase: false,
          ossprey: false,
          overmind: false,
          sandbox_url: "",
        })
      );
    getSandbox()
      .then((s) => {
        if (s.tunnel_url) {
          setTarget(s.tunnel_url);
          setSandboxMsg(`Modal Sandbox live · ${s.sandbox_id?.slice(0, 12) || "ok"}`);
        }
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!runId) return;
    const es = new EventSource(eventsUrl(runId));
    const onAny = (ev: MessageEvent) => {
      try {
        const data = JSON.parse(ev.data) as AgentEvent;
        setEvents((prev) => {
          if (prev.some((p) => p.id === data.id)) return prev;
          return [...prev, data];
        });
        if (data.kind === "finding" && data.detail) {
          const detail = data.detail;
          setFindings((prev) => {
            const id = String(detail.id || data.id);
            if (prev.some((f) => f.id === id)) return prev;
            return [
              ...prev,
              {
                id,
                title: data.message.replace(/^\[[^\]]+\]\s*/, ""),
                severity: String(detail.severity || "info"),
                category: String(detail.category || ""),
                evidence: String(detail.evidence || ""),
                remediation: String(detail.remediation || ""),
                asset: String(detail.asset || ""),
                cwe: detail.cwe ? String(detail.cwe) : null,
              },
            ];
          });
        }
        if (data.kind === "action" || data.kind === "decision") {
          setSteps((s) => s + (data.kind === "action" ? 1 : 0));
        }
        if (data.kind === "run_finished" || data.kind === "run_blocked") {
          setStatus(data.kind === "run_blocked" ? "blocked" : "completed");
          getScan(runId)
            .then((r) => {
              setFindings(r.findings || []);
              setSteps(r.steps);
              setStatus(r.status);
            })
            .catch(() => undefined);
          getReport(runId)
            .then((r) => setReportMd(r.markdown || ""))
            .catch(() => undefined);
        }
        if (data.kind === "human_gate" && data.message.toLowerCase().includes("awaiting")) {
          setStatus("awaiting_human");
        }
        if (data.kind === "run_started") setStatus("running");
      } catch {
        /* ignore malformed */
      }
    };
    [
      "narrative",
      "thought",
      "decision",
      "action",
      "action_result",
      "finding",
      "guardrail",
      "human_gate",
      "run_started",
      "run_finished",
      "run_blocked",
      "error",
    ].forEach((k) => es.addEventListener(k, onAny as EventListener));
    es.onmessage = onAny;
    es.onerror = () => {
      /* browser will retry; also refresh state */
      getScan(runId)
        .then((r) => {
          setStatus(r.status);
          setFindings(r.findings || []);
          setSteps(r.steps);
        })
        .catch(() => undefined);
    };
    return () => es.close();
  }, [runId]);

  useEffect(() => {
    const el = feedRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [events]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  }, [findings]);

  async function onStart(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setEvents([]);
    setFindings([]);
    setReportMd("");
    setSteps(0);
    setStatus("queued");
    try {
      const run = await startScan(target.trim(), mode);
      setRunId(run.id);
      setStatus(run.status);
      if (run.status === "blocked") {
        setError("Target blocked by allowlist guardrail.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
      setStatus("idle");
    } finally {
      setBusy(false);
    }
  }

  async function onHuman(approve: boolean) {
    if (!runId) return;
    await decideHuman(runId, approve, approve ? "approved from dashboard" : "denied from dashboard");
    setStatus("running");
  }

  async function onSandboxStart() {
    setSandboxBusy(true);
    setSandboxMsg("Provisioning Modal Sandbox + encrypted tunnel…");
    try {
      const s = await startSandbox(false);
      if (s.tunnel_url) {
        setTarget(s.tunnel_url);
        setSandboxMsg(`Sandbox ready · ${s.tunnel_url}`);
      } else {
        setSandboxMsg("Sandbox started but no tunnel URL returned");
      }
    } catch (err) {
      setSandboxMsg(err instanceof Error ? err.message : "Modal Sandbox failed — run modal setup");
    } finally {
      setSandboxBusy(false);
    }
  }

  async function onSandboxStop() {
    setSandboxBusy(true);
    try {
      await stopSandbox();
      setSandboxMsg("Sandbox terminated");
    } catch (err) {
      setSandboxMsg(err instanceof Error ? err.message : "Stop failed");
    } finally {
      setSandboxBusy(false);
    }
  }

  return (
    <main className="relative z-10 mx-auto flex min-h-screen max-w-[1400px] flex-col gap-6 px-4 py-6 md:px-8 md:py-8">
      <header className="animate-rise flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.35em] text-teal/80">
            scoped · read-only · audited
          </p>
          <h1 className="font-display text-5xl font-extrabold tracking-tight text-white md:text-7xl">
            PRISM
          </h1>
          <p className="mt-2 max-w-xl text-sm leading-relaxed text-mute md:text-base">
            Agentic attack surface mapper + autonomous misconfig hunter. Recon chains into
            Ossprey supply-chain checks and Overmind blast-radius context — humans stay in the loop.
          </p>
        </div>
        <div className="flex flex-wrap gap-2 text-[11px] uppercase tracking-wider">
          <Badge ok={!!health?.ok} label="API" />
          <Badge ok={!!health?.ossprey} label="Ossprey" />
          <Badge ok={!!health?.overmind} label="Overmind" />
          <Badge ok={!!health?.supabase} label="Supabase" />
          <Badge ok={!!health?.llm} label="LLM" />
        </div>
      </header>

      <section className="animate-rise scan-sheen rounded-sm border border-[var(--line)] bg-[var(--panel)] p-4 shadow-glow backdrop-blur md:p-5">
        <form onSubmit={onStart} className="flex flex-col gap-3 md:flex-row md:items-end">
          <label className="flex-1">
            <span className="mb-1 block text-[11px] uppercase tracking-[0.2em] text-mute">
              Allowlisted target
            </span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full border border-[var(--line)] bg-ink/60 px-3 py-3 font-mono text-sm text-mist outline-none ring-teal/40 focus:ring-2"
              placeholder="http://127.0.0.1:3001 or https://….modal.run"
              required
            />
          </label>
          <label>
            <span className="mb-1 block text-[11px] uppercase tracking-[0.2em] text-mute">Mode</span>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as "passive" | "assisted")}
              className="border border-[var(--line)] bg-ink/60 px-3 py-3 font-mono text-sm text-mist outline-none"
            >
              <option value="passive">Passive (auto)</option>
              <option value="assisted">Assisted (human gates)</option>
            </select>
          </label>
          <button
            type="submit"
            disabled={busy}
            className="border border-teal/50 bg-teal/15 px-5 py-3 font-display text-sm font-bold uppercase tracking-[0.18em] text-teal transition hover:bg-teal/25 disabled:opacity-50"
          >
            {busy ? "Starting…" : "Engage"}
          </button>
        </form>
        {error && <p className="mt-3 text-sm text-rose">{error}</p>}
        <div className="mt-3 flex flex-col gap-2 border-t border-[var(--line)] pt-3 md:flex-row md:items-center md:justify-between">
          <p className="text-[11px] text-mute">
            Allowlist: {(health?.allowlist || []).join(", ") || "loading…"}
            {sandboxMsg ? ` · ${sandboxMsg}` : ""}
          </p>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={sandboxBusy}
              onClick={onSandboxStart}
              className="border border-sky/40 bg-sky/10 px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider text-sky disabled:opacity-50"
            >
              {sandboxBusy ? "Sandbox…" : "Spin Modal Sandbox"}
            </button>
            <button
              type="button"
              disabled={sandboxBusy}
              onClick={onSandboxStop}
              className="border border-[var(--line)] px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider text-mute disabled:opacity-50"
            >
              Stop
            </button>
          </div>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
        <div className="flex min-h-[420px] flex-col rounded-sm border border-[var(--line)] bg-[var(--panel)] backdrop-blur">
          <div className="flex items-center justify-between border-b border-[var(--line)] px-4 py-3">
            <div className="flex items-center gap-2">
              <span className="live-dot inline-block h-2 w-2 rounded-full bg-teal" />
              <h2 className="font-display text-lg font-bold text-white">Live narrative</h2>
            </div>
            <div className="font-mono text-[11px] uppercase tracking-wider text-mute">
              {status} · step {steps} · run {runId ? runId.slice(0, 8) : "—"}
            </div>
          </div>
          <div ref={feedRef} className="scroll-thin flex-1 space-y-2 overflow-y-auto p-4 font-mono text-[12.5px] leading-relaxed">
            {events.length === 0 && (
              <p className="text-mute">Waiting for engagement… point Prism at your Modal Juice Shop or local lab sandbox.</p>
            )}
            {events.map((ev) => (
              <div key={ev.id} className="animate-rise border-l border-[var(--line)] pl-3">
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="text-[10px] uppercase tracking-wider text-mute">
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </span>
                  <span className={`text-[10px] uppercase tracking-wider ${KIND_STYLE[ev.kind] || "text-mist"}`}>
                    {ev.kind}
                  </span>
                </div>
                <p className={KIND_STYLE[ev.kind] || "text-mist"}>{ev.message}</p>
              </div>
            ))}
          </div>
          {status === "awaiting_human" && (
            <div className="flex items-center justify-between gap-3 border-t border-amber/30 bg-amber/10 px-4 py-3">
              <p className="text-sm text-amber">Human gate — approve next non-passive check?</p>
              <div className="flex gap-2">
                <button
                  onClick={() => onHuman(true)}
                  className="border border-teal/40 px-3 py-1.5 text-xs uppercase tracking-wider text-teal"
                >
                  Approve
                </button>
                <button
                  onClick={() => onHuman(false)}
                  className="border border-rose/40 px-3 py-1.5 text-xs uppercase tracking-wider text-rose"
                >
                  Deny
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="flex min-h-[420px] flex-col gap-4">
          <div className="rounded-sm border border-[var(--line)] bg-[var(--panel)] p-4 backdrop-blur">
            <h2 className="font-display text-lg font-bold text-white">Severity radar</h2>
            <div className="mt-3 grid grid-cols-5 gap-2 text-center font-mono text-xs">
              {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
                <div key={s} className={`rounded-sm border px-1 py-2 severity-${s}`}>
                  <div className="text-lg font-bold">{counts[s] || 0}</div>
                  <div className="uppercase tracking-wider opacity-80">{s}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="flex flex-1 flex-col rounded-sm border border-[var(--line)] bg-[var(--panel)] backdrop-blur">
            <div className="border-b border-[var(--line)] px-4 py-3">
              <h2 className="font-display text-lg font-bold text-white">
                Findings ({findings.length})
              </h2>
            </div>
            <div className="scroll-thin flex-1 space-y-3 overflow-y-auto p-4">
              {findings.length === 0 && (
                <p className="font-mono text-xs text-mute">No findings yet — the agent is still mapping.</p>
              )}
              {findings.map((f) => (
                <article
                  key={f.id}
                  className={`animate-rise rounded-sm border px-3 py-2 severity-${f.severity}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="font-display text-sm font-bold text-white">{f.title}</h3>
                    <span className="font-mono text-[10px] uppercase tracking-wider">{f.severity}</span>
                  </div>
                  <p className="mt-1 font-mono text-[11px] text-mist/90">{f.evidence}</p>
                  <p className="mt-1 font-mono text-[11px] text-mute">Fix: {f.remediation}</p>
                </article>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="animate-rise rounded-sm border border-[var(--line)] bg-[var(--panel)] p-4 backdrop-blur md:p-5">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="font-display text-lg font-bold text-white">Findings report</h2>
          <span className="font-mono text-[11px] uppercase tracking-wider text-mute">
            demo payoff · markdown
          </span>
        </div>
        <pre className="scroll-thin max-h-80 overflow-auto whitespace-pre-wrap font-mono text-[12px] leading-relaxed text-mist/90">
          {reportMd || "Report appears when the autonomous pass finishes."}
        </pre>
      </section>

      <footer className="pb-6 text-center font-mono text-[11px] text-mute">
        Guardrails: hardcoded allowlist · read-only checks · no auto-exploit · audit log every action ·
        Ossprey + Overmind enrichment
      </footer>
    </main>
  );
}

function Badge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={`border px-2 py-1 ${
        ok ? "border-teal/40 bg-teal/10 text-teal" : "border-[var(--line)] text-mute"
      }`}
    >
      {label} {ok ? "●" : "○"}
    </span>
  );
}
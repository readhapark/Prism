"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
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
} from "@/lib/api";

/** Live narrative kinds — include step progress, not just summaries */
const FEED_KINDS = new Set([
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
]);

const KIND_LABEL: Record<string, string> = {
  narrative: "Note",
  thought: "Thinking",
  decision: "Next",
  action: "Running",
  action_result: "Result",
  finding: "Finding",
  guardrail: "Guardrail",
  human_gate: "Approval",
  run_started: "Start",
  run_finished: "Done",
  run_blocked: "Blocked",
  error: "Error",
};

const TERMINAL = new Set(["completed", "blocked", "failed"]);

function statusLabel(status: string) {
  if (status === "idle") return "Ready";
  if (status === "running" || status === "queued") return "Scanning";
  if (status === "completed") return "Complete";
  if (status === "awaiting_human") return "Needs approval";
  if (status === "blocked") return "Blocked";
  return status;
}

export default function Console() {
  const [target, setTarget] = useState("http://127.0.0.1:3001");
  const [health, setHealth] = useState<Health | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [status, setStatus] = useState<string>("idle");
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [reportMd, setReportMd] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sandboxBusy, setSandboxBusy] = useState(false);
  const [showReport, setShowReport] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
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
        if (s.tunnel_url) setTarget(s.tunnel_url);
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!runId) return;
    let cancelled = false;
    let reportFetched = false;

    const mergeEvents = (incoming: AgentEvent[]) => {
      setEvents((prev) => {
        if (!incoming.length) return prev;
        const byId = new Map(prev.map((e) => [e.id, e]));
        for (const e of incoming) byId.set(e.id, e);
        return Array.from(byId.values()).sort((a, b) =>
          String(a.timestamp).localeCompare(String(b.timestamp))
        );
      });
    };

    const syncFromScan = async () => {
      try {
        const r = await getScan(runId);
        if (cancelled) return;
        setStatus(r.status);
        setFindings(r.findings || []);
        mergeEvents(r.events || []);
        if (TERMINAL.has(r.status) && !reportFetched) {
          reportFetched = true;
          getReport(runId)
            .then((rep) => {
              if (!cancelled) setReportMd(rep.markdown || "");
            })
            .catch(() => undefined);
        }
      } catch {
        /* ignore transient poll errors */
      }
    };

    // Polling is the reliable path through Cloudflare tunnels (SSE is often buffered).
    void syncFromScan();
    const poll = window.setInterval(() => {
      void syncFromScan();
    }, 1200);

    const es = new EventSource(eventsUrl(runId));
    const onAny = (ev: MessageEvent) => {
      try {
        const data = JSON.parse(ev.data) as AgentEvent;
        mergeEvents([data]);
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
        if (data.kind === "run_finished" || data.kind === "run_blocked") {
          setStatus(data.kind === "run_blocked" ? "blocked" : "completed");
          void syncFromScan();
        }
        if (data.kind === "human_gate" && data.message.toLowerCase().includes("awaiting")) {
          setStatus("awaiting_human");
        }
        if (data.kind === "run_started") setStatus("running");
      } catch {
        /* ignore */
      }
    };
    FEED_KINDS.forEach((k) => es.addEventListener(k, onAny as EventListener));

    return () => {
      cancelled = true;
      window.clearInterval(poll);
      es.close();
    };
  }, [runId]);

  useEffect(() => {
    const el = feedRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [events]);

  const feed = events.filter((e) => FEED_KINDS.has(e.kind));
  const criticalCount = findings.filter(
    (f) => f.severity === "critical" || f.severity === "high"
  ).length;
  const scanning = status === "running" || status === "queued";

  async function onStart(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setEvents([]);
    setFindings([]);
    setReportMd("");
    setShowReport(false);
    setExpandedId(null);
    setStatus("queued");
    try {
      const run = await startScan(target.trim(), "passive");
      setRunId(run.id);
      setStatus(run.status);
      if (run.status === "blocked") setError("Target is outside the allowlist.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start scan");
      setStatus("idle");
    } finally {
      setBusy(false);
    }
  }

  async function onHuman(approve: boolean) {
    if (!runId) return;
    await decideHuman(runId, approve, approve ? "approved" : "denied");
    setStatus("running");
  }

  async function onSandboxStart() {
    setSandboxBusy(true);
    try {
      const s = await startSandbox(false);
      if (s.tunnel_url) setTarget(s.tunnel_url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sandbox failed");
    } finally {
      setSandboxBusy(false);
    }
  }

  return (
    <main className="relative z-10 mx-auto min-h-screen max-w-5xl px-5 py-12 md:px-8 md:py-16">
      <header className="animate-rise mb-12 max-w-xl">
        <h1 className="font-display brand-sheen text-6xl font-extrabold tracking-tight md:text-7xl">
          PRISM
        </h1>
        <p className="mt-5 text-lg leading-relaxed text-soft md:text-xl">
          Map an allowlisted target. Surface misconfigurations — never exploit them.
        </p>
        <p className="mt-3 text-sm text-mute">
          {health?.ok === false
            ? "API offline — start the backend to engage."
            : health?.ok
              ? "Ready · read-only · audited"
              : "Connecting…"}
        </p>
      </header>

      <section className="animate-rise mb-12">
        <form onSubmit={onStart} className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <label className="flex-1">
            <span className="mb-1.5 block text-sm font-medium text-soft">Target</span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full border border-[var(--line)] bg-white/90 px-4 py-3.5 font-mono text-sm text-ink outline-none transition focus:border-accent focus:bg-white"
              placeholder="https://your-lab.modal.host"
              required
            />
          </label>
          <button
            type="submit"
            disabled={busy || scanning}
            className="bg-accent px-7 py-3.5 font-display text-sm font-bold uppercase tracking-[0.16em] text-white transition hover:bg-accent-ink disabled:opacity-45"
          >
            {busy || scanning ? "Running…" : "Engage"}
          </button>
        </form>
        <div className="mt-3.5 flex flex-wrap items-center justify-between gap-3 text-sm text-mute">
          <p>
            <span className="font-medium text-ink">{statusLabel(status)}</span>
            {findings.length > 0 && (
              <span>
                {" "}
                · {findings.length} finding{findings.length === 1 ? "" : "s"}
                {criticalCount > 0 && (
                  <span className="text-[var(--danger)]"> · {criticalCount} urgent</span>
                )}
              </span>
            )}
          </p>
          <button
            type="button"
            disabled={sandboxBusy}
            onClick={onSandboxStart}
            className="text-accent underline-offset-4 transition hover:underline disabled:opacity-50"
          >
            {sandboxBusy ? "Starting lab…" : "Use Modal lab"}
          </button>
        </div>
        {error && <p className="mt-3 text-sm text-[var(--danger)]">{error}</p>}
      </section>

      <section className="grid gap-12 border-t border-[var(--line)] pt-10 lg:grid-cols-[1.4fr_1fr]">
        <div className="animate-rise min-h-[360px]">
          <div className="mb-5 flex items-center gap-2.5">
            {scanning && <span className="live-dot inline-block h-2 w-2 rounded-full bg-accent" />}
            <h2 className="font-display text-2xl font-bold tracking-tight text-ink">Narrative</h2>
          </div>
          <div ref={feedRef} className="scroll-thin max-h-[480px] space-y-5 overflow-y-auto pr-1">
            {feed.length === 0 && (
              <p className="text-[15px] leading-relaxed text-soft">
                Engage a target to follow Prism’s reasoning in plain language.
              </p>
            )}
            {feed.map((ev, i) => (
              <div
                key={ev.id}
                className="animate-rise border-l-2 border-accent/25 pl-4"
                style={{ animationDelay: `${Math.min(i, 6) * 35}ms` }}
              >
                <div className="mb-1 flex items-baseline gap-2 font-mono text-[10px] uppercase tracking-[0.14em] text-mute">
                  <span>{KIND_LABEL[ev.kind] || ev.kind}</span>
                  <span aria-hidden>·</span>
                  <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                </div>
                <p className="text-[15px] leading-relaxed text-ink">{ev.message}</p>
              </div>
            ))}
          </div>

          {status === "awaiting_human" && (
            <div className="mt-8 flex flex-wrap items-center justify-between gap-3 border-y border-[var(--line)] py-4">
              <p className="text-sm text-soft">Allow a deeper check beyond passive recon?</p>
              <div className="flex gap-2">
                <button
                  onClick={() => onHuman(true)}
                  className="bg-accent px-4 py-2 text-xs font-bold uppercase tracking-wider text-white"
                >
                  Approve
                </button>
                <button
                  onClick={() => onHuman(false)}
                  className="border border-[var(--line)] bg-white px-4 py-2 text-xs font-bold uppercase tracking-wider text-soft"
                >
                  Skip
                </button>
              </div>
            </div>
          )}
        </div>

        <aside className="animate-rise">
          <h2 className="mb-5 font-display text-2xl font-bold tracking-tight text-ink">
            Findings
            {findings.length > 0 && (
              <span className="ml-2 align-middle font-ui text-base font-medium text-mute">
                {findings.length}
              </span>
            )}
          </h2>
          <div className="scroll-thin max-h-[480px] space-y-1 overflow-y-auto pr-1">
            {findings.length === 0 && (
              <p className="text-[15px] leading-relaxed text-soft">
                Confirmed issues will land here, ranked by severity.
              </p>
            )}
            {findings.map((f) => {
              const open = expandedId === f.id;
              return (
                <article key={f.id} className="animate-rise border-b border-[var(--line)] py-3.5">
                  <button
                    type="button"
                    onClick={() => setExpandedId(open ? null : f.id)}
                    className="flex w-full items-start gap-2.5 text-left"
                  >
                    <span
                      className={`mt-0.5 shrink-0 px-1.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-wider sev-${f.severity}`}
                    >
                      {f.severity}
                    </span>
                    <span className="font-display text-[15px] font-bold leading-snug text-ink">
                      {f.title}
                    </span>
                  </button>
                  {open && (
                    <div className="mt-2 space-y-1.5 pl-[4.25rem]">
                      {f.evidence && (
                        <p className="text-sm leading-relaxed text-soft">{f.evidence}</p>
                      )}
                      {f.remediation && (
                        <p className="text-sm leading-relaxed text-mute">
                          <span className="font-medium text-ink">Fix — </span>
                          {f.remediation}
                        </p>
                      )}
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        </aside>
      </section>

      {reportMd && (
        <section className="animate-rise mt-14 border-t border-[var(--line)] pt-8">
          <button
            type="button"
            onClick={() => setShowReport((v) => !v)}
            className="flex items-baseline gap-3 font-display text-xl font-bold text-ink"
          >
            Full report
            <span className="font-ui text-sm font-medium text-mute">
              {showReport ? "Hide" : "Show"}
            </span>
          </button>
          {showReport && (
            <pre className="scroll-thin mt-4 max-h-64 overflow-auto whitespace-pre-wrap font-mono text-[12px] leading-relaxed text-soft">
              {reportMd}
            </pre>
          )}
        </section>
      )}

      <footer className="mt-20 pb-6 text-center text-xs tracking-wide text-mute">
        Allowlisted targets · findings only · audit trail preserved
      </footer>
    </main>
  );
}
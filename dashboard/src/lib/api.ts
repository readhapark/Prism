const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") || "http://127.0.0.1:8787";

export type RunSummary = {
  id: string;
  target: string;
  status: string;
  mode: string;
  steps: number;
  findings_count: number;
  allowlist_ok: boolean;
  created_at: string;
  updated_at: string;
  report_path?: string | null;
};

export type Finding = {
  id: string;
  title: string;
  severity: string;
  category: string;
  evidence: string;
  remediation: string;
  asset?: string;
  cwe?: string | null;
  confidence?: number;
};

export type AgentEvent = {
  id: string;
  run_id: string;
  kind: string;
  message: string;
  detail?: Record<string, unknown>;
  timestamp: string;
};

export type Health = {
  ok: boolean;
  allowlist: string[];
  llm: boolean;
  supabase: boolean;
  ossprey: boolean;
  overmind: boolean;
  sandbox_url: string;
  integrations?: Record<string, string>;
};

export async function getHealth(): Promise<Health> {
  const res = await fetch(`${API_BASE}/api/health`, { cache: "no-store" });
  if (!res.ok) throw new Error("API unreachable");
  return res.json();
}

export async function startScan(target: string, mode: "passive" | "assisted" = "passive") {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ target, mode }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<RunSummary>;
}

export async function getScan(runId: string) {
  const res = await fetch(`${API_BASE}/api/scans/${runId}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Run not found");
  return res.json() as Promise<
    RunSummary & { findings: Finding[]; events: AgentEvent[]; recon: Record<string, unknown> | null }
  >;
}

export async function getReport(runId: string) {
  const res = await fetch(`${API_BASE}/api/scans/${runId}/report`, { cache: "no-store" });
  if (!res.ok) throw new Error("Report not ready");
  return res.json() as Promise<{ markdown: string; json: unknown }>;
}

export async function decideHuman(runId: string, approve: boolean, note = "") {
  const res = await fetch(`${API_BASE}/api/scans/${runId}/human`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ approve, note }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export type SandboxInfo = {
  running?: boolean;
  ok?: boolean;
  tunnel_url?: string | null;
  sandbox_id?: string;
  dashboard_url?: string;
  error?: string;
  hint?: string;
};

export async function getSandbox(): Promise<SandboxInfo> {
  const res = await fetch(`${API_BASE}/api/sandbox`, { cache: "no-store" });
  return res.json();
}

export async function startSandbox(fullJuice = false): Promise<SandboxInfo> {
  const res = await fetch(`${API_BASE}/api/sandbox/start?full_juice=${fullJuice}`, {
    method: "POST",
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(detail);
  }
  return res.json();
}

export async function stopSandbox(): Promise<{ ok: boolean }> {
  const res = await fetch(`${API_BASE}/api/sandbox/stop`, { method: "POST" });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export function eventsUrl(runId: string) {
  return `${API_BASE}/api/scans/${runId}/events`;
}

export { API_BASE };
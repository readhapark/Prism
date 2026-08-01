# PRISM

**Agentic Attack Surface Mapper + Autonomous Misconfig Hunter**

Point Prism at a scoped target (a domain you own, or a deliberately-vulnerable sandbox like OWASP Juice Shop on Modal). It autonomously chains:

**recon → enumeration → known-misconfig checks → Ossprey supply-chain scan → Overmind Lab traces → prioritized findings report**

…like a junior pentester’s first pass — with hard guardrails so humans stay in the loop.

---

## Why it scores on judging criteria

| Criterion | How Prism hits it |
|---|---|
| **AI autonomy** | Agent picks the next check from what it just found (Juice Shop → API enum; `package.json` → Ossprey; S3 hints → Overmind). Not a fixed script. |
| **Security impact** | Same workflow junior pentesters / bug-bounty triage do manually. |
| **Safety / responsible design** | Hardcoded allowlist, read-only checks, no auto-exploitation, human gates for deeper probes, full audit log (local JSONL + optional Supabase). |

---

## Architecture

```
dashboard (Next.js)  --SSE-->  api (FastAPI)  -->  agent loop
                                                    ├─ guardrails (allowlist / read-only)
                                                    ├─ recon (dns, ports, tech, paths)
                                                    ├─ misconfig hunter
                                                    ├─ Ossprey (supply-chain malware)
                                                    ├─ Overmind (blast radius)
                                                    └─ report writer
sandbox: Modal Sandbox (tunneled)  |  demo/sandbox_app.py  |  docker Juice Shop
```

---

## Modal Sandbox target (recommended)

Prism uses a real **Modal Sandbox** (encrypted tunnel + optional stateful code interpreter), not just a web Function:

```bash
modal setup   # once — browser auth
python -m prism_modal.sandbox_target spawn
# → {"tunnel_url": "https://….modal.host", ...}

# Point the dashboard / API at that tunnel URL
# Or: POST http://127.0.0.1:8787/api/sandbox/start
```

Stateful interpreter demo (Modal docs pattern):

```bash
python -m prism_modal.sandbox_target demo-interp
```

Full OWASP Juice Shop inside the Sandbox (slower first image build):

```bash
python -m prism_modal.sandbox_target spawn --full-juice
```

Alternate durable web endpoint (not a Sandbox):

```bash
modal deploy prism_modal/juice_shop.py
```

---

## Quick start (local demo)

```bash
# 1) Python deps
python3 -m pip install -r requirements.txt
cp .env.example .env   # add OSSPREY_API_KEY, optional OVM_API_KEY / OPENAI / Supabase

# 2) Lab sandbox (Juice Shop–style misconfigs on :3001)
python3 demo/sandbox_app.py &

# 3) Agent API
export PYTHONPATH=.
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8787 &

# 4) Live narrative dashboard
cd dashboard && npm install && npm run dev
# → http://localhost:3000
```

Or one-shot API+sandbox:

```bash
chmod +x scripts/run_demo.sh && ./scripts/run_demo.sh
```

Headless smoke test:

```bash
python3 demo/sandbox_app.py &
python3 scripts/smoke_scan.py http://127.0.0.1:3001
```

---

Docker alternative (no Modal):

```bash
docker compose up -d   # Juice Shop on :3001
# or: python3 demo/sandbox_app.py
```

---

## Integrations

### Ossprey (supply-chain)

When Prism finds `package.json` / Node deps, it runs an **Ossprey** malware check on the dependency set.

```bash
export OSSPREY_API_KEY=ospy_...
# optional CLI
curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh \
  | OSSPREY_INSTALL_DIR=$HOME/.local/bin sh
```

### Overmind (blast radius)

Cloud / infra-related findings are enriched with Overmind source + recent change context.

```bash
export OVM_API_KEY=...   # or OVERMIND_API_KEY
```

Cursor MCP (already in `.cursor/mcp.json`):

```json
{ "mcpServers": { "overmind": { "url": "https://api.overmind.tech/api/mcp" } } }
```

### Supabase audit log

Apply `supabase/schema.sql`, then set `SUPABASE_URL` + `SUPABASE_SERVICE_KEY`.  
Without Supabase, every action still lands in `data/audit/<run_id>.jsonl`.

---

## Guardrails (non-negotiable)

1. **Allowlist only** — targets must match `ALLOWLIST` (default: localhost + `*.modal.run` labs).
2. **Read-only** — GET/HEAD/OPTIONS only; exploit-like payloads blocked.
3. **No auto-exploitation** — findings + remediation only.
4. **Human gates** — CMS deep checks (and `assisted` mode actions) require dashboard approval.
5. **Audit everything** — thoughts, decisions, actions, findings, guardrail blocks.

---

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Allowlist + integration status |
| `POST` | `/api/scans` | `{ "target": "…", "mode": "passive\|assisted" }` |
| `GET` | `/api/scans/{id}` | Run detail + findings |
| `GET` | `/api/scans/{id}/events` | **SSE live narrative** |
| `POST` | `/api/scans/{id}/human` | Approve/deny gated step |
| `GET` | `/api/scans/{id}/report` | Markdown + JSON report |

---

## Demo script (90 seconds)

1. Open dashboard → brand **PRISM**, live narrative empty.
2. Engage `http://127.0.0.1:3001` (or Modal URL).
3. Watch autonomy: tech fingerprint → path probe → **exposed .git / .env / APIs** → **Ossprey** → **Overmind** → report.
4. Call out the guardrail strip: allowlist, read-only, audit, human gate.
5. Show prioritized report with remediations.

---

## Repo layout

```
agent/          # autonomy loop, recon, checks, guardrails, integrations
api/            # FastAPI + SSE
dashboard/      # Next.js live narrative UI
demo/           # local vulnerable sandbox
prism_modal/    # Modal Sandbox lab target + Juice Shop deploy
supabase/       # audit schema
scripts/        # demo + smoke helpers
```

Built for hackathon demos — only scan systems you own or explicit lab sandboxes.

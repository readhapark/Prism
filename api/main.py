from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.config import REPORTS_DIR, ensure_data_dirs, get_settings  # noqa: E402
from agent.core.events import bus  # noqa: E402
from agent.core.loop import runner  # noqa: E402
from agent.integrations.overmind import init_overmind, status as overmind_status  # noqa: E402
from agent.models import HumanDecisionRequest, StartScanRequest  # noqa: E402

ensure_data_dirs()
settings = get_settings()
_overmind_boot = init_overmind()

app = FastAPI(
    title="Prism Agent API",
    description="Agentic Attack Surface Mapper + Autonomous Misconfig Hunter",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list + ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health():
    return {
        "ok": True,
        "service": "prism",
        "read_only": settings.read_only,
        "allowlist": settings.allowlist_patterns,
        "llm": settings.has_llm,
        "llm_backend": settings.llm_backend,
        "llm_model": (
            settings.anthropic_model
            if settings.llm_backend == "anthropic"
            else settings.openai_model
            if settings.llm_backend == "openai"
            else None
        ),
        "supabase": settings.has_supabase,
        "ossprey": settings.has_ossprey,
        "overmind": settings.has_overmind,
        "overmind_status": overmind_status(),
        "overmind_boot": _overmind_boot,
        "sandbox_url": settings.sandbox_url,
        "integrations": {
            "ossprey": "supply-chain malware verdicts on discovered manifests",
            "overmind": "Overmind Lab agent observability / evals (overmindlab.ai)",
            "overmind_docs": "https://docs.overmindlab.ai",
            "overmind_console": "https://console.overmindlab.ai",
        },
    }


@app.get("/api/allowlist")
async def allowlist():
    return {"patterns": settings.allowlist_patterns, "read_only": True}


# ---------------------------------------------------------------------------
# Modal Sandbox lifecycle — true Sandbox with encrypted tunnel
# ---------------------------------------------------------------------------

@app.get("/api/sandbox")
async def sandbox_status():
    try:
        from prism_modal.sandbox_target import status as modal_status

        return modal_status()
    except Exception as exc:  # noqa: BLE001
        return {"running": False, "error": str(exc), "hint": "Run `modal setup` then POST /api/sandbox/start"}


@app.post("/api/sandbox/start")
async def sandbox_start(full_juice: bool = False):
    """Spin up the lab target inside a Modal Sandbox; return tunnel URL."""
    try:
        from prism_modal.sandbox_target import spawn

        ps = await asyncio.to_thread(spawn, full_juice=full_juice)
        return {"ok": True, **ps.to_dict()}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail=f"Modal Sandbox unavailable: {exc}. Authenticate with `modal setup`.",
        ) from exc


@app.post("/api/sandbox/stop")
async def sandbox_stop():
    try:
        from prism_modal.sandbox_target import terminate

        ok = await asyncio.to_thread(terminate)
        return {"ok": ok}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/scans")
async def start_scan(body: StartScanRequest):
    run = await runner.start(body.target.strip(), mode=body.mode)
    return _run_public(run)


@app.get("/api/scans")
async def list_scans():
    return [_run_public(r) for r in runner.list_runs()]


@app.get("/api/scans/{run_id}")
async def get_scan(run_id: str):
    run = runner.get_run(run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    return _run_detail(run)


@app.post("/api/scans/{run_id}/human")
async def human_gate(run_id: str, body: HumanDecisionRequest):
    run = runner.get_run(run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    if run.status != "awaiting_human":
        raise HTTPException(400, "Run is not awaiting human approval")
    run = await runner.resolve_human_gate(run_id, body.approve, body.note)
    return _run_public(run)


@app.get("/api/scans/{run_id}/events")
async def stream_events(run_id: str):
    run = runner.get_run(run_id)
    if not run:
        # Still allow subscribe for race where client connects immediately
        pass

    async def gen():
        # Padding + heartbeats help reverse proxies flush SSE chunks.
        yield ": " + (" " * 2048) + "\n\n"
        stream = bus.subscribe(run_id).__aiter__()
        while True:
            try:
                event = await asyncio.wait_for(stream.__anext__(), timeout=1.5)
            except StopAsyncIteration:
                break
            except asyncio.TimeoutError:
                yield ": ping\n\n"
                continue
            payload = event.model_dump(mode="json")
            yield f"event: {event.kind.value}\ndata: {json.dumps(payload)}\n\n"
            if event.kind.value in {"run_finished", "run_blocked"}:
                break

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "Content-Encoding": "identity",
        },
    )


@app.get("/api/scans/{run_id}/report")
async def get_report(run_id: str):
    run = runner.get_run(run_id)
    md = REPORTS_DIR / f"{run_id}.md"
    js = REPORTS_DIR / f"{run_id}.json"
    if not md.exists() and not (run and run.report_path):
        raise HTTPException(404, "Report not ready")
    return {
        "markdown": md.read_text(encoding="utf-8") if md.exists() else "",
        "json": json.loads(js.read_text(encoding="utf-8")) if js.exists() else None,
    }


@app.get("/api/scans/{run_id}/report.md")
async def download_report(run_id: str):
    md = REPORTS_DIR / f"{run_id}.md"
    if not md.exists():
        raise HTTPException(404, "Report not ready")
    return FileResponse(md, media_type="text/markdown", filename=f"prism-{run_id}.md")


def _run_public(run) -> dict:
    return {
        "id": run.id,
        "target": run.target,
        "status": run.status,
        "mode": run.mode,
        "steps": run.steps,
        "findings_count": len(run.findings),
        "allowlist_ok": run.allowlist_ok,
        "created_at": run.created_at.isoformat(),
        "updated_at": run.updated_at.isoformat(),
        "report_path": run.report_path,
    }


def _run_detail(run) -> dict:
    data = _run_public(run)
    data["findings"] = [f.model_dump(mode="json") for f in run.findings]
    data["recon"] = run.recon.model_dump(mode="json") if run.recon else None
    data["events"] = [e.model_dump(mode="json") for e in run.events[-200:]]
    return data


# Optional: serve built dashboard if present
DASHBOARD_OUT = ROOT / "dashboard" / "out"
if DASHBOARD_OUT.exists():
    app.mount("/", StaticFiles(directory=str(DASHBOARD_OUT), html=True), name="dashboard")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.main:app",
        host=settings.agent_host,
        port=settings.agent_port,
        reload=False,
    )
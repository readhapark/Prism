#!/usr/bin/env python3
"""Headless smoke test: start agent loop against local sandbox (no UI)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.config import ensure_data_dirs
from agent.core.loop import AgentRunner


async def main() -> int:
    ensure_data_dirs()
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3001"
    runner = AgentRunner()
    run = await runner.start(target, mode="passive")
    print(f"run_id={run.id} status={run.status}")
    if run.status == "blocked":
        return 2

    # Poll until complete (Ossprey can take ~90s)
    for _ in range(360):
        await asyncio.sleep(0.5)
        r = runner.get_run(run.id)
        assert r
        if r.status in {"completed", "failed", "blocked"}:
            print(f"final_status={r.status} steps={r.steps} findings={len(r.findings)}")
            for f in r.findings:
                print(f"  [{f.severity.value}] {f.title}")
            if r.report_path:
                print(f"report={r.report_path}")
            return 0 if r.status == "completed" and len(r.findings) > 0 else 1
    print("timeout")
    r = runner.get_run(run.id)
    if r:
        print(f"partial_status={r.status} steps={r.steps} findings={len(r.findings)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.config import AUDIT_DIR, ensure_data_dirs, get_settings
from agent.models import AgentEvent


class AuditLogger:
    """Dual-write audit log: local JSONL always, Supabase when configured."""

    def __init__(self) -> None:
        ensure_data_dirs()
        self.settings = get_settings()
        self._supabase = None
        self._lock = asyncio.Lock()

    def _local_path(self, run_id: str) -> Path:
        return AUDIT_DIR / f"{run_id}.jsonl"

    async def log_event(self, event: AgentEvent) -> None:
        row = {
            "id": event.id,
            "run_id": event.run_id,
            "kind": event.kind.value if hasattr(event.kind, "value") else event.kind,
            "message": event.message,
            "detail": event.detail,
            "timestamp": event.timestamp.isoformat(),
        }
        async with self._lock:
            path = self._local_path(event.run_id)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, default=str) + "\n")

        if self.settings.has_supabase:
            await self._supabase_insert("audit_events", row)

    async def log_finding(self, run_id: str, finding: dict[str, Any]) -> None:
        row = {
            "run_id": run_id,
            **finding,
            "logged_at": datetime.now(timezone.utc).isoformat(),
        }
        async with self._lock:
            path = AUDIT_DIR / f"{run_id}.findings.jsonl"
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, default=str) + "\n")
        if self.settings.has_supabase:
            await self._supabase_insert("findings", row)

    async def log_run_meta(self, run_id: str, meta: dict[str, Any]) -> None:
        row = {"run_id": run_id, **meta, "logged_at": datetime.now(timezone.utc).isoformat()}
        async with self._lock:
            path = AUDIT_DIR / f"{run_id}.meta.json"
            path.write_text(json.dumps(row, indent=2, default=str), encoding="utf-8")
        if self.settings.has_supabase:
            await self._supabase_insert("scan_runs", row)

    def read_events(self, run_id: str) -> list[dict[str, Any]]:
        path = self._local_path(run_id)
        if not path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    async def _supabase_insert(self, table: str, row: dict[str, Any]) -> None:
        try:
            client = self._get_supabase()
            if client is None:
                return
            # supabase-py is sync; offload
            await asyncio.to_thread(lambda: client.table(table).insert(row).execute())
        except Exception as exc:  # noqa: BLE001 — audit must never crash the agent
            async with self._lock:
                fail = AUDIT_DIR / "supabase_errors.jsonl"
                with fail.open("a", encoding="utf-8") as f:
                    f.write(
                        json.dumps(
                            {
                                "table": table,
                                "error": str(exc),
                                "at": datetime.now(timezone.utc).isoformat(),
                            }
                        )
                        + "\n"
                    )

    def _get_supabase(self):
        if self._supabase is not None:
            return self._supabase
        if not self.settings.has_supabase:
            return None
        try:
            from supabase import create_client

            self._supabase = create_client(
                self.settings.supabase_url,
                self.settings.supabase_service_key,
            )
            return self._supabase
        except Exception:
            return None
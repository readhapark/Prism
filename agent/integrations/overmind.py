"""Overmind blast-radius / infra-context enrichment.

When Prism finds cloud misconfigs (S3, open admin, etc.), Overmind supplies
live dependency context and recent change risks so remediation advice
includes blast radius — not just 'close the bucket'.

Auth: OVM_API_KEY or OVERMIND_API_KEY
MCP (Cursor): https://api.overmind.tech/api/mcp  (see .cursor/mcp.json)
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from agent.config import get_settings
from agent.models import Finding, Severity


async def list_infra_context() -> dict[str, Any]:
    """Pull connected sources + recent high-level change risks (read-only)."""
    settings = get_settings()
    api_key = settings.overmind_api_key_resolved
    if not api_key:
        return {
            "skipped": True,
            "reason": "OVM_API_KEY / OVERMIND_API_KEY not set",
            "sources": [],
            "changes": [],
        }

    headers = _headers(api_key)
    base = settings.overmind_api_url.rstrip("/")

    async with httpx.AsyncClient(timeout=30.0) as client:
        sources = await _get_json(client, f"{base}/api/sources", headers) or await _get_json(
            client, f"{base}/sources", headers
        )
        changes = await _get_json(client, f"{base}/api/changes", headers) or await _get_json(
            client, f"{base}/changes", headers
        )

    return {
        "sources": _normalize_list(sources, "sources"),
        "changes": _normalize_list(changes, "changes"),
        "api_base": base,
    }


async def enrich_with_blast_radius(
    findings: list[Finding],
    cloud_hints: list[str] | None = None,
) -> dict[str, Any]:
    """Attach Overmind infra context to cloud-related findings.

    Does not mutate cloud — read-only inventory + recent risk summaries.
    """
    ctx = await list_infra_context()
    if ctx.get("skipped"):
        return ctx

    relevant = [
        f
        for f in findings
        if f.category in {"cloud_storage", "ops_exposure", "backup_exposure", "admin_exposure"}
        or "s3" in f.title.lower()
        or "bucket" in f.title.lower()
    ]
    hints = cloud_hints or []

    narrative_bits: list[str] = []
    sources = ctx.get("sources") or []
    changes = ctx.get("changes") or []

    healthy = [s for s in sources if str(s.get("status", "")).lower() in {"healthy", "ok", "connected", ""}]
    narrative_bits.append(
        f"Overmind sources: {len(sources)} connected ({len(healthy)} reporting healthy)."
    )
    if changes:
        top = changes[0]
        title = top.get("title") or top.get("name") or top.get("uuid") or "recent change"
        risks = top.get("risk_counts") or top.get("risks") or {}
        narrative_bits.append(f"Latest change context: {title} — risks={risks}")

    enrichment_findings: list[Finding] = []
    if relevant or any("s3" in h.lower() or "aws" in h.lower() for h in hints):
        enrichment_findings.append(
            Finding(
                title="Overmind: blast-radius context available for cloud findings",
                severity=Severity.INFO,
                category="blast_radius",
                asset="overmind",
                evidence="; ".join(narrative_bits) + (
                    f" | Related Prism findings: {len(relevant)}"
                ),
                remediation=(
                    "Before remediating cloud exposures, review Overmind blast radius for "
                    "dependent compute/network/IAM. Use Overmind MCP "
                    "(`list_sources`, `list_changes`, `get_change_risks`) or "
                    "`overmind changes submit-plan` for Terraform fixes."
                ),
                references=[
                    "https://docs.overmind.tech/integrations/mcp",
                    "https://docs.overmind.tech/creating-changes/blast-radius",
                ],
                confidence=0.8,
            )
        )

    # Surface unhealthy sources as operational risk
    for src in sources:
        status = str(src.get("status", "")).lower()
        if status in {"unhealthy", "error", "disconnected", "stale"}:
            enrichment_findings.append(
                Finding(
                    title=f"Overmind source unhealthy: {src.get('name') or src.get('id')}",
                    severity=Severity.MEDIUM,
                    category="blast_radius",
                    asset=str(src.get("id") or "overmind-source"),
                    evidence=json.dumps({k: src.get(k) for k in ("name", "type", "status", "heartbeat") if k in src})[:300],
                    remediation="Restore the Overmind source heartbeat so blast-radius analysis stays current.",
                    confidence=0.7,
                )
            )

    return {
        "sources": sources,
        "changes": changes[:10],
        "narrative": " ".join(narrative_bits),
        "enrichment_findings": enrichment_findings,
        "related_finding_ids": [f.id for f in relevant],
    }


def _headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "X-Api-Key": api_key,
        "Accept": "application/json",
    }


async def _get_json(client: httpx.AsyncClient, url: str, headers: dict[str, str]) -> Any | None:
    try:
        resp = await client.get(url, headers=headers)
        if resp.status_code >= 400:
            return None
        return resp.json()
    except Exception:
        return None


def _normalize_list(payload: Any, key: str) -> list[dict[str, Any]]:
    if payload is None:
        return []
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        for k in (key, "items", "data", "results"):
            if isinstance(payload.get(k), list):
                return [x for x in payload[k] if isinstance(x, dict)]
    return []
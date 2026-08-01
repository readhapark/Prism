"""Overmind Lab (overmindlab.ai) — agent observability & evals.

This is NOT overmind.tech (infra blast radius). Prism uses the Overmind Lab
Python SDK to trace every scan run: entry point → workflow → tool spans, plus
automatic LLM provider instrumentation when Anthropic/OpenAI keys are set.

Docs: https://docs.overmindlab.ai/core/observability
Console: https://console.overmindlab.ai
Auth: OVERMIND_API_KEY=ovr_...
"""

from __future__ import annotations

from typing import Any

from agent.config import get_settings

_initialized = False


def init_overmind() -> dict[str, Any]:
    """Call once at API startup. Safe no-op without OVERMIND_API_KEY."""
    global _initialized
    settings = get_settings()
    if _initialized:
        return {"ok": True, "already": True}
    if not settings.has_overmind:
        return {
            "ok": False,
            "skipped": True,
            "reason": "OVERMIND_API_KEY not set (expect ovr_… from console.overmindlab.ai)",
        }

    try:
        from overmind import init, set_agent_name

        providers: list[str] = []
        if settings.has_anthropic:
            providers.append("anthropic")
        if settings.has_openai:
            providers.append("openai")

        init(
            overmind_api_key=settings.overmind_api_key_resolved,
            service_name=settings.overmind_service_name,
            environment=settings.overmind_environment,
            providers=providers or None,
            overmind_base_url=settings.overmind_api_url or None,
        )
        set_agent_name(settings.overmind_agent_name)
        _initialized = True
        return {
            "ok": True,
            "service": settings.overmind_service_name,
            "agent": settings.overmind_agent_name,
            "environment": settings.overmind_environment,
            "providers": providers,
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def annotate_run(run_id: str, target: str, mode: str) -> None:
    if not _initialized:
        return
    try:
        from overmind import set_conversation_id, set_tag

        set_conversation_id(run_id)
        set_tag("prism.run_id", run_id)
        set_tag("prism.target", target)
        set_tag("prism.mode", mode)
    except Exception:
        pass


def flush() -> None:
    if not _initialized:
        return
    try:
        from overmind import force_flush_traces

        force_flush_traces()
    except Exception:
        pass


def status() -> dict[str, Any]:
    settings = get_settings()
    return {
        "configured": settings.has_overmind,
        "initialized": _initialized,
        "product": "overmindlab.ai",
        "docs": "https://docs.overmindlab.ai",
        "console": "https://console.overmindlab.ai",
        "agent_name": settings.overmind_agent_name,
        "service_name": settings.overmind_service_name,
    }
from __future__ import annotations

import json
import re
from typing import Any

from agent.config import get_settings
from agent.models import ActionType, PlannedAction, ReconState


SYSTEM_PROMPT = """You are Prism, an autonomous but strictly defensive security recon agent.
You choose the NEXT single read-only check based on current recon state.
Never suggest exploitation, brute force, DoS, or write operations.
Prefer the highest-signal unused action. When enough evidence exists, choose generate_report or stop.
Return ONLY JSON: {"action": "<ActionType>", "rationale": "...", "params": {}, "risk": "passive|active_safe|needs_human"}
Valid actions: dns_enum, port_fingerprint, tech_detect, header_audit, path_probe, tls_check,
cors_check, api_enum, cms_checks, s3_hint_check, git_exposure, robots_sitemap, cookie_audit,
ossprey_scan, overmind_blast, generate_report, stop.
When package.json / npm / pypi deps are visible, prefer ossprey_scan.
Call overmind_blast once per run to confirm Overmind Lab observability is attached.
"""


async def plan_next_action(
    recon: ReconState,
    done_actions: list[str],
    findings_count: int,
    step: int,
    max_steps: int,
) -> PlannedAction:
    settings = get_settings()
    if settings.has_llm:
        planned = await _llm_plan(recon, done_actions, findings_count, step, max_steps)
        if planned:
            return planned
    return _rule_plan(recon, done_actions, findings_count, step, max_steps)


async def _llm_plan(
    recon: ReconState,
    done_actions: list[str],
    findings_count: int,
    step: int,
    max_steps: int,
) -> PlannedAction | None:
    settings = get_settings()
    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=settings.openai_api_key)
        user = {
            "target": recon.target,
            "technologies": recon.technologies,
            "open_ports": recon.open_ports,
            "interesting_paths": recon.interesting_paths[:30],
            "apis": recon.apis,
            "done_actions": done_actions,
            "findings_count": findings_count,
            "step": step,
            "max_steps": max_steps,
            "notes": recon.notes[-8:],
        }
        resp = await client.chat.completions.create(
            model=settings.openai_model,
            temperature=0.2,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(user)},
            ],
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content or "{}"
        data = json.loads(content)
        action = ActionType(data["action"])
        return PlannedAction(
            action=action,
            rationale=data.get("rationale", "LLM selected next step"),
            params=data.get("params") or {},
            risk=data.get("risk", "passive"),
        )
    except Exception:
        return None


def _rule_plan(
    recon: ReconState,
    done_actions: list[str],
    findings_count: int,
    step: int,
    max_steps: int,
) -> PlannedAction:
    """Deterministic autonomy: chain next checks from what recon already revealed."""
    done = set(done_actions)
    tech = {t.lower() for t in recon.technologies}
    paths = " ".join(recon.interesting_paths).lower()

    def unused(action: ActionType) -> bool:
        return action.value not in done

    if step >= max_steps - 1:
        return PlannedAction(
            action=ActionType.GENERATE_REPORT,
            rationale="Step budget nearly exhausted — synthesizing prioritized report.",
        )

    # Classic recon pipeline then adaptive branches
    pipeline: list[tuple[ActionType, str]] = [
        (ActionType.DNS_ENUM, "Map related hostnames before probing services."),
        (ActionType.PORT_FINGERPRINT, "Identify listening services on the scoped host."),
        (ActionType.TECH_DETECT, "Fingerprint stack to choose relevant misconfig checks."),
        (ActionType.HEADER_AUDIT, "Audit security headers and cookie issuance."),
        (ActionType.ROBOTS_SITEMAP, "Harvest robots/sitemap hints for hidden surfaces."),
        (ActionType.PATH_PROBE, "Probe known sensitive paths (read-only GET)."),
    ]
    for action, why in pipeline:
        if unused(action):
            return PlannedAction(action=action, rationale=why)

    # Adaptive chains based on discoveries
    if unused(ActionType.GIT_EXPOSURE) and (".git" in paths or "git" in tech):
        return PlannedAction(
            action=ActionType.GIT_EXPOSURE,
            rationale="Path probe suggested VCS exposure — confirming .git/HEAD (read-only).",
        )

    if unused(ActionType.API_ENUM) and (
        "api" in paths or "juice shop" in tech or "swagger" in paths or "graphql" in paths
    ):
        return PlannedAction(
            action=ActionType.API_ENUM,
            rationale="API-like surfaces discovered — enumerating unauthenticated endpoints.",
        )

    if unused(ActionType.CORS_CHECK):
        return PlannedAction(
            action=ActionType.CORS_CHECK,
            rationale="Validate CORS allowlist behavior with a benign Origin probe.",
        )

    if unused(ActionType.COOKIE_AUDIT) and recon.headers:
        return PlannedAction(
            action=ActionType.COOKIE_AUDIT,
            rationale="Re-check session cookie flags after header capture.",
        )

    if unused(ActionType.S3_HINT_CHECK) and (
        "amazon s3" in tech or "s3" in paths or "amazonaws" in paths
    ):
        return PlannedAction(
            action=ActionType.S3_HINT_CHECK,
            rationale="Cloud storage fingerprints seen — checking for public bucket hints.",
        )

    # Supply-chain: exposed package.json / npm stack → Ossprey
    if unused(ActionType.OSSPREY_SCAN) and (
        "package.json" in paths
        or "juice shop" in tech
        or "npm" in paths
        or any("express" in t.lower() or "node" in t.lower() for t in recon.technologies)
    ):
        return PlannedAction(
            action=ActionType.OSSPREY_SCAN,
            rationale=(
                "Dependency manifest / Node stack visible — handing packages to Ossprey "
                "for supply-chain malware analysis."
            ),
        )

    # Confirm Overmind Lab tracing is attached once we have signal
    if unused(ActionType.OVERMIND_BLAST) and findings_count > 0:
        return PlannedAction(
            action=ActionType.OVERMIND_BLAST,
            rationale=(
                "Attaching / verifying Overmind Lab observability so this run is "
                "available for datasets, evals, and optimisation."
            ),
        )

    if unused(ActionType.CMS_CHECKS) and ("wordpress" in tech or "drupal" in tech):
        return PlannedAction(
            action=ActionType.CMS_CHECKS,
            rationale="CMS detected — run safe plugin/path enumeration (human-gated).",
            risk="needs_human",
        )

    if unused(ActionType.TLS_CHECK) and recon.base_url.startswith("https"):
        return PlannedAction(
            action=ActionType.TLS_CHECK,
            rationale="HTTPS target — capture TLS version/cipher metadata.",
        )

    if findings_count > 0 or step >= 8:
        return PlannedAction(
            action=ActionType.GENERATE_REPORT,
            rationale="Sufficient recon + findings collected — writing prioritized report.",
        )

    return PlannedAction(
        action=ActionType.STOP,
        rationale="No further high-signal passive checks remain.",
    )


def extract_json_object(text: str) -> dict[str, Any] | None:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
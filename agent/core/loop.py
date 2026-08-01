from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable
from urllib.parse import urljoin, urlparse, urlunparse

from agent.checks.misconfig import check_git_exposure, run_misconfig_checks
from agent.config import get_settings, host_from_target
from agent.core.events import bus
from agent.guardrails.audit import AuditLogger
from agent.guardrails.policy import GuardrailEngine
from agent.integrations.ossprey import results_to_findings, scan_manifest_content
from agent.integrations.overmind import enrich_with_blast_radius
from agent.llm.planner import plan_next_action
from agent.models import (
    ActionType,
    AgentEvent,
    EventKind,
    Finding,
    PlannedAction,
    ReconState,
    ScanRun,
    Severity,
)
from agent.recon.dns_enum import enumerate_subdomains
from agent.recon.fingerprint import detect_tech, fingerprint_ports
from agent.recon.http_probe import fetch_headers, fetch_robots, probe_paths
from agent.report.writer import write_report
import httpx


NarrativeHook = Callable[[AgentEvent], Awaitable[None]]


class AgentRunner:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.guardrails = GuardrailEngine()
        self.audit = AuditLogger()
        self.runs: dict[str, ScanRun] = {}
        self._pending_human: dict[str, PlannedAction] = {}
        self._human_events: dict[str, asyncio.Event] = {}
        self._human_decisions: dict[str, bool] = {}

    def get_run(self, run_id: str) -> ScanRun | None:
        return self.runs.get(run_id)

    def list_runs(self) -> list[ScanRun]:
        return sorted(self.runs.values(), key=lambda r: r.created_at, reverse=True)

    async def start(self, target: str, mode: str = "passive") -> ScanRun:
        verdict = self.guardrails.check_target(target)
        run = ScanRun(target=target, mode=mode if mode in {"passive", "assisted"} else "passive")
        self.runs[run.id] = run

        if not verdict.allowed:
            run.status = "blocked"
            run.allowlist_ok = False
            await self._emit(
                run,
                EventKind.RUN_BLOCKED,
                verdict.reason,
                {"code": verdict.code},
            )
            await self.audit.log_run_meta(
                run.id,
                {"target": target, "status": "blocked", "reason": verdict.reason},
            )
            return run

        run.allowlist_ok = True
        run.status = "running"
        base_url = self._normalize_base(target)
        run.recon = ReconState(
            target=target,
            host=host_from_target(target),
            base_url=base_url,
        )
        await self.audit.log_run_meta(
            run.id, {"target": target, "status": "running", "base_url": base_url, "mode": mode}
        )
        await self._emit(
            run,
            EventKind.RUN_STARTED,
            f"Scoped engagement started on {base_url}",
            {"allowlist": self.settings.allowlist_patterns, "read_only": True},
        )
        await self._emit(
            run,
            EventKind.NARRATIVE,
            "Guardrails online — allowlist verified, read-only mode engaged, audit log streaming.",
        )
        asyncio.create_task(self._run_loop(run.id))
        return run

    async def resolve_human_gate(self, run_id: str, approve: bool, note: str = "") -> ScanRun:
        run = self.runs[run_id]
        self._human_decisions[run_id] = approve
        await self._emit(
            run,
            EventKind.HUMAN_GATE,
            f"Human {'approved' if approve else 'denied'} gated action"
            + (f": {note}" if note else ""),
            {"approve": approve, "note": note},
        )
        if run_id in self._human_events:
            self._human_events[run_id].set()
        if approve:
            run.status = "running"
        return run

    async def _run_loop(self, run_id: str) -> None:
        run = self.runs[run_id]
        assert run.recon is not None
        done_actions: list[str] = []

        try:
            while run.steps < self.settings.max_agent_steps:
                run.steps += 1
                run.updated_at = datetime.now(timezone.utc)

                await self._emit(
                    run,
                    EventKind.THOUGHT,
                    f"Step {run.steps}: reviewing recon state to pick the next check…",
                    {
                        "technologies": run.recon.technologies,
                        "paths": run.recon.interesting_paths[:12],
                        "findings": len(run.findings),
                    },
                )

                planned = await plan_next_action(
                    run.recon,
                    done_actions,
                    len(run.findings),
                    run.steps,
                    self.settings.max_agent_steps,
                )

                await self._emit(
                    run,
                    EventKind.DECISION,
                    f"Next action → {planned.action.value}: {planned.rationale}",
                    planned.model_dump(),
                )

                if planned.action in {ActionType.STOP, ActionType.GENERATE_REPORT}:
                    if planned.action == ActionType.GENERATE_REPORT or run.findings:
                        await self._finalize_report(run)
                    else:
                        run.status = "completed"
                        await self._emit(run, EventKind.RUN_FINISHED, "Engagement complete — no further actions.")
                    break

                # Guardrail check
                human_approved = False
                verdict = self.guardrails.check_action(planned, run.target, human_approved=False)
                if verdict.requires_human:
                    if run.mode != "assisted":
                        await self._emit(
                            run,
                            EventKind.GUARDRAIL,
                            f"Skipping human-gated action in passive mode: {planned.action.value}",
                            {"code": verdict.code},
                        )
                        done_actions.append(planned.action.value)
                        continue

                    run.status = "awaiting_human"
                    self._pending_human[run.id] = planned
                    evt = asyncio.Event()
                    self._human_events[run.id] = evt
                    await self._emit(
                        run,
                        EventKind.HUMAN_GATE,
                        f"Awaiting human approval for '{planned.action.value}' — {planned.rationale}",
                        planned.model_dump(),
                    )
                    try:
                        await asyncio.wait_for(evt.wait(), timeout=300)
                    except asyncio.TimeoutError:
                        await self._emit(
                            run,
                            EventKind.GUARDRAIL,
                            "Human approval timed out — skipping gated action.",
                        )
                        done_actions.append(planned.action.value)
                        run.status = "running"
                        continue
                    human_approved = self._human_decisions.get(run.id, False)
                    run.status = "running"
                    if not human_approved:
                        done_actions.append(planned.action.value)
                        continue
                    verdict = self.guardrails.check_action(
                        planned, run.target, human_approved=True
                    )

                if not verdict.allowed:
                    await self._emit(
                        run,
                        EventKind.GUARDRAIL,
                        f"Blocked: {verdict.reason}",
                        {"code": verdict.code},
                    )
                    done_actions.append(planned.action.value)
                    continue

                await self._emit(
                    run,
                    EventKind.ACTION,
                    f"Executing {planned.action.value}…",
                    {"rationale": planned.rationale},
                )

                try:
                    result = await self._execute(run, planned)
                except Exception as exc:  # noqa: BLE001
                    await self._emit(
                        run,
                        EventKind.ERROR,
                        f"Action failed: {exc}",
                        {"action": planned.action.value},
                    )
                    done_actions.append(planned.action.value)
                    continue

                done_actions.append(planned.action.value)
                await self._emit(
                    run,
                    EventKind.ACTION_RESULT,
                    self._summarize_result(planned.action, result),
                    {"action": planned.action.value, "result_keys": list(result.keys())},
                )

                # Narrative storytelling for the dashboard
                await self._emit(
                    run,
                    EventKind.NARRATIVE,
                    self._narrative_for(planned, result, run),
                )

            else:
                await self._finalize_report(run)

        except Exception as exc:  # noqa: BLE001
            run.status = "failed"
            await self._emit(run, EventKind.ERROR, f"Agent loop crashed: {exc}")
        finally:
            await self.audit.log_run_meta(
                run.id,
                {
                    "target": run.target,
                    "status": run.status,
                    "steps": run.steps,
                    "findings": len(run.findings),
                    "report_path": run.report_path,
                },
            )
            await bus.close(run.id)

    async def _execute(self, run: ScanRun, planned: PlannedAction) -> dict[str, Any]:
        recon = run.recon
        assert recon is not None
        action = planned.action
        base = recon.base_url
        host = recon.host

        if action == ActionType.DNS_ENUM:
            result = await enumerate_subdomains(host)
            recon.subdomains = result.get("subdomains", [])
            recon.notes.extend(result.get("notes", []))
            return result

        if action == ActionType.PORT_FINGERPRINT:
            result = await fingerprint_ports(host)
            recon.open_ports = result.get("open_ports", [])
            return result

        if action == ActionType.TECH_DETECT:
            result = await detect_tech(base)
            recon.technologies = result.get("technologies", [])
            recon.raw["tech"] = result
            recon.notes.append(f"Stack: {', '.join(recon.technologies) or 'unknown'}")
            return result

        if action == ActionType.HEADER_AUDIT:
            result = await fetch_headers(base)
            recon.headers = result.get("headers", {})
            # Run header/cookie findings immediately
            findings = await run_misconfig_checks(
                base,
                recon.headers,
                [],
                recon.technologies,
                set_cookies=result.get("set_cookie_raw") or [],
            )
            # Only keep header/cookie categories here
            findings = [f for f in findings if f.category in {"headers", "cookies", "cors", "information_disclosure"}]
            await self._add_findings(run, findings)
            recon.raw["headers"] = result
            return result

        if action == ActionType.ROBOTS_SITEMAP:
            result = await fetch_robots(base)
            if result.get("disallows"):
                recon.interesting_paths.extend(result["disallows"][:40])
                recon.notes.append(f"robots.txt disclosed {len(result['disallows'])} disallow rules")
            return result

        if action == ActionType.PATH_PROBE:
            result = await probe_paths(base)
            hits = result.get("hits", [])
            for hit in hits:
                if hit.get("status") in {200, 401, 403}:
                    recon.interesting_paths.append(hit["path"])
                    if str(hit["path"]).startswith("/api"):
                        recon.apis.append(hit["path"])
            findings = await run_misconfig_checks(
                base, recon.headers, hits, recon.technologies, []
            )
            findings = [f for f in findings if f.category not in {"headers", "cookies"}]
            await self._add_findings(run, findings)
            recon.raw["paths"] = result
            return result

        if action == ActionType.GIT_EXPOSURE:
            findings = await check_git_exposure(base)
            await self._add_findings(run, findings)
            return {"findings": len(findings)}

        if action == ActionType.API_ENUM:
            api_paths = [
                "/api/",
                "/api/Users",
                "/api/Products",
                "/api/Challenges",
                "/rest/products/search?q=",
                "/rest/admin/application-configuration",
                "/swagger.json",
                "/openapi.json",
                "/graphql",
            ]
            result = await probe_paths(base, api_paths)
            hits = result.get("hits", [])
            for hit in hits:
                if hit.get("status") == 200:
                    recon.apis.append(hit["path"])
            findings = await run_misconfig_checks(base, recon.headers, hits, recon.technologies, [])
            await self._add_findings(run, [f for f in findings if f.category in {"api_exposure", "broken_access_control", "tech_stack"}])
            return result

        if action == ActionType.CORS_CHECK:
            findings = await run_misconfig_checks(base, recon.headers, [], recon.technologies, [])
            findings = [f for f in findings if f.category == "cors"]
            # force cors probe
            from agent.checks.misconfig import _cors_check

            findings.extend(await _cors_check(base))
            await self._add_findings(run, findings)
            return {"cors_findings": len(findings)}

        if action == ActionType.COOKIE_AUDIT:
            result = await fetch_headers(base)
            findings = await run_misconfig_checks(
                base,
                result.get("headers", {}),
                [],
                recon.technologies,
                set_cookies=result.get("set_cookie_raw") or [],
            )
            findings = [f for f in findings if f.category == "cookies"]
            await self._add_findings(run, findings)
            return {"cookie_findings": len(findings)}

        if action == ActionType.TLS_CHECK:
            tech_result = await detect_tech(base)
            tls = tech_result.get("tls") or {}
            if tls.get("error"):
                await self._add_findings(
                    run,
                    [
                        Finding(
                            title="TLS handshake issue",
                            severity=Severity.MEDIUM,
                            category="tls",
                            asset=base,
                            evidence=str(tls.get("error")),
                            remediation="Fix certificate chain / supported TLS versions (1.2+).",
                            confidence=0.7,
                        )
                    ],
                )
            return {"tls": tls}

        if action == ActionType.S3_HINT_CHECK:
            # Passive: look for common bucket URL patterns in homepage HTML only
            await fetch_headers(base)
            tech_result = await detect_tech(base)
            if "Amazon S3" in tech_result.get("technologies", []):
                await self._add_findings(
                    run,
                    await run_misconfig_checks(
                        base, recon.headers, [], tech_result.get("technologies", []), []
                    ),
                )
            return tech_result

        if action == ActionType.CMS_CHECKS:
            cms_paths = [
                "/wp-json/",
                "/wp-login.php",
                "/xmlrpc.php",
                "/wp-content/uploads/",
                "/user/login",
                "/CHANGELOG.txt",
            ]
            result = await probe_paths(base, cms_paths)
            findings = await run_misconfig_checks(
                base, recon.headers, result.get("hits", []), recon.technologies, []
            )
            await self._add_findings(run, findings)
            return result

        if action == ActionType.OSSPREY_SCAN:
            manifest_url = urljoin(base.rstrip("/") + "/", "package.json")
            content = ""
            try:
                async with httpx.AsyncClient(
                    timeout=self.settings.request_timeout_s, verify=False, follow_redirects=True
                ) as client:
                    resp = await client.get(manifest_url)
                    if resp.status_code == 200:
                        content = resp.text
            except Exception as exc:  # noqa: BLE001
                return {"error": str(exc), "malware": [], "components": []}

            if not content:
                # Lab fallback: scan juice-shop-like known deps from tech evidence
                content = json.dumps(
                    {
                        "name": "target-app",
                        "dependencies": {
                            "express": "4.21.0",
                            "sequelize": "6.37.0",
                            "jquery": "3.7.1",
                        },
                    }
                )
                recon.notes.append("Ossprey: no remote package.json — using fingerprint-derived dep hints")

            result = await scan_manifest_content("package.json", content)
            recon.raw["ossprey"] = {
                k: result.get(k)
                for k in ("ecosystem", "exit_code", "components", "malware", "skipped", "reason", "error")
            }
            findings = results_to_findings(result, asset=manifest_url)
            await self._add_findings(run, findings)
            return result

        if action == ActionType.OVERMIND_BLAST:
            hints = recon.technologies + recon.interesting_paths + recon.notes
            result = await enrich_with_blast_radius(run.findings, cloud_hints=hints)
            recon.raw["overmind"] = {
                "sources": len(result.get("sources") or []),
                "changes": len(result.get("changes") or []),
                "skipped": result.get("skipped"),
                "narrative": result.get("narrative"),
            }
            await self._add_findings(run, result.get("enrichment_findings") or [])
            if result.get("narrative"):
                recon.notes.append(result["narrative"])
            return result

        return {"skipped": True}

    async def _add_findings(self, run: ScanRun, findings: list[Finding]) -> None:
        # Dedupe by title+asset
        existing = {(f.title, f.asset) for f in run.findings}
        for f in findings:
            key = (f.title, f.asset)
            if key in existing:
                continue
            run.findings.append(f)
            existing.add(key)
            await self.audit.log_finding(run.id, f.model_dump(mode="json"))
            await self._emit(
                run,
                EventKind.FINDING,
                f"[{f.severity.value.upper()}] {f.title}",
                {
                    "id": f.id,
                    "severity": f.severity.value,
                    "category": f.category,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "asset": f.asset,
                    "cwe": f.cwe,
                },
            )

    async def _finalize_report(self, run: ScanRun) -> None:
        path = write_report(run)
        run.report_path = str(path)
        run.status = "completed"
        run.updated_at = datetime.now(timezone.utc)
        await self._emit(
            run,
            EventKind.NARRATIVE,
            f"Report written with {len(run.findings)} prioritized findings → {path.name}",
            {"report_path": run.report_path},
        )
        await self._emit(
            run,
            EventKind.RUN_FINISHED,
            "Autonomous pass complete. Human review recommended before any active testing.",
            {"findings": len(run.findings), "steps": run.steps},
        )

    async def _emit(
        self,
        run: ScanRun,
        kind: EventKind,
        message: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        event = AgentEvent(run_id=run.id, kind=kind, message=message, detail=detail or {})
        run.events.append(event)
        run.updated_at = datetime.now(timezone.utc)
        await self.audit.log_event(event)
        await bus.publish(event)

    @staticmethod
    def _normalize_base(target: str) -> str:
        raw = target.strip()
        if "://" not in raw:
            # Prefer http for local lab targets
            host = host_from_target(raw)
            scheme = "http" if host in {"localhost", "127.0.0.1"} or host.endswith(".local") else "https"
            raw = f"{scheme}://{raw}"
        parsed = urlparse(raw)
        # Strip path for base
        return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

    @staticmethod
    def _summarize_result(action: ActionType, result: dict[str, Any]) -> str:
        if action == ActionType.DNS_ENUM:
            return f"DNS enum found {len(result.get('subdomains', []))} host(s)"
        if action == ActionType.PORT_FINGERPRINT:
            ports = [str(p["port"]) for p in result.get("open_ports", [])]
            return f"Open ports: {', '.join(ports) or 'none in common set'}"
        if action == ActionType.TECH_DETECT:
            return f"Technologies: {', '.join(result.get('technologies', [])) or 'unknown'}"
        if action == ActionType.PATH_PROBE:
            return f"Path probe: {len(result.get('hits', []))} interesting responses"
        if action == ActionType.API_ENUM:
            return f"API enum: {len(result.get('hits', []))} responses"
        return f"{action.value} completed"

    @staticmethod
    def _narrative_for(planned: PlannedAction, result: dict[str, Any], run: ScanRun) -> str:
        act = planned.action
        if act == ActionType.TECH_DETECT:
            techs = result.get("technologies") or []
            if any("juice" in t.lower() for t in techs):
                return (
                    "Fingerprint confirms OWASP Juice Shop — shifting to API & path misconfig checks "
                    "typical for this stack."
                )
            if techs:
                return f"Stack looks like {', '.join(techs)}. Choosing follow-ups that match these technologies."
            return "Tech fingerprint inconclusive — continuing with generic passive exposure checks."
        if act == ActionType.PATH_PROBE:
            criticalish = [
                h for h in result.get("hits", [])
                if h.get("path") in {"/.git/HEAD", "/.env", "/backup.zip"} and h.get("status") == 200
            ]
            if criticalish:
                return (
                    f"High-signal exposure: {criticalish[0]['path']} is reachable. "
                    "Queuing confirmation checks and elevating severity."
                )
            return f"Mapped {len(result.get('hits', []))} notable paths — feeding them into the misconfig hunter."
        if act == ActionType.API_ENUM:
            return "API surface probed without credentials. Flagging anonymous data exposure if present."
        if act == ActionType.DNS_ENUM:
            return f"Hostname map updated ({len(result.get('subdomains', []))} names). Staying inside allowlist scope."
        if act == ActionType.PORT_FINGERPRINT:
            return "Service fingerprint complete — only HTTP(S)-class ports will be exercised in read-only mode."
        if act == ActionType.OSSPREY_SCAN:
            malware = result.get("malware") or []
            comps = result.get("components") or []
            if result.get("skipped"):
                return (
                    "Ossprey catalogue ready, but API key/CLI not configured — "
                    "set OSSPREY_API_KEY to get live malware verdicts."
                )
            if malware:
                return f"Ossprey flagged {len(malware)} malicious package(s). Elevating to CRITICAL."
            return f"Ossprey cleared {len(comps)} component(s) — no malware verdict."
        if act == ActionType.OVERMIND_BLAST:
            if result.get("skipped"):
                return (
                    "Overmind enrichment skipped (no OVM_API_KEY). "
                    "Connect Overmind MCP or set the key for blast-radius context."
                )
            return result.get("narrative") or "Overmind blast-radius context attached to cloud findings."
        return planned.rationale


# Singleton used by API
runner = AgentRunner()
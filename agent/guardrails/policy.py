from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from agent.config import get_settings, host_from_target, is_allowlisted
from agent.models import ActionType, PlannedAction


# Patterns that look like exploitation — blocked always
EXPLOIT_MARKERS = (
    "../",
    "..\\",
    "<script",
    "union select",
    "' or ",
    '" or ',
    "${jndi",
    "{{",
    "`",
    "$(",
    "; rm ",
    "| bash",
    "cmd.exe",
    "/etc/passwd",
    "wp-login.php?action=register",
)

# Actions that never run automatically — human must approve
HUMAN_GATED = {
    ActionType.CMS_CHECKS,  # may hit many plugin endpoints
}


@dataclass
class GuardrailVerdict:
    allowed: bool
    reason: str
    requires_human: bool = False
    code: str = "ok"


class GuardrailEngine:
    """Hard safety rails: allowlist, read-only, no exploit payloads, audit every gate."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def check_target(self, target: str) -> GuardrailVerdict:
        host = host_from_target(target)
        if not host:
            return GuardrailVerdict(False, "Could not parse target host", code="bad_target")
        if not is_allowlisted(target):
            return GuardrailVerdict(
                False,
                f"Target '{host}' is not on the allowlist. "
                f"Allowed patterns: {', '.join(self.settings.allowlist_patterns)}",
                code="not_allowlisted",
            )
        # Block obvious public internet unless explicitly allowlisted pattern
        if self._looks_like_production_forbidden(host):
            return GuardrailVerdict(
                False,
                f"Refusing scan of '{host}' — only sandbox / allowlisted lab targets.",
                code="production_block",
            )
        return GuardrailVerdict(True, f"Allowlisted host: {host}")

    def check_action(
        self,
        action: PlannedAction,
        target: str,
        human_approved: bool = False,
    ) -> GuardrailVerdict:
        target_v = self.check_target(target)
        if not target_v.allowed:
            return target_v

        if action.risk == "needs_human" or action.action in HUMAN_GATED:
            if not human_approved:
                return GuardrailVerdict(
                    False,
                    f"Action '{action.action.value}' requires human approval "
                    "(beyond passive reconnaissance).",
                    requires_human=True,
                    code="human_gate",
                )

        # Never allow write methods / exploit-looking params
        for key, val in action.params.items():
            blob = f"{key}={val}".lower()
            for marker in EXPLOIT_MARKERS:
                if marker in blob:
                    return GuardrailVerdict(
                        False,
                        f"Blocked suspected exploit content in params: {marker!r}",
                        code="exploit_block",
                    )

        if self.settings.read_only and action.params.get("method", "GET").upper() not in {
            "GET",
            "HEAD",
            "OPTIONS",
        }:
            return GuardrailVerdict(
                False,
                "Read-only mode: only GET/HEAD/OPTIONS are permitted",
                code="read_only",
            )

        return GuardrailVerdict(True, f"Action '{action.action.value}' permitted")

    def sanitize_url(self, url: str, allowed_host: str) -> str | None:
        """Ensure a derived URL stays on the same allowlisted host."""
        try:
            if "://" not in url:
                url = f"http://{url}"
            p = urlparse(url)
            host = (p.hostname or "").lower()
            if host != allowed_host.lower() and not is_allowlisted(url):
                return None
            if p.scheme not in {"http", "https"}:
                return None
            return url
        except Exception:
            return None

    def audit_payload(
        self,
        run_id: str,
        kind: str,
        message: str,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "run_id": run_id,
            "kind": kind,
            "message": message,
            "detail": detail or {},
            "read_only": self.settings.read_only,
            "allowlist": self.settings.allowlist_patterns,
        }

    @staticmethod
    def _looks_like_production_forbidden(host: str) -> bool:
        # Extra soft block for common production TLDs when not matching sandbox patterns.
        # Allowlist still wins — this only catches empty/misconfigured allowlists.
        if host in {"localhost", "127.0.0.1", "0.0.0.0", "juice-shop.local"}:
            return False
        sandbox_markers = (
            ".modal.run",
            ".modal.host",
            ".trycloudflare.com",
            ".ngrok.io",
            ".ngrok-free.app",
            ".loca.lt",
            "juice-shop",
            "dvwa",
            "localtest.me",
        )
        return not any(m in host for m in sandbox_markers) and not is_allowlisted(host)
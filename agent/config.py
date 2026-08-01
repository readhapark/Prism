from __future__ import annotations

import fnmatch
import os
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from pydantic_settings import BaseSettings, SettingsConfigDict


ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIR = ROOT / "data" / "audit"
REPORTS_DIR = ROOT / "data" / "reports"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    allowlist: str = (
        "localhost,127.0.0.1,juice-shop.local,"
        "*.modal.run,*.modal.host,*.trycloudflare.com"
    )
    # LLM planner — Claude preferred; OpenAI optional fallback
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-5"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    llm_provider: str = "auto"  # auto | anthropic | openai | none
    supabase_url: str = ""
    supabase_service_key: str = ""
    # Ossprey — supply-chain malware
    ossprey_api_key: str = ""
    ossprey_api_url: str = "https://api.ossprey.com"
    # Overmind Lab (overmindlab.ai) — agent observability / evals
    # API key from https://console.overmindlab.ai (ovr_…)
    overmind_api_key: str = ""
    overmind_api_url: str = "https://api.overmindlab.ai"
    overmind_service_name: str = "prism"
    overmind_agent_name: str = "Prism Attack Surface Mapper"
    overmind_environment: str = "hackathon"
    agent_host: str = "0.0.0.0"
    agent_port: int = 8787
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    sandbox_url: str = "http://127.0.0.1:3001"
    max_agent_steps: int = 18
    request_timeout_s: float = 12.0
    # Hard safety: never send exploit payloads / write actions
    read_only: bool = True

    @property
    def allowlist_patterns(self) -> list[str]:
        return [p.strip().lower() for p in self.allowlist.split(",") if p.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def llm_backend(self) -> str | None:
        pref = (self.llm_provider or "auto").lower()
        if pref == "none":
            return None
        if pref == "anthropic" and self.anthropic_api_key:
            return "anthropic"
        if pref == "openai" and self.openai_api_key:
            return "openai"
        if pref == "auto":
            if self.anthropic_api_key:
                return "anthropic"
            if self.openai_api_key:
                return "openai"
        return None

    @property
    def has_llm(self) -> bool:
        return self.llm_backend is not None

    @property
    def has_anthropic(self) -> bool:
        return bool(self.anthropic_api_key)

    @property
    def has_openai(self) -> bool:
        return bool(self.openai_api_key)

    @property
    def has_supabase(self) -> bool:
        return bool(self.supabase_url and self.supabase_service_key)

    @property
    def has_ossprey(self) -> bool:
        return bool(self.ossprey_api_key)

    @property
    def overmind_api_key_resolved(self) -> str:
        return self.overmind_api_key

    @property
    def has_overmind(self) -> bool:
        return bool(self.overmind_api_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()


def host_from_target(target: str) -> str:
    raw = target.strip()
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    return host


def is_allowlisted(target: str, patterns: list[str] | None = None) -> bool:
    host = host_from_target(target)
    if not host:
        return False
    pats = patterns or get_settings().allowlist_patterns
    for pat in pats:
        if pat.startswith("*."):
            suffix = pat[1:]  # .example.com
            if host.endswith(suffix) or host == pat[2:]:
                return True
        elif fnmatch.fnmatch(host, pat) or host == pat:
            return True
    return False


def ensure_data_dirs() -> None:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("PRISM_DATA", str(ROOT / "data"))
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventKind(str, Enum):
    RUN_STARTED = "run_started"
    RUN_FINISHED = "run_finished"
    RUN_BLOCKED = "run_blocked"
    THOUGHT = "thought"
    DECISION = "decision"
    ACTION = "action"
    ACTION_RESULT = "action_result"
    FINDING = "finding"
    GUARDRAIL = "guardrail"
    HUMAN_GATE = "human_gate"
    ERROR = "error"
    NARRATIVE = "narrative"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    severity: Severity
    category: str
    evidence: str
    remediation: str
    asset: str = ""
    cwe: str | None = None
    references: list[str] = Field(default_factory=list)
    confidence: float = 0.8
    timestamp: datetime = Field(default_factory=utcnow)


class AgentEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    kind: EventKind
    message: str
    detail: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utcnow)


class ActionType(str, Enum):
    DNS_ENUM = "dns_enum"
    PORT_FINGERPRINT = "port_fingerprint"
    TECH_DETECT = "tech_detect"
    HEADER_AUDIT = "header_audit"
    PATH_PROBE = "path_probe"
    TLS_CHECK = "tls_check"
    CORS_CHECK = "cors_check"
    API_ENUM = "api_enum"
    CMS_CHECKS = "cms_checks"
    S3_HINT_CHECK = "s3_hint_check"
    GIT_EXPOSURE = "git_exposure"
    ROBOTS_SITEMAP = "robots_sitemap"
    COOKIE_AUDIT = "cookie_audit"
    OSSPREY_SCAN = "ossprey_scan"
    OVERMIND_BLAST = "overmind_blast"
    GENERATE_REPORT = "generate_report"
    STOP = "stop"


class PlannedAction(BaseModel):
    action: ActionType
    rationale: str
    params: dict[str, Any] = Field(default_factory=dict)
    risk: Literal["passive", "active_safe", "needs_human"] = "passive"


class ReconState(BaseModel):
    target: str
    host: str
    base_url: str
    open_ports: list[dict[str, Any]] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    subdomains: list[str] = Field(default_factory=list)
    interesting_paths: list[str] = Field(default_factory=list)
    apis: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class ScanRun(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    target: str
    status: Literal[
        "queued", "running", "awaiting_human", "completed", "blocked", "failed"
    ] = "queued"
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    steps: int = 0
    findings: list[Finding] = Field(default_factory=list)
    events: list[AgentEvent] = Field(default_factory=list)
    recon: ReconState | None = None
    report_path: str | None = None
    allowlist_ok: bool = False
    mode: Literal["passive", "assisted"] = "passive"


class StartScanRequest(BaseModel):
    target: str
    mode: Literal["passive", "assisted"] = "passive"
    notes: str = ""


class HumanDecisionRequest(BaseModel):
    approve: bool
    note: str = ""
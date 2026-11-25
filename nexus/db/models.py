"""Pydantic data models for NEXUS engagements, findings, and attack chains."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _now() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EngagementPhase(StrEnum):
    INIT = "init"
    RECON = "recon"
    SCAN = "scan"
    CORRELATE = "correlate"
    EXPLOIT = "exploit"
    REPORT = "report"
    COMPLETE = "complete"


class Engagement(BaseModel):
    id: str = Field(default_factory=_new_id)
    name: str = ""
    target: str = ""
    scope_file: str = ""
    phase: EngagementPhase = EngagementPhase.INIT
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)
    stealth: str = "medium"
    tier: str = "minimal"
    notes: str = ""


class Target(BaseModel):
    id: str = Field(default_factory=_new_id)
    engagement_id: str = ""
    host: str = ""
    ip: str = ""
    is_live: bool = False
    os_guess: str = ""
    tech_stack: list[str] = Field(default_factory=list)
    waf_detected: str = ""


class Port(BaseModel):
    id: str = Field(default_factory=_new_id)
    target_id: str = ""
    port: int = Field(default=0, ge=0, le=65535)
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""


class Finding(BaseModel):
    id: str = Field(default_factory=_new_id)
    engagement_id: str = ""
    host: str = ""
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cve_ids: list[str] = Field(default_factory=list)
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    cwe_id: str = ""
    owasp_category: str = ""
    tool_source: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
    remediation: str = ""
    false_positive: bool = False
    confirmed: bool = False
    discovered_at: datetime = Field(default_factory=_now)


class Credential(BaseModel):
    id: str = Field(default_factory=_new_id)
    engagement_id: str = ""
    host: str = ""
    port: int = Field(default=0, ge=0, le=65535)
    service: str = ""
    username: str = ""
    password: str = Field(default="", exclude=True, repr=False)
    hash_value: str = Field(default="", exclude=True, repr=False)
    source: str = ""  # how it was obtained
    confirmed: bool = False


class ChainStep(BaseModel):
    order: int = 0
    action: str = ""
    tool: str = ""
    target: str = ""
    finding_id: str = ""
    result: str = ""
    confirmed: bool = False


class AttackChain(BaseModel):
    id: str = Field(default_factory=_new_id)
    engagement_id: str = ""
    name: str = ""
    description: str = ""
    steps: list[ChainStep] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)  # 0.0 (low) to 1.0 (high)
    impact: Severity = Severity.INFO
    confirmed: bool = False
    poc_script: str = ""


class Evidence(BaseModel):
    id: str = Field(default_factory=_new_id)
    finding_id: str = ""
    evidence_type: str = ""  # screenshot, request_response, poc_code, file
    content: str = ""
    file_path: str = ""


class ReportMeta(BaseModel):
    engagement_id: str = ""
    title: str = ""
    author: str = "NEXUS Automated Report"
    client: str = ""
    date: datetime = Field(default_factory=_now)
    format: str = "pdf"
    template: str = "default"
    output_path: str = ""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    chains_found: int = 0

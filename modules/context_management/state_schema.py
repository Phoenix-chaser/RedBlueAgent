"""
Central Pydantic state models shared across all modules.
Every module reads/writes these types — build first.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class PentestStage(str, Enum):
    TARGET_CONFIRMATION = "target_confirmation"
    INFORMATION_GATHERING = "information_gathering"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    VULNERABILITY_EXPLOITATION = "vulnerability_exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORT_GENERATION = "report_generation"
    FINISHED = "finished"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackNodeStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# Service / Host Discovery
# ---------------------------------------------------------------------------

class ServiceInfo(BaseModel):
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    version: str | None = None
    banner: str | None = None
    state: str = "open"

    class Config:
        frozen = False


class HostInfo(BaseModel):
    ip: str
    hostname: str | None = None
    os: str | None = None
    os_confidence: int | None = None
    services: list[ServiceInfo] = Field(default_factory=list)
    is_alive: bool = True


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------

class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    cve_id: str | None = None
    severity: Severity = Severity.MEDIUM
    affected_component: str
    description: str
    evidence: str = ""
    exploited: bool = False
    remediation: str | None = None
    discovered_by_tool: str = "unknown"
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Attack Path Tracking
# ---------------------------------------------------------------------------

class AttackPathEntry(BaseModel):
    step: int
    stage: str
    tool: str
    command: str
    outcome: str
    success: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# LLM Turn History
# ---------------------------------------------------------------------------

class LLMTurn(BaseModel):
    iteration: int
    thought: str
    action_type: str
    action_tool: str | None = None
    action_params: dict[str, Any] = Field(default_factory=dict)
    observation: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Core Pentest Session State
# ---------------------------------------------------------------------------

class PentestState(BaseModel):
    session_id: str = Field(default_factory=lambda: str(uuid4()))
    target: str
    scope: list[str] = Field(default_factory=list)
    current_stage: PentestStage = PentestStage.TARGET_CONFIRMATION

    # Discovered data
    hosts: list[HostInfo] = Field(default_factory=list)
    web_paths: list[str] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    credentials: list[dict[str, str]] = Field(default_factory=list)

    # Process tracking
    attack_paths: list[AttackPathEntry] = Field(default_factory=list)
    llm_turns: list[LLMTurn] = Field(default_factory=list)
    summary_chunks: list[str] = Field(default_factory=list)

    # Statistics
    total_iterations: int = 0
    started_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None

    # Stage completion tracking
    stages_completed: list[str] = Field(default_factory=list)

    def get_open_services(self) -> list[ServiceInfo]:
        """Flatten all open services across all discovered hosts."""
        services = []
        for host in self.hosts:
            services.extend(host.services)
        return services

    def get_services_by_type(self, service_name: str) -> list[ServiceInfo]:
        return [s for s in self.get_open_services() if service_name.lower() in s.service.lower()]

    @staticmethod
    def _norm_component(c: str) -> str:
        """Lowercase + strip trailing slash for component comparison."""
        return c.lower().rstrip("/")

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        # Deduplicate by title + normalized component (case-insensitive, prefix match).
        # Prefix matching handles cases like nikto's "/admin" vs dirsearch's "/admin/login.php".
        # If the existing entry was attributed to nikto but a more specific tool now
        # claims the same finding, update attribution to credit the right tool.
        norm_new = self._norm_component(vuln.affected_component)
        for existing in self.vulnerabilities:
            if existing.title.lower() != vuln.title.lower():
                continue
            norm_old = self._norm_component(existing.affected_component)
            # Match if equal, or one component is a path prefix of the other
            if norm_old == norm_new or norm_old.startswith(norm_new) or norm_new.startswith(norm_old):
                if existing.discovered_by_tool == "nikto" and vuln.discovered_by_tool != "nikto":
                    existing.discovered_by_tool = vuln.discovered_by_tool
                    existing.evidence = vuln.evidence
                return
        self.vulnerabilities.append(vuln)

    def touch(self) -> None:
        self.updated_at = datetime.utcnow()


# ---------------------------------------------------------------------------
# Tool Result Models
# ---------------------------------------------------------------------------

class ToolResult(BaseModel):
    tool: str
    command: str
    raw_stdout: str = ""
    raw_stderr: str = ""
    parsed: dict[str, Any] = Field(default_factory=dict)
    success: bool = True
    elapsed_seconds: float = 0.0
    error_message: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Action Decision (LLM output)
# ---------------------------------------------------------------------------

class ActionDecision(BaseModel):
    type: Literal["tool", "finish", "wait"] = "tool"
    tool: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""


# ---------------------------------------------------------------------------
# Report Models
# ---------------------------------------------------------------------------

class ScanMetrics(BaseModel):
    total_vulns_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    exploited_count: int = 0
    total_scan_time_seconds: float = 0.0
    stages_completed: int = 0
    total_iterations: int = 0


class PentestReport(BaseModel):
    session_id: str
    target: str
    executive_summary: str
    vulnerabilities: list[Vulnerability]
    attack_paths: list[AttackPathEntry]
    metrics: ScanMetrics
    recommendations: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)

"""Data models shared by checks, the gate and the report."""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    NOT_RUN = "NOT_RUN"  # counts as FAIL in the gate: a scan that didn't run is never a pass


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def norm_severity(raw: str | None) -> str:
    s = (raw or "").strip().lower()
    return {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "inventory": "info",
        "experiment": "info",
    }.get(s, s if s in SEVERITY_ORDER else "medium")


class Finding(BaseModel):
    tool: str
    category: str  # "code" | "library" | "package" | "test" | "performance"
    rule_id: str = ""
    severity: str = "medium"
    title: str = ""
    message: str = ""
    file: str = ""
    line: int = 0
    cwe: list[str] = Field(default_factory=list)
    fix_hint: str = ""
    # library fields
    package: str = ""
    version: str = ""
    fixed_in: list[str] = Field(default_factory=list)
    identifiers: list[str] = Field(default_factory=list)
    url: str = ""
    sources: list[str] = Field(default_factory=list)  # every tool that reported this location


class SecretFinding(BaseModel):
    scanner: str
    rule_id: str = ""
    kind: str = ""
    file: str = ""
    line: int = 0
    masked_value: str = ""
    message: str = ""
    sources: list[str] = Field(default_factory=list)


class CommandRecord(BaseModel):
    name: str
    argv: list[str]
    cwd: str = ""
    started_at: float = 0.0
    exit_code: Optional[int]
    duration_s: float
    stdout_path: str = ""
    stderr_path: str = ""
    timed_out: bool = False
    error: str = ""


class SubCheck(BaseModel):
    """One line of the go-live checklist."""

    id: str
    label: str
    status: Status
    detail: str = ""


class CheckResult(BaseModel):
    name: str  # security | functional | performance
    status: Status = Status.NOT_RUN
    summary: str = ""
    reason_not_run: str = ""
    findings: list[Finding] = Field(default_factory=list)
    secrets: list[SecretFinding] = Field(default_factory=list)
    subchecks: list[SubCheck] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    commands: list[CommandRecord] = Field(default_factory=list)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None


class RunOptions(BaseModel):
    project_path: str
    target_url: Optional[str] = None
    mode: str = "quick"  # quick | gate
    peak_users: int = 100
    response_time_p95_ms: int = 1000
    checks: list[str] = Field(default_factory=lambda: ["security", "functional", "performance"])
    locustfile: Optional[str] = None
    coverage_threshold: float = 70.0
    stop_on_security_fail: bool = False
    spawn_rate: int = 10
    duration: Optional[str] = None  # override, e.g. "5m"
    open_report: bool = True  # open the finished report in the default browser


class RunState(BaseModel):
    run_id: str
    options: RunOptions
    state: str = "queued"  # queued | running | done | error
    current: str = ""
    progress: dict[str, str] = Field(default_factory=dict)  # check -> queued|running|done|skipped
    messages: list[str] = Field(default_factory=list)
    results: dict[str, CheckResult] = Field(default_factory=dict)
    verdict: Optional[str] = None
    report_path: Optional[str] = None
    pdf_path: Optional[str] = None  # PDF copy beside the report, when a Chromium browser was found
    report_opened: Optional[bool] = None  # None = not attempted
    journal: list[dict] = Field(default_factory=list)  # every step and command, in order
    ai_summary: Optional[dict] = None
    summary_path: Optional[str] = None
    error: Optional[str] = None
    created_at: float = 0.0
    finished_at: Optional[float] = None
    tool_versions: dict[str, str] = Field(default_factory=dict)
    code_version: dict = Field(default_factory=dict)  # git commit/branch/uncommitted changes (vcs.snapshot)

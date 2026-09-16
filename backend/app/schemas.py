from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class PolicyHeaderIn(BaseModel):
    header_name: str = Field(..., min_length=1, max_length=200)
    expected_value: str = Field(default="", max_length=8000)
    required: bool = True


class PolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    headers: list[PolicyHeaderIn] = Field(default_factory=list)


class PolicyUpdate(PolicyCreate):
    pass


class PolicyOut(BaseModel):
    id: str
    name: str
    description: str
    headers: list[PolicyHeaderIn]
    is_baseline: bool
    baseline_key: str | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


class ScanSource(str, Enum):
    url = "url"
    raw = "raw"


class ScanRequest(BaseModel):
    source: ScanSource
    url: str | None = None
    raw_response: str | None = None
    policy_id: str | None = None
    policy: PolicyCreate | None = None


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    INFO = "INFO"


class CheckResult(BaseModel):
    name: str
    description: str
    status: Status
    expected: str | None = None
    actual: str | None = None


class HeaderFinding(BaseModel):
    header: str
    required: bool
    present: bool
    status: Status
    severity: Literal["low", "medium", "high", "critical", "info"]
    weight: float
    score_earned: float
    score_possible: float
    policy_expected: str | None
    actual_value: str | None
    checks: list[CheckResult] = Field(default_factory=list)
    recommendation: str | None = None


class CSPFinding(BaseModel):
    present: bool
    actual_value: str | None
    policy_checks: list[CheckResult] = Field(default_factory=list)
    security_checks: list[CheckResult] = Field(default_factory=list)
    directives: dict[str, list[str]] = Field(default_factory=dict)


class ScanResult(BaseModel):
    id: str
    source: ScanSource
    target: str | None
    fetched_status_code: int | None = None
    policy_name: str
    score: float
    max_score: float
    grade: str
    findings: list[HeaderFinding]
    csp_finding: CSPFinding | None = None
    raw_headers: dict[str, str]
    scanned_at: datetime


# ---------------------------------------------------------------------------
# AI Explanation (deterministic engine decides PASS/FAIL - AI only explains)
# ---------------------------------------------------------------------------


class ExplainCheckIn(BaseModel):
    name: str
    description: str
    status: Status
    expected: str | None = None
    actual: str | None = None


class ExplainRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    policy_expected: str | None = None
    actual_value: str | None = None
    checks: list[ExplainCheckIn] = Field(default_factory=list, max_length=50)


class RecommendationItem(BaseModel):
    check: str
    fix: str


class ExplainResponse(BaseModel):
    what_it_does: str
    why_it_matters: str
    recommendations: list[RecommendationItem]
    tradeoffs: str

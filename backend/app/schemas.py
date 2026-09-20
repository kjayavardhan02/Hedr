from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class UserCreate(BaseModel):
    email: EmailStr
    # max_length keeps this comfortably under bcrypt's hard 72-byte input
    # limit even for multi-byte UTF-8 passwords.
    password: str = Field(..., min_length=8, max_length=72)
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)

    @field_validator("first_name", "last_name")
    @classmethod
    def _strip_and_require_non_empty(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("This field cannot be blank.")
        return stripped


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=72)


class UserOut(BaseModel):
    id: str
    email: str
    first_name: str
    last_name: str
    created_at: datetime

    class Config:
        from_attributes = True


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
    owner_id: str | None = None
    version: int
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
    url: str | None = Field(default=None, max_length=2000)
    raw_response: str | None = Field(default=None, max_length=200_000)
    # Only meaningful for source=raw, where there's no URL to label the
    # target with. Optional - defaults to "HTTP Response Scan" if omitted.
    target_name: str | None = Field(default=None, max_length=200)
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
# Saved scan reports
#
# Deliberately narrower than ScanResult: no raw_headers and no max_score.
# A report only ever stores findings for headers the policy actually named
# (see models.ScanReport for why), so there is nothing else to expose here.
# ---------------------------------------------------------------------------


class ScanReportSummary(BaseModel):
    id: str
    scan_number: int
    # The Policy id used at scan time, or null for an ad-hoc policy. This is
    # the historical value as stored - it is NOT re-checked for existence
    # here. Callers that want to link to the policy should attempt
    # GET /api/policies/{policy_id} and fall back gracefully on a 404.
    policy_id: str | None
    policy_name: str
    policy_version: str
    source: ScanSource
    target: str | None
    headers_evaluated: int
    score: float
    grade: str
    scanned_at: datetime

    class Config:
        from_attributes = True


class ScanReportOut(BaseModel):
    id: str
    scan_number: int
    policy_id: str | None
    policy_name: str
    policy_version: str
    source: ScanSource
    target: str | None
    fetched_status_code: int | None = None
    headers_evaluated: int
    score: float
    grade: str
    findings: list[HeaderFinding]
    csp_finding: CSPFinding | None = None
    scanned_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# AI Explanation (deterministic engine decides PASS/FAIL - AI only explains)
# ---------------------------------------------------------------------------


class ExplainCheckIn(BaseModel):
    name: str = Field(..., max_length=200)
    description: str = Field(..., max_length=1000)
    status: Status
    expected: str | None = Field(default=None, max_length=1000)
    actual: str | None = Field(default=None, max_length=1000)


class ExplainRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    policy_expected: str | None = Field(default=None, max_length=4000)
    actual_value: str | None = Field(default=None, max_length=4000)
    checks: list[ExplainCheckIn] = Field(default_factory=list, max_length=50)


class RecommendationItem(BaseModel):
    check: str
    fix: str


class ExplainResponse(BaseModel):
    what_it_does: str
    why_it_matters: str
    recommendations: list[RecommendationItem]
    tradeoffs: str

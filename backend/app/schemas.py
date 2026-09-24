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


# ---------------------------------------------------------------------------
# Content-Security-Policy is NOT just another header. Unlike every other
# header (one flat expected-value string, compared as a whole), CSP is a
# collection of independently-addressable directives, each with its own set
# of source expressions - so it gets its own structured rule model instead
# of being squeezed into PolicyHeaderIn.expected_value. See
# app.core.csp_analyzer for the evaluator that consumes this shape.
# ---------------------------------------------------------------------------


class CSPDirectiveRule(BaseModel):
    directive: str = Field(..., min_length=1, max_length=100)
    # Source expressions that MUST be present in this directive's value.
    must_contain: list[str] = Field(default_factory=list, max_length=50)
    # Source expressions that must NOT be present.
    must_not_contain: list[str] = Field(default_factory=list, max_length=50)
    # None = no allowlist enforced. A non-None list means every actual source
    # in this directive must be one of these (anything else fails).
    allowed_sources: list[str] | None = None
    # Configurable pattern restrictions (spec: these should be opt-in per
    # policy, not universal assumptions - e.g. img-src legitimately uses
    # data: URIs constantly, so this can't be a blanket rule).
    disallow_wildcards: bool = False
    disallow_external: bool = False
    disallow_http: bool = False
    disallow_data: bool = False
    disallow_blob: bool = False


class CSPPolicy(BaseModel):
    # Whether the CSP header must be present at all.
    required: bool = True
    # Directives that must simply exist, regardless of their value.
    required_directives: list[str] = Field(default_factory=list, max_length=50)
    directive_rules: list[CSPDirectiveRule] = Field(default_factory=list, max_length=50)


class PolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    headers: list[PolicyHeaderIn] = Field(default_factory=list)
    csp_policy: CSPPolicy | None = None

    @field_validator("headers")
    @classmethod
    def _reject_csp_in_generic_headers(cls, headers: list[PolicyHeaderIn]) -> list[PolicyHeaderIn]:
        for h in headers:
            if h.header_name.strip().lower() == "content-security-policy":
                raise ValueError(
                    "Content-Security-Policy is configured via 'csp_policy', not as a generic header."
                )
        return headers

    @field_validator("headers")
    @classmethod
    def _reject_duplicate_headers(cls, headers: list[PolicyHeaderIn]) -> list[PolicyHeaderIn]:
        # Every row is evaluated and scored independently, so a repeated
        # header would be counted twice and can't be told apart in reports or
        # scan comparisons. Header names are case-insensitive.
        seen: dict[str, str] = {}
        duplicates: list[str] = []
        for h in headers:
            key = h.header_name.strip().lower()
            if key in seen and seen[key] not in duplicates:
                duplicates.append(seen[key])
            seen.setdefault(key, h.header_name.strip())
        if duplicates:
            raise ValueError(
                "Each header can only appear once in a policy. Duplicate: " + ", ".join(duplicates) + "."
            )
        return headers


class PolicyUpdate(PolicyCreate):
    pass


class PolicyOut(BaseModel):
    id: str
    name: str
    description: str
    headers: list[PolicyHeaderIn]
    csp_policy: CSPPolicy | None = None
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
    # Kept short: it is shown in tables and cards across the app.
    target_name: str | None = Field(default=None, max_length=50)
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
    # Populated only for CSP findings (None for every generic-header check,
    # which comparators.py never sets these on). `id` is a stable CSP-###
    # identifier from app.core.csp_findings, never derived from check text.
    id: str | None = None
    severity: Literal["low", "medium", "high", "critical", "info"] | None = None
    directive: str | None = None
    evidence: str | None = None


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
    # Score breakdown (see app.core.csp_analyzer.compute_csp_score) - kept as
    # two independent tallies so a report can show "policy compliance" and
    # "best-practice" separately, per the product spec, rather than only the
    # single blended overall_score used for the report's overall score.
    policy_checks_passed: int = 0
    policy_checks_total: int = 0
    best_practice_passed: int = 0
    best_practice_total: int = 0
    overall_score: float = 100.0


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
    previous_report_id: str | None = None

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
# Scan comparison
#
# Computed dynamically from two existing ScanReport rows - no persisted
# comparison table. See app.core.scan_comparison for how these are built.
# ---------------------------------------------------------------------------


class ComparisonReportRef(BaseModel):
    id: str
    scan_number: int
    target: str | None = None
    score: float
    grade: str
    scanned_at: datetime


class HeaderAdded(BaseModel):
    header: str
    latest_value: str | None


class HeaderRemoved(BaseModel):
    header: str
    previous_value: str | None


class HeaderChanged(BaseModel):
    header: str
    previous_value: str | None
    latest_value: str | None


class FindingRef(BaseModel):
    header: str
    severity: Literal["low", "medium", "high", "critical", "info"]
    previous_status: Status
    latest_status: Status


class SeverityChange(BaseModel):
    header: str
    previous_severity: Literal["low", "medium", "high", "critical", "info"]
    latest_severity: Literal["low", "medium", "high", "critical", "info"]


class CSPCheckRef(BaseModel):
    id: str
    directive: str | None
    category: Literal["policy", "security"]
    description: str
    severity: Literal["low", "medium", "high", "critical", "info"] | None
    previous_status: Status
    latest_status: Status


class CSPDirectiveChanged(BaseModel):
    directive: str
    previous_value: list[str] | None
    latest_value: list[str] | None


class CSPChanges(BaseModel):
    resolved: list[CSPCheckRef] = Field(default_factory=list)
    new: list[CSPCheckRef] = Field(default_factory=list)
    severity_changed: list[CSPCheckRef] = Field(default_factory=list)
    directive_changes: list[CSPDirectiveChanged] = Field(default_factory=list)
    previous_policy_checks_passed: int
    previous_policy_checks_total: int
    latest_policy_checks_passed: int
    latest_policy_checks_total: int
    previous_best_practice_passed: int
    previous_best_practice_total: int
    latest_best_practice_passed: int
    latest_best_practice_total: int
    previous_overall_score: float
    latest_overall_score: float


class ComparisonSummary(BaseModel):
    previous_score: float
    latest_score: float
    score_delta: float
    previous_grade: str
    latest_grade: str
    headers_added: int
    headers_removed: int
    headers_changed: int
    findings_resolved: int
    findings_new: int
    severity_changes: int


class ComparisonChanges(BaseModel):
    headers_added: list[HeaderAdded] = Field(default_factory=list)
    headers_removed: list[HeaderRemoved] = Field(default_factory=list)
    headers_changed: list[HeaderChanged] = Field(default_factory=list)
    findings_resolved: list[FindingRef] = Field(default_factory=list)
    findings_new: list[FindingRef] = Field(default_factory=list)
    severity_changes: list[SeverityChange] = Field(default_factory=list)
    csp_changes: CSPChanges | None = None


class ComparisonResponse(BaseModel):
    has_comparison: bool
    # Populated only when has_comparison is False - explains why, so the
    # frontend can show the right empty-state copy (see app.core.scan_comparison).
    reason: (
        Literal[
            "ad_hoc_policy",
            "raw_default_target",
            "different_policy",
            "policy_version_changed",
            "previous_report_unavailable",
            "no_previous_scan",
        ]
        | None
    ) = None
    previous_report: ComparisonReportRef | None = None
    latest_report: ComparisonReportRef | None = None
    summary: ComparisonSummary | None = None
    changes: ComparisonChanges | None = None


# ---------------------------------------------------------------------------
# Dashboard summary
# ---------------------------------------------------------------------------


class DashboardReportsInfo(BaseModel):
    total: int


class DashboardPoliciesInfo(BaseModel):
    total: int


class DashboardBaselinesInfo(BaseModel):
    total: int


class DashboardFindings(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DashboardScan(BaseModel):
    """Shared shape for the dashboard's latest-scan panel and its recent-scans
    list. `passed`/`failed` count the header findings PLUS the CSP check as
    one combined pass/fail unit (CSP has no single status of its own, so it
    counts as failed if any of its policy/best-practice checks failed - the
    same all-or-nothing rule the regular header comparators already use).
    This makes `passed + failed` always equal `headers_evaluated`, which
    mirrors ScanReportOut's property of the same name and agrees with the
    policy's own rule count shown elsewhere on the dashboard. `findings` is
    this single report's own FAIL-by-severity tally (not the site-wide one
    on DashboardSummary) and folds in a failed CSP the same way."""

    id: str
    scan_number: int
    policy_id: str | None
    policy_name: str
    policy_version: str
    source: ScanSource
    target: str | None
    score: float
    grade: str
    passed: int
    failed: int
    headers_evaluated: int
    findings: DashboardFindings
    scanned_at: datetime


class DashboardRecentPolicy(BaseModel):
    id: str
    name: str
    version: int
    header_count: int
    has_csp_policy: bool
    created_at: datetime
    updated_at: datetime


class DashboardSummary(BaseModel):
    reports: DashboardReportsInfo
    policies: DashboardPoliciesInfo
    baselines: DashboardBaselinesInfo
    # Both null together when the user has no saved reports yet.
    average_score: float | None
    average_grade: str | None
    latest_scan: DashboardScan | None
    recent_scans: list[DashboardScan]
    # Scoped to ALL of the user's saved reports, not just recent_scans.
    findings: DashboardFindings
    recent_policies: list[DashboardRecentPolicy]


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

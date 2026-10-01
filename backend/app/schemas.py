from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, EmailStr, Field, field_validator

# Single source of truth for every valid theme value, used wherever `theme`
# appears (UserOut, ProfileOut, PreferencesOut, PreferencesUpdate) so the
# allowed set can't drift out of sync between them.
ThemeName = Literal["dark", "light", "offwhite", "cyberpunk", "terminal", "midnight", "arctic", "dracula", "forest", "sunset", "lavender"]

# Same idea for the (independent - see spec) accent-color preference. Not
# every id is offered for every theme in the UI (each theme curates a subset
# that fits its palette), but the stored value is validated against this
# full set regardless of the currently-selected theme.
AccentColor = Literal["default", "cyan", "blue", "purple", "green", "pink", "orange"]


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class UserCreate(BaseModel):
    email: EmailStr
    # max_length keeps this comfortably under bcrypt's hard 72-byte input
    # limit even for multi-byte UTF-8 passwords.
    password: str = Field(..., min_length=8, max_length=72)
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(..., min_length=1, max_length=50)

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
    username: str | None = None
    organization: str | None = None
    job_title: str | None = None
    # The policy pre-selected on the Scan page, if the user set one.
    default_policy_id: str | None = None
    # Never null on the way out (see User.theme).
    theme: ThemeName = "dark"
    # Never null on the way out (see User.accent_color) - independent of theme.
    accent_color: AccentColor = "default"
    created_at: datetime

    @field_validator("theme", mode="before")
    @classmethod
    def _default_theme_to_dark(cls, value: str | None) -> str:
        # "system" was removed as a selectable theme (it offered nothing
        # Default didn't already cover) - any account whose row still has it
        # from before that change reads back as "dark" rather than 500ing.
        if not value or value == "system":
            return "dark"
        return value

    @field_validator("accent_color", mode="before")
    @classmethod
    def _default_accent_to_default(cls, value: str | None) -> str:
        return value or "default"

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Profile / account management
# ---------------------------------------------------------------------------


class ProfileOut(BaseModel):
    id: str
    email: str
    first_name: str
    last_name: str
    username: str | None = None
    organization: str | None = None
    job_title: str | None = None
    default_policy_id: str | None = None
    theme: ThemeName = "dark"
    accent_color: AccentColor = "default"
    created_at: datetime
    # Null until the password has ever been changed - the frontend falls
    # back to `created_at` ("since account creation") in that case.
    password_changed_at: datetime | None = None
    # Always False for now - there's no 2FA implementation yet (see
    # Feature_Pending.md). A real field rather than hardcoding "Not enabled"
    # in the frontend, so turning 2FA on later is a backend-only change.
    two_factor_enabled: bool = False

    @field_validator("theme", mode="before")
    @classmethod
    def _default_theme_to_dark(cls, value: str | None) -> str:
        # "system" was removed as a selectable theme (it offered nothing
        # Default didn't already cover) - any account whose row still has it
        # from before that change reads back as "dark" rather than 500ing.
        if not value or value == "system":
            return "dark"
        return value

    @field_validator("accent_color", mode="before")
    @classmethod
    def _default_accent_to_default(cls, value: str | None) -> str:
        return value or "default"

    class Config:
        from_attributes = True


class ProfileUpdate(BaseModel):
    # Every field is optional and independent - a PATCH only touches the
    # fields it includes. Sending "" for username/organization/job_title
    # clears it back to unset; first/last name can't be blanked out.
    first_name: str | None = Field(default=None, max_length=50)
    last_name: str | None = Field(default=None, max_length=50)
    username: str | None = Field(default=None, max_length=50)
    organization: str | None = Field(default=None, max_length=100)
    job_title: str | None = Field(default=None, max_length=100)

    @field_validator("first_name", "last_name")
    @classmethod
    def _non_blank_if_given(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise ValueError("This field cannot be blank.")
        return stripped

    @field_validator("username", "organization", "job_title")
    @classmethod
    def _strip_or_clear(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=72)
    # Same rule as account creation (UserCreate.password) - min_length=8,
    # max_length keeps it under bcrypt's 72-byte input limit.
    new_password: str = Field(..., min_length=8, max_length=72)


class PreferencesOut(BaseModel):
    default_policy_id: str | None = None
    theme: ThemeName = "dark"
    accent_color: AccentColor = "default"

    @field_validator("theme", mode="before")
    @classmethod
    def _default_theme_to_dark(cls, value: str | None) -> str:
        # "system" was removed as a selectable theme (it offered nothing
        # Default didn't already cover) - any account whose row still has it
        # from before that change reads back as "dark" rather than 500ing.
        if not value or value == "system":
            return "dark"
        return value

    @field_validator("accent_color", mode="before")
    @classmethod
    def _default_accent_to_default(cls, value: str | None) -> str:
        return value or "default"


class PreferencesUpdate(BaseModel):
    # Explicit null clears the default policy back to "none selected".
    default_policy_id: str | None = None
    # Omitted (the default) leaves the current theme unchanged - there's no
    # "clear" state to distinguish from "dark" the way there is for
    # default_policy_id, so unlike that field this is never treated as null.
    theme: ThemeName | None = None
    # Same "omitted leaves it unchanged" rule as theme.
    accent_color: AccentColor | None = None


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class PolicyHeaderIn(BaseModel):
    header_name: str = Field(..., min_length=1, max_length=100)
    expected_value: str = Field(default="", max_length=2000)
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
    # Mirrored by the frontend's lib/limits.ts - keep the two in step.
    name: str = Field(..., min_length=1, max_length=50)
    description: str = Field(default="", max_length=200)
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
# Multi-factor authentication (email one-time codes)
# ---------------------------------------------------------------------------

_OTP_CODE_PATTERN = r"^\d{6}$"


class MFAStatusOut(BaseModel):
    enabled: bool
    masked_email: str
    # False when the server has no SMTP settings - enabling MFA would fail.
    email_configured: bool = True


class MFACodeIssuedOut(BaseModel):
    """A code was emailed. `resend_available_in` is the cooldown, in seconds."""

    masked_email: str
    expires_in: int
    resend_available_in: int


class MFALoginChallengeOut(BaseModel):
    """Returned by POST /api/auth/login instead of a user when the account has
    MFA on. NOT a session: `challenge_id` only lets the caller submit the code."""

    mfa_required: Literal[True] = True
    challenge_id: str
    masked_email: str
    expires_in: int
    resend_available_in: int


class MFACodeIn(BaseModel):
    code: str = Field(..., pattern=_OTP_CODE_PATTERN)

    @field_validator("code", mode="before")
    @classmethod
    def _strip(cls, value):
        return value.strip() if isinstance(value, str) else value


class MFALoginVerifyIn(MFACodeIn):
    challenge_id: str = Field(..., min_length=1, max_length=200)


class MFALoginResendIn(BaseModel):
    challenge_id: str = Field(..., min_length=1, max_length=200)


class MFADisableRequestIn(BaseModel):
    password: str = Field(..., min_length=1, max_length=200)


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


class ScanSource(str, Enum):
    url = "url"
    raw = "raw"
    burp = "burp"


class TargetType(str, Enum):
    """What kind of thing is being scanned - decides which headers apply (see
    app.core.applicability). The stored/API value is the snake_case id, never
    the display label."""

    WEB_APPLICATION = "web_application"
    REST_API = "rest_api"
    API_GATEWAY = "api_gateway"
    # No automatic applicability rules: every header in the policy is checked,
    # so the policy alone decides what is evaluated (how scans worked before
    # target types existed).
    CUSTOM = "custom"


class ConditionalNotApplicable(BaseModel):
    header: str
    # Plain-language condition under which this header is N/A.
    when: str


class TargetTypeInfo(BaseModel):
    """What a target type means and which headers it marks N/A (served by
    GET /api/scan/target-types, built from the same rules the engine uses)."""

    id: TargetType
    label: str
    description: str
    always_not_applicable: list[str] = Field(default_factory=list)
    sometimes_not_applicable: list[ConditionalNotApplicable] = Field(default_factory=list)


class ScanRequest(BaseModel):
    source: ScanSource
    # Defaults to Web Application, the behaviour every scan had before target
    # types existed. An unknown value is rejected (422) by the enum.
    target_type: TargetType = TargetType.WEB_APPLICATION
    url: str | None = Field(default=None, max_length=2000)
    raw_response: str | None = Field(default=None, max_length=200_000)
    # Only meaningful for source=raw, where there's no URL to label the
    # target with. Optional - defaults to "HTTP Response Scan" if omitted.
    # Kept short: it is shown in tables and cards across the app.
    target_name: str | None = Field(default=None, max_length=50)
    # Required for source=raw (enforced in the router, not here, since it's
    # ignored - not required - for source=url): the URL this response is said
    # to come from. Never fetched - purely an identity for matching this scan,
    # in comparisons, against other scans (raw or URL-mode) of the same
    # address. Ignored for source=url, whose target is already the fetched URL.
    target_url: str | None = Field(default=None, max_length=2000)
    policy_id: str | None = None
    policy: PolicyCreate | None = None

    @field_validator("target_url")
    @classmethod
    def _target_url_must_look_like_a_url(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        candidate = value.strip()
        parsed = urlsplit(candidate)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Target URL must be a full http:// or https:// URL, e.g. https://example.com.")
        return candidate


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    INFO = "INFO"
    # The header does not apply to this target/response (see
    # app.core.applicability). Never a pass, never a failure, never scored.
    NOT_APPLICABLE = "NOT_APPLICABLE"


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
    # CORS origin checks only: the policy's origin(s) after canonicalization
    # (set when normalization changed either side), and a plain-language reason
    # for the verdict. Both stay None for every other check.
    normalized_expected: str | None = None
    reason: str | None = None


class Advisory(BaseModel):
    """A caveat about a header that is separate from policy compliance: the
    value may PASS its policy check and still be legacy or obsolete."""

    status: Status
    severity: Literal["low", "medium", "high", "critical", "info"]
    title: str
    message: str
    recommendation: str | None = None


class ScoreBreakdown(BaseModel):
    """How the score's denominator was built: only applicable checks count,
    so `applicable == passed + failed` and N/A checks are reported alongside
    rather than inside the score."""

    applicable: int
    passed: int
    failed: int
    not_applicable: int


class HeaderFinding(BaseModel):
    header: str
    required: bool
    present: bool
    status: Status
    # None for a not-applicable header: it has no severity.
    severity: Literal["low", "medium", "high", "critical", "info"] | None
    weight: float
    score_earned: float
    score_possible: float
    policy_expected: str | None
    actual_value: str | None
    checks: list[CheckResult] = Field(default_factory=list)
    # `issue` says what is wrong, `recommendation` how to fix it; both only
    # when the header did not pass. Reports saved before these existed lack them.
    issue: str | None = None
    recommendation: str | None = None
    advisories: list[Advisory] = Field(default_factory=list)
    # False when the header was skipped as not applicable (status is then
    # NOT_APPLICABLE and `applicability_reason` says why). Reports saved before
    # applicability existed lack both fields and read as applicable.
    applicable: bool = True
    applicability_reason: str | None = None


class CSPFinding(BaseModel):
    present: bool
    actual_value: str | None
    applicable: bool = True
    applicability_reason: str | None = None
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
    # Set only for a raw-response scan given a Target URL; null otherwise.
    target_url: str | None = None
    fetched_status_code: int | None = None
    policy_name: str
    score: float
    max_score: float
    grade: str
    findings: list[HeaderFinding]
    csp_finding: CSPFinding | None = None
    raw_headers: dict[str, str]
    scanned_at: datetime
    scanner_version: str | None = None
    target_type: TargetType | None = None
    breakdown: ScoreBreakdown | None = None


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
    target_url: str | None = None
    headers_evaluated: int
    score: float
    grade: str
    scanned_at: datetime
    previous_report_id: str | None = None
    # Null for reports saved before target types existed ("Not recorded").
    target_type: TargetType | None = None

    class Config:
        from_attributes = True


class ReportsExportRequest(BaseModel):
    # Matches the list endpoint's cap (MAX_REPORTS_LISTED).
    ids: list[str] = Field(..., min_length=1, max_length=200)


class ScanReportOut(BaseModel):
    id: str
    scan_number: int
    policy_id: str | None
    policy_name: str
    policy_version: str
    source: ScanSource
    target: str | None
    target_url: str | None = None
    fetched_status_code: int | None = None
    headers_evaluated: int
    score: float
    grade: str
    findings: list[HeaderFinding]
    csp_finding: CSPFinding | None = None
    scanned_at: datetime
    scanner_version: str | None = None
    target_type: TargetType | None = None
    breakdown: ScoreBreakdown | None = None

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
    target_url: str | None = None
    target_type: TargetType | None = None
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


class ApplicabilityChange(BaseModel):
    """A header whose applicability flipped between the two scans. Reported
    on its own - never as a resolved/new finding - because N/A <-> applicable
    says nothing about the target's real security posture."""

    header: str
    previous_applicable: bool
    latest_applicable: bool
    # PASS/FAIL when applicable, NOT_APPLICABLE otherwise.
    previous_status: Status
    latest_status: Status
    reason: str | None = None


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
    applicability_changes: int = 0


class ComparisonChanges(BaseModel):
    headers_added: list[HeaderAdded] = Field(default_factory=list)
    headers_removed: list[HeaderRemoved] = Field(default_factory=list)
    headers_changed: list[HeaderChanged] = Field(default_factory=list)
    findings_resolved: list[FindingRef] = Field(default_factory=list)
    findings_new: list[FindingRef] = Field(default_factory=list)
    severity_changes: list[SeverityChange] = Field(default_factory=list)
    csp_changes: CSPChanges | None = None
    applicability_changes: list[ApplicabilityChange] = Field(default_factory=list)


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
    # Set when both scans recorded a target type and they differ.
    target_type_changed: bool = False


# ---------------------------------------------------------------------------
# Target score history (the "Score History" chart on a report page)
#
# Same target-identity rule as comparison (app.core.scan_comparison), but
# spans every scan of that target - not just the immediately preceding one -
# across policy versions, oldest first.
# ---------------------------------------------------------------------------


class TargetHistoryPoint(BaseModel):
    id: str
    scan_number: int
    score: float
    grade: str
    policy_name: str
    policy_version: str
    scanned_at: datetime


class TargetHistoryResponse(BaseModel):
    has_history: bool
    # Populated only when has_history is False - explains why, so the
    # frontend can show the right empty-state copy.
    reason: Literal["ad_hoc_policy", "anonymous_target", "not_enough_data"] | None = None
    # Present even when has_history is False, so a single existing scan can
    # still be acknowledged ("not enough history yet") rather than shown as
    # if it never happened.
    points: list[TargetHistoryPoint] = Field(default_factory=list)


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
    target_url: str | None
    score: float
    grade: str
    passed: int
    failed: int
    headers_evaluated: int
    findings: DashboardFindings
    scanned_at: datetime


class DashboardBurpImport(BaseModel):
    """Shared shape for the dashboard's Recent Burp Imports list - mirrors
    DashboardScan's fields closely so the two tables render the same way,
    but score/policy are nullable since an import can still be sitting
    unanalyzed (status "parsed")."""

    id: str
    name: str
    policy_name: str | None
    policy_version: str | None
    score: float | None
    responses_analyzed: int
    imported_at: datetime
    analyzed_at: datetime | None


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
    recent_burp_imports: list[DashboardBurpImport]


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


# ---------------------------------------------------------------------------
# Burp History Import
#
# Burp History is a third analysis SOURCE, not a separate security-analysis
# engine (see Feature Docs/hedr-burp-history-import-feature.md, section 36):
# each surviving entry is run through the exact same app.core.policy_engine
# used by a normal scan. Everything here is the shape of that reuse, plus the
# aggregation layer needed to summarize hundreds/thousands of per-response
# results instead of showing them one at a time.
# ---------------------------------------------------------------------------

BurpEntryStatus = Literal["parsed", "partial", "failed", "skipped"]
HeaderCoverageStatus = Literal["present", "missing", "invalid", "not_applicable"]


class BurpImportFacets(BaseModel):
    """Distinct values seen across the parsed entries, so the frontend can
    render filter checkboxes without guessing what's actually in the file."""

    hosts: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    status_buckets: list[str] = Field(default_factory=list)
    content_types: list[str] = Field(default_factory=list)


class BurpImportSummary(BaseModel):
    """Response of POST /api/burp/import - the pre-analysis summary shown
    before the user picks filters and a policy (spec section 11)."""

    id: str
    name: str
    source_filename: str
    entries_found: int
    parsed_count: int
    partial_count: int
    failed_count: int
    skipped_count: int
    facets: BurpImportFacets
    imported_at: datetime


class BurpFiltersIn(BaseModel):
    """`None` on a list field means "no filter on this dimension" - an empty
    list would exclude everything, which is never what an unset filter
    checkbox group means."""

    hosts: list[str] | None = None
    methods: list[str] | None = None
    status_buckets: list[str] | None = None
    content_types: list[str] | None = None
    https_only: bool = False
    exclude_static: bool = False
    deduplicate: bool = True


class BurpAnalyzeRequest(BaseModel):
    policy_id: str
    filters: BurpFiltersIn = Field(default_factory=BurpFiltersIn)
    name: str | None = Field(default=None, max_length=100)
    # Applies to the whole import (one file can hold many endpoints; per-endpoint
    # classification is future work).
    target_type: TargetType = TargetType.WEB_APPLICATION


class HeaderResultOut(BaseModel):
    header: str
    status: HeaderCoverageStatus
    # Why the header was skipped; only set when status is "not_applicable".
    applicability_reason: str | None = None
    actual_value: str | None = None
    expected_value: str | None = None
    severity: Literal["low", "medium", "high", "critical", "info"] | None = None


class EndpointAnalysisOut(BaseModel):
    domain: str
    path: str
    raw_url: str
    method: str
    status_code: int | None
    content_type: str | None
    header_results: list[HeaderResultOut]
    policy_score: float
    has_findings: bool


class HostSummaryRow(BaseModel):
    host: str
    responses: int
    unique_paths: int
    score: float


class HeaderCoverageRow(BaseModel):
    header: str
    present: int
    missing: int
    invalid: int
    not_applicable: int
    coverage: float  # percent, present / (present + missing + invalid)


class FindingGroupOut(BaseModel):
    header: str
    status: Literal["missing", "invalid"]
    severity: Literal["low", "medium", "high", "critical", "info"]
    affected_count: int
    # Capped preview of affected endpoints - `affected_count` is the true total.
    affected_endpoints: list[str]


class InconsistencyConfigOut(BaseModel):
    # The actual header value shared by every endpoint in this group.
    value: str
    count: int
    affected_endpoints: list[str]


class HeaderInconsistencyOut(BaseModel):
    header: str
    configurations: list[InconsistencyConfigOut]


class ImportIssueOut(BaseModel):
    index: int
    url: str | None
    host: str | None
    path: str | None
    status: BurpEntryStatus
    reason: str | None


class BurpAnalysisSummaryOut(BaseModel):
    responses_analyzed: int
    unique_hosts: int
    unique_paths: int
    overall_score: float
    responses_with_findings: int
    severity_counts: dict[str, int]
    # Header checks across every analyzed response, with N/A kept out of the
    # applicable/passed/failed tallies. None on analyses saved before this.
    checks: ScoreBreakdown | None = None


class BurpAnalysisResult(BaseModel):
    """The full normalized analysis result - built once by
    app.core.burp_aggregation, then reused as-is for the UI, stored as the
    report, and (in a later phase) fed to the Excel generator. See spec
    section 33: "Analyze once, store normalized results, generate multiple
    views from the same result."."""

    # Null on analyses saved before target types existed.
    target_type: TargetType | None = None
    summary: BurpAnalysisSummaryOut
    host_summary: list[HostSummaryRow]
    header_coverage: list[HeaderCoverageRow]
    findings: list[FindingGroupOut]
    inconsistencies: list[HeaderInconsistencyOut]
    endpoints: list[EndpointAnalysisOut]
    import_issues: list[ImportIssueOut]


class BurpImportListItem(BaseModel):
    id: str
    name: str
    status: str
    source_filename: str
    policy_id: str | None = None
    policy_name: str | None = None
    policy_version: str | None = None
    target_type: TargetType | None = None
    score: float | None = None
    responses_analyzed: int
    responses_skipped: int
    parse_failures: int
    imported_at: datetime
    analyzed_at: datetime | None = None

    class Config:
        from_attributes = True


class BurpImportOut(BaseModel):
    id: str
    name: str
    status: str
    source_filename: str
    policy_id: str | None = None
    policy_name: str | None = None
    policy_version: str | None = None
    target_type: TargetType | None = None
    filters: BurpFiltersIn | None = None
    imported_at: datetime
    analyzed_at: datetime | None = None
    analysis: BurpAnalysisResult | None = None

    class Config:
        from_attributes = True

"""Header applicability: is a configured policy header relevant to this
response at all?

Deterministic and rule-based - no AI, no body inspection. The decision looks
only at the selected target type, the transport (HTTP vs HTTPS) and the
response's Content-Type / headers. A header that is not applicable is skipped
by the policy engine: it produces no failure, carries no severity or
remediation, and is left out of the score denominator.

The rules are initial product rules (spec: Feature 12 section 8), not
permanent universal security rules - extend `_BROWSER_DOCUMENT_HEADERS` /
`check_applicability` as they evolve.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.schemas import CSPFinding, HeaderFinding, ScoreBreakdown, Status, TargetType

TARGET_TYPE_LABELS: dict[TargetType, str] = {
    TargetType.WEB_APPLICATION: "Web Application",
    TargetType.REST_API: "REST API",
    TargetType.API_GATEWAY: "API Gateway",
}

DEFAULT_TARGET_TYPE = TargetType.WEB_APPLICATION

_HSTS = "strict-transport-security"
_CSP = "content-security-policy"

# Headers that only mean something for a browser-rendered document: Web
# Application targets get them, API-style targets do not by default.
_BROWSER_DOCUMENT_HEADERS = frozenset(
    {
        _CSP,
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-embedder-policy",
        "cross-origin-resource-policy",
    }
)

_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})


@dataclass(frozen=True)
class Applicability:
    applicable: bool
    reason: str | None = None


_APPLICABLE = Applicability(True)


def media_type(content_type: str | None) -> str | None:
    """`text/html; charset=utf-8` -> `text/html`; blank or missing -> None."""
    if not content_type:
        return None
    base = content_type.split(";", 1)[0].strip().lower()
    return base or None


def is_html(content_type: str | None) -> bool:
    return media_type(content_type) in _HTML_TYPES


def is_cors_header(header_name: str) -> bool:
    return header_name.lower().startswith("access-control-")


def label(target_type: TargetType | str | None) -> str:
    if target_type is None:
        return "Not recorded"
    return TARGET_TYPE_LABELS[TargetType(target_type)]


def check_applicability(
    header_name: str,
    *,
    target_type: TargetType,
    is_https: bool | None,
    content_type: str | None,
    header_present: bool,
) -> Applicability:
    """`is_https=None` means the scheme is unknown (e.g. a pasted response
    with no usable URL) - in that case HSTS is not excused. An unknown
    Content-Type is likewise never used as a reason to excuse CSP: only a
    Content-Type that is present and not HTML does that."""
    name = header_name.strip().lower()
    type_label = label(target_type)

    if name == _HSTS:
        if is_https is False:
            return Applicability(False, "HSTS is only applicable to HTTPS responses.")
        return _APPLICABLE

    if name in _BROWSER_DOCUMENT_HEADERS:
        if target_type != TargetType.WEB_APPLICATION:
            return Applicability(
                False,
                f"{header_name.strip()} is a browser-document header and is not applicable to "
                f"{type_label} targets by default.",
            )
        if name == _CSP and media_type(content_type) is not None and not is_html(content_type):
            return Applicability(
                False,
                "Content-Security-Policy is intended for browser document content and this "
                "response is not an HTML document.",
            )
        return _APPLICABLE

    if is_cors_header(name):
        if target_type == TargetType.WEB_APPLICATION and not header_present:
            # CORS only matters on a normal web page when something is
            # actually using it; an HTML document that sends no CORS headers
            # is not a CORS endpoint. Non-HTML responses (JSON fetched by the
            # page, etc.) may be cross-origin resources, so stay applicable.
            if is_html(content_type):
                return Applicability(
                    False,
                    "This HTML page sends no CORS headers, so cross-origin resource sharing "
                    "does not apply to it.",
                )
        return _APPLICABLE

    return _APPLICABLE


def not_applicable_finding(
    *, header_name: str, required: bool, policy_expected: str | None, actual_value: str | None, reason: str
) -> HeaderFinding:
    """A finding for a skipped header: no verdict, severity, weight or advice."""
    return HeaderFinding(
        header=header_name,
        required=required,
        present=actual_value is not None,
        status=Status.NOT_APPLICABLE,
        severity=None,
        weight=0.0,
        score_earned=0.0,
        score_possible=0.0,
        policy_expected=policy_expected,
        actual_value=actual_value,
        applicable=False,
        applicability_reason=reason,
    )


def not_applicable_csp_finding(*, actual_value: str | None, reason: str) -> CSPFinding:
    return CSPFinding(
        present=actual_value is not None,
        actual_value=actual_value,
        applicable=False,
        applicability_reason=reason,
        policy_checks_passed=0,
        policy_checks_total=0,
        best_practice_passed=0,
        best_practice_total=0,
        overall_score=0.0,
    )


def build_breakdown(findings: list[dict | HeaderFinding], csp_finding: dict | CSPFinding | None) -> ScoreBreakdown:
    """Applicable / passed / failed / not-applicable counts. Works on either
    model objects or the plain dicts stored on a saved report; findings saved
    before applicability existed have no `applicable` field and count as
    applicable."""

    def get(obj, key, default=None):
        return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)

    passed = failed = not_applicable = 0
    for f in findings or []:
        if get(f, "applicable", True) is False or get(f, "status") in (Status.NOT_APPLICABLE, "NOT_APPLICABLE"):
            not_applicable += 1
        elif get(f, "status") in (Status.PASS, "PASS"):
            passed += 1
        else:
            failed += 1

    if csp_finding is not None:
        if get(csp_finding, "applicable", True) is False:
            not_applicable += 1
        else:
            # CSP has no single verdict of its own: like the dashboard's
            # passed/failed tally, it fails if ANY of its checks failed.
            checks = [*(get(csp_finding, "policy_checks", None) or []), *(get(csp_finding, "security_checks", None) or [])]
            if any(get(c, "status") in (Status.FAIL, "FAIL") for c in checks):
                failed += 1
            else:
                passed += 1

    return ScoreBreakdown(
        applicable=passed + failed, passed=passed, failed=failed, not_applicable=not_applicable
    )

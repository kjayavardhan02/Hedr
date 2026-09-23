"""Ties header parsing, comparators, and the CSP analyzer together into
findings + an overall score. This module is 100% deterministic - no AI.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core import csp_analyzer
from app.core.comparators import get_comparator
from app.core.csp_findings import CSPFindingId, severity_for
from app.core.scoring import get_severity, get_weight, grade_for_score
from app.schemas import (
    CheckResult,
    CSPFinding,
    CSPPolicy,
    HeaderFinding,
    PolicyHeaderIn,
    ScanResult,
    ScanSource,
    Status,
)

CSP_HEADER_NAME = "content-security-policy"
CORS_ACAO_HEADER_NAME = "access-control-allow-origin"
CORS_ACAC_HEADER_NAME = "access-control-allow-credentials"
XFO_HEADER_NAME = "x-frame-options"

# CSP's `frame-ancestors` directive (Level 2+) provides the same
# clickjacking protection as X-Frame-Options, and modern browsers that
# understand it ignore XFO entirely in its favor. Maps each XFO value we
# know how to reason about to its frame-ancestors equivalent - anything not
# in this table (e.g. the deprecated `ALLOW-FROM <uri>`) is left alone
# rather than guessed at.
XFO_TO_FRAME_ANCESTORS_EQUIVALENT = {
    "deny": "'none'",
    "sameorigin": "'self'",
}


def _recommendation_for(header: str, status: Status, present: bool) -> str | None:
    if status == Status.PASS:
        return None
    if not present:
        return f"Add the '{header}' header to your HTTP response according to your security policy."
    return f"Update the '{header}' header so its value complies with the configured policy."


def _evaluate_xfo_via_csp_frame_ancestors(
    policy_header: PolicyHeaderIn, raw_headers: dict[str, str]
) -> tuple[Status, list[CheckResult]] | None:
    """Only called when X-Frame-Options itself is missing. If the response's
    actual CSP header sets `frame-ancestors`, that already covers clickjacking
    protection in any browser that honors it, so a missing XFO header isn't
    automatically a real gap - check whether frame-ancestors is at least as
    strict as what the policy expects from XFO, rather than flatly failing on
    "missing". Returns None when there's nothing to fall back to (no CSP, no
    frame-ancestors, or an XFO value we don't know how to compare), so the
    caller can use its normal missing-header handling instead."""
    csp_value = raw_headers.get(CSP_HEADER_NAME)
    if not csp_value:
        return None
    directives = csp_analyzer.parse_csp(csp_value)
    if "frame-ancestors" not in directives:
        return None

    frame_ancestors_sources = directives["frame-ancestors"]
    actual_display = f"frame-ancestors {' '.join(frame_ancestors_sources) or '(empty)'}"
    expected = policy_header.expected_value.strip()

    if not expected:
        # Presence-only rule - any frame-ancestors value at all covers it.
        return Status.PASS, [
            CheckResult(
                name="csp-frame-ancestors-fallback",
                description=(
                    "'X-Frame-Options' is missing, but the response's Content-Security-Policy "
                    "sets 'frame-ancestors', which provides equivalent clickjacking protection "
                    "in browsers that support it."
                ),
                status=Status.PASS,
                expected="present (or covered by CSP frame-ancestors)",
                actual=actual_display,
            )
        ]

    equivalent = XFO_TO_FRAME_ANCESTORS_EQUIVALENT.get(expected.lower())
    if equivalent is None:
        return None

    ok = equivalent in {s.lower() for s in frame_ancestors_sources}
    return Status.PASS if ok else Status.FAIL, [
        CheckResult(
            name="csp-frame-ancestors-fallback",
            description=(
                "'X-Frame-Options' is missing; checking whether the response's CSP "
                "'frame-ancestors' directive provides equivalent protection instead."
            ),
            status=Status.PASS if ok else Status.FAIL,
            expected=f"frame-ancestors {equivalent} (equivalent to X-Frame-Options: {expected})",
            actual=actual_display,
        )
    ]


def evaluate_header(policy_header: PolicyHeaderIn, raw_headers: dict[str, str]) -> HeaderFinding:
    name = policy_header.header_name.strip()
    name_lower = name.lower()
    actual_value = raw_headers.get(name_lower)
    present = actual_value is not None
    weight = get_weight(name_lower)
    severity = get_severity(name_lower)

    if not present:
        xfo_fallback = (
            _evaluate_xfo_via_csp_frame_ancestors(policy_header, raw_headers)
            if name_lower == XFO_HEADER_NAME
            else None
        )
        if xfo_fallback is not None:
            status, checks = xfo_fallback
            score_earned = weight if status == Status.PASS else 0.0
        elif policy_header.required:
            status = Status.FAIL
            checks = [
                CheckResult(
                    name="presence",
                    description=f"'{name}' header must be present.",
                    status=Status.FAIL,
                    expected="present",
                    actual="missing",
                )
            ]
            score_earned = 0.0
        else:
            status = Status.PASS
            checks = [
                CheckResult(
                    name="presence",
                    description=f"'{name}' header is optional and was not sent.",
                    status=Status.PASS,
                    expected="present (optional)",
                    actual="missing",
                )
            ]
            score_earned = weight
    else:
        if not policy_header.expected_value.strip():
            # Presence-only rule.
            status = Status.PASS
            checks = [
                CheckResult(
                    name="presence",
                    description=f"'{name}' header must be present.",
                    status=Status.PASS,
                    expected="present",
                    actual=actual_value,
                )
            ]
            score_earned = weight
        else:
            comparator = get_comparator(name_lower)
            outcome = comparator(name, policy_header.expected_value, actual_value)
            status = outcome.status
            checks = outcome.checks
            score_earned = weight * (outcome.passed_count / outcome.total_count)

    # Access-Control-Allow-Credentials has no effect in the browser unless
    # Access-Control-Allow-Origin is also present on the same response - so
    # when ACAO is missing, ACAC being "wrong" isn't a real exposure. Never
    # flag it in that situation, regardless of what the policy expected.
    if name_lower == CORS_ACAC_HEADER_NAME and present and CORS_ACAO_HEADER_NAME not in raw_headers:
        status = Status.PASS
        score_earned = weight
        checks = [
            CheckResult(
                name="acao-context",
                description=(
                    "'Access-Control-Allow-Credentials' has no effect without "
                    "'Access-Control-Allow-Origin' on the same response, so it "
                    "isn't flagged here."
                ),
                status=Status.PASS,
                expected=None,
                actual=actual_value,
            )
        ]

    return HeaderFinding(
        header=name,
        required=policy_header.required,
        present=present,
        status=status,
        severity=severity,  # type: ignore[arg-type]
        weight=weight,
        score_earned=round(score_earned, 2),
        score_possible=weight,
        policy_expected=policy_header.expected_value or None,
        actual_value=actual_value,
        checks=checks,
        recommendation=_recommendation_for(name, status, present),
    )


def evaluate_csp(csp_policy: CSPPolicy | None, raw_headers: dict[str, str]) -> CSPFinding:
    actual_value = raw_headers.get(CSP_HEADER_NAME)
    present = actual_value is not None
    actual_directives = csp_analyzer.parse_csp(actual_value) if present else None

    policy_checks: list[CheckResult] = []
    if csp_policy is not None:
        if not present:
            # Header missing entirely - report that once rather than
            # cascading a "missing" FAIL for every required directive/rule.
            status = Status.FAIL if csp_policy.required else Status.PASS
            policy_checks = [
                CheckResult(
                    id=CSPFindingId.HEADER_MISSING,
                    name="presence",
                    description="'Content-Security-Policy' header must be present.",
                    status=status,
                    severity=severity_for(CSPFindingId.HEADER_MISSING),
                    expected="present" if csp_policy.required else "present (optional)",
                    actual="missing",
                )
            ]
        else:
            policy_checks = csp_analyzer.evaluate_csp_policy(csp_policy, actual_directives)

    security_checks = csp_analyzer.evaluate_security_best_practices(actual_directives)

    policy_passed, policy_total, bp_passed, bp_total, overall_score = csp_analyzer.compute_csp_score(
        policy_checks, security_checks
    )

    return CSPFinding(
        present=present,
        actual_value=actual_value,
        policy_checks=policy_checks,
        security_checks=security_checks,
        directives=actual_directives or {},
        policy_checks_passed=policy_passed,
        policy_checks_total=policy_total,
        best_practice_passed=bp_passed,
        best_practice_total=bp_total,
        overall_score=overall_score,
    )


def _csp_score(csp_finding: CSPFinding, weight: float) -> tuple[float, float]:
    """Reads the blended score evaluate_csp() already computed (see
    csp_analyzer.compute_csp_score) rather than recomputing it here."""
    return round(weight * csp_finding.overall_score / 100, 2), weight


def run_scan(
    *,
    raw_headers: dict[str, str],
    policy_name: str,
    policy_headers: list[PolicyHeaderIn],
    source: ScanSource,
    target: str | None,
    fetched_status_code: int | None,
    csp_policy: CSPPolicy | None = None,
) -> ScanResult:
    findings: list[HeaderFinding] = []
    earned_total = 0.0
    possible_total = 0.0

    # policy_headers can never contain a Content-Security-Policy entry -
    # that's enforced at the schema layer (PolicyCreate rejects it) - so the
    # generic per-header engine never needs to know CSP exists.
    for ph in policy_headers:
        finding = evaluate_header(ph, raw_headers)
        findings.append(finding)
        earned_total += finding.score_earned
        possible_total += finding.score_possible

    csp_finding: CSPFinding | None = None
    if csp_policy is not None:
        csp_finding = evaluate_csp(csp_policy, raw_headers)
        csp_weight = get_weight(CSP_HEADER_NAME)
        earned, possible = _csp_score(csp_finding, csp_weight)
        earned_total += earned
        possible_total += possible

    score = round((earned_total / possible_total) * 100, 1) if possible_total > 0 else 100.0

    return ScanResult(
        id=str(uuid.uuid4()),
        source=source,
        target=target,
        fetched_status_code=fetched_status_code,
        policy_name=policy_name,
        score=score,
        max_score=100.0,
        grade=grade_for_score(score),
        findings=findings,
        csp_finding=csp_finding,
        raw_headers=raw_headers,
        scanned_at=datetime.now(timezone.utc),
    )

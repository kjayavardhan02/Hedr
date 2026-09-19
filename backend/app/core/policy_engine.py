"""Ties header parsing, comparators, and the CSP analyzer together into
findings + an overall score. This module is 100% deterministic - no AI.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core import csp_analyzer
from app.core.comparators import get_comparator
from app.core.scoring import get_severity, get_weight, grade_for_score
from app.schemas import (
    CheckResult,
    CSPFinding,
    HeaderFinding,
    PolicyHeaderIn,
    ScanResult,
    ScanSource,
    Status,
)

CSP_HEADER_NAME = "content-security-policy"
CORS_ACAO_HEADER_NAME = "access-control-allow-origin"
CORS_ACAC_HEADER_NAME = "access-control-allow-credentials"


def _recommendation_for(header: str, status: Status, present: bool) -> str | None:
    if status == Status.PASS:
        return None
    if not present:
        return f"Add the '{header}' header to your HTTP response according to your security policy."
    return f"Update the '{header}' header so its value complies with the configured policy."


def evaluate_header(policy_header: PolicyHeaderIn, raw_headers: dict[str, str]) -> HeaderFinding:
    name = policy_header.header_name.strip()
    name_lower = name.lower()
    actual_value = raw_headers.get(name_lower)
    present = actual_value is not None
    weight = get_weight(name_lower)
    severity = get_severity(name_lower)

    if not present:
        if policy_header.required:
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


def evaluate_csp(policy_header: PolicyHeaderIn | None, raw_headers: dict[str, str]) -> CSPFinding:
    actual_value = raw_headers.get(CSP_HEADER_NAME)
    present = actual_value is not None
    actual_directives = csp_analyzer.parse_csp(actual_value) if present else None

    policy_checks: list[CheckResult] = []
    if policy_header is not None and policy_header.expected_value.strip():
        expected_directives = csp_analyzer.parse_csp(policy_header.expected_value)
        policy_checks = csp_analyzer.evaluate_policy_compliance(expected_directives, actual_directives)
    elif policy_header is not None and not present:
        policy_checks = [
            CheckResult(
                name="presence",
                description="'content-security-policy' header must be present.",
                status=Status.FAIL,
                expected="present",
                actual="missing",
            )
        ]
    elif policy_header is not None:
        policy_checks = [
            CheckResult(
                name="presence",
                description="'content-security-policy' header must be present.",
                status=Status.PASS,
                expected="present",
                actual=actual_value,
            )
        ]

    security_checks = csp_analyzer.evaluate_security_best_practices(actual_directives)

    return CSPFinding(
        present=present,
        actual_value=actual_value,
        policy_checks=policy_checks,
        security_checks=security_checks,
        directives=actual_directives or {},
    )


def _csp_score(csp_finding: CSPFinding, weight: float) -> tuple[float, float]:
    """CSP scoring blends policy compliance (if any) with best-practice checks."""
    all_checks = list(csp_finding.policy_checks) + list(csp_finding.security_checks)
    if not all_checks:
        return weight, weight
    passed = sum(1 for c in all_checks if c.status == Status.PASS)
    total = len(all_checks)
    return round(weight * (passed / total), 2), weight


def run_scan(
    *,
    raw_headers: dict[str, str],
    policy_name: str,
    policy_headers: list[PolicyHeaderIn],
    source: ScanSource,
    target: str | None,
    fetched_status_code: int | None,
) -> ScanResult:
    findings: list[HeaderFinding] = []
    csp_policy_header: PolicyHeaderIn | None = None
    earned_total = 0.0
    possible_total = 0.0

    for ph in policy_headers:
        if ph.header_name.strip().lower() == CSP_HEADER_NAME:
            csp_policy_header = ph
            continue
        finding = evaluate_header(ph, raw_headers)
        findings.append(finding)
        earned_total += finding.score_earned
        possible_total += finding.score_possible

    csp_finding: CSPFinding | None = None
    if csp_policy_header is not None:
        csp_finding = evaluate_csp(csp_policy_header, raw_headers)
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

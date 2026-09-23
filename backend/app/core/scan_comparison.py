"""Scan-to-scan comparison ("Changes Since Previous Scan").

Computed dynamically from two existing ScanReport rows - no persisted
comparison table. A report's `findings`/`csp_finding` columns are already
JSON-decoded dicts (HeaderFinding/CSPFinding-shaped) by the time SQLAlchemy
hands them back, so this module only ever reads plain dicts, never
re-evaluates a policy or recomputes a score.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app import models
from app.schemas import (
    ComparisonChanges,
    ComparisonReportRef,
    ComparisonResponse,
    ComparisonSummary,
    CSPChanges,
    CSPCheckRef,
    CSPDirectiveChanged,
    FindingRef,
    HeaderAdded,
    HeaderChanged,
    HeaderRemoved,
    SeverityChange,
)

_FAIL = "FAIL"

# What a raw-response scan is labeled when the user gives no target name.
# It's a placeholder, not an identity - two pasted responses left at this
# default could come from entirely unrelated systems, so they never compare.
DEFAULT_RAW_TARGET_NAME = "HTTP Response Scan"


def is_anonymous_raw_target(report: models.ScanReport) -> bool:
    return report.source == "raw" and report.target == DEFAULT_RAW_TARGET_NAME


def find_previous_comparable_report(db: Session, current: models.ScanReport) -> models.ScanReport | None:
    """Same user + target + policy identity + policy version, scanned
    strictly earlier, most recent first. Ad-hoc reports (no policy_id) have
    no stable identity to compare across scans, so they never match; nor do
    raw-response scans left at the default target name."""
    if current.policy_id is None or is_anonymous_raw_target(current):
        return None
    return (
        db.query(models.ScanReport)
        .filter(
            models.ScanReport.owner_id == current.owner_id,
            models.ScanReport.target == current.target,
            models.ScanReport.policy_id == current.policy_id,
            models.ScanReport.policy_version == current.policy_version,
            models.ScanReport.id != current.id,
            models.ScanReport.scanned_at < current.scanned_at,
        )
        .order_by(models.ScanReport.scanned_at.desc(), models.ScanReport.id.desc())
        .first()
    )


def _has_prior_scan_different_version(db: Session, current: models.ScanReport) -> bool:
    """Used only to choose the empty-state reason/message - never as a
    comparison source. True when a prior report exists for the same
    user+target+policy but under a different policy_version."""
    return (
        db.query(models.ScanReport)
        .filter(
            models.ScanReport.owner_id == current.owner_id,
            models.ScanReport.target == current.target,
            models.ScanReport.policy_id == current.policy_id,
            models.ScanReport.id != current.id,
            models.ScanReport.scanned_at < current.scanned_at,
        )
        .first()
    ) is not None


def build_comparison_for_report(db: Session, report: models.ScanReport) -> ComparisonResponse:
    if report.policy_id is None:
        return ComparisonResponse(has_comparison=False, reason="ad_hoc_policy")
    if is_anonymous_raw_target(report):
        return ComparisonResponse(has_comparison=False, reason="raw_default_target")

    previous = find_previous_comparable_report(db, report)
    if previous is None:
        if _has_prior_scan_different_version(db, report):
            return ComparisonResponse(has_comparison=False, reason="policy_version_changed")
        return ComparisonResponse(has_comparison=False, reason="no_previous_scan")

    return compare_reports(previous, report)


def compare_reports(previous: models.ScanReport, latest: models.ScanReport) -> ComparisonResponse:
    headers_added, headers_removed, headers_changed = _diff_headers(
        previous.findings or [], latest.findings or []
    )
    findings_resolved, findings_new, severity_changes = _diff_findings(
        previous.findings or [], latest.findings or []
    )
    csp_changes = _diff_csp(previous.csp_finding, latest.csp_finding)

    summary = ComparisonSummary(
        previous_score=previous.score,
        latest_score=latest.score,
        score_delta=round(latest.score - previous.score, 2),
        previous_grade=previous.grade,
        latest_grade=latest.grade,
        headers_added=len(headers_added),
        headers_removed=len(headers_removed),
        headers_changed=len(headers_changed),
        findings_resolved=len(findings_resolved),
        findings_new=len(findings_new),
        severity_changes=len(severity_changes),
    )

    changes = ComparisonChanges(
        headers_added=headers_added,
        headers_removed=headers_removed,
        headers_changed=headers_changed,
        findings_resolved=findings_resolved,
        findings_new=findings_new,
        severity_changes=severity_changes,
        csp_changes=csp_changes,
    )

    return ComparisonResponse(
        has_comparison=True,
        previous_report=ComparisonReportRef(
            id=previous.id,
            scan_number=previous.scan_number,
            score=previous.score,
            grade=previous.grade,
            scanned_at=previous.scanned_at,
        ),
        latest_report=ComparisonReportRef(
            id=latest.id,
            scan_number=latest.scan_number,
            score=latest.score,
            grade=latest.grade,
            scanned_at=latest.scanned_at,
        ),
        summary=summary,
        changes=changes,
    )


def _diff_headers(
    prev_findings: list[dict], latest_findings: list[dict]
) -> tuple[list[HeaderAdded], list[HeaderRemoved], list[HeaderChanged]]:
    prev_by_name = {f["header"]: f for f in prev_findings}
    latest_by_name = {f["header"]: f for f in latest_findings}

    added: list[HeaderAdded] = []
    removed: list[HeaderRemoved] = []
    changed: list[HeaderChanged] = []

    for name in sorted(set(prev_by_name) | set(latest_by_name)):
        prev = prev_by_name.get(name)
        latest = latest_by_name.get(name)
        prev_present = bool(prev and prev.get("present"))
        latest_present = bool(latest and latest.get("present"))

        if not prev_present and latest_present:
            added.append(HeaderAdded(header=name, latest_value=latest.get("actual_value")))
        elif prev_present and not latest_present:
            removed.append(HeaderRemoved(header=name, previous_value=prev.get("actual_value")))
        elif prev_present and latest_present:
            prev_value = prev.get("actual_value")
            latest_value = latest.get("actual_value")
            if prev_value != latest_value:
                changed.append(
                    HeaderChanged(header=name, previous_value=prev_value, latest_value=latest_value)
                )

    return added, removed, changed


def _diff_findings(
    prev_findings: list[dict], latest_findings: list[dict]
) -> tuple[list[FindingRef], list[FindingRef], list[SeverityChange]]:
    """A generic HeaderFinding's status is always PASS or FAIL (never
    WARNING/INFO - those only occur on CSP checks), so "active finding"
    simply means status == FAIL."""
    prev_by_name = {f["header"]: f for f in prev_findings}
    latest_by_name = {f["header"]: f for f in latest_findings}

    resolved: list[FindingRef] = []
    new: list[FindingRef] = []
    severity_changed: list[SeverityChange] = []

    for name in sorted(set(prev_by_name) | set(latest_by_name)):
        prev = prev_by_name.get(name)
        latest = latest_by_name.get(name)
        prev_status = prev.get("status") if prev else "PASS"
        latest_status = latest.get("status") if latest else "PASS"
        prev_failing = prev_status == _FAIL
        latest_failing = latest_status == _FAIL

        if prev_failing and not latest_failing:
            resolved.append(
                FindingRef(
                    header=name,
                    severity=prev.get("severity", "info"),
                    previous_status=prev_status,
                    latest_status=latest_status,
                )
            )
        elif not prev_failing and latest_failing:
            new.append(
                FindingRef(
                    header=name,
                    severity=latest.get("severity", "info"),
                    previous_status=prev_status,
                    latest_status=latest_status,
                )
            )
        elif prev and latest and prev.get("severity") != latest.get("severity"):
            severity_changed.append(
                SeverityChange(
                    header=name,
                    previous_severity=prev.get("severity", "info"),
                    latest_severity=latest.get("severity", "info"),
                )
            )

    return resolved, new, severity_changed


def _csp_identity(check: dict) -> tuple[str | None, str | None]:
    return check.get("id"), check.get("directive")


def _index_csp_checks(checks: list[dict], category: str) -> dict[tuple[str | None, str | None], dict]:
    indexed = {}
    for c in checks:
        key = _csp_identity(c)
        if key[0] is None:
            continue
        indexed[key] = {**c, "_category": category}
    return indexed


def _diff_csp(prev_csp: dict | None, latest_csp: dict | None) -> CSPChanges | None:
    if prev_csp is None and latest_csp is None:
        return None

    prev_csp = prev_csp or {
        "policy_checks": [],
        "security_checks": [],
        "policy_checks_passed": 0,
        "policy_checks_total": 0,
        "best_practice_passed": 0,
        "best_practice_total": 0,
        "overall_score": 100.0,
        "directives": {},
    }
    latest_csp = latest_csp or {
        "policy_checks": [],
        "security_checks": [],
        "policy_checks_passed": 0,
        "policy_checks_total": 0,
        "best_practice_passed": 0,
        "best_practice_total": 0,
        "overall_score": 100.0,
        "directives": {},
    }

    prev_indexed = {
        **_index_csp_checks(prev_csp.get("policy_checks") or [], "policy"),
        **_index_csp_checks(prev_csp.get("security_checks") or [], "security"),
    }
    latest_indexed = {
        **_index_csp_checks(latest_csp.get("policy_checks") or [], "policy"),
        **_index_csp_checks(latest_csp.get("security_checks") or [], "security"),
    }

    resolved: list[CSPCheckRef] = []
    new: list[CSPCheckRef] = []
    severity_changed: list[CSPCheckRef] = []

    for key in sorted(set(prev_indexed) | set(latest_indexed), key=lambda k: (k[0] or "", k[1] or "")):
        prev = prev_indexed.get(key)
        latest = latest_indexed.get(key)
        prev_status = prev.get("status") if prev else "PASS"
        latest_status = latest.get("status") if latest else "PASS"
        prev_failing = prev_status == _FAIL
        latest_failing = latest_status == _FAIL
        source = latest or prev

        if prev_failing and not latest_failing:
            resolved.append(_check_ref(key, source, prev_status, latest_status))
        elif not prev_failing and latest_failing:
            new.append(_check_ref(key, source, prev_status, latest_status))
        elif prev and latest and prev.get("severity") != latest.get("severity"):
            severity_changed.append(_check_ref(key, source, prev_status, latest_status))

    directive_changes = _diff_directives(
        prev_csp.get("directives") or {}, latest_csp.get("directives") or {}
    )

    return CSPChanges(
        resolved=resolved,
        new=new,
        severity_changed=severity_changed,
        directive_changes=directive_changes,
        previous_policy_checks_passed=prev_csp.get("policy_checks_passed", 0),
        previous_policy_checks_total=prev_csp.get("policy_checks_total", 0),
        latest_policy_checks_passed=latest_csp.get("policy_checks_passed", 0),
        latest_policy_checks_total=latest_csp.get("policy_checks_total", 0),
        previous_best_practice_passed=prev_csp.get("best_practice_passed", 0),
        previous_best_practice_total=prev_csp.get("best_practice_total", 0),
        latest_best_practice_passed=latest_csp.get("best_practice_passed", 0),
        latest_best_practice_total=latest_csp.get("best_practice_total", 0),
        previous_overall_score=prev_csp.get("overall_score", 100.0),
        latest_overall_score=latest_csp.get("overall_score", 100.0),
    )


def _check_ref(
    key: tuple[str | None, str | None], source: dict, prev_status: str, latest_status: str
) -> CSPCheckRef:
    return CSPCheckRef(
        id=key[0],
        directive=key[1],
        category=source.get("_category", "policy"),
        description=source.get("description", ""),
        severity=source.get("severity"),
        previous_status=prev_status,
        latest_status=latest_status,
    )


def _diff_directives(
    prev_directives: dict[str, list[str]], latest_directives: dict[str, list[str]]
) -> list[CSPDirectiveChanged]:
    changes: list[CSPDirectiveChanged] = []
    for directive in sorted(set(prev_directives) | set(latest_directives)):
        prev_value = prev_directives.get(directive)
        latest_value = latest_directives.get(directive)
        if prev_value != latest_value:
            changes.append(
                CSPDirectiveChanged(directive=directive, previous_value=prev_value, latest_value=latest_value)
            )
    return changes

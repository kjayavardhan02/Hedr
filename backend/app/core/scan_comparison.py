"""Scan-to-scan comparison ("Changes Since Previous Scan").

Computed dynamically from two existing ScanReport rows - no persisted
comparison table. A report's `findings`/`csp_finding` columns are already
JSON-decoded dicts (HeaderFinding/CSPFinding-shaped) by the time SQLAlchemy
hands them back, so this module only ever reads plain dicts, never
re-evaluates a policy or recomputes a score.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app import models
from app.core.applicability import label as target_type_label
from app.core.comparators import values_equivalent
from app.schemas import (
    ApplicabilityChange,
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
    TargetHistoryPoint,
    TargetHistoryResponse,
)

_FAIL = "FAIL"

# What a raw-response scan is labeled when the user gives no target name.
# It's a placeholder, not an identity - two pasted responses left at this
# default could come from entirely unrelated systems, so they never compare.
DEFAULT_RAW_TARGET_NAME = "HTTP Response Scan"

# A user-typed name is compared loosely (case, surrounding and repeated
# spaces ignored) so "Production API" and " production   api " are one target.
# The original spelling is always kept for display.


def normalize_target_name(name: str | None) -> str:
    return re.sub(r"\s+", " ", (name or "").strip()).lower()


# Default port per scheme, for stripping it from a URL identity - mirrors
# comparators.normalize_origin, kept separate since that function only
# canonicalises bare origins (no path) and this one canonicalises full URLs.
_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_target_url(url: str) -> str:
    """Canonical form of a URL for target-identity matching: scheme and host
    lower-cased, a default port dropped, and a bare root path ("" vs "/")
    treated as the same address. The rest of the path (and query) stays
    case-sensitive - different resources are different targets. Falls back to
    lower-cased opaque text for anything that isn't a plain http(s) URL, so a
    malformed value still normalises deterministically instead of raising."""
    text = re.sub(r"\s+", " ", url.strip())
    try:
        parts = urlsplit(text)
    except ValueError:
        return text.lower()
    if not parts.scheme or not parts.hostname:
        return text.lower()
    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    host_text = f"[{host}]" if ":" in host else host
    port = parts.port
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        host_text = f"{host_text}:{port}"
    path = "" if parts.path in ("", "/") else parts.path
    query = f"?{parts.query}" if parts.query else ""
    return f"{scheme}://{host_text}{path}{query}"


def _target_identity(report: models.ScanReport) -> tuple[str, str]:
    """This report's comparison identity: a normalised URL when one exists
    (a fetched URL, or a raw scan's user-supplied Target URL), otherwise the
    normalised target name. Two reports are the same target exactly when
    their identities are equal - this is what lets a raw-response scan with a
    Target URL compare against a real URL-mode scan of the same address, not
    just against other raw scans."""
    if report.source == "url" and report.target:
        return ("url", normalize_target_url(report.target))
    if report.source == "raw" and report.target_url:
        return ("url", normalize_target_url(report.target_url))
    return ("name", normalize_target_name(report.target))


def is_anonymous_raw_target(report: models.ScanReport) -> bool:
    """No stable identity to compare by: a raw scan left at the default name
    and given no Target URL. The API now requires a Target URL for every new
    raw scan, so this only ever applies to a scan saved before that - never
    to one made after this validation was added."""
    if report.source != "raw" or report.target_url:
        return False
    return normalize_target_name(report.target) == normalize_target_name(DEFAULT_RAW_TARGET_NAME)


def _same_target(current: models.ScanReport, other: models.ScanReport) -> bool:
    """Same logical target - by identity (see `_target_identity`), not by
    source, so a raw scan tagged with a Target URL matches a real URL-mode
    scan of the same address."""
    return _target_identity(current) == _target_identity(other)


def _earlier_reports(db: Session, current: models.ScanReport):
    """The same user's earlier reports (any source - `_same_target` decides
    what counts as the same target), most recent first."""
    return (
        db.query(models.ScanReport)
        .filter(
            models.ScanReport.owner_id == current.owner_id,
            models.ScanReport.id != current.id,
            models.ScanReport.scanned_at < current.scanned_at,
        )
        .order_by(models.ScanReport.scanned_at.desc(), models.ScanReport.id.desc())
    )


def find_previous_comparable_report(db: Session, current: models.ScanReport) -> models.ScanReport | None:
    """The immediately preceding eligible scan: same user, target, policy and
    policy version, scanned strictly earlier. Ad-hoc reports (no policy_id)
    and raw-response scans left at the default target name have no stable
    identity, so they never match."""
    if current.policy_id is None or is_anonymous_raw_target(current):
        return None
    for candidate in _earlier_reports(db, current).filter(
        models.ScanReport.policy_id == current.policy_id,
        models.ScanReport.policy_version == current.policy_version,
    ):
        if _same_target(current, candidate):
            return candidate
    return None


def _why_no_comparison(db: Session, current: models.ScanReport) -> str:
    """Explains a missing comparison by looking at the most recent earlier scan
    of the same target, whatever policy it used."""
    for candidate in _earlier_reports(db, current):
        if not _same_target(current, candidate):
            continue
        if candidate.policy_id != current.policy_id:
            return "different_policy"
        if candidate.policy_version != current.policy_version:
            return "policy_version_changed"
    return "no_previous_scan"


def build_comparison_for_report(db: Session, report: models.ScanReport) -> ComparisonResponse:
    if report.policy_id is None:
        return ComparisonResponse(has_comparison=False, reason="ad_hoc_policy")
    if is_anonymous_raw_target(report):
        return ComparisonResponse(has_comparison=False, reason="raw_default_target")

    if report.previous_report_id:
        # The scan this one was compared against when it was saved. If it has
        # been deleted the comparison is unavailable - never re-pointed at an
        # older scan.
        previous = db.get(models.ScanReport, report.previous_report_id)
        if previous is None or previous.owner_id != report.owner_id:
            return ComparisonResponse(has_comparison=False, reason="previous_report_unavailable")
        return compare_reports(previous, report)

    # Reports saved before the link was recorded (or with no earlier scan).
    previous = find_previous_comparable_report(db, report)
    if previous is None:
        return ComparisonResponse(has_comparison=False, reason=_why_no_comparison(db, report))
    return compare_reports(previous, report)


def find_target_history(db: Session, current: models.ScanReport) -> list[models.ScanReport]:
    """Every one of the user's scans of the same target as `current` (see
    `_target_identity`) - unlike `find_previous_comparable_report`, this spans
    every policy version, not just the current one, and returns every match,
    not just the immediately preceding one. Oldest first, `current` included.
    Ad-hoc scans and raw scans with no stable identity are never candidates,
    same rule as comparison."""
    if current.policy_id is None or is_anonymous_raw_target(current):
        return []
    candidates = (
        db.query(models.ScanReport)
        .filter(
            models.ScanReport.owner_id == current.owner_id,
            models.ScanReport.policy_id.isnot(None),
        )
        .order_by(models.ScanReport.scanned_at.asc(), models.ScanReport.id.asc())
        .all()
    )
    return [r for r in candidates if not is_anonymous_raw_target(r) and _same_target(current, r)]


def build_target_history(db: Session, report: models.ScanReport) -> TargetHistoryResponse:
    """The data behind the report page's Score History chart: this target's
    score across every scan, spanning policy versions (the frontend marks
    where the policy version changes rather than hiding those scans)."""
    if report.policy_id is None:
        return TargetHistoryResponse(has_history=False, reason="ad_hoc_policy")
    if is_anonymous_raw_target(report):
        return TargetHistoryResponse(has_history=False, reason="anonymous_target")

    points = [
        TargetHistoryPoint(
            id=r.id,
            scan_number=r.scan_number,
            score=r.score,
            grade=r.grade,
            policy_name=r.policy_name,
            policy_version=r.policy_version,
            scanned_at=r.scanned_at,
        )
        for r in find_target_history(db, report)
    ]
    if len(points) < 2:
        # A single scan has nothing to trend against yet - still hand back
        # the one point so the frontend can say "not enough history yet"
        # instead of pretending this scan doesn't exist.
        return TargetHistoryResponse(has_history=False, reason="not_enough_data", points=points)
    return TargetHistoryResponse(has_history=True, points=points)


def compare_reports(previous: models.ScanReport, latest: models.ScanReport) -> ComparisonResponse:
    headers_added, headers_removed, headers_changed = _diff_headers(
        previous.findings or [], latest.findings or []
    )
    findings_resolved, findings_new, severity_changes = _diff_findings(
        previous.findings or [], latest.findings or []
    )
    csp_changes = _diff_csp(previous.csp_finding, latest.csp_finding)
    applicability_changes = _diff_applicability(
        previous.findings or [],
        latest.findings or [],
        previous.csp_finding,
        latest.csp_finding,
        previous.target_type,
        latest.target_type,
    )

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
        applicability_changes=len(applicability_changes),
    )

    changes = ComparisonChanges(
        headers_added=headers_added,
        headers_removed=headers_removed,
        headers_changed=headers_changed,
        findings_resolved=findings_resolved,
        findings_new=findings_new,
        severity_changes=severity_changes,
        csp_changes=csp_changes,
        applicability_changes=applicability_changes,
    )

    return ComparisonResponse(
        has_comparison=True,
        previous_report=ComparisonReportRef(
            id=previous.id,
            scan_number=previous.scan_number,
            target=previous.target,
            target_url=previous.target_url,
            target_type=previous.target_type,
            score=previous.score,
            grade=previous.grade,
            scanned_at=previous.scanned_at,
        ),
        latest_report=ComparisonReportRef(
            id=latest.id,
            scan_number=latest.scan_number,
            target=latest.target,
            target_url=latest.target_url,
            target_type=latest.target_type,
            score=latest.score,
            grade=latest.grade,
            scanned_at=latest.scanned_at,
        ),
        summary=summary,
        changes=changes,
        target_type_changed=bool(
            previous.target_type and latest.target_type and previous.target_type != latest.target_type
        ),
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
            # Formatting-only differences (spacing, directive order, origin
            # casing) are not changes; each header judges its own values.
            if not values_equivalent(name, prev_value, latest_value):
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
        # N/A <-> applicable is reported separately (see _diff_applicability);
        # it is not a security improvement or regression.
        if _applicable(prev) != _applicable(latest):
            continue
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


def _applicable(finding: dict | None) -> bool:
    """Findings saved before applicability existed have no flag: applicable."""
    return True if finding is None else finding.get("applicable", True) is not False


def _applicability_reason(
    prev: dict | None, latest: dict | None, previous_type: str | None, latest_type: str | None
) -> str | None:
    if previous_type and latest_type and previous_type != latest_type:
        return f"Target type changed from {target_type_label(previous_type)} to {target_type_label(latest_type)}."
    if not _applicable(latest):
        return (latest or {}).get("applicability_reason")
    reason = (prev or {}).get("applicability_reason")
    return f"Previously not applicable: {reason}" if reason else None


def _applicability_status(finding: dict | None) -> str:
    if not _applicable(finding):
        return "NOT_APPLICABLE"
    return (finding or {}).get("status", "PASS")


def _diff_applicability(
    prev_findings: list[dict],
    latest_findings: list[dict],
    prev_csp: dict | None,
    latest_csp: dict | None,
    previous_type: str | None,
    latest_type: str | None,
) -> list[ApplicabilityChange]:
    changes: list[ApplicabilityChange] = []
    prev_by_name = {f["header"]: f for f in prev_findings}
    latest_by_name = {f["header"]: f for f in latest_findings}
    for name in sorted(set(prev_by_name) & set(latest_by_name)):
        prev, latest = prev_by_name[name], latest_by_name[name]
        if _applicable(prev) == _applicable(latest):
            continue
        changes.append(
            ApplicabilityChange(
                header=name,
                previous_applicable=_applicable(prev),
                latest_applicable=_applicable(latest),
                previous_status=_applicability_status(prev),
                latest_status=_applicability_status(latest),
                reason=_applicability_reason(prev, latest, previous_type, latest_type),
            )
        )
    if prev_csp is not None and latest_csp is not None and _applicable(prev_csp) != _applicable(latest_csp):
        def csp_status(c: dict) -> str:
            if not _applicable(c):
                return "NOT_APPLICABLE"
            return "PASS" if c.get("policy_checks_passed", 0) == c.get("policy_checks_total", 0) else "FAIL"

        changes.append(
            ApplicabilityChange(
                header="Content-Security-Policy",
                previous_applicable=_applicable(prev_csp),
                latest_applicable=_applicable(latest_csp),
                previous_status=csp_status(prev_csp),
                latest_status=csp_status(latest_csp),
                reason=_applicability_reason(prev_csp, latest_csp, previous_type, latest_type),
            )
        )
    return changes


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
    # A CSP that was (or is now) not applicable has no checks to compare; the
    # flip itself is reported by _diff_applicability.
    if (prev_csp is not None and not _applicable(prev_csp)) or (
        latest_csp is not None and not _applicable(latest_csp)
    ):
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
        if _source_set(prev_value) != _source_set(latest_value):
            changes.append(
                CSPDirectiveChanged(directive=directive, previous_value=prev_value, latest_value=latest_value)
            )
    return changes


def _source_set(sources: list[str] | None) -> frozenset[str] | None:
    """CSP source order and casing carry no meaning, so directives compare as sets."""
    return None if sources is None else frozenset(t.lower() for t in sources)

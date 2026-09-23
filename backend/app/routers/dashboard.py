from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models
from app.core.deps import get_current_user
from app.core.scoring import grade_for_score
from app.database import get_db
from app.schemas import (
    DashboardBaselinesInfo,
    DashboardFindings,
    DashboardPoliciesInfo,
    DashboardRecentPolicy,
    DashboardReportsInfo,
    DashboardScan,
    DashboardSummary,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

# The dashboard is an overview, not a second Reports/Policies page - these
# caps deliberately keep it to a small, glanceable slice of the user's data.
RECENT_SCANS_LIMIT = 5
RECENT_POLICIES_LIMIT = 4

# Only these severities are shown on the findings summary (matches the
# product spec's Critical/High/Medium/Low table). Anything else - e.g. the
# "info" severity - is left out of the tally rather than folded into one of
# these.
TRACKED_SEVERITIES = ("critical", "high", "medium", "low")


def _csp_passed(csp_finding: dict | None) -> bool | None:
    """CSP has no single PASS/FAIL field of its own - it's a list of policy
    and best-practice checks - so, same rule the regular header comparators
    already use, it counts as failed if ANY of its checks failed. Returns
    None when the policy didn't check CSP at all (nothing to count)."""
    if csp_finding is None:
        return None
    checks = [*(csp_finding.get("policy_checks") or []), *(csp_finding.get("security_checks") or [])]
    return not any(c.get("status") == "FAIL" for c in checks)


def _passed_failed(report: models.ScanReport) -> tuple[int, int]:
    findings = report.findings or []
    passed = sum(1 for f in findings if f.get("status") == "PASS")
    failed = sum(1 for f in findings if f.get("status") == "FAIL")
    csp_ok = _csp_passed(report.csp_finding)
    if csp_ok is True:
        passed += 1
    elif csp_ok is False:
        failed += 1
    return passed, failed


def _severity_counts(report: models.ScanReport) -> dict[str, int]:
    """Each failing regular-header finding is bucketed by its header's own
    severity. Each failing CSP check is now bucketed by *its own* severity
    (app.core.csp_findings) rather than a single flat severity for the whole
    CSP header - individual CSP findings genuinely differ in severity (e.g.
    a missing base-uri is low, unsafe-inline is high)."""
    counts = {s: 0 for s in TRACKED_SEVERITIES}
    for finding in report.findings or []:
        if finding.get("status") != "FAIL":
            continue
        severity = finding.get("severity")
        if severity in counts:
            counts[severity] += 1

    csp_finding = report.csp_finding or {}
    csp_checks = [*(csp_finding.get("policy_checks") or []), *(csp_finding.get("security_checks") or [])]
    for check in csp_checks:
        if check.get("status") != "FAIL":
            continue
        severity = check.get("severity")
        if severity in counts:
            counts[severity] += 1

    return counts


def _to_dashboard_scan(report: models.ScanReport) -> DashboardScan:
    passed, failed = _passed_failed(report)
    return DashboardScan(
        id=report.id,
        scan_number=report.scan_number,
        policy_id=report.policy_id,
        policy_name=report.policy_name,
        policy_version=report.policy_version,
        source=report.source,
        target=report.target,
        score=report.score,
        grade=report.grade,
        passed=passed,
        failed=failed,
        headers_evaluated=report.headers_evaluated,
        findings=DashboardFindings(**_severity_counts(report)),
        scanned_at=report.scanned_at,
    )


@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    reports = (
        db.query(models.ScanReport)
        .filter(models.ScanReport.owner_id == current_user.id)
        .order_by(models.ScanReport.scanned_at.desc())
        .all()
    )

    total_reports = len(reports)
    average_score: float | None = None
    average_grade: str | None = None
    if total_reports:
        average_score = round(sum(r.score for r in reports) / total_reports, 1)
        average_grade = grade_for_score(average_score)

    severity_counts = {s: 0 for s in TRACKED_SEVERITIES}
    for report in reports:
        for severity, count in _severity_counts(report).items():
            severity_counts[severity] += count

    latest_scan = _to_dashboard_scan(reports[0]) if reports else None
    recent_scans = [_to_dashboard_scan(r) for r in reports[:RECENT_SCANS_LIMIT]]

    total_policies = (
        db.query(func.count(models.Policy.id))
        .filter(models.Policy.owner_id == current_user.id)
        .scalar()
        or 0
    )
    total_baselines = (
        db.query(func.count(models.Policy.id))
        .filter(models.Policy.is_baseline.is_(True))
        .scalar()
        or 0
    )
    recent_policies = (
        db.query(models.Policy)
        .filter(models.Policy.owner_id == current_user.id)
        .order_by(models.Policy.updated_at.desc())
        .limit(RECENT_POLICIES_LIMIT)
        .all()
    )

    return DashboardSummary(
        reports=DashboardReportsInfo(total=total_reports),
        policies=DashboardPoliciesInfo(total=total_policies),
        baselines=DashboardBaselinesInfo(total=total_baselines),
        average_score=average_score,
        average_grade=average_grade,
        latest_scan=latest_scan,
        recent_scans=recent_scans,
        findings=DashboardFindings(**severity_counts),
        recent_policies=[
            DashboardRecentPolicy(
                id=p.id,
                name=p.name,
                version=p.version,
                header_count=len(p.headers or []),
                has_csp_policy=p.csp_policy is not None,
                created_at=p.created_at,
                updated_at=p.updated_at,
            )
            for p in recent_policies
        ],
    )

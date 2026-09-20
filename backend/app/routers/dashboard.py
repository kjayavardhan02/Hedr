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
# "info" severity, or a CSP finding, which never appears in `findings` at
# all - is left out of the tally rather than folded into one of these.
TRACKED_SEVERITIES = ("critical", "high", "medium", "low")


def _passed_failed(findings: list[dict]) -> tuple[int, int]:
    passed = sum(1 for f in findings if f.get("status") == "PASS")
    failed = sum(1 for f in findings if f.get("status") == "FAIL")
    return passed, failed


def _to_dashboard_scan(report: models.ScanReport) -> DashboardScan:
    passed, failed = _passed_failed(report.findings or [])
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
        for finding in report.findings or []:
            if finding.get("status") != "FAIL":
                continue
            severity = finding.get("severity")
            if severity in severity_counts:
                severity_counts[severity] += 1

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
                created_at=p.created_at,
                updated_at=p.updated_at,
            )
            for p in recent_policies
        ],
    )

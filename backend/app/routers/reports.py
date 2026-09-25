from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models
from app.core import scan_comparison
from app.core.deps import get_current_user
from app.database import get_db
from app.schemas import ComparisonResponse, ReportsExportRequest, ScanReportOut, ScanReportSummary

router = APIRouter(prefix="/api/reports", tags=["reports"])

# A soft cap on how many saved reports a single list call returns. Reports
# accumulate over time (one per scan), so this keeps the response bounded
# without needing full pagination for what is, for now, a hobby-scale table.
MAX_REPORTS_LISTED = 200


@router.get("", response_model=list[ScanReportSummary])
def list_reports(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return (
        db.query(models.ScanReport)
        .filter(models.ScanReport.owner_id == current_user.id)
        .order_by(models.ScanReport.scanned_at.desc())
        .limit(MAX_REPORTS_LISTED)
        .all()
    )


@router.post("/export", response_model=list[ScanReportOut])
def export_reports(
    payload: ReportsExportRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Full reports (findings included) for the given ids, for bulk export.
    Ids that don't exist or belong to someone else are silently skipped, the
    same not-found treatment as the single-report endpoint."""
    return (
        db.query(models.ScanReport)
        .filter(
            models.ScanReport.owner_id == current_user.id,
            models.ScanReport.id.in_(payload.ids),
        )
        .order_by(models.ScanReport.scanned_at.desc())
        .all()
    )


@router.get("/{report_id}", response_model=ScanReportOut)
def get_report(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    report = db.get(models.ScanReport, report_id)
    if report is None or report.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Report not found.")
    return report


@router.get("/{report_id}/comparison", response_model=ComparisonResponse)
def get_report_comparison(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    report = db.get(models.ScanReport, report_id)
    if report is None or report.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Report not found.")
    return scan_comparison.build_comparison_for_report(db, report)


@router.delete("/{report_id}", status_code=204)
def delete_report(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    report = db.get(models.ScanReport, report_id)
    if report is None or report.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Report not found.")
    db.delete(report)
    db.commit()
    return None

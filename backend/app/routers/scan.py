from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models
from app.core.applicability import describe_target_types
from app.core.deps import get_current_user
from app.core.fetcher import FetchError, SSRFBlockedError, fetch_headers
from app.core.header_parser import RawResponseParseError, parse_raw_response
from app.core.policy_engine import run_scan
from app.core.policy_resolution import PolicyNotFoundError, resolve_policy_by_id
from app.core.scan_comparison import DEFAULT_RAW_TARGET_NAME, find_previous_comparable_report
from app.database import get_db
from app.schemas import CSPPolicy, PolicyHeaderIn, ScanRequest, ScanResult, ScanSource, TargetTypeInfo

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.get("/target-types", response_model=list[TargetTypeInfo])
def list_target_types(current_user: models.User = Depends(get_current_user)):
    """Each target type, with the headers it marks N/A."""
    return describe_target_types()


@router.post("", response_model=ScanResult)
def scan(
    payload: ScanRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # --- Resolve headers to analyze -----------------------------------
    target: str | None = None
    target_url: str | None = None
    fetched_status_code: int | None = None

    if payload.source == ScanSource.url:
        if not payload.url or not payload.url.strip():
            raise HTTPException(status_code=422, detail="A URL is required for source=url.")
        try:
            result = fetch_headers(payload.url.strip())
        except SSRFBlockedError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except FetchError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        raw_headers = result.headers
        target = result.final_url
        fetched_status_code = result.status_code
    else:
        if not payload.raw_response or not payload.raw_response.strip():
            raise HTTPException(status_code=422, detail="raw_response is required for source=raw.")
        if not payload.target_url:
            raise HTTPException(
                status_code=422,
                detail="A Target URL is required for source=raw, so this scan can be matched to future scans "
                "of the same target.",
            )
        try:
            status_code, raw_headers = parse_raw_response(payload.raw_response)
        except RawResponseParseError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        fetched_status_code = status_code
        # There's no URL to label a pasted response with - let the user
        # name it, or fall back to a generic label.
        target = (
            payload.target_name.strip()
            if payload.target_name and payload.target_name.strip()
            else DEFAULT_RAW_TARGET_NAME
        )
        # Already validated (http/https, has a host) and never fetched - it's
        # purely a comparison identity for this pasted response.
        target_url = payload.target_url

    # --- Resolve policy --------------------------------------------------
    policy_headers: list[PolicyHeaderIn]
    policy_name: str
    policy_version: str
    used_policy_id: str | None
    csp_policy: CSPPolicy | None

    if payload.policy_id:
        try:
            resolved = resolve_policy_by_id(db, payload.policy_id, current_user)
        except PolicyNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Policy not found.") from exc
        policy_headers = resolved.policy_headers
        policy_name = resolved.policy_name
        policy_version = resolved.policy_version
        used_policy_id = resolved.policy.id
        csp_policy = resolved.csp_policy
    elif payload.policy:
        if not payload.policy.headers and payload.policy.csp_policy is None:
            raise HTTPException(
                status_code=422, detail="Inline policy must include at least one header or a CSP policy."
            )
        policy_headers = payload.policy.headers
        policy_name = payload.policy.name or "Ad-hoc Policy"
        # Ad-hoc policies aren't saved anywhere, so "v1" would falsely
        # imply a version history that doesn't exist - label it plainly.
        policy_version = "ad-hoc"
        used_policy_id = None
        csp_policy = payload.policy.csp_policy
    else:
        raise HTTPException(status_code=422, detail="Either policy_id or policy must be provided.")

    scan_result = run_scan(
        raw_headers=raw_headers,
        policy_name=policy_name,
        policy_headers=policy_headers,
        source=payload.source,
        target=target,
        fetched_status_code=fetched_status_code,
        csp_policy=csp_policy,
        target_url=target_url,
        target_type=payload.target_type,
    )

    # Save a report of this scan - only the policy-scoped findings/CSP
    # finding, never the full raw_headers dump (see models.ScanReport). A
    # failure here must never take down the scan itself - the caller's
    # deterministic result is the primary value of this endpoint.
    try:
        last_scan_number = (
            db.query(func.max(models.ScanReport.scan_number))
            .filter(models.ScanReport.owner_id == current_user.id)
            .scalar()
        )
        report = models.ScanReport(
            owner_id=current_user.id,
            scan_number=(last_scan_number or 0) + 1,
            policy_id=used_policy_id,
            policy_name=scan_result.policy_name,
            policy_version=policy_version,
            source=scan_result.source.value,
            target=scan_result.target,
            target_url=scan_result.target_url,
            fetched_status_code=scan_result.fetched_status_code,
            target_type=payload.target_type.value,
            score=scan_result.score,
            grade=scan_result.grade,
            findings=[f.model_dump(mode="json") for f in scan_result.findings],
            csp_finding=(
                scan_result.csp_finding.model_dump(mode="json") if scan_result.csp_finding else None
            ),
            scanned_at=scan_result.scanned_at,
            scanner_version=scan_result.scanner_version,
        )
        # Remember which scan this one is compared against, so deleting that
        # scan later makes the comparison unavailable rather than re-pointing it.
        previous = find_previous_comparable_report(db, report)
        report.previous_report_id = previous.id if previous else None
        db.add(report)
        db.commit()
    except Exception:
        db.rollback()

    return scan_result

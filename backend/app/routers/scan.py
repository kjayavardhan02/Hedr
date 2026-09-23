from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models
from app.core.deps import get_current_user
from app.core.fetcher import FetchError, SSRFBlockedError, fetch_headers
from app.core.header_parser import RawResponseParseError, parse_raw_response
from app.core.policy_engine import run_scan
from app.core.scan_comparison import DEFAULT_RAW_TARGET_NAME
from app.database import get_db
from app.schemas import CSPPolicy, PolicyHeaderIn, ScanRequest, ScanResult, ScanSource

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("", response_model=ScanResult)
def scan(
    payload: ScanRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # --- Resolve headers to analyze -----------------------------------
    target: str | None = None
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

    # --- Resolve policy --------------------------------------------------
    policy_headers: list[PolicyHeaderIn]
    policy_name: str
    policy_version: str
    used_policy_id: str | None
    csp_policy: CSPPolicy | None

    if payload.policy_id:
        policy = db.get(models.Policy, payload.policy_id)
        if not policy or not (policy.is_baseline or policy.owner_id == current_user.id):
            raise HTTPException(status_code=404, detail="Policy not found.")
        policy_headers = [PolicyHeaderIn(**h) for h in policy.headers]
        policy_name = policy.name
        policy_version = f"v{policy.version}"
        used_policy_id = policy.id
        csp_policy = CSPPolicy(**policy.csp_policy) if policy.csp_policy else None
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
            fetched_status_code=scan_result.fetched_status_code,
            score=scan_result.score,
            grade=scan_result.grade,
            findings=[f.model_dump(mode="json") for f in scan_result.findings],
            csp_finding=(
                scan_result.csp_finding.model_dump(mode="json") if scan_result.csp_finding else None
            ),
            scanned_at=scan_result.scanned_at,
        )
        db.add(report)
        db.commit()
    except Exception:
        db.rollback()

    return scan_result

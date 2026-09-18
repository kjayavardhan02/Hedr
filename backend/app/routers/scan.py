from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models
from app.core.deps import get_current_user
from app.core.fetcher import FetchError, SSRFBlockedError, fetch_headers
from app.core.header_parser import RawResponseParseError, parse_raw_response
from app.core.policy_engine import run_scan
from app.database import get_db
from app.schemas import PolicyHeaderIn, ScanRequest, ScanResult, ScanSource

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

    # --- Resolve policy --------------------------------------------------
    policy_headers: list[PolicyHeaderIn]
    policy_name: str

    if payload.policy_id:
        policy = db.get(models.Policy, payload.policy_id)
        if not policy or not (policy.is_baseline or policy.owner_id == current_user.id):
            raise HTTPException(status_code=404, detail="Policy not found.")
        policy_headers = [PolicyHeaderIn(**h) for h in policy.headers]
        policy_name = policy.name
    elif payload.policy:
        if not payload.policy.headers:
            raise HTTPException(status_code=422, detail="Inline policy must include at least one header.")
        policy_headers = payload.policy.headers
        policy_name = payload.policy.name or "Ad-hoc Policy"
    else:
        raise HTTPException(status_code=422, detail="Either policy_id or policy must be provided.")

    return run_scan(
        raw_headers=raw_headers,
        policy_name=policy_name,
        policy_headers=policy_headers,
        source=payload.source,
        target=target,
        fetched_status_code=fetched_status_code,
    )

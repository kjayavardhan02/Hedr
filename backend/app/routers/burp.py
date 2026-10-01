from datetime import datetime, timezone

from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Response, UploadFile
from sqlalchemy.orm import Session

from app import models
from app.core.burp_aggregation import build_analysis
from app.core.burp_import import (
    BurpFilters,
    BurpParseError,
    EntryStatus,
    apply_filters,
    discover_facets,
    entry_from_dict,
    entry_to_dict,
    parse_burp_export,
)
from app.core.deps import get_current_user
from app.core.excel_export import build_workbook, export_filename
from app.core.policy_resolution import PolicyNotFoundError, resolve_policy_by_id
from app.database import get_db
from app.schemas import (
    BurpAnalyzeRequest,
    BurpFiltersIn,
    BurpImportFacets,
    BurpImportListItem,
    BurpImportOut,
    BurpImportSummary,
)

router = APIRouter(prefix="/api/burp", tags=["burp"])

MAX_IMPORTS_LISTED = 200


def _default_report_name(filename: str) -> str:
    stem = filename.rsplit(".", 1)[0] if "." in filename else filename
    return f"Burp History - {stem}"


def _get_owned_import(db: Session, import_id: str, current_user: models.User) -> models.BurpImport:
    record = db.get(models.BurpImport, import_id)
    if record is None or record.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Burp import not found.")
    return record


def _to_burp_filters(filters_in: BurpFiltersIn) -> BurpFilters:
    return BurpFilters(
        hosts=set(filters_in.hosts) if filters_in.hosts is not None else None,
        methods={m.upper() for m in filters_in.methods} if filters_in.methods is not None else None,
        status_buckets=set(filters_in.status_buckets) if filters_in.status_buckets is not None else None,
        content_types=set(filters_in.content_types) if filters_in.content_types is not None else None,
        https_only=filters_in.https_only,
        exclude_static=filters_in.exclude_static,
        deduplicate=filters_in.deduplicate,
    )


@router.post("/import", response_model=BurpImportSummary)
async def import_burp_history(
    file: UploadFile,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not file.filename:
        raise HTTPException(status_code=422, detail="No file was uploaded.")

    data = await file.read()
    try:
        entries = parse_burp_export(data)
    except BurpParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    parsed_count = sum(1 for e in entries if e.status == EntryStatus.PARSED)
    partial_count = sum(1 for e in entries if e.status == EntryStatus.PARTIAL)
    failed_count = sum(1 for e in entries if e.status == EntryStatus.FAILED)
    skipped_count = sum(1 for e in entries if e.status == EntryStatus.SKIPPED)
    facets = discover_facets(entries)

    record = models.BurpImport(
        owner_id=current_user.id,
        name=_default_report_name(file.filename),
        source_filename=file.filename,
        status="parsed",
        parsed_entries=[entry_to_dict(e) for e in entries],
        entries_found=len(entries),
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return BurpImportSummary(
        id=record.id,
        name=record.name,
        source_filename=record.source_filename,
        entries_found=len(entries),
        parsed_count=parsed_count,
        partial_count=partial_count,
        failed_count=failed_count,
        skipped_count=skipped_count,
        facets=BurpImportFacets(**facets),
        imported_at=record.imported_at,
    )


@router.post("/{import_id}/analyze", response_model=BurpImportOut)
def analyze_burp_import(
    import_id: str,
    payload: BurpAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    record = _get_owned_import(db, import_id, current_user)

    try:
        resolved = resolve_policy_by_id(db, payload.policy_id, current_user)
    except PolicyNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Policy not found.") from exc

    entries = [entry_from_dict(e) for e in record.parsed_entries]
    apply_filters(entries, _to_burp_filters(payload.filters))
    analysis = build_analysis(entries, resolved)

    record.policy_id = resolved.policy.id
    record.policy_name = resolved.policy_name
    record.policy_version = resolved.policy_version
    record.filters = payload.filters.model_dump(mode="json")
    record.analysis = analysis.model_dump(mode="json")
    record.score = analysis.summary.overall_score
    record.responses_analyzed = analysis.summary.responses_analyzed
    record.responses_skipped = sum(1 for e in entries if e.status == EntryStatus.SKIPPED)
    record.parse_failures = sum(1 for e in entries if e.status == EntryStatus.FAILED)
    record.status = "analyzed"
    record.analyzed_at = datetime.now(timezone.utc)
    if payload.name and payload.name.strip():
        record.name = payload.name.strip()

    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.get("", response_model=list[BurpImportListItem])
def list_burp_imports(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return (
        db.query(models.BurpImport)
        .filter(models.BurpImport.owner_id == current_user.id)
        .order_by(models.BurpImport.imported_at.desc())
        .limit(MAX_IMPORTS_LISTED)
        .all()
    )


@router.get("/{import_id}", response_model=BurpImportOut)
def get_burp_import(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return _get_owned_import(db, import_id, current_user)


@router.get("/{import_id}/export")
def export_burp_import(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    record = _get_owned_import(db, import_id, current_user)
    if record.analysis is None:
        raise HTTPException(status_code=409, detail="This import hasn't been analyzed yet.")

    # The policy the import was analyzed against, for the workbook's Policy
    # sheet - it may have been deleted or edited since (build_workbook copes).
    policy = db.get(models.Policy, record.policy_id) if record.policy_id else None
    workbook_bytes = build_workbook(record, policy)
    filename = export_filename(record)
    # ASCII fallback for older clients, plus the UTF-8 filename* form so a
    # report name with non-ASCII characters still downloads with the right name.
    ascii_fallback = filename.encode("ascii", "ignore").decode("ascii") or "Burp History Security Header Analysis.xlsx"
    content_disposition = f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{quote(filename)}"

    return Response(
        content=workbook_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": content_disposition},
    )


@router.delete("/{import_id}", status_code=204)
def delete_burp_import(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    record = _get_owned_import(db, import_id, current_user)
    db.delete(record)
    db.commit()
    return None

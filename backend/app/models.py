import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """SQLite has no timezone-aware datetime type - a tz-aware value written
    via plain DateTime comes back on read stripped to naive, which then
    serializes to JSON with no offset and gets misread as local time by the
    browser (e.g. a UTC timestamp read as IST, ~5.5h off). This re-attaches
    UTC on the way out so every API response is unambiguous."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is not None and value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value: datetime | None, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    first_name: Mapped[str] = mapped_column(String, nullable=False)
    last_name: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    # List[{"header_name": str, "expected_value": str, "required": bool}].
    # Never contains a Content-Security-Policy entry - CSP is configured
    # separately below, since it needs a structured rule set rather than one
    # opaque expected-value string (see schemas.CSPPolicy).
    headers: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # CSPPolicy-shaped dict, or null when this policy doesn't evaluate CSP.
    csp_policy: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    is_baseline: Mapped[bool] = mapped_column(Boolean, default=False)
    baseline_key: Mapped[str | None] = mapped_column(String, nullable=True)
    # Null for baseline policies (shared/global). Every custom policy is
    # owned by exactly the user who created it - only that user may view,
    # use, edit, or delete it.
    owner_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("users.id"), nullable=True, index=True
    )
    # Starts at 1 on creation, incremented on every successful edit. Never
    # reset or diffed against content - each saved edit is a new version.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=_now, onupdate=_now
    )


class ScanReport(Base):
    """A saved scan result. Deliberately does NOT store the raw response
    headers - only the per-header findings the policy actually evaluated
    (plus the CSP finding, when the policy checks CSP). A scan can return
    dozens of unrelated headers (Date, Server, Set-Cookie, ...); saving all
    of them for every scan would bloat the table for data nobody asked to
    track. Findings are already scoped to exactly the headers named in the
    policy, so persisting them as-is naturally satisfies that constraint."""

    __tablename__ = "scan_reports"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    owner_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    # Per-user sequential number (1, 2, 3, ...). Computed as MAX+1 at
    # creation time rather than a row count, so deleting a report never
    # causes a later scan to reuse a number that's still in use elsewhere.
    scan_number: Mapped[int] = mapped_column(Integer, nullable=False)
    # The id of the Policy used for this scan, or null for an ad-hoc policy.
    # Deliberately not a ForeignKey - this is a historical pointer, not a
    # live relationship. Deleting the policy later must NOT touch this row;
    # the frontend re-checks GET /api/policies/{id} to see if it still
    # resolves before treating it as a working link.
    policy_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    policy_name: Mapped[str] = mapped_column(String, nullable=False)
    # The report this one was compared against when it was saved (the
    # immediately preceding eligible scan), or null when there was none.
    # Like policy_id it is a historical pointer, not a ForeignKey: if that
    # report is later deleted the comparison is reported as unavailable
    # instead of silently switching to an older scan.
    previous_report_id: Mapped[str | None] = mapped_column(String, nullable=True)
    # No real policy versioning exists yet - every report is stamped "v1"
    # until that's built, so the column already exists when it is.
    policy_version: Mapped[str] = mapped_column(String, nullable=False, default="v1")
    source: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str | None] = mapped_column(String, nullable=True)
    fetched_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    grade: Mapped[str] = mapped_column(String, nullable=False)
    # List[HeaderFinding-shaped dicts], scoped to only the headers the
    # policy named - never the full raw response header set.
    findings: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # CSPFinding-shaped dict, or null when the policy didn't check CSP.
    csp_finding: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, index=True)

    @property
    def headers_evaluated(self) -> int:
        """Count of headers this scan actually evaluated - the findings
        plus one more if CSP was checked (CSP isn't in `findings`, it has
        its own dedicated finding)."""
        return len(self.findings or []) + (1 if self.csp_finding else 0)

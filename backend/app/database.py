import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./hedr.db")

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_schema(bind=engine) -> None:
    """Adds columns introduced after a database was first created.

    create_all() only creates missing tables, never missing columns, and this
    project has no migration tooling, so a new nullable column would otherwise
    require deleting the database. Each entry here is idempotent."""
    from sqlalchemy import inspect, text

    inspector = inspect(bind)
    if "scan_reports" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("scan_reports")}
    if "previous_report_id" not in existing:
        with bind.begin() as conn:
            conn.execute(text("ALTER TABLE scan_reports ADD COLUMN previous_report_id VARCHAR"))
    if "scanner_version" not in existing:
        with bind.begin() as conn:
            conn.execute(text("ALTER TABLE scan_reports ADD COLUMN scanner_version VARCHAR"))
    if "target_url" not in existing:
        with bind.begin() as conn:
            conn.execute(text("ALTER TABLE scan_reports ADD COLUMN target_url VARCHAR"))
    if "target_type" not in existing:
        with bind.begin() as conn:
            conn.execute(text("ALTER TABLE scan_reports ADD COLUMN target_type VARCHAR"))

    if "burp_imports" in inspector.get_table_names():
        existing_burp_cols = {c["name"] for c in inspector.get_columns("burp_imports")}
        if "target_type" not in existing_burp_cols:
            with bind.begin() as conn:
                conn.execute(text("ALTER TABLE burp_imports ADD COLUMN target_type VARCHAR"))

    if "users" in inspector.get_table_names():
        existing_user_cols = {c["name"] for c in inspector.get_columns("users")}
        for column in (
            "username",
            "organization",
            "job_title",
            "password_changed_at",
            "default_policy_id",
            "theme",
            "accent_color",
        ):
            if column not in existing_user_cols:
                with bind.begin() as conn:
                    conn.execute(text(f"ALTER TABLE users ADD COLUMN {column} VARCHAR"))

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

"""Test setup: point the app at a throwaway SQLite file before anything
imports app.database, so tests never touch the real hedr.db.
"""
import atexit
import os
import tempfile

import pytest

_fd, _db_path = tempfile.mkstemp(suffix=".db", prefix="hedr-test-")
os.close(_fd)
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"
atexit.register(lambda: os.path.exists(_db_path) and os.remove(_db_path))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c

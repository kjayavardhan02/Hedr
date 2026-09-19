"""Test setup: point the app at a throwaway SQLite file and a fixed test
JWT secret before anything imports app.database / app.core.security, so
tests never touch the real hedr.db or depend on a real secret being set.
"""
import atexit
import os
import tempfile
import uuid

import pytest

_fd, _db_path = tempfile.mkstemp(suffix=".db", prefix="hedr-test-")
os.close(_fd)
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"
os.environ["JWT_SECRET_KEY"] = "test-only-secret-not-for-production"
os.environ["COOKIE_SECURE"] = "false"
atexit.register(lambda: os.path.exists(_db_path) and os.remove(_db_path))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

DEFAULT_PASSWORD = "correct-horse-battery-staple"
DEFAULT_FIRST_NAME = "Ada"
DEFAULT_LAST_NAME = "Lovelace"


@pytest.fixture
def client():
    """A fresh TestClient (and cookie jar) per test, sharing the one
    persistent temp DB across the whole run."""
    with TestClient(app) as c:
        yield c


def _unique_email() -> str:
    return f"user-{uuid.uuid4().hex}@example.com"


@pytest.fixture
def auth_client(client):
    """A TestClient already logged in as a freshly-registered, unique user.
    Returns (client, user_dict) - the session cookie lives on `client`."""
    email = _unique_email()
    resp = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": DEFAULT_PASSWORD,
            "first_name": DEFAULT_FIRST_NAME,
            "last_name": DEFAULT_LAST_NAME,
        },
    )
    assert resp.status_code == 201, resp.text
    return client, resp.json()


@pytest.fixture
def make_user(client):
    """Factory for a second (or third...) independent, already-authenticated
    user, sharing the same underlying TestClient instance. Since the two
    users can't be logged in on the same cookie jar simultaneously, this
    returns a helper that logs the given user back in on demand."""

    created = []

    def _create():
        email = _unique_email()
        resp = client.post(
            "/api/auth/register",
            json={
                "email": email,
                "password": DEFAULT_PASSWORD,
                "first_name": DEFAULT_FIRST_NAME,
                "last_name": DEFAULT_LAST_NAME,
            },
        )
        assert resp.status_code == 201, resp.text
        user = resp.json()
        created.append(user)
        return user

    return _create

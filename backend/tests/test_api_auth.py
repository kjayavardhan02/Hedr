import jwt

from app.config import JWT_ALGORITHM, JWT_SECRET_KEY, SESSION_COOKIE_NAME
from tests.conftest import DEFAULT_PASSWORD

POLICY_PAYLOAD = {
    "name": "Alice's Secret Policy",
    "description": "should not be visible to anyone else",
    "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
}


class TestRegister:
    def test_register_returns_user_without_password(self, client):
        resp = client.post(
            "/api/auth/register", json={"email": "a@example.com", "password": DEFAULT_PASSWORD}
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["email"] == "a@example.com"
        assert "password" not in body
        assert "hashed_password" not in body

    def test_register_sets_httponly_cookie(self, client):
        resp = client.post(
            "/api/auth/register", json={"email": "b@example.com", "password": DEFAULT_PASSWORD}
        )
        set_cookie = resp.headers.get("set-cookie", "")
        assert SESSION_COOKIE_NAME in set_cookie
        assert "httponly" in set_cookie.lower()
        assert "samesite=lax" in set_cookie.lower()

    def test_duplicate_email_rejected(self, client):
        payload = {"email": "dup@example.com", "password": DEFAULT_PASSWORD}
        first = client.post("/api/auth/register", json=payload)
        assert first.status_code == 201
        second = client.post("/api/auth/register", json=payload)
        assert second.status_code == 409

    def test_duplicate_email_case_insensitive(self, client):
        client.post("/api/auth/register", json={"email": "Case@Example.com", "password": DEFAULT_PASSWORD})
        second = client.post(
            "/api/auth/register", json={"email": "case@example.com", "password": DEFAULT_PASSWORD}
        )
        assert second.status_code == 409

    def test_weak_password_rejected(self, client):
        resp = client.post("/api/auth/register", json={"email": "weak@example.com", "password": "short"})
        assert resp.status_code == 422

    def test_invalid_email_rejected(self, client):
        resp = client.post(
            "/api/auth/register", json={"email": "not-an-email", "password": DEFAULT_PASSWORD}
        )
        assert resp.status_code == 422

    def test_overlong_password_rejected(self, client):
        resp = client.post(
            "/api/auth/register", json={"email": "long@example.com", "password": "a" * 200}
        )
        assert resp.status_code == 422


class TestLogin:
    def _register(self, client, email):
        client.post("/api/auth/register", json={"email": email, "password": DEFAULT_PASSWORD})
        client.post("/api/auth/logout")

    def test_login_success(self, client):
        self._register(client, "login-ok@example.com")
        resp = client.post(
            "/api/auth/login", json={"email": "login-ok@example.com", "password": DEFAULT_PASSWORD}
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "login-ok@example.com"

    def test_wrong_password_returns_generic_401(self, client):
        self._register(client, "login-wrong@example.com")
        resp = client.post(
            "/api/auth/login", json={"email": "login-wrong@example.com", "password": "wrong-password"}
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid email or password."

    def test_nonexistent_email_returns_same_generic_401(self, client):
        resp = client.post(
            "/api/auth/login", json={"email": "never-registered@example.com", "password": "whatever123"}
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid email or password."


class TestMe:
    def test_me_without_cookie_401(self, client):
        assert client.get("/api/auth/me").status_code == 401

    def test_me_with_valid_session(self, auth_client):
        client, user = auth_client
        resp = client.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.json()["id"] == user["id"]

    def test_me_with_garbage_cookie_401(self, client):
        client.cookies.set(SESSION_COOKIE_NAME, "not-a-real-jwt")
        assert client.get("/api/auth/me").status_code == 401

    def test_me_with_expired_token_401(self, client, auth_client):
        _, user = auth_client
        expired = jwt.encode(
            {"sub": user["id"], "exp": 1},  # epoch 1 - long expired
            JWT_SECRET_KEY,
            algorithm=JWT_ALGORITHM,
        )
        client.cookies.set(SESSION_COOKIE_NAME, expired)
        assert client.get("/api/auth/me").status_code == 401

    def test_me_with_token_for_deleted_user_401(self, client):
        forged = jwt.encode({"sub": "no-such-user-id"}, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        client.cookies.set(SESSION_COOKIE_NAME, forged)
        assert client.get("/api/auth/me").status_code == 401

    def test_me_with_wrong_signature_401(self, client, auth_client):
        _, user = auth_client
        forged = jwt.encode({"sub": user["id"]}, "wrong-secret", algorithm=JWT_ALGORITHM)
        client.cookies.set(SESSION_COOKIE_NAME, forged)
        assert client.get("/api/auth/me").status_code == 401


class TestLogout:
    def test_logout_clears_session(self, auth_client):
        client, _ = auth_client
        assert client.get("/api/auth/me").status_code == 200
        logout_resp = client.post("/api/auth/logout")
        assert logout_resp.status_code == 200
        assert client.get("/api/auth/me").status_code == 401


class TestOwnershipIsolation:
    """The core ask: a policy created by one user must not be usable,
    viewable, editable, or deletable by any other user."""

    def test_other_user_cannot_list_your_policy(self, auth_client, make_user):
        client, _owner = auth_client
        created = client.post("/api/policies", json=POLICY_PAYLOAD).json()

        make_user()  # switches the shared client's session to a second user
        listed_ids = {p["id"] for p in client.get("/api/policies").json()}
        assert created["id"] not in listed_ids

    def test_other_user_cannot_get_your_policy(self, auth_client, make_user):
        client, _owner = auth_client
        created = client.post("/api/policies", json=POLICY_PAYLOAD).json()

        make_user()
        resp = client.get(f"/api/policies/{created['id']}")
        assert resp.status_code == 404

    def test_other_user_cannot_update_your_policy(self, auth_client, make_user):
        client, _owner = auth_client
        created = client.post("/api/policies", json=POLICY_PAYLOAD).json()

        make_user()
        resp = client.put(
            f"/api/policies/{created['id']}",
            json={"name": "Hijacked", "description": "", "headers": POLICY_PAYLOAD["headers"]},
        )
        assert resp.status_code == 404

    def test_other_user_cannot_delete_your_policy(self, auth_client, make_user):
        client, _owner = auth_client
        created = client.post("/api/policies", json=POLICY_PAYLOAD).json()

        make_user()
        resp = client.delete(f"/api/policies/{created['id']}")
        assert resp.status_code == 404

    def test_other_user_cannot_scan_with_your_policy_id(self, auth_client, make_user):
        client, _owner = auth_client
        created = client.post("/api/policies", json=POLICY_PAYLOAD).json()

        make_user()
        resp = client.post(
            "/api/scan",
            json={
                "source": "raw",
                "raw_response": "HTTP/1.1 200 OK\nX-Frame-Options: DENY\n\n",
                "policy_id": created["id"],
            },
        )
        assert resp.status_code == 404

    def test_owner_still_has_full_access_after_another_user_exists(self, auth_client, make_user):
        client, owner = auth_client
        created = client.post("/api/policies", json=POLICY_PAYLOAD).json()

        make_user()  # a second user now exists and is the active session
        # Log back in as the original owner.
        client.post("/api/auth/login", json={"email": owner["email"], "password": DEFAULT_PASSWORD})

        assert client.get(f"/api/policies/{created['id']}").status_code == 200
        update = client.put(
            f"/api/policies/{created['id']}",
            json={"name": "Still mine", "description": "", "headers": POLICY_PAYLOAD["headers"]},
        )
        assert update.status_code == 200
        assert client.delete(f"/api/policies/{created['id']}").status_code == 204

    def test_all_users_can_see_and_use_baselines(self, auth_client, make_user):
        client, _owner = auth_client
        baseline_id = client.get("/api/policies/baselines").json()[0]["id"]

        make_user()
        assert client.get(f"/api/policies/{baseline_id}").status_code == 200
        listed_ids = {p["id"] for p in client.get("/api/policies").json()}
        assert baseline_id in listed_ids

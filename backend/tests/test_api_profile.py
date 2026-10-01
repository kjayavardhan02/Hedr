import uuid

import pytest

from tests.conftest import DEFAULT_PASSWORD


def _unique_username() -> str:
    return f"user-{uuid.uuid4().hex[:12]}"


def test_get_profile_requires_auth(client):
    assert client.get("/api/profile").status_code == 401


def test_get_profile_returns_defaults(auth_client):
    client, _ = auth_client
    body = client.get("/api/profile").json()
    assert body["username"] is None
    assert body["organization"] is None
    assert body["job_title"] is None
    assert body["default_policy_id"] is None
    assert body["password_changed_at"] is None
    assert body["two_factor_enabled"] is False
    assert body["theme"] == "dark"
    assert body["accent_color"] == "default"
    assert "hashed_password" not in body


class TestUpdateProfile:
    def test_patch_requires_auth(self, client):
        assert client.patch("/api/profile", json={"organization": "Acme"}).status_code == 401

    def test_updates_only_the_given_fields(self, auth_client):
        client, _ = auth_client
        resp = client.patch("/api/profile", json={"organization": "Acme Corp", "job_title": "Security Engineer"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["organization"] == "Acme Corp"
        assert body["job_title"] == "Security Engineer"
        # Untouched fields keep their existing values.
        assert body["first_name"]

    def test_sets_username(self, auth_client):
        client, _ = auth_client
        name = _unique_username()
        resp = client.patch("/api/profile", json={"username": name})
        assert resp.status_code == 200
        assert resp.json()["username"] == name

    def test_duplicate_username_rejected(self, auth_client, make_user):
        client, _ = auth_client
        name = _unique_username()
        assert client.patch("/api/profile", json={"username": name}).status_code == 200

        make_user()
        resp = client.patch("/api/profile", json={"username": name})
        assert resp.status_code == 409

    def test_blank_first_name_rejected(self, auth_client):
        client, _ = auth_client
        assert client.patch("/api/profile", json={"first_name": "   "}).status_code == 422

    def test_empty_string_clears_optional_fields(self, auth_client):
        client, _ = auth_client
        client.patch("/api/profile", json={"organization": "Acme"})
        resp = client.patch("/api/profile", json={"organization": ""})
        assert resp.status_code == 200
        assert resp.json()["organization"] is None

    def test_username_can_be_reused_after_being_cleared(self, auth_client, make_user):
        client, _ = auth_client
        name = _unique_username()
        assert client.patch("/api/profile", json={"username": name}).status_code == 200
        assert client.patch("/api/profile", json={"username": ""}).json()["username"] is None

        make_user()
        resp = client.patch("/api/profile", json={"username": name})
        assert resp.status_code == 200


class TestChangePassword:
    def test_requires_auth(self, client):
        resp = client.post(
            "/api/profile/password/change",
            json={"current_password": DEFAULT_PASSWORD, "new_password": "a-new-password-1"},
        )
        assert resp.status_code == 401

    def test_wrong_current_password_rejected(self, auth_client):
        client, _ = auth_client
        resp = client.post(
            "/api/profile/password/change",
            json={"current_password": "not-the-password", "new_password": "a-new-password-1"},
        )
        assert resp.status_code == 401
        assert client.get("/api/profile").json()["password_changed_at"] is None

    def test_same_password_rejected(self, auth_client):
        client, _ = auth_client
        resp = client.post(
            "/api/profile/password/change",
            json={"current_password": DEFAULT_PASSWORD, "new_password": DEFAULT_PASSWORD},
        )
        assert resp.status_code == 422

    def test_new_password_too_short_rejected(self, auth_client):
        client, _ = auth_client
        resp = client.post(
            "/api/profile/password/change",
            json={"current_password": DEFAULT_PASSWORD, "new_password": "short"},
        )
        assert resp.status_code == 422

    def test_successful_change_updates_timestamp_and_login(self, auth_client):
        client, user = auth_client
        resp = client.post(
            "/api/profile/password/change",
            json={"current_password": DEFAULT_PASSWORD, "new_password": "a-new-password-1"},
        )
        assert resp.status_code == 204
        assert client.get("/api/profile").json()["password_changed_at"] is not None

        client.post("/api/auth/logout")
        old_login = client.post("/api/auth/login", json={"email": user["email"], "password": DEFAULT_PASSWORD})
        assert old_login.status_code == 401
        new_login = client.post(
            "/api/auth/login", json={"email": user["email"], "password": "a-new-password-1"}
        )
        assert new_login.status_code == 200


class TestPreferences:
    def test_requires_auth(self, client):
        assert client.get("/api/profile/preferences").status_code == 401

    def test_defaults_to_no_default_policy(self, auth_client):
        client, _ = auth_client
        assert client.get("/api/profile/preferences").json() == {
            "default_policy_id": None,
            "theme": "dark",
            "accent_color": "default",
        }

    def test_can_set_an_owned_policy_as_default(self, auth_client):
        client, _ = auth_client
        policy = client.post(
            "/api/policies",
            json={
                "name": "My Policy",
                "description": "",
                "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
            },
        ).json()

        resp = client.patch("/api/profile/preferences", json={"default_policy_id": policy["id"]})
        assert resp.status_code == 200
        assert resp.json()["default_policy_id"] == policy["id"]
        assert client.get("/api/profile").json()["default_policy_id"] == policy["id"]

    def test_can_set_a_baseline_as_default(self, auth_client):
        client, _ = auth_client
        baseline = client.get("/api/policies/baselines").json()[0]
        resp = client.patch("/api/profile/preferences", json={"default_policy_id": baseline["id"]})
        assert resp.status_code == 200
        assert resp.json()["default_policy_id"] == baseline["id"]

    def test_cannot_default_to_someone_elses_policy(self, auth_client, make_user):
        client, _ = auth_client
        policy = client.post(
            "/api/policies",
            json={
                "name": "Owner Only",
                "description": "",
                "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
            },
        ).json()

        make_user()
        resp = client.patch("/api/profile/preferences", json={"default_policy_id": policy["id"]})
        assert resp.status_code == 404

    def test_can_clear_the_default_policy(self, auth_client):
        client, _ = auth_client
        baseline = client.get("/api/policies/baselines").json()[0]
        client.patch("/api/profile/preferences", json={"default_policy_id": baseline["id"]})

        resp = client.patch("/api/profile/preferences", json={"default_policy_id": None})
        assert resp.status_code == 200
        assert resp.json()["default_policy_id"] is None

    def test_can_set_theme(self, auth_client):
        client, _ = auth_client
        resp = client.patch("/api/profile/preferences", json={"theme": "light"})
        assert resp.status_code == 200
        assert resp.json()["theme"] == "light"
        assert client.get("/api/profile/preferences").json()["theme"] == "light"

    @pytest.mark.parametrize("theme", ["cyberpunk", "terminal", "midnight", "arctic", "offwhite"])
    def test_can_set_named_theme(self, auth_client, theme):
        client, _ = auth_client
        resp = client.patch("/api/profile/preferences", json={"theme": theme})
        assert resp.status_code == 200
        assert resp.json()["theme"] == theme
        assert client.get("/api/profile/preferences").json()["theme"] == theme

    def test_invalid_theme_rejected(self, auth_client):
        client, _ = auth_client
        resp = client.patch("/api/profile/preferences", json={"theme": "solarized"})
        assert resp.status_code == 422

    def test_system_theme_no_longer_accepted(self, auth_client):
        # "system" was removed as a selectable theme (it never offered
        # anything Default didn't already cover) - new writes of it are
        # rejected just like any other invalid value.
        client, _ = auth_client
        resp = client.patch("/api/profile/preferences", json={"theme": "system"})
        assert resp.status_code == 422

    @pytest.mark.parametrize("accent", ["cyan", "blue", "purple", "green", "pink", "orange"])
    def test_can_set_accent_color(self, auth_client, accent):
        client, _ = auth_client
        resp = client.patch("/api/profile/preferences", json={"accent_color": accent})
        assert resp.status_code == 200
        assert resp.json()["accent_color"] == accent
        assert client.get("/api/profile/preferences").json()["accent_color"] == accent

    def test_can_reset_accent_color_to_default(self, auth_client):
        client, _ = auth_client
        client.patch("/api/profile/preferences", json={"accent_color": "cyan"})
        resp = client.patch("/api/profile/preferences", json={"accent_color": "default"})
        assert resp.status_code == 200
        assert resp.json()["accent_color"] == "default"

    def test_invalid_accent_color_rejected(self, auth_client):
        client, _ = auth_client
        resp = client.patch("/api/profile/preferences", json={"accent_color": "chartreuse"})
        assert resp.status_code == 422

    def test_updating_accent_color_does_not_change_theme(self, auth_client):
        client, _ = auth_client
        client.patch("/api/profile/preferences", json={"theme": "cyberpunk"})
        resp = client.patch("/api/profile/preferences", json={"accent_color": "pink"})
        assert resp.status_code == 200
        assert resp.json()["theme"] == "cyberpunk"
        assert resp.json()["accent_color"] == "pink"

    def test_updating_theme_does_not_clear_default_policy(self, auth_client):
        client, _ = auth_client
        baseline = client.get("/api/policies/baselines").json()[0]
        client.patch("/api/profile/preferences", json={"default_policy_id": baseline["id"]})

        resp = client.patch("/api/profile/preferences", json={"theme": "light"})

        assert resp.status_code == 200
        assert resp.json()["default_policy_id"] == baseline["id"]
        assert resp.json()["theme"] == "light"

    def test_updating_default_policy_does_not_reset_theme(self, auth_client):
        client, _ = auth_client
        client.patch("/api/profile/preferences", json={"theme": "midnight"})
        baseline = client.get("/api/policies/baselines").json()[0]

        resp = client.patch("/api/profile/preferences", json={"default_policy_id": baseline["id"]})

        assert resp.status_code == 200
        assert resp.json()["theme"] == "midnight"

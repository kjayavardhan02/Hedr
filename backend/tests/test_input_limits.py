"""Server-side input length limits. The frontend caps the same fields via
lib/limits.ts; these make sure the API can't be used to get around the UI."""

import pytest

from tests.conftest import DEFAULT_PASSWORD

HEADER = {"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}


def _policy(**overrides):
    body = {"name": "p", "description": "", "headers": [HEADER]}
    body.update(overrides)
    return body


class TestPolicyLimits:
    @pytest.mark.parametrize(
        "field, limit",
        [("name", 50), ("description", 200)],
    )
    def test_policy_text_fields(self, auth_client, field, limit):
        client, _ = auth_client
        assert client.post("/api/policies", json=_policy(**{field: "x" * limit})).status_code == 201
        assert client.post("/api/policies", json=_policy(**{field: "x" * (limit + 1)})).status_code == 422

    def test_header_expected_value(self, auth_client):
        client, _ = auth_client
        ok = _policy(headers=[{**HEADER, "header_name": "X-Custom", "expected_value": "a" * 2000}])
        too_long = _policy(headers=[{**HEADER, "header_name": "X-Custom", "expected_value": "a" * 2001}])
        assert client.post("/api/policies", json=ok).status_code == 201
        assert client.post("/api/policies", json=too_long).status_code == 422

    def test_header_name(self, auth_client):
        client, _ = auth_client
        assert client.post("/api/policies", json=_policy(headers=[{**HEADER, "header_name": "X" * 100}])).status_code == 201
        assert client.post("/api/policies", json=_policy(headers=[{**HEADER, "header_name": "X" * 101}])).status_code == 422

    def test_update_enforces_the_same_limits(self, auth_client):
        client, _ = auth_client
        created = client.post("/api/policies", json=_policy()).json()
        r = client.put(f"/api/policies/{created['id']}", json=_policy(name="x" * 51))
        assert r.status_code == 422


class TestSignupLimits:
    def _register(self, client, first, last):
        return client.post(
            "/api/auth/register",
            json={
                "email": f"limits-{len(first)}-{len(last)}@example.com",
                "password": DEFAULT_PASSWORD,
                "first_name": first,
                "last_name": last,
            },
        )

    def test_names_capped_at_50(self, client):
        assert self._register(client, "a" * 50, "b" * 50).status_code == 201

    @pytest.mark.parametrize("first, last", [("a" * 51, "b"), ("a", "b" * 51)])
    def test_names_over_50_rejected(self, client, first, last):
        assert self._register(client, first, last).status_code == 422


class TestScanLimits:
    def test_url_and_raw_response_caps(self, auth_client):
        client, _ = auth_client
        policy = _policy()
        assert client.post("/api/scan", json={"source": "url", "url": "http://a.com/" + "x" * 2000, "policy": policy}).status_code == 422
        big = "HTTP/1.1 200 OK\n" + "A" * 200_001
        assert client.post("/api/scan", json={"source": "raw", "raw_response": big, "policy": policy}).status_code == 422

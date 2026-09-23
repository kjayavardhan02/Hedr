BASELINE_KEYS = {"basic", "strict", "saas", "fintech"}

POLICY_PAYLOAD = {
    "name": "My Policy",
    "description": "test",
    "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
}


def test_baselines_are_seeded_on_startup(auth_client):
    client, _ = auth_client
    resp = client.get("/api/policies/baselines")
    assert resp.status_code == 200
    baselines = resp.json()
    assert {b["baseline_key"] for b in baselines} == BASELINE_KEYS
    assert all(b["is_baseline"] is True for b in baselines)
    assert all(b["owner_id"] is None for b in baselines)


def test_create_policy(auth_client):
    client, user = auth_client
    resp = client.post("/api/policies", json=POLICY_PAYLOAD)
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "My Policy"
    assert body["is_baseline"] is False
    assert body["owner_id"] == user["id"]
    assert body["version"] == 1
    assert body["id"]


def test_create_policy_without_headers_fails(auth_client):
    client, _ = auth_client
    resp = client.post("/api/policies", json={"name": "Empty", "description": "", "headers": []})
    assert resp.status_code == 422


def test_get_policy_roundtrip(auth_client):
    client, _ = auth_client
    create = client.post("/api/policies", json=POLICY_PAYLOAD)
    policy_id = create.json()["id"]
    resp = client.get(f"/api/policies/{policy_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == policy_id


def test_get_nonexistent_policy_404(auth_client):
    client, _ = auth_client
    resp = client.get("/api/policies/does-not-exist")
    assert resp.status_code == 404


def test_update_policy(auth_client):
    client, _ = auth_client
    create = client.post("/api/policies", json=POLICY_PAYLOAD)
    policy_id = create.json()["id"]
    resp = client.put(
        f"/api/policies/{policy_id}",
        json={
            "name": "After",
            "description": "updated",
            "headers": [{"header_name": "X-Frame-Options", "expected_value": "SAMEORIGIN", "required": True}],
        },
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "After"


def test_update_increments_version_each_time(auth_client):
    client, _ = auth_client
    create = client.post("/api/policies", json=POLICY_PAYLOAD)
    policy_id = create.json()["id"]
    assert create.json()["version"] == 1

    edit_payload = {
        "name": "After",
        "description": "updated",
        "headers": [{"header_name": "X-Frame-Options", "expected_value": "SAMEORIGIN", "required": True}],
    }
    first_edit = client.put(f"/api/policies/{policy_id}", json=edit_payload)
    assert first_edit.json()["version"] == 2

    second_edit = client.put(f"/api/policies/{policy_id}", json=edit_payload)
    assert second_edit.json()["version"] == 3

    # Confirm it's persisted, not just returned once.
    assert client.get(f"/api/policies/{policy_id}").json()["version"] == 3


def test_baseline_version_never_changes(auth_client):
    client, _ = auth_client
    baseline = client.get("/api/policies/baselines").json()[0]
    assert baseline["version"] == 1


def test_update_baseline_policy_forbidden(auth_client):
    client, _ = auth_client
    baseline_id = client.get("/api/policies/baselines").json()[0]["id"]
    resp = client.put(
        f"/api/policies/{baseline_id}",
        json={"name": "Hacked", "description": "", "headers": [{"header_name": "X", "expected_value": "Y"}]},
    )
    assert resp.status_code == 400


def test_delete_policy(auth_client):
    client, _ = auth_client
    create = client.post("/api/policies", json={**POLICY_PAYLOAD, "name": "ToDelete"})
    policy_id = create.json()["id"]
    resp = client.delete(f"/api/policies/{policy_id}")
    assert resp.status_code == 204
    assert client.get(f"/api/policies/{policy_id}").status_code == 404


def test_delete_baseline_policy_forbidden(auth_client):
    client, _ = auth_client
    baseline_id = client.get("/api/policies/baselines").json()[0]["id"]
    resp = client.delete(f"/api/policies/{baseline_id}")
    assert resp.status_code == 400


def test_delete_nonexistent_policy_404(auth_client):
    client, _ = auth_client
    resp = client.delete("/api/policies/does-not-exist")
    assert resp.status_code == 404


def test_list_policies_includes_created_policy(auth_client):
    client, _ = auth_client
    create = client.post("/api/policies", json={**POLICY_PAYLOAD, "name": "Listed"})
    policy_id = create.json()["id"]
    resp = client.get("/api/policies")
    assert resp.status_code == 200
    assert any(p["id"] == policy_id for p in resp.json())


CSP_POLICY_PAYLOAD = {
    "required": True,
    "required_directives": ["default-src"],
    "directive_rules": [
        {
            "directive": "object-src",
            "must_contain": ["'none'"],
            "must_not_contain": [],
            "allowed_sources": None,
            "disallow_wildcards": False,
            "disallow_external": False,
            "disallow_http": False,
            "disallow_data": False,
            "disallow_blob": False,
        }
    ],
}


class TestCspPolicy:
    def test_create_policy_rejects_csp_in_generic_headers(self, auth_client):
        client, _ = auth_client
        resp = client.post(
            "/api/policies",
            json={
                "name": "Bad",
                "description": "",
                "headers": [
                    {"header_name": "Content-Security-Policy", "expected_value": "default-src 'self'"}
                ],
            },
        )
        assert resp.status_code == 422
        assert "csp_policy" in resp.text

    def test_create_policy_with_csp_policy_only_no_headers(self, auth_client):
        client, _ = auth_client
        resp = client.post(
            "/api/policies",
            json={"name": "CSP Only", "description": "", "headers": [], "csp_policy": CSP_POLICY_PAYLOAD},
        )
        assert resp.status_code == 201
        assert resp.json()["csp_policy"]["required_directives"] == ["default-src"]

    def test_csp_policy_roundtrips_through_get(self, auth_client):
        client, _ = auth_client
        create = client.post(
            "/api/policies",
            json={"name": "CSP Roundtrip", "description": "", "headers": [], "csp_policy": CSP_POLICY_PAYLOAD},
        )
        policy_id = create.json()["id"]
        resp = client.get(f"/api/policies/{policy_id}")
        assert resp.status_code == 200
        assert resp.json()["csp_policy"]["directive_rules"][0]["directive"] == "object-src"

    def test_csp_policy_can_be_updated(self, auth_client):
        client, _ = auth_client
        create = client.post(
            "/api/policies",
            json={"name": "CSP Update", "description": "", "headers": [], "csp_policy": CSP_POLICY_PAYLOAD},
        )
        policy_id = create.json()["id"]
        updated_csp = {**CSP_POLICY_PAYLOAD, "required": False}
        resp = client.put(
            f"/api/policies/{policy_id}",
            json={"name": "CSP Update", "description": "", "headers": [], "csp_policy": updated_csp},
        )
        assert resp.status_code == 200
        assert resp.json()["csp_policy"]["required"] is False

    def test_policy_without_headers_but_with_csp_policy_is_valid(self, auth_client):
        client, _ = auth_client
        resp = client.post(
            "/api/policies",
            json={"name": "CSP Valid", "description": "", "headers": [], "csp_policy": CSP_POLICY_PAYLOAD},
        )
        assert resp.status_code == 201

    def test_policy_with_neither_headers_nor_csp_policy_fails(self, auth_client):
        client, _ = auth_client
        resp = client.post(
            "/api/policies",
            json={"name": "Nothing", "description": "", "headers": [], "csp_policy": None},
        )
        assert resp.status_code == 422


class TestDuplicateHeaderRules:
    def _payload(self, headers):
        return {"name": "Dupes", "description": "", "headers": headers}

    @staticmethod
    def _hsts(value="max-age=100"):
        return {"header_name": "Strict-Transport-Security", "expected_value": value, "required": True}

    def _detail_text(self, resp):
        return " ".join(e["msg"] for e in resp.json()["detail"])

    def test_exact_duplicate_rejected_on_create(self, auth_client):
        client, _ = auth_client
        resp = client.post("/api/policies", json=self._payload([self._hsts(), self._hsts("max-age=200")]))
        assert resp.status_code == 422
        assert "Strict-Transport-Security" in self._detail_text(resp)

    def test_duplicate_is_case_and_whitespace_insensitive(self, auth_client):
        client, _ = auth_client
        headers = [self._hsts(), {**self._hsts(), "header_name": "  strict-transport-security "}]
        assert client.post("/api/policies", json=self._payload(headers)).status_code == 422

    def test_each_repeated_header_is_named_once(self, auth_client):
        client, _ = auth_client
        xfo = {"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}
        headers = [self._hsts(), xfo, self._hsts(), xfo, self._hsts()]
        text = self._detail_text(client.post("/api/policies", json=self._payload(headers)))
        assert text.count("Strict-Transport-Security") == 1
        assert text.count("X-Frame-Options") == 1

    def test_distinct_headers_are_fine(self, auth_client):
        client, _ = auth_client
        xfo = {"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}
        assert client.post("/api/policies", json=self._payload([self._hsts(), xfo])).status_code == 201

    def test_duplicate_rejected_on_update(self, auth_client):
        client, _ = auth_client
        created = client.post("/api/policies", json=self._payload([self._hsts()])).json()
        resp = client.put(
            f"/api/policies/{created['id']}",
            json=self._payload([self._hsts(), self._hsts("max-age=5")]),
        )
        assert resp.status_code == 422
        assert client.get(f"/api/policies/{created['id']}").json()["version"] == 1

    def test_duplicate_rejected_for_an_inline_scan_policy(self, auth_client):
        client, _ = auth_client
        resp = client.post(
            "/api/scan",
            json={
                "source": "raw",
                "raw_response": "HTTP/1.1 200 OK\nServer: x\n\n",
                "policy": self._payload([self._hsts(), self._hsts()]),
            },
        )
        assert resp.status_code == 422


class TestPoliciesRequireAuth:
    def test_list_requires_auth(self, client):
        assert client.get("/api/policies").status_code == 401

    def test_baselines_require_auth(self, client):
        assert client.get("/api/policies/baselines").status_code == 401

    def test_get_requires_auth(self, client):
        assert client.get("/api/policies/some-id").status_code == 401

    def test_create_requires_auth(self, client):
        assert client.post("/api/policies", json=POLICY_PAYLOAD).status_code == 401

    def test_update_requires_auth(self, client):
        assert client.put("/api/policies/some-id", json=POLICY_PAYLOAD).status_code == 401

    def test_delete_requires_auth(self, client):
        assert client.delete("/api/policies/some-id").status_code == 401

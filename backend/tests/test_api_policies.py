BASELINE_KEYS = {"basic", "strict", "saas", "fintech"}


def test_baselines_are_seeded_on_startup(client):
    resp = client.get("/api/policies/baselines")
    assert resp.status_code == 200
    baselines = resp.json()
    assert {b["baseline_key"] for b in baselines} == BASELINE_KEYS
    assert all(b["is_baseline"] is True for b in baselines)


def test_create_policy(client):
    payload = {
        "name": "My Policy",
        "description": "test",
        "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
    }
    resp = client.post("/api/policies", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "My Policy"
    assert body["is_baseline"] is False
    assert body["id"]


def test_create_policy_without_headers_fails(client):
    resp = client.post("/api/policies", json={"name": "Empty", "description": "", "headers": []})
    assert resp.status_code == 422


def test_get_policy_roundtrip(client):
    create = client.post(
        "/api/policies",
        json={
            "name": "Roundtrip",
            "description": "",
            "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
        },
    )
    policy_id = create.json()["id"]
    resp = client.get(f"/api/policies/{policy_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == policy_id


def test_get_nonexistent_policy_404(client):
    resp = client.get("/api/policies/does-not-exist")
    assert resp.status_code == 404


def test_update_policy(client):
    create = client.post(
        "/api/policies",
        json={
            "name": "Before",
            "description": "",
            "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
        },
    )
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


def test_update_baseline_policy_forbidden(client):
    baseline_id = client.get("/api/policies/baselines").json()[0]["id"]
    resp = client.put(
        f"/api/policies/{baseline_id}",
        json={"name": "Hacked", "description": "", "headers": [{"header_name": "X", "expected_value": "Y"}]},
    )
    assert resp.status_code == 400


def test_delete_policy(client):
    create = client.post(
        "/api/policies",
        json={
            "name": "ToDelete",
            "description": "",
            "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
        },
    )
    policy_id = create.json()["id"]
    resp = client.delete(f"/api/policies/{policy_id}")
    assert resp.status_code == 204
    assert client.get(f"/api/policies/{policy_id}").status_code == 404


def test_delete_baseline_policy_forbidden(client):
    baseline_id = client.get("/api/policies/baselines").json()[0]["id"]
    resp = client.delete(f"/api/policies/{baseline_id}")
    assert resp.status_code == 400


def test_delete_nonexistent_policy_404(client):
    resp = client.delete("/api/policies/does-not-exist")
    assert resp.status_code == 404


def test_list_policies_includes_created_policy(client):
    create = client.post(
        "/api/policies",
        json={
            "name": "Listed",
            "description": "",
            "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
        },
    )
    policy_id = create.json()["id"]
    resp = client.get("/api/policies")
    assert resp.status_code == 200
    assert any(p["id"] == policy_id for p in resp.json())

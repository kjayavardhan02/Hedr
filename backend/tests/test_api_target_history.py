RAW_V1 = (
    "HTTP/1.1 200 OK\n"
    "Date: Fri, 18 Sep 2026 12:00:00 GMT\n"
    "Strict-Transport-Security: max-age=31536000\n"
    "\n"
)
RAW_V2 = (
    "HTTP/1.1 200 OK\n"
    "Date: Fri, 18 Sep 2026 12:00:00 GMT\n"
    "Strict-Transport-Security: max-age=86400\n"
    "Referrer-Policy: strict-origin-when-cross-origin\n"
    "\n"
)

HISTORY_POLICY_HEADERS = [
    {"header_name": "Strict-Transport-Security", "expected_value": "", "required": True},
]

TARGET_URL = "https://example.com/history-test"


def make_policy(client, name, headers, description=""):
    resp = client.post("/api/policies", json={"name": name, "description": description, "headers": headers})
    assert resp.status_code == 201, resp.text
    return resp.json()


def run_scan(client, policy_id, raw_response, target_url=TARGET_URL):
    resp = client.post(
        "/api/scan",
        json={
            "source": "raw",
            "raw_response": raw_response,
            "policy_id": policy_id,
            "target_url": target_url,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def get_report_id_for_scan_number(client, scan_number):
    reports = client.get("/api/reports").json()
    matches = [r for r in reports if r["scan_number"] == scan_number]
    assert len(matches) == 1
    return matches[0]["id"]


def test_history_requires_auth(client):
    assert client.get("/api/reports/some-id/history").status_code == 401


def test_history_404_for_unknown_or_foreign_report(auth_client, make_user):
    client, _ = auth_client
    policy = make_policy(client, "Owner Policy", HISTORY_POLICY_HEADERS)
    run_scan(client, policy["id"], RAW_V1)
    report_id = get_report_id_for_scan_number(client, 1)

    assert client.get("/api/reports/does-not-exist/history").status_code == 404

    make_user()  # switches the shared client's session to a second user
    assert client.get(f"/api/reports/{report_id}/history").status_code == 404


def test_single_scan_has_no_history_but_names_the_reason(auth_client):
    client, _ = auth_client
    policy = make_policy(client, "Solo Policy", HISTORY_POLICY_HEADERS)
    run_scan(client, policy["id"], RAW_V1)
    report_id = get_report_id_for_scan_number(client, 1)

    data = client.get(f"/api/reports/{report_id}/history").json()

    assert data["has_history"] is False
    assert data["reason"] == "not_enough_data"
    assert [p["id"] for p in data["points"]] == [report_id]


def test_ad_hoc_scan_has_no_history(auth_client):
    client, _ = auth_client
    resp = client.post(
        "/api/scan",
        json={
            "source": "raw",
            "raw_response": RAW_V1,
            "target_url": TARGET_URL,
            "policy": {"name": "Ad hoc", "description": "", "headers": HISTORY_POLICY_HEADERS},
        },
    )
    assert resp.status_code == 200
    report_id = get_report_id_for_scan_number(client, 1)

    data = client.get(f"/api/reports/{report_id}/history").json()

    assert data["has_history"] is False
    assert data["reason"] == "ad_hoc_policy"
    assert data["points"] == []


def test_history_spans_scans_and_policy_versions_oldest_first(auth_client):
    client, _ = auth_client
    policy = make_policy(client, "History Policy", HISTORY_POLICY_HEADERS)
    run_scan(client, policy["id"], RAW_V1)
    run_scan(client, policy["id"], RAW_V2)

    # Editing the policy bumps its version - a third scan is stamped v2.
    client.put(
        f"/api/policies/{policy['id']}",
        json={"name": policy["name"], "description": "", "headers": HISTORY_POLICY_HEADERS},
    )
    run_scan(client, policy["id"], RAW_V2)

    latest_report_id = get_report_id_for_scan_number(client, 3)
    data = client.get(f"/api/reports/{latest_report_id}/history").json()

    assert data["has_history"] is True
    assert data["reason"] is None
    assert [p["scan_number"] for p in data["points"]] == [1, 2, 3]
    assert [p["policy_version"] for p in data["points"]] == ["v1", "v1", "v2"]


def test_history_never_includes_another_users_scans(auth_client, make_user):
    client, _ = auth_client
    policy = make_policy(client, "Shared-Looking Policy", HISTORY_POLICY_HEADERS)
    run_scan(client, policy["id"], RAW_V1)

    make_user()
    other_policy = make_policy(client, "Shared-Looking Policy", HISTORY_POLICY_HEADERS)
    run_scan(client, other_policy["id"], RAW_V1)
    report_id = get_report_id_for_scan_number(client, 1)

    data = client.get(f"/api/reports/{report_id}/history").json()

    assert len(data["points"]) == 1
    assert data["points"][0]["id"] == report_id

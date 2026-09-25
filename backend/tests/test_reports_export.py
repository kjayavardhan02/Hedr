def _scan(client, name):
    r = client.post(
        "/api/scan",
        json={
            "source": "raw",
            "raw_response": "HTTP/1.1 200 OK\nX-Frame-Options: DENY\n\n",
            "target_name": name,
            "policy": {
                "name": "p",
                "description": "",
                "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
            },
        },
    )
    assert r.status_code == 200, r.text


def _ids(client):
    return [r["id"] for r in client.get("/api/reports").json()]


def test_export_returns_full_reports_for_requested_ids(auth_client):
    auth_client, _ = auth_client
    _scan(auth_client, "one")
    _scan(auth_client, "two")
    ids = _ids(auth_client)
    r = auth_client.post("/api/reports/export", json={"ids": ids[:1]})
    assert r.status_code == 200
    body = r.json()
    assert [x["id"] for x in body] == ids[:1]
    assert "findings" in body[0] and "csp_finding" in body[0]


def test_export_skips_unknown_ids(auth_client):
    auth_client, _ = auth_client
    _scan(auth_client, "one")
    ids = _ids(auth_client)
    r = auth_client.post("/api/reports/export", json={"ids": ids + ["nope"]})
    assert r.status_code == 200 and len(r.json()) == 1


def test_export_never_returns_other_users_reports(auth_client, make_user):
    auth_client, _ = auth_client
    _scan(auth_client, "mine")
    mine = _ids(auth_client)
    make_user()  # switches the shared client's session to a second user
    r = auth_client.post("/api/reports/export", json={"ids": mine})
    assert r.status_code == 200 and r.json() == []


def test_export_validates_body_and_requires_auth(auth_client):
    client, _ = auth_client
    assert client.post("/api/reports/export", json={"ids": []}).status_code == 422
    assert client.post("/api/reports/export", json={"ids": ["x"] * 201}).status_code == 422
    client.cookies.clear()
    assert client.post("/api/reports/export", json={"ids": ["x"]}).status_code == 401

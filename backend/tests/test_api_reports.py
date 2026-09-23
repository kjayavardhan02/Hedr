RAW_RESPONSE_WITH_EXTRA_HEADERS = (
    "HTTP/1.1 200 OK\n"
    "Date: Fri, 18 Sep 2026 12:00:00 GMT\n"
    "Server: nginx\n"
    "Content-Type: text/html; charset=utf-8\n"
    "Set-Cookie: session=abc123; Path=/\n"
    "X-Frame-Options: DENY\n"
    "Content-Security-Policy: default-src 'self'\n"
    "\n"
)

POLICY_WITH_CSP = {
    "name": "Frame + CSP Policy",
    "headers": [
        {"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True},
    ],
    "csp_policy": {
        "required": True,
        "required_directives": [],
        "directive_rules": [
            {
                "directive": "default-src",
                "must_contain": ["'self'"],
                "must_not_contain": [],
                "allowed_sources": None,
                "disallow_wildcards": False,
                "disallow_external": False,
                "disallow_http": False,
                "disallow_data": False,
                "disallow_blob": False,
            }
        ],
    },
}


def run_scan(client, policy=POLICY_WITH_CSP, raw_response=RAW_RESPONSE_WITH_EXTRA_HEADERS):
    resp = client.post(
        "/api/scan",
        json={"source": "raw", "raw_response": raw_response, "policy": policy},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestReportsRequireAuth:
    def test_list_requires_auth(self, client):
        assert client.get("/api/reports").status_code == 401

    def test_get_requires_auth(self, client):
        assert client.get("/api/reports/some-id").status_code == 401

    def test_delete_requires_auth(self, client):
        assert client.delete("/api/reports/some-id").status_code == 401


class TestScanCreatesReport:
    def test_scan_creates_a_listed_report(self, auth_client):
        client, _ = auth_client
        assert client.get("/api/reports").json() == []

        run_scan(client)

        reports = client.get("/api/reports").json()
        assert len(reports) == 1
        summary = reports[0]
        assert summary["policy_name"] == "Frame + CSP Policy"
        assert summary["source"] == "raw"
        assert summary["scan_number"] == 1
        assert summary["policy_version"] == "ad-hoc"
        # X-Frame-Options + the dedicated CSP finding = 2 headers evaluated.
        assert summary["headers_evaluated"] == 2
        assert "score" in summary and "grade" in summary
        # Summary is intentionally lightweight - no findings/csp_finding here.
        assert "findings" not in summary
        assert "raw_headers" not in summary

    def test_scan_numbers_increment_per_user_and_survive_deletion(self, auth_client):
        client, _ = auth_client
        run_scan(client, policy={**POLICY_WITH_CSP, "name": "Scan A"})
        run_scan(client, policy={**POLICY_WITH_CSP, "name": "Scan B"})

        reports = client.get("/api/reports").json()
        numbers = {r["policy_name"]: r["scan_number"] for r in reports}
        assert numbers == {"Scan A": 1, "Scan B": 2}

        # Delete scan #1, then scan again - the next number must be 3, not
        # a reused 1, so it never collides with an id another view might
        # still reference.
        scan_a_id = next(r["id"] for r in reports if r["policy_name"] == "Scan A")
        assert client.delete(f"/api/reports/{scan_a_id}").status_code == 204

        run_scan(client, policy={**POLICY_WITH_CSP, "name": "Scan C"})
        remaining = client.get("/api/reports").json()
        numbers = {r["policy_name"]: r["scan_number"] for r in remaining}
        assert numbers == {"Scan B": 2, "Scan C": 3}

    def test_report_detail_has_no_raw_headers_field(self, auth_client):
        client, _ = auth_client
        run_scan(client)
        report_id = client.get("/api/reports").json()[0]["id"]

        detail = client.get(f"/api/reports/{report_id}").json()
        assert "raw_headers" not in detail
        assert detail["scan_number"] == 1
        assert detail["policy_version"] == "ad-hoc"
        assert detail["headers_evaluated"] == 2

    def test_report_findings_only_include_policy_headers(self, auth_client):
        client, _ = auth_client
        run_scan(client)
        report_id = client.get("/api/reports").json()[0]["id"]
        detail = client.get(f"/api/reports/{report_id}").json()

        finding_headers = {f["header"] for f in detail["findings"]}
        # The raw response also sent Date/Server/Content-Type/Set-Cookie -
        # none of those may appear, since the policy never mentioned them.
        assert finding_headers == {"X-Frame-Options"}
        assert "Content-Security-Policy" not in finding_headers

    def test_report_includes_csp_finding_when_policy_checks_csp(self, auth_client):
        client, _ = auth_client
        run_scan(client)
        report_id = client.get("/api/reports").json()[0]["id"]
        detail = client.get(f"/api/reports/{report_id}").json()

        assert detail["csp_finding"] is not None
        assert detail["csp_finding"]["present"] is True

    def test_report_csp_finding_null_when_policy_does_not_check_csp(self, auth_client):
        client, _ = auth_client
        policy = {
            "name": "Frame Only",
            "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
        }
        run_scan(client, policy=policy)
        report_id = client.get("/api/reports").json()[0]["id"]
        detail = client.get(f"/api/reports/{report_id}").json()

        assert detail["csp_finding"] is None

    def test_adhoc_scan_report_has_null_policy_id(self, auth_client):
        client, _ = auth_client
        run_scan(client)
        summary = client.get("/api/reports").json()[0]
        assert summary["policy_id"] is None
        detail = client.get(f"/api/reports/{summary['id']}").json()
        assert detail["policy_id"] is None

    def test_saved_policy_scan_report_stores_policy_id(self, auth_client):
        client, _ = auth_client
        create = client.post(
            "/api/policies",
            json={
                "name": "Linked Policy",
                "description": "",
                "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
            },
        )
        policy_id = create.json()["id"]
        client.post(
            "/api/scan",
            json={
                "source": "raw",
                "raw_response": "HTTP/1.1 200 OK\nX-Frame-Options: DENY\n\n",
                "policy_id": policy_id,
            },
        )
        summary = client.get("/api/reports").json()[0]
        assert summary["policy_id"] == policy_id
        detail = client.get(f"/api/reports/{summary['id']}").json()
        assert detail["policy_id"] == policy_id

    def test_report_keeps_policy_id_after_the_policy_is_deleted(self, auth_client):
        client, _ = auth_client
        create = client.post(
            "/api/policies",
            json={
                "name": "Doomed Policy",
                "description": "",
                "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
            },
        )
        policy_id = create.json()["id"]
        client.post(
            "/api/scan",
            json={
                "source": "raw",
                "raw_response": "HTTP/1.1 200 OK\nX-Frame-Options: DENY\n\n",
                "policy_id": policy_id,
            },
        )
        report_id = client.get("/api/reports").json()[0]["id"]

        assert client.delete(f"/api/policies/{policy_id}").status_code == 204

        # The report keeps its historical policy_id even though the policy
        # is gone - it's the caller's job to notice the 404 below and treat
        # the link as dead, not the report's.
        detail = client.get(f"/api/reports/{report_id}").json()
        assert detail["policy_id"] == policy_id
        assert client.get(f"/api/policies/{policy_id}").status_code == 404

    def test_report_snapshots_the_saved_policys_current_version(self, auth_client):
        client, _ = auth_client
        create = client.post(
            "/api/policies",
            json={
                "name": "Versioned Policy",
                "description": "",
                "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}],
            },
        )
        policy_id = create.json()["id"]

        first_scan = client.post(
            "/api/scan",
            json={
                "source": "raw",
                "raw_response": "HTTP/1.1 200 OK\nX-Frame-Options: DENY\n\n",
                "policy_id": policy_id,
            },
        )
        assert first_scan.status_code == 200
        first_report_id = client.get("/api/reports").json()[0]["id"]
        assert client.get(f"/api/reports/{first_report_id}").json()["policy_version"] == "v1"

        # Edit the policy - it's now v2.
        client.put(
            f"/api/policies/{policy_id}",
            json={
                "name": "Versioned Policy",
                "description": "",
                "headers": [{"header_name": "X-Frame-Options", "expected_value": "SAMEORIGIN", "required": True}],
            },
        )

        second_scan = client.post(
            "/api/scan",
            json={
                "source": "raw",
                "raw_response": "HTTP/1.1 200 OK\nX-Frame-Options: SAMEORIGIN\n\n",
                "policy_id": policy_id,
            },
        )
        assert second_scan.status_code == 200
        reports = client.get("/api/reports").json()
        second_report_id = next(r["id"] for r in reports if r["id"] != first_report_id)
        assert client.get(f"/api/reports/{second_report_id}").json()["policy_version"] == "v2"

        # The first report's snapshot must stay "v1" - it isn't retroactively
        # updated by the later edit.
        assert client.get(f"/api/reports/{first_report_id}").json()["policy_version"] == "v1"

    def test_multiple_scans_listed_most_recent_first(self, auth_client):
        client, _ = auth_client
        run_scan(client, policy={**POLICY_WITH_CSP, "name": "First scan"})
        run_scan(client, policy={**POLICY_WITH_CSP, "name": "Second scan"})

        reports = client.get("/api/reports").json()
        assert len(reports) == 2
        assert reports[0]["policy_name"] == "Second scan"
        assert reports[1]["policy_name"] == "First scan"


class TestReportOwnershipIsolation:
    def test_other_user_cannot_list_your_report(self, auth_client, make_user):
        client, _owner = auth_client
        run_scan(client)

        make_user()
        assert client.get("/api/reports").json() == []

    def test_other_user_cannot_get_your_report(self, auth_client, make_user):
        client, _owner = auth_client
        run_scan(client)
        report_id = client.get("/api/reports").json()[0]["id"]

        make_user()
        assert client.get(f"/api/reports/{report_id}").status_code == 404

    def test_other_user_cannot_delete_your_report(self, auth_client, make_user):
        client, owner = auth_client
        run_scan(client)
        report_id = client.get("/api/reports").json()[0]["id"]

        make_user()
        assert client.delete(f"/api/reports/{report_id}").status_code == 404

        # Confirm it's untouched - the true owner can still see it.
        from tests.conftest import DEFAULT_PASSWORD

        client.post("/api/auth/login", json={"email": owner["email"], "password": DEFAULT_PASSWORD})
        assert client.get(f"/api/reports/{report_id}").status_code == 200

    def test_get_nonexistent_report_404(self, auth_client):
        client, _ = auth_client
        assert client.get("/api/reports/does-not-exist").status_code == 404


class TestDeleteReport:
    def test_delete_report(self, auth_client):
        client, _ = auth_client
        run_scan(client)
        report_id = client.get("/api/reports").json()[0]["id"]

        assert client.delete(f"/api/reports/{report_id}").status_code == 204
        assert client.get(f"/api/reports/{report_id}").status_code == 404
        assert client.get("/api/reports").json() == []

    def test_delete_nonexistent_report_404(self, auth_client):
        client, _ = auth_client
        assert client.delete("/api/reports/does-not-exist").status_code == 404

RAW_NO_HEADERS = "HTTP/1.1 200 OK\nDate: Fri, 18 Sep 2026 12:00:00 GMT\n\n"


def run_scan(client, policy, raw_response=RAW_NO_HEADERS, policy_id=None, target_name=None):
    payload = {"source": "raw", "raw_response": raw_response}
    if policy_id:
        payload["policy_id"] = policy_id
    else:
        payload["policy"] = policy
    if target_name:
        payload["target_name"] = target_name
    resp = client.post("/api/scan", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


def make_policy(client, name, headers, description=""):
    resp = client.post(
        "/api/policies",
        json={"name": name, "description": description, "headers": headers},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


HIGH_SEVERITY_FAIL = [
    {"header_name": "Strict-Transport-Security", "expected_value": "", "required": True}
]
MEDIUM_SEVERITY_FAIL = [
    {"header_name": "X-Content-Type-Options", "expected_value": "", "required": True}
]
LOW_SEVERITY_FAIL = [
    {"header_name": "Referrer-Policy", "expected_value": "", "required": True}
]
ALL_PASS_POLICY = [
    {"header_name": "Strict-Transport-Security", "expected_value": "", "required": False}
]


class TestDashboardRequiresAuth:
    def test_summary_requires_auth(self, client):
        assert client.get("/api/dashboard/summary").status_code == 401


class TestEmptyDashboard:
    def test_fresh_account_shows_zeros_and_baseline_count(self, auth_client):
        client, _ = auth_client
        summary = client.get("/api/dashboard/summary").json()

        assert summary["reports"]["total"] == 0
        assert summary["policies"]["total"] == 0
        assert summary["baselines"]["total"] == 4
        assert summary["average_score"] is None
        assert summary["average_grade"] is None
        assert summary["latest_scan"] is None
        assert summary["recent_scans"] == []
        assert summary["recent_policies"] == []
        assert summary["findings"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}


class TestDashboardReports:
    def test_latest_scan_reflects_most_recent_report(self, auth_client):
        client, _ = auth_client
        run_scan(client, {"name": "First", "headers": ALL_PASS_POLICY})
        run_scan(client, {"name": "Second", "headers": ALL_PASS_POLICY})

        summary = client.get("/api/dashboard/summary").json()
        assert summary["reports"]["total"] == 2
        assert summary["latest_scan"]["policy_name"] == "Second"

    def test_recent_scans_limited_to_five_most_recent(self, auth_client):
        client, _ = auth_client
        for i in range(7):
            run_scan(client, {"name": f"Scan {i}", "headers": ALL_PASS_POLICY})

        summary = client.get("/api/dashboard/summary").json()
        assert summary["reports"]["total"] == 7
        assert len(summary["recent_scans"]) == 5
        names = [s["policy_name"] for s in summary["recent_scans"]]
        assert names == ["Scan 6", "Scan 5", "Scan 4", "Scan 3", "Scan 2"]

    def test_average_score_is_mean_of_final_scores_not_zero_when_empty(self, auth_client):
        client, _ = auth_client
        run_scan(client, {"name": "Passing", "headers": ALL_PASS_POLICY})
        run_scan(client, {"name": "Failing", "headers": HIGH_SEVERITY_FAIL})

        reports = client.get("/api/reports").json()
        scores = [r["score"] for r in reports]
        expected_avg = round(sum(scores) / len(scores), 1)

        summary = client.get("/api/dashboard/summary").json()
        assert summary["average_score"] == expected_avg
        assert summary["average_grade"] is not None

    def test_passed_and_failed_counts_exclude_csp_and_match_findings(self, auth_client):
        client, _ = auth_client
        policy = {
            "name": "Mixed",
            "headers": [
                {"header_name": "Strict-Transport-Security", "expected_value": "", "required": True},
                {"header_name": "X-Content-Type-Options", "expected_value": "", "required": False},
            ],
        }
        run_scan(client, policy)
        summary = client.get("/api/dashboard/summary").json()
        latest = summary["latest_scan"]
        assert latest["passed"] == 1
        assert latest["failed"] == 1

    def test_raw_scan_target_name_used_on_dashboard(self, auth_client):
        client, _ = auth_client
        run_scan(client, {"name": "Named", "headers": ALL_PASS_POLICY}, target_name="My API")
        summary = client.get("/api/dashboard/summary").json()
        assert summary["latest_scan"]["target"] == "My API"

    def test_saved_policy_scan_reports_current_version_snapshot(self, auth_client):
        client, _ = auth_client
        policy = make_policy(client, "Versioned", ALL_PASS_POLICY)
        run_scan(client, policy=None, policy_id=policy["id"])

        summary = client.get("/api/dashboard/summary").json()
        assert summary["latest_scan"]["policy_id"] == policy["id"]
        assert summary["latest_scan"]["policy_version"] == "v1"


class TestDashboardFindingsSeverity:
    def test_severity_tally_scoped_across_all_saved_reports(self, auth_client):
        client, _ = auth_client
        run_scan(client, {"name": "High fail", "headers": HIGH_SEVERITY_FAIL})
        run_scan(client, {"name": "Medium fail", "headers": MEDIUM_SEVERITY_FAIL})
        run_scan(client, {"name": "Low fail", "headers": LOW_SEVERITY_FAIL})
        run_scan(client, {"name": "All pass", "headers": ALL_PASS_POLICY})

        summary = client.get("/api/dashboard/summary").json()
        assert summary["findings"] == {"critical": 0, "high": 1, "medium": 1, "low": 1}

    def test_only_recent_five_scans_shown_but_findings_cover_everything(self, auth_client):
        client, _ = auth_client
        for _ in range(6):
            run_scan(client, {"name": "High fail", "headers": HIGH_SEVERITY_FAIL})

        summary = client.get("/api/dashboard/summary").json()
        assert len(summary["recent_scans"]) == 5
        assert summary["findings"]["high"] == 6


class TestDashboardPolicies:
    def test_policy_count_excludes_baselines(self, auth_client):
        client, _ = auth_client
        make_policy(client, "Custom One", ALL_PASS_POLICY)

        summary = client.get("/api/dashboard/summary").json()
        assert summary["policies"]["total"] == 1
        assert summary["baselines"]["total"] == 4

    def test_recent_policies_limited_and_ordered_by_update(self, auth_client):
        client, _ = auth_client
        created = [make_policy(client, f"Policy {i}", ALL_PASS_POLICY) for i in range(6)]
        first_created = created[0]

        # Edit the first-created policy so it becomes the most-recently-updated.
        client.put(
            f"/api/policies/{first_created['id']}",
            json={"name": first_created["name"], "description": "", "headers": ALL_PASS_POLICY},
        )

        summary = client.get("/api/dashboard/summary").json()
        assert len(summary["recent_policies"]) == 4
        assert summary["recent_policies"][0]["id"] == first_created["id"]
        assert summary["recent_policies"][0]["version"] == 2

    def test_recent_policies_never_include_baselines(self, auth_client):
        client, _ = auth_client
        summary = client.get("/api/dashboard/summary").json()
        assert summary["recent_policies"] == []

    def test_recent_policies_include_created_at_unaffected_by_later_edits(self, auth_client):
        client, _ = auth_client
        created = make_policy(client, "Timestamped", ALL_PASS_POLICY)

        client.put(
            f"/api/policies/{created['id']}",
            json={"name": "Timestamped", "description": "", "headers": ALL_PASS_POLICY},
        )

        summary = client.get("/api/dashboard/summary").json()
        entry = summary["recent_policies"][0]
        assert entry["created_at"] == created["created_at"]
        assert entry["updated_at"] != created["created_at"]


class TestDashboardOwnershipIsolation:
    def test_other_users_reports_and_policies_not_counted(self, auth_client, make_user):
        client, _owner = auth_client
        run_scan(client, {"name": "Owner scan", "headers": ALL_PASS_POLICY})
        make_policy(client, "Owner policy", ALL_PASS_POLICY)

        make_user()
        summary = client.get("/api/dashboard/summary").json()
        assert summary["reports"]["total"] == 0
        assert summary["policies"]["total"] == 0
        assert summary["latest_scan"] is None
        assert summary["recent_policies"] == []
        # Baselines are shared, so both users see the same count.
        assert summary["baselines"]["total"] == 4

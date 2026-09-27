RAW_V1 = (
    "HTTP/1.1 200 OK\n"
    "Date: Fri, 18 Sep 2026 12:00:00 GMT\n"
    "Strict-Transport-Security: max-age=31536000\n"
    "\n"
)
RAW_V2_CHANGED_AND_ADDED = (
    "HTTP/1.1 200 OK\n"
    "Date: Fri, 18 Sep 2026 12:00:00 GMT\n"
    "Strict-Transport-Security: max-age=86400\n"
    "Referrer-Policy: strict-origin-when-cross-origin\n"
    "\n"
)

COMPARISON_POLICY_HEADERS = [
    {"header_name": "Strict-Transport-Security", "expected_value": "", "required": True},
    {"header_name": "Referrer-Policy", "expected_value": "", "required": True},
]

# Shared default for tests where every scan represents the same one target -
# a Target URL is required for every raw scan now, so this is what
# establishes "same target", not the (still-optional) target_name.
TARGET_URL = "https://example.com/comparison-test"
OTHER_TARGET_URL = "https://other.example.com/comparison-test"


def make_policy(client, name, headers, description=""):
    resp = client.post(
        "/api/policies",
        json={"name": name, "description": description, "headers": headers},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def run_scan_with_policy_id(client, policy_id, raw_response, target_name, target_url=TARGET_URL):
    resp = client.post(
        "/api/scan",
        json={
            "source": "raw",
            "raw_response": raw_response,
            "policy_id": policy_id,
            "target_name": target_name,
            "target_url": target_url,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def run_ad_hoc_scan(client, raw_response, target_name, target_url=TARGET_URL):
    resp = client.post(
        "/api/scan",
        json={
            "source": "raw",
            "raw_response": raw_response,
            "policy": {"name": "Ad hoc", "description": "", "headers": COMPARISON_POLICY_HEADERS},
            "target_name": target_name,
            "target_url": target_url,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def get_report_id_for_scan_number(client, scan_number):
    reports = client.get("/api/reports").json()
    matches = [r for r in reports if r["scan_number"] == scan_number]
    assert len(matches) == 1, f"expected exactly one report with scan_number={scan_number}"
    return matches[0]["id"]


class TestComparisonRequiresAuth:
    def test_comparison_requires_auth(self, client):
        assert client.get("/api/reports/some-id/comparison").status_code == 401


class TestComparisonOwnership:
    def test_other_user_cannot_fetch_your_comparison(self, auth_client, make_user):
        client, _owner = auth_client
        policy = make_policy(client, "Owner Policy", COMPARISON_POLICY_HEADERS)
        run_scan_with_policy_id(client, policy["id"], RAW_V1, "Target A")
        run_scan_with_policy_id(client, policy["id"], RAW_V2_CHANGED_AND_ADDED, "Target A")
        report_id = get_report_id_for_scan_number(client, 2)

        make_user()  # switches the shared client's session to a second user
        resp = client.get(f"/api/reports/{report_id}/comparison")
        assert resp.status_code == 404


class TestComparisonHappyPath:
    def test_full_comparison_detects_added_removed_changed(self, auth_client):
        client, _ = auth_client
        policy = make_policy(client, "Comparison Policy", COMPARISON_POLICY_HEADERS)
        run_scan_with_policy_id(client, policy["id"], RAW_V1, "Target A")
        run_scan_with_policy_id(client, policy["id"], RAW_V2_CHANGED_AND_ADDED, "Target A")

        latest_report_id = get_report_id_for_scan_number(client, 2)
        resp = client.get(f"/api/reports/{latest_report_id}/comparison")
        assert resp.status_code == 200, resp.text
        data = resp.json()

        assert data["has_comparison"] is True
        assert data["previous_report"]["scan_number"] == 1
        assert data["latest_report"]["scan_number"] == 2

        header_names_changed = {h["header"] for h in data["changes"]["headers_changed"]}
        assert "Strict-Transport-Security" in header_names_changed

        header_names_added = {h["header"] for h in data["changes"]["headers_added"]}
        assert "Referrer-Policy" in header_names_added

        resolved_headers = {f["header"] for f in data["changes"]["findings_resolved"]}
        assert "Referrer-Policy" in resolved_headers


class TestComparisonEmptyStates:
    def test_first_scan_has_no_previous(self, auth_client):
        client, _ = auth_client
        policy = make_policy(client, "Solo Policy", COMPARISON_POLICY_HEADERS)
        run_scan_with_policy_id(client, policy["id"], RAW_V1, "Target A")

        report_id = get_report_id_for_scan_number(client, 1)
        resp = client.get(f"/api/reports/{report_id}/comparison")
        data = resp.json()

        assert data["has_comparison"] is False
        assert data["reason"] == "no_previous_scan"

    def test_ad_hoc_scan_has_no_comparison(self, auth_client):
        client, _ = auth_client
        run_ad_hoc_scan(client, RAW_V1, "Target A")

        report_id = get_report_id_for_scan_number(client, 1)
        resp = client.get(f"/api/reports/{report_id}/comparison")
        data = resp.json()

        assert data["has_comparison"] is False
        assert data["reason"] == "ad_hoc_policy"

    def test_policy_version_changed_is_not_auto_compared(self, auth_client):
        client, _ = auth_client
        policy = make_policy(client, "Versioned Policy", COMPARISON_POLICY_HEADERS)
        run_scan_with_policy_id(client, policy["id"], RAW_V1, "Target A")

        # Editing the policy bumps its version - the next scan is stamped v2.
        resp = client.put(
            f"/api/policies/{policy['id']}",
            json={"name": policy["name"], "description": "", "headers": COMPARISON_POLICY_HEADERS},
        )
        assert resp.status_code == 200, resp.text

        run_scan_with_policy_id(client, policy["id"], RAW_V2_CHANGED_AND_ADDED, "Target A")
        latest_report_id = get_report_id_for_scan_number(client, 2)

        data = client.get(f"/api/reports/{latest_report_id}/comparison").json()

        assert data["has_comparison"] is False
        assert data["reason"] == "policy_version_changed"

    def test_different_policies_on_the_same_target_are_not_compared(self, auth_client):
        client, _ = auth_client
        basic = make_policy(client, "Basic", COMPARISON_POLICY_HEADERS)
        strict = make_policy(client, "Strict", COMPARISON_POLICY_HEADERS)
        run_scan_with_policy_id(client, basic["id"], RAW_V1, "Target A")
        run_scan_with_policy_id(client, strict["id"], RAW_V2_CHANGED_AND_ADDED, "Target A")

        latest_report_id = get_report_id_for_scan_number(client, 2)
        data = client.get(f"/api/reports/{latest_report_id}/comparison").json()

        assert data["has_comparison"] is False
        assert data["reason"] == "different_policy"


class TestComparisonTargetIdentity:
    """The API requires a Target URL on every raw scan, and that URL - not
    the still-optional target_name - is what establishes "same target" (see
    scan_comparison._target_identity). Name-only matching now only applies to
    scans saved before this validation existed, which can't be produced
    through this API - that legacy behaviour is covered directly at the unit
    level in test_scan_comparison.py instead."""

    def test_a_blank_target_name_does_not_prevent_comparison(self, auth_client):
        client, _ = auth_client
        policy = make_policy(client, "Blank Name Policy", COMPARISON_POLICY_HEADERS)
        run_scan_with_policy_id(client, policy["id"], RAW_V1, None)
        run_scan_with_policy_id(client, policy["id"], RAW_V2_CHANGED_AND_ADDED, None)

        data = client.get(f"/api/reports/{get_report_id_for_scan_number(client, 2)}/comparison").json()

        assert data["has_comparison"] is True
        # Both reports fall back to the same default display name, but that's
        # not why they matched - the shared Target URL is.
        assert data["previous_report"]["target"] == "HTTP Response Scan"

    def test_different_target_urls_are_different_targets_even_with_the_same_name(self, auth_client):
        client, _ = auth_client
        policy = make_policy(client, "Names Policy", COMPARISON_POLICY_HEADERS)
        run_scan_with_policy_id(client, policy["id"], RAW_V1, "Production API", target_url=TARGET_URL)
        run_scan_with_policy_id(
            client, policy["id"], RAW_V2_CHANGED_AND_ADDED, "Production API", target_url=OTHER_TARGET_URL
        )

        data = client.get(f"/api/reports/{get_report_id_for_scan_number(client, 2)}/comparison").json()

        assert data["has_comparison"] is False
        assert data["reason"] == "no_previous_scan"

    def test_repeated_scans_of_the_same_target_each_compare_with_the_one_before(self, auth_client):
        client, _ = auth_client
        policy = make_policy(client, "Repeats Policy", COMPARISON_POLICY_HEADERS)
        for raw in (RAW_V1, RAW_V2_CHANGED_AND_ADDED, RAW_V1):
            run_scan_with_policy_id(client, policy["id"], raw, "Production API")

        assert len(client.get("/api/reports").json()) == 3
        for number, previous in ((2, 1), (3, 2)):
            data = client.get(f"/api/reports/{get_report_id_for_scan_number(client, number)}/comparison").json()
            assert data["previous_report"]["scan_number"] == previous

    def test_a_client_supplied_previous_report_id_is_ignored(self, auth_client, make_user):
        client, _ = auth_client
        policy = make_policy(client, "Spoof Policy", COMPARISON_POLICY_HEADERS)
        run_scan_with_policy_id(client, policy["id"], RAW_V1, "Other Target")
        victim_report_id = get_report_id_for_scan_number(client, 1)

        make_user()  # a second user now attacks by naming the first user's report
        other_policy = make_policy(client, "Attacker Policy", COMPARISON_POLICY_HEADERS)
        resp = client.post(
            "/api/scan",
            json={
                "source": "raw",
                "raw_response": RAW_V1,
                "policy_id": other_policy["id"],
                "target_name": "Other Target",
                "target_url": TARGET_URL,
                "previous_report_id": victim_report_id,
            },
        )
        assert resp.status_code == 200
        report_id = get_report_id_for_scan_number(client, 1)
        data = client.get(f"/api/reports/{report_id}/comparison").json()
        assert data["has_comparison"] is False
        assert data["reason"] == "no_previous_scan"


class TestComparisonDeletedPolicyAndReports:
    def test_comparison_still_works_after_policy_deleted(self, auth_client):
        client, _ = auth_client
        policy = make_policy(client, "Doomed Policy", COMPARISON_POLICY_HEADERS)
        run_scan_with_policy_id(client, policy["id"], RAW_V1, "Target A")
        run_scan_with_policy_id(client, policy["id"], RAW_V2_CHANGED_AND_ADDED, "Target A")

        assert client.delete(f"/api/policies/{policy['id']}").status_code == 204

        latest_report_id = get_report_id_for_scan_number(client, 2)
        data = client.get(f"/api/reports/{latest_report_id}/comparison").json()

        assert data["has_comparison"] is True
        assert data["previous_report"]["scan_number"] == 1

    def test_deleted_previous_report_makes_the_comparison_unavailable(self, auth_client):
        client, _ = auth_client
        policy = make_policy(client, "Multi Scan Policy", COMPARISON_POLICY_HEADERS)
        run_scan_with_policy_id(client, policy["id"], RAW_V1, "Target A")
        run_scan_with_policy_id(client, policy["id"], RAW_V1, "Target A")
        run_scan_with_policy_id(client, policy["id"], RAW_V2_CHANGED_AND_ADDED, "Target A")

        middle_report_id = get_report_id_for_scan_number(client, 2)
        assert client.delete(f"/api/reports/{middle_report_id}").status_code == 204

        latest_report_id = get_report_id_for_scan_number(client, 3)
        resp = client.get(f"/api/reports/{latest_report_id}/comparison")
        data = resp.json()

        # The report itself still loads; only the comparison is unavailable,
        # and it is NOT quietly re-pointed at the older scan #1.
        assert client.get(f"/api/reports/{latest_report_id}").status_code == 200
        assert resp.status_code == 200
        assert data["has_comparison"] is False
        assert data["reason"] == "previous_report_unavailable"

    def test_deleting_one_report_does_not_affect_other_comparisons(self, auth_client):
        client, _ = auth_client
        policy = make_policy(client, "Chain Policy", COMPARISON_POLICY_HEADERS)
        for raw in (RAW_V1, RAW_V1, RAW_V1, RAW_V2_CHANGED_AND_ADDED):
            run_scan_with_policy_id(client, policy["id"], raw, "Target A")

        assert client.delete(f"/api/reports/{get_report_id_for_scan_number(client, 2)}").status_code == 204

        fourth = client.get(f"/api/reports/{get_report_id_for_scan_number(client, 4)}/comparison").json()
        assert fourth["has_comparison"] is True
        assert fourth["previous_report"]["scan_number"] == 3
        third = client.get(f"/api/reports/{get_report_id_for_scan_number(client, 3)}/comparison").json()
        assert third["reason"] == "previous_report_unavailable"

    def test_report_saved_without_a_stored_link_still_falls_back_dynamically(self, auth_client):
        """Reports saved before the link existed have previous_report_id NULL."""
        from app import models
        from app.database import SessionLocal

        client, _ = auth_client
        policy = make_policy(client, "Legacy Policy", COMPARISON_POLICY_HEADERS)
        for raw in (RAW_V1, RAW_V1, RAW_V2_CHANGED_AND_ADDED):
            run_scan_with_policy_id(client, policy["id"], raw, "Target A")
        latest_id = get_report_id_for_scan_number(client, 3)
        with SessionLocal() as db:
            report = db.get(models.ScanReport, latest_id)
            report.previous_report_id = None
            db.commit()
        assert client.delete(f"/api/reports/{get_report_id_for_scan_number(client, 2)}").status_code == 204

        data = client.get(f"/api/reports/{latest_id}/comparison").json()
        assert data["has_comparison"] is True
        assert data["previous_report"]["scan_number"] == 1


class TestComparisonSkipsNonComparableScans:
    def test_compares_against_previous_comparable_scan_not_just_scan_number_minus_one(self, auth_client):
        client, _ = auth_client
        policy = make_policy(client, "Skip Policy", COMPARISON_POLICY_HEADERS)
        run_scan_with_policy_id(client, policy["id"], RAW_V1, "Target A")  # scan_number=1
        run_ad_hoc_scan(client, RAW_V1, "Target A")  # scan_number=2, not comparable (ad-hoc)
        run_scan_with_policy_id(client, policy["id"], RAW_V2_CHANGED_AND_ADDED, "Target A")  # scan_number=3

        latest_report_id = get_report_id_for_scan_number(client, 3)
        data = client.get(f"/api/reports/{latest_report_id}/comparison").json()

        assert data["has_comparison"] is True
        assert data["previous_report"]["scan_number"] == 1

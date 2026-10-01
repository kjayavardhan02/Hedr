"""Feature 12: target type & header applicability."""
import pytest

from app.core.applicability import BROWSER_DOCUMENT_HEADER_NAMES, build_breakdown, check_applicability, describe_target_types
from app.core.policy_engine import run_scan
from app.schemas import CSPPolicy, PolicyHeaderIn, ScanSource, Status, TargetType

WEB = TargetType.WEB_APPLICATION
REST = TargetType.REST_API
GATEWAY = TargetType.API_GATEWAY
CUSTOM = TargetType.CUSTOM


def _check(header, *, target_type=WEB, is_https=True, content_type="text/html", present=False):
    return check_applicability(
        header, target_type=target_type, is_https=is_https, content_type=content_type, header_present=present
    )


class TestCustomTargetType:
    @pytest.mark.parametrize(
        "header",
        [*BROWSER_DOCUMENT_HEADER_NAMES, "Strict-Transport-Security", "Access-Control-Allow-Origin", "X-Custom"],
    )
    def test_nothing_is_automatically_not_applicable(self, header):
        # JSON response over plain HTTP: every other type would skip several of these.
        assert _check(header, target_type=CUSTOM, is_https=False, content_type="application/json").applicable

    def test_scan_checks_every_policy_header_like_before_target_types(self):
        headers = {"content-type": "application/json", "x-content-type-options": "nosniff"}
        result = _scan(headers, [XCTO, XFO, HSTS], target_type=CUSTOM, target="http://api.example.com")
        assert [f.applicable for f in result.findings] == [True, True, True]
        assert result.breakdown.not_applicable == 0
        assert result.breakdown.failed == 2  # X-Frame-Options and HSTS count as missing
        assert result.target_type == CUSTOM

    def test_csp_is_evaluated_for_custom_even_on_json(self):
        result = _scan(
            {"content-type": "application/json"}, [], target_type=CUSTOM, csp_policy=CSPPolicy(required=True)
        )
        assert result.csp_finding.applicable is True


class TestRules:
    def test_web_app_html_csp_applicable(self):
        assert _check("Content-Security-Policy").applicable

    @pytest.mark.parametrize("target_type", [REST, GATEWAY])
    def test_api_json_csp_not_applicable(self, target_type):
        result = _check("Content-Security-Policy", target_type=target_type, content_type="application/json")
        assert not result.applicable
        assert result.reason

    def test_web_app_json_csp_not_applicable(self):
        result = _check("Content-Security-Policy", content_type="application/json")
        assert not result.applicable
        assert "not an HTML document" in result.reason

    def test_unknown_content_type_never_excuses_csp(self):
        assert _check("Content-Security-Policy", content_type=None).applicable

    def test_http_hsts_not_applicable_https_applicable(self):
        assert not _check("Strict-Transport-Security", is_https=False).applicable
        assert _check("Strict-Transport-Security", is_https=True).applicable
        # unknown scheme: not excused
        assert _check("Strict-Transport-Security", is_https=None).applicable

    @pytest.mark.parametrize("target_type", [WEB, REST, GATEWAY])
    @pytest.mark.parametrize("header", ["X-Content-Type-Options", "Cache-Control"])
    def test_universal_headers_always_applicable(self, header, target_type):
        assert _check(header, target_type=target_type, content_type="application/json").applicable

    @pytest.mark.parametrize(
        "header",
        [
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Resource-Policy",
        ],
    )
    def test_browser_headers_applicable_for_web_not_for_apis(self, header):
        assert _check(header).applicable
        assert not _check(header, target_type=REST, content_type="application/json").applicable
        assert not _check(header, target_type=GATEWAY, content_type="application/json").applicable

    def test_cors_rules(self):
        assert _check("Access-Control-Allow-Origin", target_type=REST, content_type="application/json").applicable
        assert _check("Access-Control-Allow-Origin", target_type=GATEWAY, content_type="application/json").applicable
        # HTML page sending no CORS headers: N/A. Sending one: applicable.
        assert not _check("Access-Control-Allow-Origin", present=False).applicable
        assert _check("Access-Control-Allow-Origin", present=True).applicable
        # non-HTML web response stays applicable
        assert _check("Access-Control-Allow-Origin", content_type="application/json").applicable

    def test_custom_headers_default_to_applicable(self):
        assert _check("X-Custom", target_type=REST).applicable


def _scan(headers, policy_headers, *, target_type=WEB, csp_policy=None, target="https://example.com"):
    return run_scan(
        raw_headers=headers,
        policy_name="p",
        policy_headers=policy_headers,
        source=ScanSource.raw,
        target=target,
        fetched_status_code=200,
        csp_policy=csp_policy,
        target_url=target,
        target_type=target_type,
    )


XCTO = PolicyHeaderIn(header_name="X-Content-Type-Options", expected_value="nosniff", required=True)
XFO = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY", required=True)
HSTS = PolicyHeaderIn(header_name="Strict-Transport-Security", expected_value="", required=True)


class TestScoring:
    def test_na_header_does_not_reduce_score_or_create_findings(self):
        result = _scan(
            {"x-content-type-options": "nosniff", "content-type": "application/json"},
            [XCTO, XFO],
            target_type=REST,
        )
        assert result.score == 100.0
        xfo = next(f for f in result.findings if f.header == "X-Frame-Options")
        assert xfo.status == Status.NOT_APPLICABLE
        assert xfo.applicable is False
        # no severity, weight, remediation or advice
        assert xfo.severity is None
        assert xfo.score_possible == 0 and xfo.score_earned == 0
        assert xfo.issue is None and xfo.recommendation is None
        assert xfo.applicability_reason
        assert result.breakdown.model_dump() == {"applicable": 1, "passed": 1, "failed": 0, "not_applicable": 1}

    def test_same_scan_as_web_app_fails_on_the_missing_header(self):
        result = _scan({"x-content-type-options": "nosniff"}, [XCTO, XFO], target_type=WEB)
        assert result.score < 100.0
        assert result.breakdown.failed == 1

    def test_na_is_not_a_pass(self):
        result = _scan({"content-type": "application/json"}, [XFO], target_type=REST)
        assert result.findings[0].status != Status.PASS

    def test_http_hsts_is_na_and_not_a_failure(self):
        result = _scan({}, [HSTS], target="http://example.com")
        assert result.findings[0].status == Status.NOT_APPLICABLE
        assert result.breakdown.failed == 0

    def test_https_missing_hsts_still_fails(self):
        result = _scan({}, [HSTS], target="https://example.com")
        assert result.findings[0].status == Status.FAIL

    def test_csp_na_for_api_is_skipped_and_unscored(self):
        result = _scan(
            {"x-content-type-options": "nosniff", "content-type": "application/json"},
            [XCTO],
            target_type=REST,
            csp_policy=CSPPolicy(required=True),
        )
        assert result.csp_finding is not None
        assert result.csp_finding.applicable is False
        assert result.csp_finding.applicability_reason
        assert result.csp_finding.policy_checks == []
        assert result.score == 100.0
        assert result.breakdown.not_applicable == 1

    def test_csp_applies_for_web_app_html(self):
        result = _scan({"content-type": "text/html"}, [], csp_policy=CSPPolicy(required=True))
        assert result.csp_finding.applicable is True
        assert result.score < 100.0

    def test_default_target_type_is_web_application(self):
        result = run_scan(
            raw_headers={},
            policy_name="p",
            policy_headers=[XFO],
            source=ScanSource.raw,
            target="https://x.com",
            fetched_status_code=200,
        )
        assert result.target_type == WEB
        assert result.findings[0].applicable is True


def test_breakdown_reads_legacy_findings_without_applicability_fields():
    legacy = [{"header": "X", "status": "PASS"}, {"header": "Y", "status": "FAIL"}]
    assert build_breakdown(legacy, None).model_dump() == {
        "applicable": 2,
        "passed": 1,
        "failed": 1,
        "not_applicable": 0,
    }


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

JSON_RESPONSE = (
    "HTTP/1.1 200 OK\n"
    "Content-Type: application/json\n"
    "X-Content-Type-Options: nosniff\n"
    "\n"
)
POLICY = {
    "name": "Mixed",
    "headers": [
        {"header_name": "X-Content-Type-Options", "expected_value": "nosniff", "required": True},
        {"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True},
    ],
}


def _post_scan(client, **extra):
    payload = {
        "source": "raw",
        "raw_response": JSON_RESPONSE,
        "target_url": "https://api.example.com/users",
        "policy": POLICY,
        **extra,
    }
    return client.post("/api/scan", json=payload)


class TestApi:
    def test_default_target_type_web_application(self, auth_client):
        client, _ = auth_client
        body = _post_scan(client).json()
        assert body["target_type"] == "web_application"

    @pytest.mark.parametrize("value", ["web_application", "rest_api", "api_gateway", "custom"])
    def test_valid_target_types_accepted(self, auth_client, value):
        client, _ = auth_client
        resp = _post_scan(client, target_type=value)
        assert resp.status_code == 200
        assert resp.json()["target_type"] == value

    @pytest.mark.parametrize("value", ["Web Application", "graphql", ""])
    def test_invalid_target_type_rejected(self, auth_client, value):
        client, _ = auth_client
        assert _post_scan(client, target_type=value).status_code == 422

    def test_rest_api_scan_has_na_header_and_unpenalized_score(self, auth_client):
        client, _ = auth_client
        body = _post_scan(client, target_type="rest_api").json()
        assert body["score"] == 100.0
        assert body["breakdown"] == {"applicable": 1, "passed": 1, "failed": 0, "not_applicable": 1}

    def test_target_type_persisted_on_the_report(self, auth_client):
        client, _ = auth_client
        _post_scan(client, target_type="api_gateway")
        reports = client.get("/api/reports").json()
        assert reports[0]["target_type"] == "api_gateway"
        full = client.get(f"/api/reports/{reports[0]['id']}").json()
        assert full["target_type"] == "api_gateway"
        assert full["breakdown"]["not_applicable"] == 1
        assert full["headers_evaluated"] == 1
        na = next(f for f in full["findings"] if f["header"] == "X-Frame-Options")
        assert na["status"] == "NOT_APPLICABLE" and na["severity"] is None and na["applicability_reason"]

    def test_legacy_report_without_target_type_is_readable(self, auth_client):
        from app import models
        from app.database import SessionLocal

        client, user = auth_client
        db = SessionLocal()
        try:
            report = models.ScanReport(
                owner_id=user["id"],
                scan_number=1,
                policy_name="old",
                policy_version="v1",
                source="raw",
                target="x",
                score=50.0,
                grade="F",
                findings=[
                    {
                        "header": "X-Frame-Options",
                        "required": True,
                        "present": False,
                        "status": "FAIL",
                        "severity": "medium",
                        "weight": 10,
                        "score_earned": 0,
                        "score_possible": 10,
                        "policy_expected": "DENY",
                        "actual_value": None,
                    }
                ],
            )
            db.add(report)
            db.commit()
            report_id = report.id
        finally:
            db.close()
        body = client.get(f"/api/reports/{report_id}").json()
        assert body["target_type"] is None
        assert body["findings"][0]["applicable"] is True
        assert body["breakdown"] == {"applicable": 1, "passed": 0, "failed": 1, "not_applicable": 0}
        assert client.get(f"/api/reports/{report_id}/comparison").status_code == 200


class TestComparison:
    def _saved_policy(self, client):
        resp = client.post("/api/policies", json={**POLICY, "name": "Cmp policy"})
        assert resp.status_code == 201, resp.text
        return resp.json()["id"]

    def test_target_type_change_is_an_applicability_change_not_an_improvement(self, auth_client):
        client, _ = auth_client
        policy_id = self._saved_policy(client)
        first = _post_scan(client, policy=None, policy_id=policy_id, target_type="web_application")
        assert first.status_code == 200
        second = _post_scan(client, policy=None, policy_id=policy_id, target_type="rest_api")
        assert second.status_code == 200
        latest = client.get("/api/reports").json()[0]
        comparison = client.get(f"/api/reports/{latest['id']}/comparison").json()
        assert comparison["has_comparison"] is True
        assert comparison["target_type_changed"] is True
        # X-Frame-Options went FAIL -> N/A: reported as applicability, NOT as a resolved finding.
        assert comparison["changes"]["findings_resolved"] == []
        changes = comparison["changes"]["applicability_changes"]
        assert [c["header"] for c in changes] == ["X-Frame-Options"]
        assert changes[0]["previous_status"] == "FAIL"
        assert changes[0]["latest_status"] == "NOT_APPLICABLE"
        assert "Web Application" in changes[0]["reason"] and "REST API" in changes[0]["reason"]
        assert comparison["summary"]["applicability_changes"] == 1

    def test_same_target_type_has_no_applicability_changes(self, auth_client):
        client, _ = auth_client
        policy_id = self._saved_policy(client)
        _post_scan(client, policy=None, policy_id=policy_id, target_type="rest_api")
        _post_scan(client, policy=None, policy_id=policy_id, target_type="rest_api")
        latest = client.get("/api/reports").json()[0]
        comparison = client.get(f"/api/reports/{latest['id']}/comparison").json()
        assert comparison["target_type_changed"] is False
        assert comparison["changes"]["applicability_changes"] == []


class TestTargetTypeCatalog:
    def test_endpoint_lists_every_type_with_its_na_headers(self, auth_client):
        client, _ = auth_client
        resp = client.get("/api/scan/target-types")
        assert resp.status_code == 200
        by_id = {t["id"]: t for t in resp.json()}
        assert set(by_id) == {"web_application", "rest_api", "api_gateway", "custom"}
        assert by_id["custom"]["always_not_applicable"] == []
        assert by_id["custom"]["sometimes_not_applicable"] == []
        assert by_id["web_application"]["always_not_applicable"] == []
        assert "Content-Security-Policy" in by_id["rest_api"]["always_not_applicable"]
        assert by_id["rest_api"]["always_not_applicable"] == by_id["api_gateway"]["always_not_applicable"]
        assert all(t["label"] and t["description"] for t in by_id.values())

    def test_endpoint_requires_auth(self, client):
        assert client.get("/api/scan/target-types").status_code == 401

    def test_the_listed_always_na_headers_really_are_na(self):
        """The UI shows these lists; they must match what the engine does."""
        for info in describe_target_types():
            for header in info.always_not_applicable:
                for content_type in ("text/html", "application/json", None):
                    result = _check(header, target_type=info.id, content_type=content_type)
                    assert not result.applicable, (info.id, header)
            # ...and nothing else in the browser-header family is silently N/A.
            for header in set(BROWSER_DOCUMENT_HEADER_NAMES) - set(info.always_not_applicable):
                if info.id == WEB:
                    continue  # CSP can be N/A on non-HTML; listed as conditional
                assert _check(header, target_type=info.id, content_type="text/html").applicable, (info.id, header)

    def test_conditional_entries_match_the_engine(self):
        by_id = {i.id: i for i in describe_target_types()}
        web_conditional = {c.header for c in by_id[WEB].sometimes_not_applicable}
        assert web_conditional == {
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "Access-Control-* (CORS headers)",
        }
        assert not _check("Strict-Transport-Security", is_https=False).applicable
        assert not _check("Content-Security-Policy", content_type="application/json").applicable
        assert not _check("Access-Control-Allow-Origin", content_type="text/html").applicable

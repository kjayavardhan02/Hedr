"""Data the PDF report is built from: actionable issue/remediation text, legacy
advisories, normalized CORS values, scanner version, and the CSP score model
from the report spec's examples."""
import pytest

from app.core.csp_analyzer import compute_csp_score, evaluate_csp_policy, parse_csp
from app.core.policy_engine import evaluate_header
from app.schemas import CheckResult, CSPDirectiveRule, CSPPolicy, PolicyHeaderIn, Status
from app.version import SCANNER_VERSION


def finding(header, expected, actual, required=True):
    raw = {} if actual is None else {header.lower(): actual}
    return evaluate_header(PolicyHeaderIn(header_name=header, expected_value=expected, required=required), raw)


class TestActionableRecommendations:
    def test_cache_control_extra_directive_spec_example(self):
        f = finding("Cache-Control", "no-store, private", "private, no-store, must-revalidate")
        assert f.status == Status.FAIL
        assert "must-revalidate" in f.issue and "additional directives" in f.issue
        assert "Remove must-revalidate" in f.recommendation
        assert "update the policy" in f.recommendation

    def test_cache_control_mode_a_allows_extras(self):
        # Mode A (required directives, extras allowed): trailing '+'.
        assert finding("Cache-Control", "no-store, private, +", "private, no-store, must-revalidate").status == Status.PASS

    def test_cache_control_mode_b_is_exact_by_default(self):
        assert finding("Cache-Control", "no-store, private", "private, no-store, must-revalidate").status == Status.FAIL

    def test_missing_header_names_the_expected_value(self):
        f = finding("X-Frame-Options", "DENY", None)
        assert f.issue == "The response does not include the X-Frame-Options header."
        assert f.recommendation == "Add the X-Frame-Options header with the value 'DENY'."

    def test_hsts_low_max_age(self):
        f = finding("Strict-Transport-Security", "max-age=31536000", "max-age=100")
        assert "lower than the required minimum" in f.issue
        assert "at least 31536000" in f.recommendation

    def test_wrong_exact_value(self):
        f = finding("X-Content-Type-Options", "nosniff", "sniff")
        assert f.recommendation == "Set the header to exactly 'nosniff'."

    def test_cors_wildcard_when_not_allowed(self):
        f = finding("Access-Control-Allow-Origin", "https://a.com", "*")
        assert "any origin" in f.issue and "specific allowed origin" in f.recommendation

    def test_passing_header_has_no_issue_or_recommendation(self):
        f = finding("X-Frame-Options", "DENY", "DENY")
        assert f.issue is None and f.recommendation is None


class TestLegacyAdvisories:
    def test_allow_from_passes_policy_but_carries_a_warning(self):
        f = finding("X-Frame-Options", "ALLOW-FROM https://trusted.example.com", "ALLOW-FROM https://trusted.example.com")
        assert f.status == Status.PASS
        (advisory,) = f.advisories
        assert advisory.status == Status.WARNING and advisory.severity == "info"
        assert "frame-ancestors" in advisory.recommendation

    def test_xss_protection_is_flagged_as_legacy_without_changing_the_verdict(self):
        f = finding("X-XSS-Protection", "1; mode=block", "1; mode=block")
        assert f.status == Status.PASS
        (advisory,) = f.advisories
        assert advisory.status == Status.INFO and "Legacy" in advisory.title

    def test_modern_headers_have_no_advisories(self):
        assert finding("X-Frame-Options", "DENY", "DENY").advisories == []
        assert finding("X-Content-Type-Options", "nosniff", "nosniff").advisories == []

    def test_absent_xss_header_has_no_advisory(self):
        assert finding("X-XSS-Protection", "0", None, required=False).advisories == []


class TestNormalizedCorsValue:
    def test_raw_value_kept_and_normalized_value_exposed(self):
        f = finding("Access-Control-Allow-Origin", "https://EXAMPLE.COM", "https://EXAMPLE.COM:443")
        assert f.status == Status.PASS
        (check,) = f.checks
        assert check.actual == "https://EXAMPLE.COM:443"
        assert check.evidence == "Normalized: https://example.com"
        assert "canonicalization" in check.description

    def test_no_evidence_when_nothing_was_normalized(self):
        (check,) = finding("Access-Control-Allow-Origin", "https://example.com", "https://example.com").checks
        assert check.evidence is None


class TestCspModel:
    def test_default_src_self_is_evaluated_on_parsed_sources_not_raw_text(self):
        directives = parse_csp("default-src 'self'; script-src 'self' https://cdn.example.com")
        assert directives["default-src"] == ["'self'"]
        policy = CSPPolicy(
            required=True,
            required_directives=[],
            directive_rules=[CSPDirectiveRule(directive="default-src", must_contain=["'self'"])],
        )
        checks = evaluate_csp_policy(policy, directives)
        contain = [c for c in checks if "contain" in c.description.lower() and c.directive == "default-src"]
        assert contain and all(c.status == Status.PASS for c in contain)

    def test_overall_score_pools_policy_and_best_practice_like_the_spec_example(self):
        # 27/29 policy + 16/17 best practice -> 43/46 = 93.5
        make = lambda n, ok: [CheckResult(name=f"c{i}", description="d", status=Status.PASS if i < ok else Status.FAIL) for i in range(n)]
        p_pass, p_total, b_pass, b_total, overall = compute_csp_score(make(29, 27), make(17, 16))
        assert (p_pass, p_total, b_pass, b_total) == (27, 29, 16, 17)
        assert overall == 93.5


class TestScannerVersion:
    def test_scan_response_and_saved_report_carry_the_version(self, auth_client):
        client, _ = auth_client
        r = client.post(
            "/api/scan",
            json={
                "source": "raw",
                "raw_response": "HTTP/1.1 200 OK\nX-Frame-Options: DENY\n\n",
                "target_name": "versioned",
                "policy": {"name": "p", "description": "", "headers": [{"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True}]},
            },
        )
        assert r.status_code == 200 and r.json()["scanner_version"] == SCANNER_VERSION
        report_id = client.get("/api/reports").json()[0]["id"]
        assert client.get(f"/api/reports/{report_id}").json()["scanner_version"] == SCANNER_VERSION

    def test_new_fields_round_trip_through_a_saved_report(self, auth_client):
        client, _ = auth_client
        client.post(
            "/api/scan",
            json={
                "source": "raw",
                "raw_response": "HTTP/1.1 200 OK\nX-Frame-Options: ALLOW-FROM https://a.com\nCache-Control: private, no-store, must-revalidate\n\n",
                "target_name": "roundtrip",
                "policy": {
                    "name": "p",
                    "description": "",
                    "headers": [
                        {"header_name": "X-Frame-Options", "expected_value": "ALLOW-FROM https://a.com", "required": True},
                        {"header_name": "Cache-Control", "expected_value": "no-store, private", "required": True},
                    ],
                },
            },
        )
        report = client.get(f"/api/reports/{client.get('/api/reports').json()[0]['id']}").json()
        by_header = {f["header"]: f for f in report["findings"]}
        assert by_header["X-Frame-Options"]["advisories"][0]["status"] == "WARNING"
        assert "must-revalidate" in by_header["Cache-Control"]["issue"]

from app.core.policy_engine import evaluate_csp, evaluate_header, run_scan
from app.schemas import PolicyHeaderIn, ScanSource, Status


class TestEvaluateHeader:
    def test_required_missing_fails_with_zero_score(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY", required=True)
        finding = evaluate_header(ph, {})
        assert finding.status == Status.FAIL
        assert finding.present is False
        assert finding.score_earned == 0.0
        assert finding.recommendation is not None

    def test_optional_missing_passes_with_full_score(self):
        ph = PolicyHeaderIn(header_name="X-Xss-Protection", expected_value="0", required=False)
        finding = evaluate_header(ph, {})
        assert finding.status == Status.PASS
        assert finding.score_earned == finding.score_possible

    def test_presence_only_rule_passes_when_present(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="", required=True)
        finding = evaluate_header(ph, {"x-frame-options": "anything"})
        assert finding.status == Status.PASS
        assert finding.score_earned == finding.weight

    def test_partial_pass_gives_proportional_score(self):
        ph = PolicyHeaderIn(
            header_name="Strict-Transport-Security",
            expected_value="max-age=31536000; includeSubDomains",
            required=True,
        )
        finding = evaluate_header(ph, {"strict-transport-security": "max-age=31536000"})
        assert finding.status == Status.FAIL
        assert 0 < finding.score_earned < finding.score_possible

    def test_recommendation_none_on_pass(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY", required=True)
        finding = evaluate_header(ph, {"x-frame-options": "DENY"})
        assert finding.status == Status.PASS
        assert finding.recommendation is None


class TestEvaluateCsp:
    def test_no_policy_header_still_runs_best_practice_checks(self):
        finding = evaluate_csp(None, {"content-security-policy": "default-src *"})
        assert finding.present is True
        assert finding.policy_checks == []
        assert any(c.name == "no-wildcard:default-src" for c in finding.security_checks)

    def test_policy_header_with_missing_csp_fails_presence(self):
        ph = PolicyHeaderIn(header_name="Content-Security-Policy", expected_value="default-src 'self'")
        finding = evaluate_csp(ph, {})
        assert finding.present is False
        assert finding.policy_checks[0].status == Status.FAIL

    def test_policy_header_present_only_rule_passes(self):
        ph = PolicyHeaderIn(header_name="Content-Security-Policy", expected_value="")
        finding = evaluate_csp(ph, {"content-security-policy": "default-src 'self'"})
        assert finding.policy_checks[0].status == Status.PASS


class TestRunScan:
    def test_empty_policy_yields_perfect_score(self):
        result = run_scan(
            raw_headers={},
            policy_name="Empty",
            policy_headers=[],
            source=ScanSource.raw,
            target=None,
            fetched_status_code=200,
        )
        assert result.score == 100.0
        assert result.grade == "A"

    def test_all_passing_headers_yields_perfect_score(self):
        policy_headers = [
            PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY"),
            PolicyHeaderIn(header_name="X-Content-Type-Options", expected_value="nosniff"),
        ]
        raw_headers = {"x-frame-options": "DENY", "x-content-type-options": "nosniff"}
        result = run_scan(
            raw_headers=raw_headers,
            policy_name="Test",
            policy_headers=policy_headers,
            source=ScanSource.raw,
            target=None,
            fetched_status_code=200,
        )
        assert result.score == 100.0
        assert result.grade == "A"
        assert len(result.findings) == 2

    def test_all_failing_headers_yields_zero_score(self):
        policy_headers = [PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY")]
        result = run_scan(
            raw_headers={},
            policy_name="Test",
            policy_headers=policy_headers,
            source=ScanSource.raw,
            target=None,
            fetched_status_code=200,
        )
        assert result.score == 0.0
        assert result.grade == "F"

    def test_csp_header_extracted_and_not_double_counted(self):
        policy_headers = [
            PolicyHeaderIn(header_name="Content-Security-Policy", expected_value="default-src 'self'"),
            PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY"),
        ]
        raw_headers = {
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
        }
        result = run_scan(
            raw_headers=raw_headers,
            policy_name="Test",
            policy_headers=policy_headers,
            source=ScanSource.raw,
            target=None,
            fetched_status_code=200,
        )
        # CSP goes into csp_finding, not the plain findings list.
        assert len(result.findings) == 1
        assert result.findings[0].header == "X-Frame-Options"
        assert result.csp_finding is not None
        assert result.csp_finding.present is True

    def test_partial_score_rounds_to_correct_grade(self):
        policy_headers = [
            PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY"),  # pass, weight 10
            PolicyHeaderIn(header_name="X-Content-Type-Options", expected_value="nosniff"),  # fail, weight 10
        ]
        raw_headers = {"x-frame-options": "DENY"}
        result = run_scan(
            raw_headers=raw_headers,
            policy_name="Test",
            policy_headers=policy_headers,
            source=ScanSource.raw,
            target=None,
            fetched_status_code=200,
        )
        assert result.score == 50.0
        assert result.grade == "F"

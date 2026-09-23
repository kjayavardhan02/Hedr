from app.core.csp_findings import CSPFindingId
from app.core.policy_engine import evaluate_csp, evaluate_header, run_scan
from app.schemas import CSPPolicy, PolicyHeaderIn, ScanSource, Status


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

    def test_acac_without_acao_is_not_flagged_even_on_value_mismatch(self):
        ph = PolicyHeaderIn(
            header_name="Access-Control-Allow-Credentials",
            expected_value="true",
            required=True,
        )
        # Actual value doesn't match the policy, but ACAO is absent from the
        # response, so this must still pass - ACAC is inert without it.
        finding = evaluate_header(ph, {"access-control-allow-credentials": "false"})
        assert finding.status == Status.PASS
        assert finding.score_earned == finding.score_possible
        assert finding.recommendation is None

    def test_acac_is_flagged_normally_when_acao_present(self):
        ph = PolicyHeaderIn(
            header_name="Access-Control-Allow-Credentials",
            expected_value="true",
            required=True,
        )
        finding = evaluate_header(
            ph,
            {
                "access-control-allow-credentials": "false",
                "access-control-allow-origin": "https://example.com",
            },
        )
        assert finding.status == Status.FAIL

    def test_acac_still_flagged_as_missing_when_required_and_absent(self):
        ph = PolicyHeaderIn(
            header_name="Access-Control-Allow-Credentials",
            expected_value="true",
            required=True,
        )
        # ACAC is not present at all (not just missing ACAO) - the "required
        # but missing" rule still applies normally.
        finding = evaluate_header(ph, {})
        assert finding.status == Status.FAIL
        assert finding.present is False


class TestXfoViaCspFrameAncestorsFallback:
    def test_missing_xfo_passes_when_csp_frame_ancestors_is_equivalent(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY", required=True)
        finding = evaluate_header(ph, {"content-security-policy": "frame-ancestors 'none'"})
        assert finding.status == Status.PASS
        assert finding.present is False
        assert finding.score_earned == finding.score_possible
        assert finding.checks[0].name == "csp-frame-ancestors-fallback"

    def test_sameorigin_maps_to_self(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="SAMEORIGIN", required=True)
        finding = evaluate_header(ph, {"content-security-policy": "frame-ancestors 'self'"})
        assert finding.status == Status.PASS

    def test_missing_xfo_fails_when_frame_ancestors_is_weaker_than_expected(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY", required=True)
        # Policy wants DENY ('none'), but the response only restricts to 'self'.
        finding = evaluate_header(ph, {"content-security-policy": "frame-ancestors 'self'"})
        assert finding.status == Status.FAIL
        assert finding.score_earned == 0.0
        assert finding.checks[0].name == "csp-frame-ancestors-fallback"

    def test_presence_only_xfo_rule_satisfied_by_any_frame_ancestors_value(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="", required=True)
        finding = evaluate_header(ph, {"content-security-policy": "frame-ancestors 'self'"})
        assert finding.status == Status.PASS

    def test_falls_back_to_normal_missing_handling_when_csp_has_no_frame_ancestors(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY", required=True)
        finding = evaluate_header(ph, {"content-security-policy": "default-src 'self'"})
        assert finding.status == Status.FAIL
        assert finding.checks[0].name == "presence"

    def test_falls_back_to_normal_missing_handling_when_csp_absent(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY", required=True)
        finding = evaluate_header(ph, {})
        assert finding.status == Status.FAIL
        assert finding.checks[0].name == "presence"

    def test_falls_back_to_normal_missing_handling_for_unmapped_xfo_value(self):
        # ALLOW-FROM is deprecated and not in the equivalence table - don't guess.
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="ALLOW-FROM https://example.com", required=True)
        finding = evaluate_header(ph, {"content-security-policy": "frame-ancestors https://example.com"})
        assert finding.status == Status.FAIL
        assert finding.checks[0].name == "presence"

    def test_fallback_never_applies_when_xfo_is_actually_present(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY", required=True)
        finding = evaluate_header(
            ph, {"x-frame-options": "SAMEORIGIN", "content-security-policy": "frame-ancestors 'none'"}
        )
        # XFO is present but wrong - the normal comparator handles this, not
        # the missing-header fallback, regardless of what CSP says.
        assert finding.status == Status.FAIL
        assert finding.checks[0].name != "csp-frame-ancestors-fallback"


class TestEvaluateCsp:
    def test_no_csp_policy_still_runs_best_practice_checks(self):
        finding = evaluate_csp(None, {"content-security-policy": "default-src *"})
        assert finding.present is True
        assert finding.policy_checks == []
        assert any(c.name == "no-wildcard:default-src" for c in finding.security_checks)

    def test_csp_policy_with_missing_header_fails_presence(self):
        policy = CSPPolicy(required=True, required_directives=["default-src"])
        finding = evaluate_csp(policy, {})
        assert finding.present is False
        assert finding.policy_checks[0].status == Status.FAIL
        assert finding.policy_checks[0].id == CSPFindingId.HEADER_MISSING

    def test_csp_policy_missing_header_not_required_passes(self):
        policy = CSPPolicy(required=False, required_directives=["default-src"])
        finding = evaluate_csp(policy, {})
        assert finding.present is False
        assert finding.policy_checks[0].status == Status.PASS

    def test_csp_policy_evaluated_when_header_present(self):
        policy = CSPPolicy(required_directives=["default-src"])
        finding = evaluate_csp(policy, {"content-security-policy": "default-src 'self'"})
        assert finding.present is True
        assert finding.policy_checks[0].status == Status.PASS

    def test_score_breakdown_populated(self):
        policy = CSPPolicy(required_directives=["default-src"])
        finding = evaluate_csp(policy, {"content-security-policy": "default-src 'self'"})
        assert finding.policy_checks_total == 1
        assert finding.policy_checks_passed == 1
        assert finding.best_practice_total > 0
        assert 0 <= finding.overall_score <= 100


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

    def test_csp_policy_evaluated_separately_from_headers(self):
        policy_headers = [PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY")]
        csp_policy = CSPPolicy(required_directives=["default-src"])
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
            csp_policy=csp_policy,
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

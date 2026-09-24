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
        # A list of alternatives has no single frame-ancestors equivalent - don't guess.
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY|SAMEORIGIN", required=True)
        finding = evaluate_header(ph, {"content-security-policy": "frame-ancestors 'self'"})
        assert finding.status == Status.FAIL
        assert finding.checks[0].name == "presence"

    def test_allow_from_policy_is_satisfied_by_matching_frame_ancestors_origin(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="ALLOW-FROM https://example.com", required=True)
        finding = evaluate_header(ph, {"content-security-policy": "frame-ancestors https://example.com"})
        assert finding.status == Status.PASS
        assert finding.checks[0].name == "csp-frame-ancestors-fallback"

    def test_allow_from_fallback_compares_origins_not_text(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="ALLOW-FROM https://Example.com/page", required=True)
        finding = evaluate_header(ph, {"content-security-policy": "frame-ancestors https://example.com:443/"})
        assert finding.status == Status.PASS

    def test_allow_from_fallback_fails_for_a_different_origin(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="ALLOW-FROM https://example.com", required=True)
        for csp in ("frame-ancestors https://evil.com", "frame-ancestors 'none'", "frame-ancestors 'self'"):
            finding = evaluate_header(ph, {"content-security-policy": csp})
            assert finding.status == Status.FAIL, csp

    def test_allow_from_without_csp_frame_ancestors_is_a_normal_missing_header(self):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="ALLOW-FROM https://example.com", required=True)
        finding = evaluate_header(ph, {"content-security-policy": "default-src 'self'"})
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


class TestSemanticComparisonThroughEvaluateHeader:
    """Formatting-only differences must not change the finding; real
    differences must. Exercises the full evaluate_header path (presence
    handling, scoring) rather than the comparators in isolation."""

    def _finding(self, header, expected, actual, required=True):
        ph = PolicyHeaderIn(header_name=header, expected_value=expected, required=required)
        return evaluate_header(ph, {header.lower(): actual})

    def test_cache_control_spacing_and_order_still_full_score(self):
        finding = self._finding(
            "Cache-Control",
            "private, no-cache, no-store, max-age=0, must-revalidate",
            "must-revalidate,   max-age=0,no-store,   no-cache,private",
        )
        assert finding.status == Status.PASS
        assert finding.score_earned == finding.score_possible

    def test_cache_control_real_difference_is_flagged(self):
        finding = self._finding("Cache-Control", "private, no-store", "public, max-age=3600")
        assert finding.status == Status.FAIL
        assert finding.score_earned < finding.score_possible

    def test_cors_origin_formatting_only(self):
        finding = self._finding("Access-Control-Allow-Origin", "https://example.com", "HTTPS://EXAMPLE.COM/")
        assert finding.status == Status.PASS

    def test_cors_wildcard_is_flagged_against_a_specific_origin_policy(self):
        finding = self._finding("Access-Control-Allow-Origin", "https://example.com", "*")
        assert finding.status == Status.FAIL

    def test_xss_protection_formatting_only(self):
        assert self._finding("X-XSS-Protection", "1; mode=block", "1;mode=block").status == Status.PASS

    def test_referrer_policy_multi_token(self):
        finding = self._finding("Referrer-Policy", "strict-origin|no-referrer", "unsafe-url, no-referrer")
        assert finding.status == Status.PASS

    def test_presence_only_rule_ignores_value_for_new_comparator_headers(self):
        for header in ("Cache-Control", "X-XSS-Protection", "Access-Control-Allow-Origin", "Referrer-Policy"):
            finding = self._finding(header, "", "whatever value")
            assert finding.status == Status.PASS, header

    def test_missing_required_header_still_fails_for_new_comparator_headers(self):
        for header in ("Cache-Control", "X-XSS-Protection", "Access-Control-Allow-Origin", "Referrer-Policy"):
            ph = PolicyHeaderIn(header_name=header, expected_value="x", required=True)
            assert evaluate_header(ph, {}).status == Status.FAIL, header

    def test_acac_without_acao_is_still_never_flagged(self):
        ph = PolicyHeaderIn(header_name="Access-Control-Allow-Credentials", expected_value="true", required=True)
        finding = evaluate_header(ph, {"access-control-allow-credentials": "false"})
        assert finding.status == Status.PASS

    def test_acac_whitespace_is_ignored_when_acao_present(self):
        ph = PolicyHeaderIn(header_name="Access-Control-Allow-Credentials", expected_value="true", required=True)
        headers = {"access-control-allow-credentials": "  true ", "access-control-allow-origin": "https://a.com"}
        assert evaluate_header(ph, headers).status == Status.PASS
        headers["access-control-allow-credentials"] = "false"
        assert evaluate_header(ph, headers).status == Status.FAIL


class TestBaselinesStillEvaluateCorrectly:
    """Every built-in baseline's non-CSP rules must pass against a response
    that satisfies them and fail against one that doesn't, so a comparator
    change can never silently weaken a shipped baseline."""

    @staticmethod
    def _baselines():
        import glob
        import json
        import os

        base = os.path.join(os.path.dirname(__file__), "..", "app", "baselines", "*.json")
        return [json.load(open(p)) for p in sorted(glob.glob(base))]

    @staticmethod
    def _satisfying_value(header, expected):
        first = expected.split("|")[0].strip()
        # Permissions-Policy is written ';'-separated in baselines but is
        # sent comma-separated by real servers.
        return first.replace("; ", ", ") if header.lower() == "permissions-policy" else first

    def test_every_rule_passes_against_a_satisfying_response(self):
        for baseline in self._baselines():
            for rule in baseline["headers"]:
                raw = {rule["header_name"].lower(): self._satisfying_value(rule["header_name"], rule["expected_value"])}
                ph = PolicyHeaderIn(**rule)
                finding = evaluate_header(ph, raw)
                assert finding.status == Status.PASS, (baseline["name"], rule["header_name"], finding.checks)

    def test_every_required_rule_fails_when_the_header_is_missing(self):
        for baseline in self._baselines():
            for rule in baseline["headers"]:
                if rule["required"]:
                    finding = evaluate_header(PolicyHeaderIn(**rule), {})
                    assert finding.status == Status.FAIL, (baseline["name"], rule["header_name"])

    def test_every_rule_with_a_value_fails_against_a_wrong_value(self):
        for baseline in self._baselines():
            for rule in baseline["headers"]:
                if not rule["expected_value"].strip():
                    continue
                raw = {rule["header_name"].lower(): "definitely-not-the-right-value"}
                finding = evaluate_header(PolicyHeaderIn(**rule), raw)
                assert finding.status == Status.FAIL, (baseline["name"], rule["header_name"])

    def test_permissions_policy_baselines_check_every_feature(self):
        for baseline in self._baselines():
            for rule in baseline["headers"]:
                if rule["header_name"].lower() != "permissions-policy":
                    continue
                features = [f.split("=")[0].strip() for f in rule["expected_value"].split(";") if "=" in f]
                good = self._satisfying_value("Permissions-Policy", rule["expected_value"])
                for feature in features:
                    # Loosen exactly one feature; the baseline must notice.
                    loosened = ", ".join(
                        f"{f}=(*)" if f == feature else part
                        for f, part in zip(features, [p.strip() for p in good.split(",")])
                    )
                    finding = evaluate_header(PolicyHeaderIn(**rule), {"permissions-policy": loosened})
                    assert finding.status == Status.FAIL, (baseline["name"], feature)


class TestXFrameOptionsAllowFromThroughEvaluateHeader:
    def _finding(self, expected, actual, required=True):
        ph = PolicyHeaderIn(header_name="X-Frame-Options", expected_value=expected, required=required)
        return evaluate_header(ph, {"x-frame-options": actual})

    def test_matching_allow_from_scores_full(self):
        finding = self._finding("ALLOW-FROM https://example.com", "allow-from  HTTPS://EXAMPLE.COM/")
        assert finding.status == Status.PASS
        assert finding.score_earned == finding.score_possible

    def test_wrong_origin_scores_zero(self):
        finding = self._finding("ALLOW-FROM https://example.com", "ALLOW-FROM https://evil.com")
        assert finding.status == Status.FAIL
        assert finding.score_earned == 0

    def test_plain_deny_policy_behaviour_is_unchanged(self):
        assert self._finding("DENY", "deny").status == Status.PASS
        assert self._finding("DENY", "SAMEORIGIN").status == Status.FAIL
        assert self._finding("", "anything").status == Status.PASS

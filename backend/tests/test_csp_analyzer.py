from app.core import csp_analyzer
from app.schemas import Status


class TestParseCsp:
    def test_parses_multiple_directives(self):
        result = csp_analyzer.parse_csp("default-src 'self'; script-src 'self' https://cdn.example.com")
        assert result == {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.example.com"],
        }

    def test_directive_without_sources(self):
        result = csp_analyzer.parse_csp("upgrade-insecure-requests")
        assert result == {"upgrade-insecure-requests": []}

    def test_ignores_empty_segments(self):
        result = csp_analyzer.parse_csp("default-src 'self';; script-src 'self'")
        assert set(result.keys()) == {"default-src", "script-src"}


class TestEvaluatePolicyCompliance:
    def test_actual_none_fails_every_expected_directive(self):
        expected = {"default-src": ["'self'"]}
        checks = csp_analyzer.evaluate_policy_compliance(expected, None)
        assert len(checks) == 1
        assert checks[0].status == Status.FAIL

    def test_missing_directive_in_actual_fails(self):
        expected = {"object-src": ["'none'"]}
        checks = csp_analyzer.evaluate_policy_compliance(expected, {"default-src": ["'self'"]})
        assert checks[0].status == Status.FAIL

    def test_presence_only_directive_passes(self):
        expected = {"upgrade-insecure-requests": []}
        checks = csp_analyzer.evaluate_policy_compliance(
            expected, {"upgrade-insecure-requests": []}
        )
        assert checks[0].status == Status.PASS

    def test_source_set_match_is_order_independent(self):
        expected = {"script-src": ["'self'", "https://a.com"]}
        actual = {"script-src": ["https://a.com", "'self'"]}
        checks = csp_analyzer.evaluate_policy_compliance(expected, actual)
        assert checks[0].status == Status.PASS

    def test_source_set_mismatch_fails(self):
        expected = {"script-src": ["'self'"]}
        actual = {"script-src": ["'self'", "'unsafe-inline'"]}
        checks = csp_analyzer.evaluate_policy_compliance(expected, actual)
        assert checks[0].status == Status.FAIL


class TestEvaluateSecurityBestPractices:
    def test_returns_empty_when_no_csp(self):
        assert csp_analyzer.evaluate_security_best_practices(None) == []

    def test_wildcard_flagged_on_fetch_directives(self):
        checks = csp_analyzer.evaluate_security_best_practices({"script-src": ["*"]})
        wildcard_check = next(c for c in checks if c.name == "no-wildcard:script-src")
        assert wildcard_check.status == Status.FAIL

    def test_no_wildcard_passes(self):
        checks = csp_analyzer.evaluate_security_best_practices({"script-src": ["'self'"]})
        wildcard_check = next(c for c in checks if c.name == "no-wildcard:script-src")
        assert wildcard_check.status == Status.PASS

    def test_unsafe_inline_and_eval_detected(self):
        checks = csp_analyzer.evaluate_security_best_practices(
            {"script-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'"]}
        )
        check = next(c for c in checks if c.name == "no-unsafe-keywords:script-src")
        assert check.status == Status.FAIL
        assert "unsafe-eval" in check.actual
        assert "unsafe-inline" in check.actual

    def test_object_src_none_passes(self):
        checks = csp_analyzer.evaluate_security_best_practices({"object-src": ["'none'"]})
        check = next(c for c in checks if c.name == "object-src-none")
        assert check.status == Status.PASS

    def test_object_src_present_but_not_none_warns(self):
        checks = csp_analyzer.evaluate_security_best_practices({"object-src": ["'self'"]})
        check = next(c for c in checks if c.name == "object-src-none")
        assert check.status == Status.WARNING

    def test_object_src_missing_without_default_src_warns(self):
        checks = csp_analyzer.evaluate_security_best_practices({"script-src": ["'self'"]})
        check = next(c for c in checks if c.name == "object-src-none")
        assert check.status == Status.WARNING

    def test_object_src_missing_with_default_src_is_info(self):
        checks = csp_analyzer.evaluate_security_best_practices({"default-src": ["'self'"]})
        check = next(c for c in checks if c.name == "object-src-none")
        assert check.status == Status.INFO

    def test_base_uri_and_frame_ancestors_presence(self):
        checks = csp_analyzer.evaluate_security_best_practices({"default-src": ["'self'"]})
        base_uri = next(c for c in checks if c.name == "base-uri-present")
        frame_ancestors = next(c for c in checks if c.name == "frame-ancestors-present")
        assert base_uri.status == Status.WARNING
        assert frame_ancestors.status == Status.WARNING

        checks_ok = csp_analyzer.evaluate_security_best_practices(
            {"base-uri": ["'self'"], "frame-ancestors": ["'self'"]}
        )
        assert next(c for c in checks_ok if c.name == "base-uri-present").status == Status.PASS
        assert next(c for c in checks_ok if c.name == "frame-ancestors-present").status == Status.PASS

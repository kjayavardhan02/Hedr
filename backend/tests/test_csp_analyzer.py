from app.core import csp_analyzer
from app.core.csp_findings import CSPFindingId
from app.schemas import CSPDirectiveRule, CSPPolicy, Status


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

    def test_duplicate_directive_keeps_first_occurrence(self):
        # Real CSP parsing (and every major browser) keeps the FIRST
        # occurrence of a duplicated directive, not the last.
        result = csp_analyzer.parse_csp("script-src 'self'; script-src 'unsafe-inline'")
        assert result == {"script-src": ["'self'"]}

    def test_malformed_directive_name_is_skipped_not_crashed(self):
        result = csp_analyzer.parse_csp("default-src 'self'; %%% 'self'; script-src 'self'")
        assert set(result.keys()) == {"default-src", "script-src"}

    def test_empty_and_whitespace_input_never_crashes(self):
        assert csp_analyzer.parse_csp("") == {}
        assert csp_analyzer.parse_csp("   ;  ; ") == {}


class TestEvaluateCspPolicy:
    def test_required_directive_present_passes(self):
        policy = CSPPolicy(required=True, required_directives=["default-src"])
        checks = csp_analyzer.evaluate_csp_policy(policy, {"default-src": ["'self'"]})
        assert checks[0].status == Status.PASS
        assert checks[0].id == CSPFindingId.REQUIRED_DIRECTIVE_MISSING

    def test_required_directive_missing_fails(self):
        policy = CSPPolicy(required=True, required_directives=["object-src"])
        checks = csp_analyzer.evaluate_csp_policy(policy, {"default-src": ["'self'"]})
        assert checks[0].status == Status.FAIL

    def test_must_contain_present_passes(self):
        rule = CSPDirectiveRule(directive="object-src", must_contain=["'none'"])
        policy = CSPPolicy(directive_rules=[rule])
        checks = csp_analyzer.evaluate_csp_policy(policy, {"object-src": ["'none'"]})
        assert checks[0].status == Status.PASS
        assert checks[0].id == CSPFindingId.MUST_CONTAIN_MISSING

    def test_must_contain_absent_fails(self):
        rule = CSPDirectiveRule(directive="object-src", must_contain=["'none'"])
        policy = CSPPolicy(directive_rules=[rule])
        checks = csp_analyzer.evaluate_csp_policy(policy, {"object-src": ["'self'"]})
        assert checks[0].status == Status.FAIL

    def test_must_not_contain_absent_passes(self):
        rule = CSPDirectiveRule(directive="script-src", must_not_contain=["'unsafe-inline'"])
        policy = CSPPolicy(directive_rules=[rule])
        checks = csp_analyzer.evaluate_csp_policy(policy, {"script-src": ["'self'"]})
        assert checks[0].status == Status.PASS
        assert checks[0].id == CSPFindingId.PROHIBITED_SOURCE_PRESENT

    def test_must_not_contain_present_fails(self):
        rule = CSPDirectiveRule(directive="script-src", must_not_contain=["'unsafe-inline'"])
        policy = CSPPolicy(directive_rules=[rule])
        checks = csp_analyzer.evaluate_csp_policy(policy, {"script-src": ["'self'", "'unsafe-inline'"]})
        assert checks[0].status == Status.FAIL

    def test_allowlist_approved_source_passes(self):
        rule = CSPDirectiveRule(directive="script-src", allowed_sources=["'self'", "https://cdn.example.com"])
        policy = CSPPolicy(directive_rules=[rule])
        checks = csp_analyzer.evaluate_csp_policy(
            policy, {"script-src": ["'self'", "https://cdn.example.com"]}
        )
        assert checks[0].status == Status.PASS
        assert checks[0].id == CSPFindingId.UNAPPROVED_SOURCE

    def test_allowlist_unapproved_source_fails(self):
        rule = CSPDirectiveRule(directive="script-src", allowed_sources=["'self'"])
        policy = CSPPolicy(directive_rules=[rule])
        checks = csp_analyzer.evaluate_csp_policy(
            policy, {"script-src": ["'self'", "https://evil.example.com"]}
        )
        assert checks[0].status == Status.FAIL
        assert "evil.example.com" in checks[0].actual

    def test_disallow_wildcards_flags_bare_and_subdomain_wildcards(self):
        rule = CSPDirectiveRule(directive="script-src", disallow_wildcards=True)
        policy = CSPPolicy(directive_rules=[rule])
        checks = csp_analyzer.evaluate_csp_policy(policy, {"script-src": ["https://*.example.com"]})
        assert checks[0].status == Status.FAIL
        assert checks[0].id == CSPFindingId.WILDCARD_SOURCE

    def test_disallow_http_flags_plain_http_source(self):
        rule = CSPDirectiveRule(directive="script-src", disallow_http=True)
        policy = CSPPolicy(directive_rules=[rule])
        checks = csp_analyzer.evaluate_csp_policy(policy, {"script-src": ["http://example.com"]})
        assert checks[0].status == Status.FAIL
        assert checks[0].id == CSPFindingId.HTTP_SOURCE_DISALLOWED

    def test_disallow_data_flags_data_scheme(self):
        rule = CSPDirectiveRule(directive="img-src", disallow_data=True)
        policy = CSPPolicy(directive_rules=[rule])
        checks = csp_analyzer.evaluate_csp_policy(policy, {"img-src": ["data:"]})
        assert checks[0].status == Status.FAIL
        assert checks[0].id == CSPFindingId.DATA_SCHEME_DETECTED

    def test_disallow_blob_flags_blob_scheme(self):
        rule = CSPDirectiveRule(directive="worker-src", disallow_blob=True)
        policy = CSPPolicy(directive_rules=[rule])
        checks = csp_analyzer.evaluate_csp_policy(policy, {"worker-src": ["blob:"]})
        assert checks[0].status == Status.FAIL
        assert checks[0].id == CSPFindingId.BLOB_SCHEME_DETECTED

    def test_disallow_external_does_not_flag_self_none_nonce_or_hash(self):
        rule = CSPDirectiveRule(directive="script-src", disallow_external=True)
        policy = CSPPolicy(directive_rules=[rule])
        checks = csp_analyzer.evaluate_csp_policy(
            policy,
            {"script-src": ["'self'", "'none'", "'nonce-abc123'", "'sha256-abc'"]},
        )
        assert checks[0].status == Status.PASS

    def test_disallow_external_flags_real_url(self):
        rule = CSPDirectiveRule(directive="script-src", disallow_external=True)
        policy = CSPPolicy(directive_rules=[rule])
        checks = csp_analyzer.evaluate_csp_policy(policy, {"script-src": ["https://cdn.example.com"]})
        assert checks[0].status == Status.FAIL

    def test_actual_none_fails_every_rule(self):
        policy = CSPPolicy(
            required_directives=["default-src"],
            directive_rules=[CSPDirectiveRule(directive="object-src", must_contain=["'none'"])],
        )
        checks = csp_analyzer.evaluate_csp_policy(policy, None)
        assert all(c.status == Status.FAIL for c in checks)


class TestEvaluateSecurityBestPractices:
    def test_returns_empty_when_no_csp(self):
        assert csp_analyzer.evaluate_security_best_practices(None) == []

    def test_wildcard_flagged_on_fetch_directives(self):
        checks = csp_analyzer.evaluate_security_best_practices({"script-src": ["*"]})
        wildcard_check = next(c for c in checks if c.name == "no-wildcard:script-src")
        assert wildcard_check.status == Status.FAIL
        assert wildcard_check.id == CSPFindingId.WILDCARD_SOURCE
        assert wildcard_check.severity is not None

    def test_no_wildcard_passes(self):
        checks = csp_analyzer.evaluate_security_best_practices({"script-src": ["'self'"]})
        wildcard_check = next(c for c in checks if c.name == "no-wildcard:script-src")
        assert wildcard_check.status == Status.PASS

    def test_unsafe_inline_and_unsafe_eval_are_separate_findings(self):
        checks = csp_analyzer.evaluate_security_best_practices(
            {"script-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'"]}
        )
        inline_check = next(c for c in checks if c.name == "no-unsafe-inline:script-src")
        eval_check = next(c for c in checks if c.name == "no-unsafe-eval:script-src")
        assert inline_check.status == Status.FAIL
        assert inline_check.id == CSPFindingId.UNSAFE_INLINE
        assert eval_check.status == Status.FAIL
        assert eval_check.id == CSPFindingId.UNSAFE_EVAL

    def test_data_and_blob_detected_on_script_src(self):
        checks = csp_analyzer.evaluate_security_best_practices(
            {"script-src": ["'self'", "data:", "blob:"]}
        )
        data_check = next(c for c in checks if c.name == "no-data-scheme:script-src")
        blob_check = next(c for c in checks if c.name == "no-blob-scheme:script-src")
        assert data_check.status == Status.WARNING
        assert data_check.id == CSPFindingId.DATA_SCHEME_DETECTED
        assert blob_check.status == Status.WARNING
        assert blob_check.id == CSPFindingId.BLOB_SCHEME_DETECTED

    def test_data_and_blob_not_checked_on_img_src(self):
        # img-src legitimately uses data:/blob: constantly - this is
        # intentionally NOT a universal check there (only script/style-src).
        checks = csp_analyzer.evaluate_security_best_practices({"img-src": ["data:", "blob:"]})
        assert not any(c.name.startswith("no-data-scheme:") for c in checks)
        assert not any(c.name.startswith("no-blob-scheme:") for c in checks)

    def test_object_src_none_passes(self):
        checks = csp_analyzer.evaluate_security_best_practices({"object-src": ["'none'"]})
        check = next(c for c in checks if c.name == "object-src-none")
        assert check.status == Status.PASS
        assert check.id == CSPFindingId.OBJECT_SRC_NOT_NONE

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
        assert base_uri.id == CSPFindingId.BASE_URI_MISSING
        assert frame_ancestors.status == Status.WARNING
        assert frame_ancestors.id == CSPFindingId.FRAME_ANCESTORS_MISSING

        checks_ok = csp_analyzer.evaluate_security_best_practices(
            {"base-uri": ["'self'"], "frame-ancestors": ["'self'"]}
        )
        assert next(c for c in checks_ok if c.name == "base-uri-present").status == Status.PASS
        assert next(c for c in checks_ok if c.name == "frame-ancestors-present").status == Status.PASS


class TestComputeCspScore:
    def test_all_passing_gives_100(self):
        from app.schemas import CheckResult

        checks = [CheckResult(name="a", description="", status=Status.PASS)]
        _, _, _, _, overall = csp_analyzer.compute_csp_score(checks, [])
        assert overall == 100.0

    def test_mixed_pass_fail_blends_both_layers(self):
        from app.schemas import CheckResult

        policy_checks = [CheckResult(name="a", description="", status=Status.PASS)]
        security_checks = [
            CheckResult(name="b", description="", status=Status.PASS),
            CheckResult(name="c", description="", status=Status.FAIL),
        ]
        policy_passed, policy_total, bp_passed, bp_total, overall = csp_analyzer.compute_csp_score(
            policy_checks, security_checks
        )
        assert (policy_passed, policy_total) == (1, 1)
        assert (bp_passed, bp_total) == (1, 2)
        assert overall == round(100 * 2 / 3, 1)

    def test_no_checks_at_all_gives_100(self):
        _, _, _, _, overall = csp_analyzer.compute_csp_score([], [])
        assert overall == 100.0

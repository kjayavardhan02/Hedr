import pytest

from app.core.comparators import (
    cache_control_comparator,
    x_frame_options_comparator,
    directive_list_comparator,
    exact_or_allowed_comparator,
    get_comparator,
    normalize_origin,
    normalize_ws,
    origin_comparator,
    permissions_policy_comparator,
    referrer_policy_comparator,
    x_xss_protection_comparator,
)
from app.schemas import Status


class TestExactOrAllowedComparator:
    def test_missing_actual_fails(self):
        outcome = exact_or_allowed_comparator("X-Frame-Options", "DENY", None)
        assert outcome.status == Status.FAIL

    def test_exact_match_case_insensitive(self):
        outcome = exact_or_allowed_comparator("X-Frame-Options", "DENY", "deny")
        assert outcome.status == Status.PASS

    def test_exact_mismatch(self):
        outcome = exact_or_allowed_comparator("X-Frame-Options", "DENY", "SAMEORIGIN")
        assert outcome.status == Status.FAIL

    def test_allowed_values_syntax_pass(self):
        outcome = exact_or_allowed_comparator(
            "X-Frame-Options", "DENY|SAMEORIGIN", "sameorigin"
        )
        assert outcome.status == Status.PASS

    def test_allowed_values_syntax_fail(self):
        outcome = exact_or_allowed_comparator(
            "X-Frame-Options", "DENY|SAMEORIGIN", "ALLOW-FROM https://x"
        )
        assert outcome.status == Status.FAIL


class TestDirectiveListComparator:
    def test_missing_header_fails_all_directives(self):
        outcome = directive_list_comparator(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains", None
        )
        assert outcome.status == Status.FAIL
        assert outcome.total_count == 2

    def test_max_age_numeric_pass_when_greater_or_equal(self):
        outcome = directive_list_comparator(
            "Strict-Transport-Security", "max-age=31536000", "max-age=63072000"
        )
        assert outcome.status == Status.PASS

    def test_max_age_numeric_fail_when_lower(self):
        outcome = directive_list_comparator(
            "Strict-Transport-Security", "max-age=31536000", "max-age=100"
        )
        assert outcome.status == Status.FAIL

    def test_flag_directive_present_and_missing(self):
        expected = "max-age=31536000; includeSubDomains; preload"
        pass_outcome = directive_list_comparator(
            "Strict-Transport-Security", expected, "max-age=31536000; includeSubDomains; preload"
        )
        assert pass_outcome.status == Status.PASS

        fail_outcome = directive_list_comparator(
            "Strict-Transport-Security", expected, "max-age=31536000"
        )
        assert fail_outcome.status == Status.FAIL
        failed_names = {c.name for c in fail_outcome.checks if c.status == Status.FAIL}
        assert failed_names == {"includesubdomains", "preload"}

    def test_non_numeric_directive_exact_match(self):
        outcome = directive_list_comparator(
            "Strict-Transport-Security", "max-age=100; foo=bar", "max-age=100; foo=bar"
        )
        assert outcome.status == Status.PASS
        outcome_fail = directive_list_comparator(
            "Strict-Transport-Security", "max-age=100; foo=bar", "max-age=100; foo=baz"
        )
        assert outcome_fail.status == Status.FAIL

    def test_falls_back_to_exact_comparator_when_no_directives_parsed(self):
        outcome = directive_list_comparator("Strict-Transport-Security", "", "anything")
        assert outcome.status == Status.FAIL  # empty expected != "anything"


class TestPermissionsPolicyComparator:
    def test_missing_header_fails(self):
        outcome = permissions_policy_comparator(
            "Permissions-Policy", "geolocation=(self)", None
        )
        assert outcome.status == Status.FAIL

    def test_allowlist_matches_regardless_of_order(self):
        outcome = permissions_policy_comparator(
            "Permissions-Policy", "geolocation=(self example.com)", "geolocation=(example.com self)"
        )
        assert outcome.status == Status.PASS

    def test_allowlist_mismatch(self):
        outcome = permissions_policy_comparator(
            "Permissions-Policy", "geolocation=(self)", "geolocation=()"
        )
        assert outcome.status == Status.FAIL

    def test_missing_directive_in_actual(self):
        outcome = permissions_policy_comparator(
            "Permissions-Policy", "geolocation=(self), camera=()", "geolocation=(self)"
        )
        assert outcome.status == Status.FAIL


class TestGetComparator:
    def test_dispatches_hsts_case_insensitively(self):
        assert get_comparator("Strict-Transport-Security") is directive_list_comparator
        assert get_comparator("strict-transport-security") is directive_list_comparator

    def test_dispatches_permissions_policy(self):
        assert get_comparator("Permissions-Policy") is permissions_policy_comparator

    def test_defaults_to_exact_or_allowed(self):
        assert get_comparator("Some-Unknown-Header") is exact_or_allowed_comparator

    def test_x_frame_options_has_its_own_comparator(self):
        assert get_comparator("X-Frame-Options") is x_frame_options_comparator


PASS = Status.PASS
FAIL = Status.FAIL


class TestNormalizeWs:
    def test_trims_and_collapses_runs(self):
        assert normalize_ws("  a   b \t c  ") == "a b c"

    def test_preserves_case_and_characters(self):
        assert normalize_ws("Max-Age=1;  X") == "Max-Age=1; X"

    def test_leaves_quoted_content_untouched(self):
        assert normalize_ws('a   "b   c"   d') == 'a "b   c" d'


class TestEnumHeadersIgnoreWhitespace:
    """X-Content-Type-Options, X-Frame-Options, COOP, CORP, COEP, ACAC."""

    @pytest.mark.parametrize(
        "header, expected, actual",
        [
            ("X-Content-Type-Options", "nosniff", "  nosniff"),
            ("X-Content-Type-Options", "nosniff", "nosniff   "),
            ("X-Frame-Options", "DENY", "  deny  "),
            ("Cross-Origin-Opener-Policy", "same-origin", "  same-origin"),
            ("Cross-Origin-Opener-Policy", "same-origin", "SAME-ORIGIN"),
            ("Cross-Origin-Resource-Policy", "same-site", " same-site "),
            ("Cross-Origin-Embedder-Policy", "require-corp", "  Require-Corp "),
            ("Access-Control-Allow-Credentials", "true", "  true"),
            ("Cross-Origin-Opener-Policy", "same-origin-allow-popups", "same-origin-allow-popups"),
        ],
    )
    def test_equivalent_formatting_passes(self, header, expected, actual):
        assert exact_or_allowed_comparator(header, expected, actual).status == PASS

    @pytest.mark.parametrize(
        "header, expected, actual",
        [
            ("Cross-Origin-Opener-Policy", "same-origin", "same-origin-allow-popups"),
            ("Cross-Origin-Opener-Policy", "same-origin", "unsafe-none"),
            ("Cross-Origin-Resource-Policy", "same-origin", "cross-origin"),
            ("Cross-Origin-Embedder-Policy", "require-corp", "unsafe-none"),
            ("X-Frame-Options", "DENY", "SAMEORIGIN"),
            ("X-Content-Type-Options", "nosniff", "sniff"),
        ],
    )
    def test_different_value_still_fails(self, header, expected, actual):
        assert exact_or_allowed_comparator(header, expected, actual).status == FAIL

    def test_allowed_values_with_padding_around_the_pipe(self):
        outcome = exact_or_allowed_comparator("X-Frame-Options", " DENY | SAMEORIGIN ", "  sameorigin ")
        assert outcome.status == PASS


class TestReferrerPolicy:
    def test_single_token_formatting(self):
        assert referrer_policy_comparator("Referrer-Policy", "strict-origin", "  Strict-Origin ").status == PASS

    def test_allowed_list(self):
        outcome = referrer_policy_comparator(
            "Referrer-Policy", "strict-origin|strict-origin-when-cross-origin|no-referrer", "no-referrer"
        )
        assert outcome.status == PASS

    def test_last_recognised_token_is_effective(self):
        outcome = referrer_policy_comparator(
            "Referrer-Policy", "strict-origin", "unsafe-url,   strict-origin"
        )
        assert outcome.status == PASS

    def test_weak_last_token_fails_even_if_earlier_token_is_strong(self):
        outcome = referrer_policy_comparator("Referrer-Policy", "strict-origin", "strict-origin, unsafe-url")
        assert outcome.status == FAIL

    def test_unknown_trailing_token_is_ignored_for_the_effective_policy(self):
        outcome = referrer_policy_comparator("Referrer-Policy", "no-referrer", "no-referrer, made-up-token")
        assert outcome.status == PASS

    def test_not_in_allowed_list_fails(self):
        outcome = referrer_policy_comparator("Referrer-Policy", "strict-origin|no-referrer", "origin")
        assert outcome.status == FAIL

    def test_missing_header_fails(self):
        assert referrer_policy_comparator("Referrer-Policy", "no-referrer", None).status == FAIL


class TestHstsNormalization:
    EXPECTED = "max-age=31536000; includeSubDomains; preload"

    @pytest.mark.parametrize(
        "actual",
        [
            "max-age=31536000; includeSubDomains; preload",
            "max-age=31536000;includeSubDomains;preload",
            "max-age=31536000;   includeSubDomains;   preload",
            "  max-age=31536000 ; includeSubDomains ; preload  ",
            "preload; includeSubDomains; max-age=31536000",
            "MAX-AGE=31536000; INCLUDESUBDOMAINS; PRELOAD",
            'max-age="31536000"; includeSubDomains; preload',
            "max-age=31536000; includeSubDomains; preload;",
            "max-age=31536000;; includeSubDomains; preload",
            "max-age=63072000; includeSubDomains; preload",
        ],
    )
    def test_equivalent_formatting_passes(self, actual):
        assert directive_list_comparator("Strict-Transport-Security", self.EXPECTED, actual).status == PASS

    @pytest.mark.parametrize(
        "actual",
        [
            "max-age=100; includeSubDomains; preload",
            "max-age=31536000; preload",
            "max-age=31536000; includeSubDomains",
            "includeSubDomains; preload",
            "max-age=abc; includeSubDomains; preload",
        ],
    )
    def test_real_differences_still_fail(self, actual):
        assert directive_list_comparator("Strict-Transport-Security", self.EXPECTED, actual).status == FAIL

    def test_first_duplicate_directive_wins(self):
        outcome = directive_list_comparator(
            "Strict-Transport-Security", "max-age=31536000", "max-age=100; max-age=31536000"
        )
        assert outcome.status == FAIL


class TestCacheControl:
    def test_spec_example_spacing_is_irrelevant(self):
        expected = "private, no-cache, no-store, max-age=0, must-revalidate"
        actual = "private,   no-cache,   no-store,    max-age=0,      must-revalidate"
        assert cache_control_comparator("Cache-Control", expected, actual).status == PASS

    @pytest.mark.parametrize(
        "actual",
        [
            "private, no-cache, no-store",
            "no-store, private, no-cache",
            "no-cache,no-store,private",
            "  PRIVATE , No-Cache , NO-STORE ",
        ],
    )
    def test_directive_order_and_case_are_irrelevant(self, actual):
        assert cache_control_comparator("Cache-Control", "private, no-cache, no-store", actual).status == PASS

    def test_missing_directive_fails(self):
        assert cache_control_comparator("Cache-Control", "private, no-store", "private").status == FAIL

    def test_extra_directive_fails_by_default(self):
        outcome = cache_control_comparator("Cache-Control", "private, no-store", "private, no-store, public")
        assert outcome.status == FAIL
        assert {c.name for c in outcome.checks if c.status == FAIL} == {"no-unexpected-directives"}

    def test_plus_token_allows_extra_directives(self):
        outcome = cache_control_comparator(
            "Cache-Control", "no-store, private, +", "no-store, max-age=0, private, must-revalidate"
        )
        assert outcome.status == PASS

    def test_spec_must_contain_example(self):
        outcome = cache_control_comparator(
            "Cache-Control", "no-store, private, max-age=0, +", "no-store, max-age=0, private"
        )
        assert outcome.status == PASS

    def test_prohibited_directive_present_fails(self):
        outcome = cache_control_comparator("Cache-Control", "no-store, !public, +", "no-store, public")
        assert outcome.status == FAIL

    def test_prohibited_directive_absent_passes(self):
        outcome = cache_control_comparator("Cache-Control", "no-store, !public, +", "no-store, private")
        assert outcome.status == PASS

    def test_max_age_equality_is_numeric(self):
        assert cache_control_comparator("Cache-Control", "max-age=0", "max-age=00").status == PASS
        assert cache_control_comparator("Cache-Control", "max-age=0", "max-age=60").status == FAIL

    def test_max_age_bounds(self):
        assert cache_control_comparator("Cache-Control", "max-age<=60", "max-age=30").status == PASS
        assert cache_control_comparator("Cache-Control", "max-age<=60", "max-age=61").status == FAIL
        assert cache_control_comparator("Cache-Control", "max-age>=60", "max-age=61").status == PASS
        assert cache_control_comparator("Cache-Control", "max-age>=60", "max-age=59").status == FAIL

    def test_missing_parameter_fails(self):
        assert cache_control_comparator("Cache-Control", "no-store, max-age=0", "no-store").status == FAIL

    def test_quoted_value_with_comma_is_not_split(self):
        outcome = cache_control_comparator(
            "Cache-Control", "private, no-cache", 'private, no-cache="Set-Cookie, X-Other"'
        )
        assert outcome.status == PASS

    def test_missing_header_fails(self):
        assert cache_control_comparator("Cache-Control", "no-store", None).status == FAIL

    def test_unparseable_policy_falls_back_to_exact(self):
        assert cache_control_comparator("Cache-Control", "", "anything").status == FAIL


class TestXXssProtection:
    @pytest.mark.parametrize("actual", ["1; mode=block", "1;mode=block", "1;   mode=block", "  1 ; mode=block ", "1; MODE=BLOCK"])
    def test_spacing_and_case_are_irrelevant(self, actual):
        assert x_xss_protection_comparator("X-XSS-Protection", "1; mode=block", actual).status == PASS

    def test_spec_example(self):
        assert x_xss_protection_comparator("X-XSS-Protection", "1; mode=block", "1;mode=block").status == PASS

    def test_zero_policy_matches_zero(self):
        assert x_xss_protection_comparator("X-XSS-Protection", "0", " 0 ").status == PASS

    def test_zero_policy_rejects_enabled_protection(self):
        assert x_xss_protection_comparator("X-XSS-Protection", "0", "1; mode=block").status == FAIL

    def test_enabled_policy_rejects_zero(self):
        assert x_xss_protection_comparator("X-XSS-Protection", "1; mode=block", "0").status == FAIL

    def test_missing_required_parameter_fails(self):
        assert x_xss_protection_comparator("X-XSS-Protection", "1; mode=block", "1").status == FAIL

    def test_different_parameter_value_fails(self):
        assert x_xss_protection_comparator("X-XSS-Protection", "1; mode=block", "1; mode=other").status == FAIL

    def test_additional_parameter_is_allowed(self):
        outcome = x_xss_protection_comparator("X-XSS-Protection", "1; mode=block", "1; mode=block; report=/r")
        assert outcome.status == PASS

    def test_missing_header_fails(self):
        assert x_xss_protection_comparator("X-XSS-Protection", "0", None).status == FAIL

    def test_non_flag_policy_falls_back_to_exact(self):
        assert x_xss_protection_comparator("X-XSS-Protection", "block", "block").status == PASS


class TestNormalizeOrigin:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("https://Example.COM", "https://example.com"),
            ("https://example.com/", "https://example.com"),
            ("https://example.com:443", "https://example.com"),
            ("http://example.com:80/", "http://example.com"),
            ("https://example.com:8443", "https://example.com:8443"),
            ("  https://example.com  ", "https://example.com"),
            ("*", "*"),
            ("NULL", "null"),
        ],
    )
    def test_canonical_forms(self, raw, expected):
        assert normalize_origin(raw) == expected

    def test_different_scheme_or_host_stays_different(self):
        assert normalize_origin("http://example.com") != normalize_origin("https://example.com")
        assert normalize_origin("https://a.example.com") != normalize_origin("https://example.com")

    def test_path_bearing_value_is_not_collapsed_into_an_origin(self):
        assert normalize_origin("https://example.com/app") != normalize_origin("https://example.com")


class TestAccessControlAllowOrigin:
    def test_single_origin_formatting(self):
        assert origin_comparator("Access-Control-Allow-Origin", "https://example.com", "  HTTPS://Example.com/ ").status == PASS

    def test_allowed_origins_list_spec_example(self):
        outcome = origin_comparator(
            "Access-Control-Allow-Origin",
            "https://example.com|https://app.example.com",
            "https://app.example.com",
        )
        assert outcome.status == PASS

    def test_origin_not_in_list_fails(self):
        outcome = origin_comparator(
            "Access-Control-Allow-Origin", "https://example.com|https://app.example.com", "https://evil.com"
        )
        assert outcome.status == FAIL

    def test_lookalike_origin_is_not_equivalent(self):
        outcome = origin_comparator("Access-Control-Allow-Origin", "https://example.com", "https://example.com.evil.com")
        assert outcome.status == FAIL

    def test_wildcard_fails_when_policy_does_not_allow_it(self):
        outcome = origin_comparator("Access-Control-Allow-Origin", "https://example.com", "*")
        assert outcome.status == FAIL

    def test_wildcard_passes_when_explicitly_allowed(self):
        assert origin_comparator("Access-Control-Allow-Origin", "*", "*").status == PASS
        assert origin_comparator("Access-Control-Allow-Origin", "https://example.com|*", "*").status == PASS

    def test_specific_origin_does_not_pass_a_wildcard_only_policy(self):
        assert origin_comparator("Access-Control-Allow-Origin", "*", "https://example.com").status == FAIL

    def test_null_origin_is_literal(self):
        assert origin_comparator("Access-Control-Allow-Origin", "null", "null").status == PASS
        assert origin_comparator("Access-Control-Allow-Origin", "https://example.com", "null").status == FAIL

    def test_missing_header_fails(self):
        assert origin_comparator("Access-Control-Allow-Origin", "https://example.com", None).status == FAIL


class TestPermissionsPolicyNormalization:
    EXPECTED = "geolocation=(), camera=(), microphone=()"

    @pytest.mark.parametrize(
        "actual",
        [
            "geolocation=(), camera=(), microphone=()",
            "geolocation=(),  camera=(),   microphone=()",
            "geolocation=(),camera=(),microphone=()",
            "microphone=(), geolocation=(), camera=()",
            "  Geolocation=( ) , CAMERA=(), microphone=()  ",
        ],
    )
    def test_spec_example_formatting_and_order(self, actual):
        assert permissions_policy_comparator("Permissions-Policy", self.EXPECTED, actual).status == PASS

    def test_quoted_origin_allowlist(self):
        outcome = permissions_policy_comparator(
            "Permissions-Policy",
            'geolocation=(self "https://example.com")',
            'geolocation=( "https://example.com"   self )',
        )
        assert outcome.status == PASS

    def test_unquoted_policy_origin_matches_quoted_actual(self):
        outcome = permissions_policy_comparator(
            "Permissions-Policy", "geolocation=(self https://example.com)", 'geolocation=(self "https://example.com")'
        )
        assert outcome.status == PASS

    def test_bare_token_form_is_understood(self):
        assert permissions_policy_comparator("Permissions-Policy", "fullscreen=(*)", "fullscreen=*").status == PASS
        assert permissions_policy_comparator("Permissions-Policy", "fullscreen=(self)", "fullscreen=self").status == PASS

    def test_none_alias_means_disabled(self):
        assert permissions_policy_comparator("Permissions-Policy", "camera=(none)", "camera=()").status == PASS

    def test_params_after_semicolon_are_ignored(self):
        assert permissions_policy_comparator("Permissions-Policy", "camera=()", "camera=();report-to=x").status == PASS

    def test_enabled_feature_does_not_match_disabled_policy(self):
        assert permissions_policy_comparator("Permissions-Policy", "camera=()", "camera=(self)").status == FAIL
        assert permissions_policy_comparator("Permissions-Policy", "camera=()", "camera=*").status == FAIL

    def test_extra_origin_fails(self):
        outcome = permissions_policy_comparator(
            "Permissions-Policy", "geolocation=(self)", 'geolocation=(self "https://evil.com")'
        )
        assert outcome.status == FAIL

    def test_missing_feature_fails(self):
        assert permissions_policy_comparator("Permissions-Policy", "camera=(), microphone=()", "camera=()").status == FAIL


class TestDispatchForNewComparators:
    @pytest.mark.parametrize(
        "header, comparator",
        [
            ("Cache-Control", cache_control_comparator),
            ("cache-control", cache_control_comparator),
            ("X-XSS-Protection", x_xss_protection_comparator),
            ("Access-Control-Allow-Origin", origin_comparator),
            ("Referrer-Policy", referrer_policy_comparator),
        ],
    )
    def test_dispatch(self, header, comparator):
        assert get_comparator(header) is comparator

    @pytest.mark.parametrize(
        "header",
        [
            "X-Content-Type-Options",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
            "Cross-Origin-Embedder-Policy",
            "Access-Control-Allow-Credentials",
        ],
    )
    def test_enum_headers_use_the_normalized_enum_comparator(self, header):
        assert get_comparator(header) is exact_or_allowed_comparator

    def test_csp_is_not_routed_through_generic_comparators(self):
        assert get_comparator("Content-Security-Policy") is exact_or_allowed_comparator


class TestPermissionsPolicySemicolonSeparatedPolicies:
    """The built-in baselines write Permissions-Policy with ';' between
    features. Every feature must still be checked, not just the first."""

    EXPECTED = "geolocation=(); camera=(); microphone=(); payment=(self)"
    GOOD = "geolocation=(), camera=(), microphone=(), payment=(self)"

    def test_all_features_pass_when_all_match(self):
        assert permissions_policy_comparator("Permissions-Policy", self.EXPECTED, self.GOOD).status == PASS

    @pytest.mark.parametrize(
        "actual",
        [
            "geolocation=(self), camera=(), microphone=(), payment=(self)",
            "geolocation=(), camera=(self), microphone=(), payment=(self)",
            "geolocation=(), camera=(), microphone=(*), payment=(self)",
            "geolocation=(), camera=(), microphone=(), payment=*",
            "geolocation=(), camera=(), microphone=()",
            "geolocation=(), camera=()",
        ],
    )
    def test_any_feature_that_differs_fails(self, actual):
        assert permissions_policy_comparator("Permissions-Policy", self.EXPECTED, actual).status == FAIL

    def test_each_feature_gets_its_own_check(self):
        outcome = permissions_policy_comparator("Permissions-Policy", self.EXPECTED, self.GOOD)
        assert {c.name for c in outcome.checks} == {"geolocation", "camera", "microphone", "payment"}

    def test_semicolon_and_comma_policies_are_equivalent(self):
        for actual in (self.GOOD, "payment=(self), microphone=(), camera=(), geolocation=()"):
            a = permissions_policy_comparator("Permissions-Policy", self.EXPECTED, actual)
            b = permissions_policy_comparator("Permissions-Policy", self.EXPECTED.replace("; ", ", "), actual)
            assert a.status == b.status == PASS


class TestXFrameOptions:
    H = "X-Frame-Options"

    @pytest.mark.parametrize("actual", ["DENY", "deny", "  Deny  "])
    def test_deny_formatting(self, actual):
        assert x_frame_options_comparator(self.H, "DENY", actual).status == PASS

    @pytest.mark.parametrize("actual", ["SAMEORIGIN", "sameorigin", " SameOrigin "])
    def test_sameorigin_formatting(self, actual):
        assert x_frame_options_comparator(self.H, "SAMEORIGIN", actual).status == PASS

    def test_deny_and_sameorigin_are_different(self):
        assert x_frame_options_comparator(self.H, "DENY", "SAMEORIGIN").status == FAIL
        assert x_frame_options_comparator(self.H, "SAMEORIGIN", "DENY").status == FAIL

    def test_allowed_list_of_plain_values(self):
        assert x_frame_options_comparator(self.H, " DENY | SAMEORIGIN ", "sameorigin").status == PASS
        assert x_frame_options_comparator(self.H, "DENY|SAMEORIGIN", "ALLOW-FROM https://x.com").status == FAIL

    @pytest.mark.parametrize(
        "actual",
        [
            "ALLOW-FROM https://example.com",
            "allow-from https://example.com",
            "ALLOW-FROM    https://example.com",
            "  ALLOW-FROM https://example.com  ",
            "ALLOW-FROM HTTPS://Example.COM/",
            "ALLOW-FROM https://example.com:443",
            "ALLOW-FROM https://example.com/some/page",
        ],
    )
    def test_allow_from_matches_the_same_origin(self, actual):
        assert x_frame_options_comparator(self.H, "ALLOW-FROM https://example.com", actual).status == PASS

    @pytest.mark.parametrize(
        "actual",
        [
            "ALLOW-FROM https://evil.com",
            "ALLOW-FROM https://example.com.evil.com",
            "ALLOW-FROM http://example.com",
            "ALLOW-FROM https://sub.example.com",
            "ALLOW-FROM https://example.com:8443",
            "ALLOW-FROM",
            "DENY",
            "SAMEORIGIN",
        ],
    )
    def test_allow_from_rejects_anything_else(self, actual):
        assert x_frame_options_comparator(self.H, "ALLOW-FROM https://example.com", actual).status == FAIL

    def test_allow_from_response_does_not_satisfy_deny_or_sameorigin(self):
        assert x_frame_options_comparator(self.H, "DENY", "ALLOW-FROM https://example.com").status == FAIL
        assert x_frame_options_comparator(self.H, "SAMEORIGIN", "ALLOW-FROM https://example.com").status == FAIL

    def test_mixed_list_with_allow_from(self):
        expected = "DENY|ALLOW-FROM https://a.com|ALLOW-FROM https://b.com"
        assert x_frame_options_comparator(self.H, expected, "deny").status == PASS
        assert x_frame_options_comparator(self.H, expected, "allow-from https://B.com/").status == PASS
        assert x_frame_options_comparator(self.H, expected, "ALLOW-FROM https://c.com").status == FAIL
        assert x_frame_options_comparator(self.H, expected, "SAMEORIGIN").status == FAIL

    def test_missing_header_fails(self):
        assert x_frame_options_comparator(self.H, "ALLOW-FROM https://example.com", None).status == FAIL

    def test_obsolete_note_appears_only_when_allow_from_is_involved(self):
        with_note = x_frame_options_comparator(self.H, "ALLOW-FROM https://example.com", "ALLOW-FROM https://example.com")
        assert "obsolete" in with_note.checks[0].description
        assert "frame-ancestors" in with_note.checks[0].description
        without = x_frame_options_comparator(self.H, "DENY", "DENY")
        assert "obsolete" not in without.checks[0].description

    def test_note_also_shown_when_a_response_uses_allow_from_against_a_plain_policy(self):
        outcome = x_frame_options_comparator(self.H, "DENY", "ALLOW-FROM https://example.com")
        assert outcome.status == FAIL
        assert "obsolete" in outcome.checks[0].description

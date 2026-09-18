from app.core.comparators import (
    directive_list_comparator,
    exact_or_allowed_comparator,
    get_comparator,
    permissions_policy_comparator,
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
        assert get_comparator("X-Frame-Options") is exact_or_allowed_comparator
        assert get_comparator("Some-Unknown-Header") is exact_or_allowed_comparator

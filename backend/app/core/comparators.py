"""Structural comparators used by the policy engine.

The UI only exposes two fields per header - "header name" and
"expected value" - but under the hood we still perform the kind of
directive-aware comparison the product spec calls for (section 3: policies,
not exact-string templates). Which comparator runs is chosen by header
name, so the user never has to pick a rule type manually.

Supported expected-value mini-syntax (all still just typed into the single
"value" text field):

  - Plain value                -> exact match (case-insensitive, trimmed)
  - "a|b|c"                    -> allowed-values match (actual must be one of them)
  - "directive=value; flag"    -> directive-aware match for headers that use
                                   this grammar (e.g. Strict-Transport-Security).
                                   `max-age` is compared numerically as >=.
  - "directive=(token token)"  -> Permissions-Policy allowlist grammar.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.schemas import CheckResult, Status

NUMERIC_MIN_DIRECTIVES = {"max-age"}


@dataclass
class ComparisonOutcome:
    status: Status
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.checks if c.status == Status.PASS)

    @property
    def total_count(self) -> int:
        return len(self.checks) or 1


def _parse_directive_list(value: str) -> dict[str, str | bool]:
    """Parses "max-age=100; includeSubDomains; preload" style values."""
    directives: dict[str, str | bool] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, val = part.partition("=")
            directives[key.strip().lower()] = val.strip().strip('"')
        else:
            directives[part.strip().lower()] = True
    return directives


def exact_or_allowed_comparator(header: str, expected: str, actual: str | None) -> ComparisonOutcome:
    checks: list[CheckResult] = []

    if actual is None:
        checks.append(
            CheckResult(
                name="value-match",
                description=f"{header} must be present to evaluate its value.",
                status=Status.FAIL,
                expected=expected,
                actual=None,
            )
        )
        return ComparisonOutcome(Status.FAIL, checks)

    if "|" in expected:
        allowed = [v.strip() for v in expected.split("|") if v.strip()]
        ok = actual.strip().lower() in {v.lower() for v in allowed}
        checks.append(
            CheckResult(
                name="allowed-values",
                description=f"Value must be one of: {', '.join(allowed)}.",
                status=Status.PASS if ok else Status.FAIL,
                expected=" | ".join(allowed),
                actual=actual,
            )
        )
    else:
        ok = actual.strip().lower() == expected.strip().lower()
        checks.append(
            CheckResult(
                name="exact-value",
                description="Value must exactly match the policy.",
                status=Status.PASS if ok else Status.FAIL,
                expected=expected,
                actual=actual,
            )
        )

    overall = Status.PASS if all(c.status == Status.PASS for c in checks) else Status.FAIL
    return ComparisonOutcome(overall, checks)


def directive_list_comparator(header: str, expected: str, actual: str | None) -> ComparisonOutcome:
    """Semicolon-delimited directive grammar, e.g. Strict-Transport-Security."""
    checks: list[CheckResult] = []
    expected_directives = _parse_directive_list(expected)

    if not expected_directives:
        return exact_or_allowed_comparator(header, expected, actual)

    if actual is None:
        for name in expected_directives:
            checks.append(
                CheckResult(
                    name=name,
                    description=f"Directive '{name}' cannot be checked - header is missing.",
                    status=Status.FAIL,
                    expected=str(expected_directives[name]),
                    actual=None,
                )
            )
        return ComparisonOutcome(Status.FAIL, checks)

    actual_directives = _parse_directive_list(actual)

    for name, expected_val in expected_directives.items():
        actual_val = actual_directives.get(name)

        if name in NUMERIC_MIN_DIRECTIVES:
            try:
                expected_num = float(str(expected_val))
                actual_num = float(str(actual_val)) if actual_val is not None else None
            except ValueError:
                expected_num = None
                actual_num = None

            if actual_num is None:
                status = Status.FAIL
            else:
                status = Status.PASS if actual_num >= (expected_num or 0) else Status.FAIL

            checks.append(
                CheckResult(
                    name=name,
                    description=f"{name} must be >= {expected_val}.",
                    status=status,
                    expected=f">= {expected_val}",
                    actual=str(actual_val) if actual_val is not None else "missing",
                )
            )
            continue

        if expected_val is True:
            # Flag directive - just needs to be present.
            status = Status.PASS if name in actual_directives else Status.FAIL
            checks.append(
                CheckResult(
                    name=name,
                    description=f"Directive '{name}' is required.",
                    status=status,
                    expected="present",
                    actual="present" if name in actual_directives else "missing",
                )
            )
        else:
            status = (
                Status.PASS
                if actual_val is not None
                and str(actual_val).strip().lower() == str(expected_val).strip().lower()
                else Status.FAIL
            )
            checks.append(
                CheckResult(
                    name=name,
                    description=f"Directive '{name}' must equal '{expected_val}'.",
                    status=status,
                    expected=str(expected_val),
                    actual=str(actual_val) if actual_val is not None else "missing",
                )
            )

    overall = Status.PASS if all(c.status == Status.PASS for c in checks) else Status.FAIL
    return ComparisonOutcome(overall, checks)


_PP_DIRECTIVE_RE = re.compile(r"([a-zA-Z0-9-]+)=\(([^)]*)\)")


def _parse_permissions_policy(value: str) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for match in _PP_DIRECTIVE_RE.finditer(value):
        name = match.group(1).strip().lower()
        tokens = {t.strip() for t in match.group(2).split() if t.strip()}
        result[name] = tokens
    return result


def permissions_policy_comparator(header: str, expected: str, actual: str | None) -> ComparisonOutcome:
    checks: list[CheckResult] = []
    expected_directives = _parse_permissions_policy(expected)

    if not expected_directives:
        return exact_or_allowed_comparator(header, expected, actual)

    if actual is None:
        for name in expected_directives:
            checks.append(
                CheckResult(
                    name=name,
                    description=f"Directive '{name}' cannot be checked - header is missing.",
                    status=Status.FAIL,
                    expected=f"({' '.join(sorted(expected_directives[name]))})",
                    actual=None,
                )
            )
        return ComparisonOutcome(Status.FAIL, checks)

    actual_directives = _parse_permissions_policy(actual)

    for name, expected_tokens in expected_directives.items():
        actual_tokens = actual_directives.get(name)
        status = Status.PASS if actual_tokens == expected_tokens else Status.FAIL
        checks.append(
            CheckResult(
                name=name,
                description=f"Directive '{name}' allowlist must equal the policy.",
                status=status,
                expected=f"({' '.join(sorted(expected_tokens))})",
                actual=f"({' '.join(sorted(actual_tokens))})" if actual_tokens is not None else "missing",
            )
        )

    overall = Status.PASS if all(c.status == Status.PASS for c in checks) else Status.FAIL
    return ComparisonOutcome(overall, checks)


# Header (lower-case) -> comparator function
DIRECTIVE_GRAMMAR_HEADERS = {
    "strict-transport-security": directive_list_comparator,
    "permissions-policy": permissions_policy_comparator,
}


def get_comparator(header_name: str):
    return DIRECTIVE_GRAMMAR_HEADERS.get(header_name.lower(), exact_or_allowed_comparator)

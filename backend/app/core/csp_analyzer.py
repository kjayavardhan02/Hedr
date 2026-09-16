"""Dedicated Content-Security-Policy analyzer (spec section 10/11).

CSP gets two independent layers of analysis:

1. Policy compliance - if the user's policy defines an expected CSP value,
   each directive's source list is compared against the actual response
   (exact set match, order independent).
2. Security best-practices - run unconditionally, regardless of what the
   user's policy says, flagging classic CSP weaknesses (wildcards,
   unsafe-inline/unsafe-eval, missing object-src 'none', missing
   base-uri, missing frame-ancestors).
"""
from __future__ import annotations

from app.schemas import CheckResult, Status

DANGEROUS_SCRIPT_STYLE_KEYWORDS = {"unsafe-inline", "unsafe-eval"}
FETCH_DIRECTIVES_TO_CHECK_FOR_WILDCARD = {
    "default-src",
    "script-src",
    "style-src",
    "connect-src",
    "img-src",
    "frame-src",
    "worker-src",
    "child-src",
}


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for raw_directive in value.split(";"):
        raw_directive = raw_directive.strip()
        if not raw_directive:
            continue
        parts = raw_directive.split()
        name = parts[0].strip().lower()
        sources = parts[1:]
        directives[name] = sources
    return directives


def _tokens_equal(a: list[str], b: list[str]) -> bool:
    return {t.lower() for t in a} == {t.lower() for t in b}


def evaluate_policy_compliance(
    expected: dict[str, list[str]], actual: dict[str, list[str]] | None
) -> list[CheckResult]:
    checks: list[CheckResult] = []
    if actual is None:
        for name, sources in expected.items():
            checks.append(
                CheckResult(
                    name=f"directive:{name}",
                    description=f"Directive '{name}' cannot be checked - CSP header missing.",
                    status=Status.FAIL,
                    expected=" ".join(sources) or "(present)",
                    actual=None,
                )
            )
        return checks

    for name, expected_sources in expected.items():
        if name not in actual:
            checks.append(
                CheckResult(
                    name=f"directive:{name}",
                    description=f"Directive '{name}' is required by policy.",
                    status=Status.FAIL,
                    expected=" ".join(expected_sources) or "(present)",
                    actual="missing",
                )
            )
            continue

        actual_sources = actual[name]
        if not expected_sources:
            # Policy only requires the directive to exist.
            checks.append(
                CheckResult(
                    name=f"directive:{name}",
                    description=f"Directive '{name}' must be present.",
                    status=Status.PASS,
                    expected="(present)",
                    actual=" ".join(actual_sources) or "(empty)",
                )
            )
            continue

        ok = _tokens_equal(expected_sources, actual_sources)
        checks.append(
            CheckResult(
                name=f"directive:{name}",
                description=f"Directive '{name}' sources must match the policy.",
                status=Status.PASS if ok else Status.FAIL,
                expected=" ".join(expected_sources),
                actual=" ".join(actual_sources) or "(empty)",
            )
        )

    return checks


def evaluate_security_best_practices(actual: dict[str, list[str]] | None) -> list[CheckResult]:
    checks: list[CheckResult] = []
    if actual is None:
        return checks

    # Wildcard sources on key fetch directives.
    for directive in FETCH_DIRECTIVES_TO_CHECK_FOR_WILDCARD:
        if directive not in actual:
            continue
        sources = actual[directive]
        has_wildcard = "*" in sources
        checks.append(
            CheckResult(
                name=f"no-wildcard:{directive}",
                description=f"'{directive}' should not use a bare wildcard (*) source.",
                status=Status.FAIL if has_wildcard else Status.PASS,
                expected="no bare '*' source",
                actual=" ".join(sources),
            )
        )

    # unsafe-inline / unsafe-eval on script-src and style-src.
    for directive in ("script-src", "style-src"):
        if directive not in actual:
            continue
        sources = {s.strip("'\"").lower() for s in actual[directive]}
        found = sources & DANGEROUS_SCRIPT_STYLE_KEYWORDS
        checks.append(
            CheckResult(
                name=f"no-unsafe-keywords:{directive}",
                description=f"'{directive}' should not allow {', '.join(sorted(DANGEROUS_SCRIPT_STYLE_KEYWORDS))}.",
                status=Status.FAIL if found else Status.PASS,
                expected="no unsafe-inline / unsafe-eval",
                actual=" ".join(sorted(found)) if found else "(none found)",
            )
        )

    # object-src should be 'none' (or covered by a strict default-src).
    if "object-src" in actual:
        sources = [s.lower() for s in actual["object-src"]]
        ok = sources == ["'none'"]
        checks.append(
            CheckResult(
                name="object-src-none",
                description="'object-src' should be restricted to 'none'.",
                status=Status.PASS if ok else Status.WARNING,
                expected="'none'",
                actual=" ".join(actual["object-src"]) or "(empty)",
            )
        )
    else:
        checks.append(
            CheckResult(
                name="object-src-none",
                description="'object-src' should be explicitly set to 'none' (or covered by default-src).",
                status=Status.WARNING if "default-src" not in actual else Status.INFO,
                expected="'none'",
                actual="missing",
            )
        )

    # base-uri should exist.
    checks.append(
        CheckResult(
            name="base-uri-present",
            description="'base-uri' should be set to prevent base tag injection.",
            status=Status.PASS if "base-uri" in actual else Status.WARNING,
            expected="present",
            actual="present" if "base-uri" in actual else "missing",
        )
    )

    # frame-ancestors should exist (clickjacking protection).
    checks.append(
        CheckResult(
            name="frame-ancestors-present",
            description="'frame-ancestors' should be set for clickjacking protection.",
            status=Status.PASS if "frame-ancestors" in actual else Status.WARNING,
            expected="present",
            actual="present" if "frame-ancestors" in actual else "missing",
        )
    )

    return checks

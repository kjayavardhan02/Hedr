"""Dedicated Content-Security-Policy analyzer (spec section 10/11).

CSP gets two independent layers of analysis:

1. Policy compliance - a structured rule set (required directives,
   must-contain / must-not-contain / allowlist / pattern-restriction rules
   per directive) evaluated against the actual response. Unlike every other
   header, CSP is never compared as one opaque expected-value string - see
   app.schemas.CSPPolicy for the rule shapes this module consumes.
2. Security best-practices - run unconditionally, regardless of what the
   user's policy says, flagging classic CSP weaknesses (wildcards,
   unsafe-inline/unsafe-eval, data:/blob: on script/style, missing
   object-src 'none', missing base-uri, missing frame-ancestors).

Every finding in both layers carries a stable id (app.core.csp_findings)
and severity, never generated from the description text.
"""
from __future__ import annotations

import re

from app.core.csp_findings import CSPFindingId, severity_for
from app.schemas import CheckResult, CSPDirectiveRule, CSPPolicy, Status

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
# data:/blob: detection is intentionally scoped to these two directives only
# (not img-src/font-src, which legitimately use data: URIs constantly) -
# stricter policies opt in elsewhere via CSPDirectiveRule.disallow_data/blob.
DATA_BLOB_CHECK_DIRECTIVES = ("script-src", "style-src")

_DIRECTIVE_NAME_RE = re.compile(r"^[a-z0-9-]+$")

# CSP keywords, hashes, and nonces are never "external" - only actual URLs
# (or a bare wildcard) name an outside host.
_CSP_NON_EXTERNAL_KEYWORDS = {
    "'self'",
    "'none'",
    "'unsafe-inline'",
    "'unsafe-eval'",
    "'unsafe-hashes'",
    "'strict-dynamic'",
    "'report-sample'",
    "'wasm-unsafe-eval'",
}
_CSP_HASH_NONCE_PREFIXES = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for raw_directive in value.split(";"):
        raw_directive = raw_directive.strip()
        if not raw_directive:
            continue
        parts = raw_directive.split()
        name = parts[0].strip().lower()
        if not _DIRECTIVE_NAME_RE.match(name):
            continue  # malformed directive name - skip rather than crash
        if name in directives:
            continue  # first occurrence wins, matching real CSP parsing
        directives[name] = parts[1:]
    return directives


def _format_directive(actual: dict[str, list[str]] | None, directive: str) -> str | None:
    if actual is None or directive not in actual:
        return None
    return f"{directive} {' '.join(actual[directive])}".strip()


def _token_present(token: str, sources: list[str]) -> bool:
    return token.strip().lower() in {s.strip().lower() for s in sources}


def _is_wildcard_source(token: str) -> bool:
    return "*" in token


def _is_http_source(token: str) -> bool:
    return token.strip().lower().startswith("http://")


def _is_data_source(token: str) -> bool:
    return token.strip().lower().startswith("data:")


def _is_blob_source(token: str) -> bool:
    return token.strip().lower().startswith("blob:")


def _is_external_source(token: str) -> bool:
    """Points to a real outside host - a plain http(s)/wildcard source, not
    a CSP keyword, hash, nonce, or a bare scheme like data:/blob: (those
    have their own dedicated disallow_data/disallow_blob toggles)."""
    lowered = token.strip().lower()
    if lowered in _CSP_NON_EXTERNAL_KEYWORDS:
        return False
    if lowered.startswith(_CSP_HASH_NONCE_PREFIXES):
        return False
    if lowered.startswith(("data:", "blob:")):
        return False
    return True


def evaluate_csp_policy(
    policy: CSPPolicy, actual: dict[str, list[str]] | None
) -> list[CheckResult]:
    """Evaluates a structured CSPPolicy against the actual CSP directives.
    Only called when the CSP header IS present - see policy_engine.evaluate_csp
    for the separate "header missing entirely" handling."""
    checks: list[CheckResult] = []
    actual = actual or {}

    for directive in policy.required_directives:
        present = directive in actual
        checks.append(
            CheckResult(
                id=CSPFindingId.REQUIRED_DIRECTIVE_MISSING,
                name=f"required:{directive}",
                description=f"Directive '{directive}' is required by policy.",
                status=Status.PASS if present else Status.FAIL,
                severity=severity_for(CSPFindingId.REQUIRED_DIRECTIVE_MISSING),
                directive=directive,
                expected="present",
                actual="present" if present else "missing",
                evidence=_format_directive(actual, directive),
            )
        )

    for rule in policy.directive_rules:
        checks.extend(_evaluate_directive_rule(rule, actual))

    return checks


def _evaluate_directive_rule(rule: CSPDirectiveRule, actual: dict[str, list[str]]) -> list[CheckResult]:
    checks: list[CheckResult] = []
    sources = actual.get(rule.directive)
    evidence = _format_directive(actual, rule.directive)

    for token in rule.must_contain:
        present = sources is not None and _token_present(token, sources)
        checks.append(
            CheckResult(
                id=CSPFindingId.MUST_CONTAIN_MISSING,
                name=f"must-contain:{rule.directive}:{token}",
                description=f"Directive '{rule.directive}' must contain '{token}'.",
                status=Status.PASS if present else Status.FAIL,
                severity=severity_for(CSPFindingId.MUST_CONTAIN_MISSING),
                directive=rule.directive,
                expected=token,
                actual=evidence or "missing",
                evidence=evidence,
            )
        )

    for token in rule.must_not_contain:
        violated = sources is not None and _token_present(token, sources)
        checks.append(
            CheckResult(
                id=CSPFindingId.PROHIBITED_SOURCE_PRESENT,
                name=f"must-not-contain:{rule.directive}:{token}",
                description=f"Directive '{rule.directive}' must not contain '{token}'.",
                status=Status.FAIL if violated else Status.PASS,
                severity=severity_for(CSPFindingId.PROHIBITED_SOURCE_PRESENT),
                directive=rule.directive,
                expected=f"not {token}",
                actual=evidence if violated else "(not present)",
                evidence=evidence,
            )
        )

    if rule.allowed_sources is not None:
        allowed_lower = {s.strip().lower() for s in rule.allowed_sources}
        unapproved = [s for s in (sources or []) if s.strip().lower() not in allowed_lower]
        checks.append(
            CheckResult(
                id=CSPFindingId.UNAPPROVED_SOURCE,
                name=f"allowlist:{rule.directive}",
                description=f"Directive '{rule.directive}' sources must all be in the approved allowlist.",
                status=Status.FAIL if unapproved else Status.PASS,
                severity=severity_for(CSPFindingId.UNAPPROVED_SOURCE),
                directive=rule.directive,
                expected=f"one of: {', '.join(rule.allowed_sources)}" if rule.allowed_sources else "(none)",
                actual=", ".join(unapproved) if unapproved else (evidence or "(none)"),
                evidence=evidence,
            )
        )

    pattern_rules = (
        (rule.disallow_wildcards, _is_wildcard_source, CSPFindingId.WILDCARD_SOURCE, "wildcard sources"),
        (rule.disallow_external, _is_external_source, CSPFindingId.EXTERNAL_SOURCE_DISALLOWED, "external sources"),
        (rule.disallow_http, _is_http_source, CSPFindingId.HTTP_SOURCE_DISALLOWED, "http: sources"),
        (rule.disallow_data, _is_data_source, CSPFindingId.DATA_SCHEME_DETECTED, "data: sources"),
        (rule.disallow_blob, _is_blob_source, CSPFindingId.BLOB_SCHEME_DETECTED, "blob: sources"),
    )
    for enabled, predicate, finding_id, label in pattern_rules:
        if not enabled:
            continue
        offending = [s for s in (sources or []) if predicate(s)]
        checks.append(
            CheckResult(
                id=finding_id,
                name=f"pattern:{rule.directive}:{finding_id}",
                description=f"Directive '{rule.directive}' must not use {label}.",
                status=Status.FAIL if offending else Status.PASS,
                severity=severity_for(finding_id),
                directive=rule.directive,
                expected=f"no {label}",
                actual=", ".join(offending) if offending else (evidence or "(none)"),
                evidence=evidence,
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
        has_wildcard = any(_is_wildcard_source(s) for s in sources)
        checks.append(
            CheckResult(
                id=CSPFindingId.WILDCARD_SOURCE,
                name=f"no-wildcard:{directive}",
                description=f"'{directive}' should not use a bare wildcard (*) source.",
                status=Status.FAIL if has_wildcard else Status.PASS,
                severity=severity_for(CSPFindingId.WILDCARD_SOURCE),
                directive=directive,
                expected="no bare '*' source",
                actual=" ".join(sources),
                evidence=_format_directive(actual, directive),
            )
        )

    # unsafe-inline / unsafe-eval on script-src and style-src - separate
    # findings (CSP-004 / CSP-005), not combined, so each has its own id.
    for directive in ("script-src", "style-src"):
        if directive not in actual:
            continue
        tokens = {s.strip("'\"").lower() for s in actual[directive]}
        evidence = _format_directive(actual, directive)

        has_unsafe_inline = "unsafe-inline" in tokens
        checks.append(
            CheckResult(
                id=CSPFindingId.UNSAFE_INLINE,
                name=f"no-unsafe-inline:{directive}",
                description=f"'{directive}' should not allow 'unsafe-inline'.",
                status=Status.FAIL if has_unsafe_inline else Status.PASS,
                severity=severity_for(CSPFindingId.UNSAFE_INLINE),
                directive=directive,
                expected="no 'unsafe-inline'",
                actual="'unsafe-inline' present" if has_unsafe_inline else "(not found)",
                evidence=evidence,
            )
        )

        has_unsafe_eval = "unsafe-eval" in tokens
        checks.append(
            CheckResult(
                id=CSPFindingId.UNSAFE_EVAL,
                name=f"no-unsafe-eval:{directive}",
                description=f"'{directive}' should not allow 'unsafe-eval'.",
                status=Status.FAIL if has_unsafe_eval else Status.PASS,
                severity=severity_for(CSPFindingId.UNSAFE_EVAL),
                directive=directive,
                expected="no 'unsafe-eval'",
                actual="'unsafe-eval' present" if has_unsafe_eval else "(not found)",
                evidence=evidence,
            )
        )

    # data:/blob: on script-src/style-src - can enable script/style
    # injection via data or blob URIs (WARNING, not FAIL - less universally
    # dangerous than unsafe-inline/eval, and legitimate in some setups).
    for directive in DATA_BLOB_CHECK_DIRECTIVES:
        if directive not in actual:
            continue
        sources = actual[directive]
        evidence = _format_directive(actual, directive)

        has_data = any(_is_data_source(s) for s in sources)
        checks.append(
            CheckResult(
                id=CSPFindingId.DATA_SCHEME_DETECTED,
                name=f"no-data-scheme:{directive}",
                description=f"'{directive}' allowing 'data:' can enable injection via data URIs.",
                status=Status.WARNING if has_data else Status.PASS,
                severity=severity_for(CSPFindingId.DATA_SCHEME_DETECTED),
                directive=directive,
                expected="no 'data:' source",
                actual="data: present" if has_data else "(not found)",
                evidence=evidence,
            )
        )

        has_blob = any(_is_blob_source(s) for s in sources)
        checks.append(
            CheckResult(
                id=CSPFindingId.BLOB_SCHEME_DETECTED,
                name=f"no-blob-scheme:{directive}",
                description=f"'{directive}' allowing 'blob:' can enable injection via blob URIs.",
                status=Status.WARNING if has_blob else Status.PASS,
                severity=severity_for(CSPFindingId.BLOB_SCHEME_DETECTED),
                directive=directive,
                expected="no 'blob:' source",
                actual="blob: present" if has_blob else "(not found)",
                evidence=evidence,
            )
        )

    # object-src should be 'none' (or covered by a strict default-src).
    if "object-src" in actual:
        sources = [s.lower() for s in actual["object-src"]]
        ok = sources == ["'none'"]
        checks.append(
            CheckResult(
                id=CSPFindingId.OBJECT_SRC_NOT_NONE,
                name="object-src-none",
                description="'object-src' should be restricted to 'none'.",
                status=Status.PASS if ok else Status.WARNING,
                severity=severity_for(CSPFindingId.OBJECT_SRC_NOT_NONE),
                directive="object-src",
                expected="'none'",
                actual=" ".join(actual["object-src"]) or "(empty)",
                evidence=_format_directive(actual, "object-src"),
            )
        )
    else:
        checks.append(
            CheckResult(
                id=CSPFindingId.OBJECT_SRC_NOT_NONE,
                name="object-src-none",
                description="'object-src' should be explicitly set to 'none' (or covered by default-src).",
                status=Status.WARNING if "default-src" not in actual else Status.INFO,
                severity=severity_for(CSPFindingId.OBJECT_SRC_NOT_NONE),
                directive="object-src",
                expected="'none'",
                actual="missing",
            )
        )

    # base-uri should exist.
    checks.append(
        CheckResult(
            id=CSPFindingId.BASE_URI_MISSING,
            name="base-uri-present",
            description="'base-uri' should be set to prevent base tag injection.",
            status=Status.PASS if "base-uri" in actual else Status.WARNING,
            severity=severity_for(CSPFindingId.BASE_URI_MISSING),
            directive="base-uri",
            expected="present",
            actual="present" if "base-uri" in actual else "missing",
            evidence=_format_directive(actual, "base-uri"),
        )
    )

    # frame-ancestors should exist (clickjacking protection).
    checks.append(
        CheckResult(
            id=CSPFindingId.FRAME_ANCESTORS_MISSING,
            name="frame-ancestors-present",
            description="'frame-ancestors' should be set for clickjacking protection.",
            status=Status.PASS if "frame-ancestors" in actual else Status.WARNING,
            severity=severity_for(CSPFindingId.FRAME_ANCESTORS_MISSING),
            directive="frame-ancestors",
            expected="present",
            actual="present" if "frame-ancestors" in actual else "missing",
            evidence=_format_directive(actual, "frame-ancestors"),
        )
    )

    return checks


def compute_csp_score(
    policy_checks: list[CheckResult], security_checks: list[CheckResult]
) -> tuple[int, int, int, int, float]:
    """Equal weight per check, PASS-count / total-count - the same formula
    the old blended _csp_score used, now also exposed as two sub-tallies
    (policy compliance vs best-practice) instead of only a single number."""
    policy_passed = sum(1 for c in policy_checks if c.status == Status.PASS)
    policy_total = len(policy_checks)
    bp_passed = sum(1 for c in security_checks if c.status == Status.PASS)
    bp_total = len(security_checks)

    all_checks = policy_checks + security_checks
    if not all_checks:
        return policy_passed, policy_total, bp_passed, bp_total, 100.0

    overall = round(100 * sum(1 for c in all_checks if c.status == Status.PASS) / len(all_checks), 1)
    return policy_passed, policy_total, bp_passed, bp_total, overall

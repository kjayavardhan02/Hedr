"""Semantic comparators used by the policy engine.

Header values are compared by meaning, not raw text: formatting differences
(extra spaces, directive order, quoting, origin casing) must not cause a
false FAIL, while a real security difference must still FAIL. Which
comparator runs is chosen by header name (see get_comparator), so the user
never picks a rule type manually.

Policies still store one free-text "expected value" per header. Each
comparator reads that string using a per-header mini-syntax, so policies
saved before this module grew richer keep working unchanged:

  - Plain value                -> exact match (case-insensitive, whitespace
                                   normalised)
  - "a|b|c"                    -> allowed-values match (actual is one of them)
  - HSTS "max-age=N; flag"     -> directive-aware; `max-age` compares as >=.
  - Cache-Control "a, b=N"    -> directive set compared in any order; extra
                                   syntax: "!name" (prohibited), "name>=N" /
                                   "name<=N", and a trailing "+" token
                                   meaning extra directives are allowed.
  - X-XSS-Protection "1; mode=block" -> enabled flag + parameters.
  - Access-Control-Allow-Origin "origin|origin|*" -> origin-aware; a wildcard
                                   actual value only passes if "*" is listed.
  - Referrer-Policy "a|b"      -> compared against the *effective* policy of
                                   the response (last recognised token).
  - Permissions-Policy "feature=(a b), feature=()" -> feature allowlists.
  - X-Frame-Options "DENY|SAMEORIGIN|ALLOW-FROM https://a.com" -> any listed
                                   option; ALLOW-FROM origins are normalised.

Normalisation is deliberately per header: never a blanket lowercase or
whitespace strip, because different syntaxes have different rules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

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


# ---------------------------------------------------------------------------
# Generic normalisation
# ---------------------------------------------------------------------------


def normalize_ws(value: str) -> str:
    """Trims and collapses runs of whitespace to one space, leaving anything
    inside double quotes untouched. Never changes case or removes characters."""
    parts = re.split(r'("[^"]*")', value)
    collapsed = "".join(
        part if index % 2 == 1 else re.sub(r"\s+", " ", part)
        for index, part in enumerate(parts)
    )
    return collapsed.strip()


def _split_top_level(value: str, separator: str) -> list[str]:
    """Splits on any character in `separator` while ignoring those inside
    double quotes or parentheses (e.g. `no-cache="a, b"` or
    `geolocation=(self "x")`)."""
    parts: list[str] = []
    current: list[str] = []
    in_quote = False
    depth = 0
    for char in value:
        if char == '"':
            in_quote = not in_quote
        elif not in_quote:
            if char == "(":
                depth += 1
            elif char == ")":
                depth = max(0, depth - 1)
            elif char in separator and depth == 0:
                parts.append("".join(current))
                current = []
                continue
        current.append(char)
    parts.append("".join(current))
    return parts


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def _is_int(value: str) -> bool:
    return re.fullmatch(r"\d+", value.strip()) is not None


def _all_pass(checks: list[CheckResult]) -> Status:
    return Status.PASS if all(c.status == Status.PASS for c in checks) else Status.FAIL


# ---------------------------------------------------------------------------
# Enum / simple token headers (X-Content-Type-Options, X-Frame-Options,
# COOP, CORP, COEP, Access-Control-Allow-Credentials, ...)
# ---------------------------------------------------------------------------


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

    actual_norm = normalize_ws(actual).lower()

    if "|" in expected:
        allowed = [normalize_ws(v) for v in expected.split("|") if v.strip()]
        ok = actual_norm in {v.lower() for v in allowed}
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
        ok = actual_norm == normalize_ws(expected).lower()
        checks.append(
            CheckResult(
                name="exact-value",
                description="Value must exactly match the policy.",
                status=Status.PASS if ok else Status.FAIL,
                expected=expected,
                actual=actual,
            )
        )

    return ComparisonOutcome(_all_pass(checks), checks)


# ---------------------------------------------------------------------------
# Referrer-Policy
# ---------------------------------------------------------------------------

REFERRER_POLICY_TOKENS = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


def _effective_referrer_policy(value: str) -> str:
    """A response may list several comma-separated tokens; browsers apply the
    last one they recognise. Falls back to the normalised text when none is
    a known token, so an unknown value never accidentally matches a policy."""
    tokens = [normalize_ws(t).lower() for t in value.split(",") if t.strip()]
    recognised = [t for t in tokens if t in REFERRER_POLICY_TOKENS]
    if recognised:
        return recognised[-1]
    return normalize_ws(value).lower()


def referrer_policy_comparator(header: str, expected: str, actual: str | None) -> ComparisonOutcome:
    if actual is None:
        return exact_or_allowed_comparator(header, expected, actual)

    if "|" in expected:
        allowed = [_effective_referrer_policy(v) for v in expected.split("|") if v.strip()]
    else:
        allowed = [_effective_referrer_policy(expected)]

    effective = _effective_referrer_policy(actual)
    checks = [
        CheckResult(
            name="effective-policy",
            description=(
                "The effective referrer policy (the last recognised token) "
                f"must be one of: {', '.join(allowed)}."
            ),
            status=Status.PASS if effective in allowed else Status.FAIL,
            expected=" | ".join(allowed),
            actual=effective,
        )
    ]
    return ComparisonOutcome(_all_pass(checks), checks)


# ---------------------------------------------------------------------------
# Strict-Transport-Security (semicolon-delimited directives)
# ---------------------------------------------------------------------------


def _parse_directive_list(value: str) -> dict[str, str | bool]:
    """Parses "max-age=100; includeSubDomains; preload" style values. Empty
    segments are ignored and, as for browsers, the first occurrence of a
    duplicated directive wins."""
    directives: dict[str, str | bool] = {}
    for part in _split_top_level(value, ";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, val = part.partition("=")
            name = key.strip().lower()
            parsed: str | bool = _unquote(val.strip())
        else:
            name = part.strip().lower()
            parsed = True
        if name and name not in directives:
            directives[name] = parsed
    return directives


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

    return ComparisonOutcome(_all_pass(checks), checks)


# ---------------------------------------------------------------------------
# Cache-Control (comma-delimited directives)
# ---------------------------------------------------------------------------

_CC_RULE_RE = re.compile(r"^([A-Za-z0-9_.-]+)\s*(>=|<=|=)\s*(.+)$")


def _parse_cache_control(value: str) -> dict[str, str | bool]:
    directives: dict[str, str | bool] = {}
    for part in _split_top_level(value, ","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, val = part.partition("=")
            name = key.strip().lower()
            parsed: str | bool = _unquote(val.strip())
        else:
            name = part.lower()
            parsed = True
        if name and name not in directives:
            directives[name] = parsed
    return directives


@dataclass
class _CacheControlPolicy:
    required: dict[str, tuple[str, str | None]]  # name -> (operator, value)
    prohibited: set[str]
    allow_extras: bool


def _parse_cache_control_policy(expected: str) -> _CacheControlPolicy:
    required: dict[str, tuple[str, str | None]] = {}
    prohibited: set[str] = set()
    allow_extras = False
    for raw in _split_top_level(expected, ","):
        token = raw.strip()
        if not token:
            continue
        if token == "+":
            allow_extras = True
        elif token.startswith("!"):
            name = token[1:].strip().lower()
            if name:
                prohibited.add(name)
        else:
            match = _CC_RULE_RE.match(token)
            if match:
                name = match.group(1).lower()
                required.setdefault(name, (match.group(2), _unquote(match.group(3))))
            else:
                required.setdefault(token.lower(), ("present", None))
    return _CacheControlPolicy(required, prohibited, allow_extras)


def _compare_cache_control_value(operator: str, expected_val: str, actual_val: str) -> bool:
    if operator == "=":
        if _is_int(expected_val) and _is_int(actual_val):
            return int(expected_val) == int(actual_val)
        return actual_val.strip().lower() == expected_val.strip().lower()
    if not (_is_int(expected_val) and _is_int(actual_val)):
        return False
    if operator == ">=":
        return int(actual_val) >= int(expected_val)
    return int(actual_val) <= int(expected_val)


def cache_control_comparator(header: str, expected: str, actual: str | None) -> ComparisonOutcome:
    policy = _parse_cache_control_policy(expected)

    if not policy.required and not policy.prohibited:
        return exact_or_allowed_comparator(header, expected, actual)

    checks: list[CheckResult] = []

    if actual is None:
        for name in policy.required:
            checks.append(
                CheckResult(
                    name=name,
                    description=f"Directive '{name}' cannot be checked - header is missing.",
                    status=Status.FAIL,
                    expected="present",
                    actual=None,
                )
            )
        for name in sorted(policy.prohibited):
            checks.append(
                CheckResult(
                    name=f"!{name}",
                    description=f"Directive '{name}' cannot be checked - header is missing.",
                    status=Status.FAIL,
                    expected="absent",
                    actual=None,
                )
            )
        return ComparisonOutcome(Status.FAIL, checks)

    actual_directives = _parse_cache_control(actual)

    for name, (operator, expected_val) in policy.required.items():
        actual_val = actual_directives.get(name)
        present = name in actual_directives

        if operator == "present":
            checks.append(
                CheckResult(
                    name=name,
                    description=f"Directive '{name}' is required.",
                    status=Status.PASS if present else Status.FAIL,
                    expected="present",
                    actual="present" if present else "missing",
                )
            )
            continue

        ok = (
            present
            and actual_val is not True
            and _compare_cache_control_value(operator, str(expected_val), str(actual_val))
        )
        shown = f"{operator} {expected_val}" if operator != "=" else str(expected_val)
        checks.append(
            CheckResult(
                name=name,
                description=f"Directive '{name}' must be {shown}.",
                status=Status.PASS if ok else Status.FAIL,
                expected=shown,
                actual=(str(actual_val) if actual_val is not True else "present") if present else "missing",
            )
        )

    for name in sorted(policy.prohibited):
        present = name in actual_directives
        checks.append(
            CheckResult(
                name=f"!{name}",
                description=f"Directive '{name}' must not be present.",
                status=Status.FAIL if present else Status.PASS,
                expected="absent",
                actual="present" if present else "absent",
            )
        )

    if not policy.allow_extras:
        extras = sorted(
            n for n in actual_directives if n not in policy.required and n not in policy.prohibited
        )
        checks.append(
            CheckResult(
                name="no-unexpected-directives",
                description="No directives beyond those in the policy are allowed.",
                status=Status.FAIL if extras else Status.PASS,
                expected="none",
                actual=", ".join(extras) if extras else "none",
            )
        )

    return ComparisonOutcome(_all_pass(checks), checks)


# ---------------------------------------------------------------------------
# X-XSS-Protection ("0", "1", "1; mode=block", "1; report=<uri>")
# ---------------------------------------------------------------------------


def _parse_xss_protection(value: str) -> tuple[str, dict[str, str | bool]]:
    parts = _split_top_level(value, ";")
    flag = normalize_ws(parts[0]).lower() if parts else ""
    return flag, _parse_directive_list(";".join(parts[1:]))


def x_xss_protection_comparator(header: str, expected: str, actual: str | None) -> ComparisonOutcome:
    expected_flag, expected_params = _parse_xss_protection(expected)
    if expected_flag not in ("0", "1"):
        return exact_or_allowed_comparator(header, expected, actual)

    checks: list[CheckResult] = []

    if actual is None:
        checks.append(
            CheckResult(
                name="enabled",
                description=f"{header} must be present to evaluate its value.",
                status=Status.FAIL,
                expected=expected_flag,
                actual=None,
            )
        )
        return ComparisonOutcome(Status.FAIL, checks)

    actual_flag, actual_params = _parse_xss_protection(actual)

    checks.append(
        CheckResult(
            name="enabled",
            description=f"Protection flag must be '{expected_flag}'.",
            status=Status.PASS if actual_flag == expected_flag else Status.FAIL,
            expected=expected_flag,
            actual=actual_flag,
        )
    )

    for name, expected_val in expected_params.items():
        actual_val = actual_params.get(name)
        if expected_val is True:
            ok = name in actual_params
            shown = "present"
            actual_shown = "present" if ok else "missing"
        else:
            ok = actual_val is not None and str(actual_val).strip().lower() == str(expected_val).strip().lower()
            shown = str(expected_val)
            actual_shown = str(actual_val) if actual_val is not None else "missing"
        checks.append(
            CheckResult(
                name=name,
                description=f"Parameter '{name}' must be '{expected_val}'." if expected_val is not True else f"Parameter '{name}' is required.",
                status=Status.PASS if ok else Status.FAIL,
                expected=shown,
                actual=actual_shown,
            )
        )

    return ComparisonOutcome(_all_pass(checks), checks)


# ---------------------------------------------------------------------------
# Access-Control-Allow-Origin
# ---------------------------------------------------------------------------

_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_origin(value: str) -> str:
    """Canonical form of an origin: lower-case scheme and host, default port
    and trailing slash dropped. `*` and `null` are kept as literals. Anything
    that doesn't parse as an origin is compared as opaque lower-cased text -
    never guessed into equality with a different origin."""
    text = normalize_ws(value)
    if text in ("*", "null") or text.lower() == "null":
        return text.lower()
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return text.lower()
    if parts.scheme and parts.hostname and parts.path in ("", "/") and not parts.query and not parts.fragment:
        scheme = parts.scheme.lower()
        host = parts.hostname.lower()
        host_text = f"[{host}]" if ":" in host else host
        if port is not None and port != _DEFAULT_PORTS.get(scheme):
            return f"{scheme}://{host_text}:{port}"
        return f"{scheme}://{host_text}"
    return text.lower()


def origin_comparator(header: str, expected: str, actual: str | None) -> ComparisonOutcome:
    allowed = [normalize_origin(v) for v in expected.split("|") if v.strip()]

    if not allowed:
        return exact_or_allowed_comparator(header, expected, actual)

    if actual is None:
        return ComparisonOutcome(
            Status.FAIL,
            [
                CheckResult(
                    name="origin-match",
                    description=f"{header} must be present to evaluate its value.",
                    status=Status.FAIL,
                    expected=" | ".join(allowed),
                    actual=None,
                )
            ],
        )

    actual_origin = normalize_origin(actual)

    if actual_origin == "*":
        ok = "*" in allowed
        check = CheckResult(
            name="wildcard",
            description=(
                "Wildcard '*' origin is allowed by the policy."
                if ok
                else "Wildcard '*' origin is not allowed by the policy."
            ),
            status=Status.PASS if ok else Status.FAIL,
            expected=" | ".join(allowed),
            actual=actual,
        )
    else:
        ok = actual_origin in allowed
        check = CheckResult(
            name="origin-match",
            description=f"Origin must be one of: {', '.join(allowed)}.",
            status=Status.PASS if ok else Status.FAIL,
            expected=" | ".join(allowed),
            actual=actual,
        )
    return ComparisonOutcome(check.status, [check])


# ---------------------------------------------------------------------------
# X-Frame-Options ("DENY", "SAMEORIGIN", "ALLOW-FROM <origin>")
# ---------------------------------------------------------------------------

_XFO_ALLOW_FROM_RE = re.compile(r"^allow-from\s+(\S+)$", re.IGNORECASE)

XFO_ALLOW_FROM_NOTE = (
    " Note: ALLOW-FROM is obsolete and ignored by current browsers, so it gives "
    "no real protection on its own - pair it with CSP 'frame-ancestors'."
)


def _uri_origin(uri: str) -> str:
    """Only the origin of an ALLOW-FROM URI matters (a path is ignored)."""
    try:
        parts = urlsplit(uri)
        parts.port  # noqa: B018 - validates the port
    except ValueError:
        return uri.lower()
    if parts.scheme and parts.hostname:
        return normalize_origin(f"{parts.scheme}://{parts.netloc}")
    return uri.lower()


def parse_allow_from(value: str) -> str | None:
    """The normalised origin of an "ALLOW-FROM <uri>" value, else None."""
    match = _XFO_ALLOW_FROM_RE.match(normalize_ws(value))
    return _uri_origin(match.group(1)) if match else None


def _normalize_xfo(value: str) -> str:
    origin = parse_allow_from(value)
    if origin is not None:
        return f"allow-from {origin}"
    return normalize_ws(value).lower()


def x_frame_options_comparator(header: str, expected: str, actual: str | None) -> ComparisonOutcome:
    options = [v.strip() for v in expected.split("|") if v.strip()]
    if not options or actual is None:
        return exact_or_allowed_comparator(header, expected, actual)

    allowed = {_normalize_xfo(o) for o in options}
    ok = _normalize_xfo(actual) in allowed
    involves_allow_from = any(a.startswith("allow-from ") for a in allowed) or _normalize_xfo(
        actual
    ).startswith("allow-from ")

    if len(options) > 1:
        name = "allowed-values"
        description = f"Value must be one of: {', '.join(normalize_ws(o) for o in options)}."
        shown = " | ".join(normalize_ws(o) for o in options)
    else:
        name = "exact-value"
        description = "Value must exactly match the policy."
        shown = expected
    if involves_allow_from:
        description += XFO_ALLOW_FROM_NOTE

    check = CheckResult(
        name=name,
        description=description,
        status=Status.PASS if ok else Status.FAIL,
        expected=shown,
        actual=actual,
    )
    return ComparisonOutcome(check.status, [check])


# ---------------------------------------------------------------------------
# Permissions-Policy ("feature=(allowlist), feature=()")
# ---------------------------------------------------------------------------

_PP_FEATURE_RE = re.compile(r"^[a-zA-Z0-9-]+$")


def _split_allowlist_tokens(inner: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    in_quote = False
    for char in inner:
        if char == '"':
            in_quote = not in_quote
            current.append(char)
        elif char.isspace() and not in_quote:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
    if current:
        tokens.append("".join(current))
    return tokens


def _normalize_pp_token(token: str) -> str | None:
    token = _unquote(token.strip())
    if not token:
        return None
    lowered = token.lower()
    if lowered == "none":
        return None
    if lowered in ("self", "src", "*"):
        return lowered
    return normalize_origin(token)


def _parse_permissions_policy(value: str) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    # Real headers separate features with commas, but policies are often
    # written with semicolons (the built-in baselines are), so both are
    # accepted as separators. A stray ";param=x" therefore parses as an extra
    # feature; that is harmless because only the policy's features are checked.
    for item in _split_top_level(value, ",;"):
        item = item.strip()
        if "=" not in item:
            continue
        feature, _, rest = item.partition("=")
        feature = feature.strip().lower()
        if not _PP_FEATURE_RE.match(feature) or feature in result:
            continue
        rest = rest.strip()
        if rest.startswith("("):
            inner = rest[1:rest.rfind(")")] if ")" in rest else rest[1:]
            raw_tokens = _split_allowlist_tokens(inner)
        else:
            raw_tokens = [rest] if rest else []
        result[feature] = {t for t in (_normalize_pp_token(r) for r in raw_tokens) if t is not None}
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

    return ComparisonOutcome(_all_pass(checks), checks)


# Header (lower-case) -> comparator function. Headers not listed here are
# simple enum/token headers and use exact_or_allowed_comparator.
DIRECTIVE_GRAMMAR_HEADERS = {
    "strict-transport-security": directive_list_comparator,
    "permissions-policy": permissions_policy_comparator,
    "cache-control": cache_control_comparator,
    "x-xss-protection": x_xss_protection_comparator,
    "access-control-allow-origin": origin_comparator,
    "referrer-policy": referrer_policy_comparator,
    "x-frame-options": x_frame_options_comparator,
}


def get_comparator(header_name: str):
    return DIRECTIVE_GRAMMAR_HEADERS.get(header_name.lower(), exact_or_allowed_comparator)

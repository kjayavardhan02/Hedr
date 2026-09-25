"""Turns failing header checks into an actionable issue + remediation, e.g.

    Issue:        The response contains additional directives not permitted by the policy: must-revalidate.
    Remediation:  Remove must-revalidate, or update the policy to allow extra directives ...

Deterministic and derived only from the failing checks plus the expected/actual
values - nothing is guessed. Anything not recognised falls back to the failing
check's own description, so an unknown check never produces a wrong fix."""
from __future__ import annotations

import re

from app.schemas import CheckResult, Status

_MAX_ITEMS = 3


def _directive_names(value: str | None) -> list[str]:
    """Directive names in a Cache-Control style value, lower-cased, ignoring
    policy markers (`+`, `!`, `>=`) and `=value` parts."""
    names: list[str] = []
    for part in (value or "").split(","):
        token = part.strip().lstrip("!").rstrip("+").strip()
        token = re.split(r"[=<>]", token, maxsplit=1)[0].strip().lower()
        if token and token != "+":
            names.append(token)
    return names


def _join(items: list[str]) -> str:
    unique = list(dict.fromkeys(items))
    shown = unique[:_MAX_ITEMS]
    text = " ".join(shown)
    if len(unique) > _MAX_ITEMS:
        text += f" (and {len(unique) - _MAX_ITEMS} more)"
    return text


def _explain_check(check: CheckResult, expected: str | None, actual: str | None) -> tuple[str, str]:
    name, desc = check.name, check.description

    if name == "no-unexpected-directives":
        extras = [d for d in _directive_names(actual) if d not in _directive_names(expected)]
        listed = ", ".join(extras) if extras else "additional directives"
        return (
            f"The response contains additional directives not permitted by the policy: {listed}.",
            f"Remove {listed}, or update the policy to allow extra directives "
            "(end its value with '+') if they are intentional.",
        )
    if name.startswith("!"):
        d = name[1:]
        return f"The response contains the prohibited directive '{d}'.", f"Remove '{d}' from the header."
    if desc.startswith("Directive '") and desc.endswith("is required."):
        return f"The required directive '{name}' is missing.", f"Add '{name}' to the header."
    if match := re.fullmatch(r"Directive '(.+)' must equal '(.*)'\.", desc):
        return f"Directive '{match[1]}' does not have the required value.", f"Set {match[1]} to '{match[2]}'."
    if match := re.fullmatch(r"(.+) must be >= (\d+)\.", desc):
        return f"{match[1]} is lower than the required minimum of {match[2]}.", f"Increase {match[1]} to at least {match[2]}."
    if match := re.fullmatch(r"Directive '(.+)' must be (.+)\.", desc):
        return (
            f"Directive '{match[1]}' does not satisfy the policy (must be {match[2]}).",
            f"Change '{match[1]}' so that it is {match[2]}.",
        )
    if name == "exact-value":
        return "The value does not match the policy.", f"Set the header to exactly '{expected}'." if expected else "Match the policy value."
    if name == "allowed-values":
        return "The value is not one of the allowed values.", desc.replace("Value must be one of:", "Use one of:")
    if name == "effective-policy":
        allowed = ", ".join(v.strip() for v in (expected or "").split("|") if v.strip())
        return f"The effective policy '{actual}' is not allowed.", f"Use one of: {allowed}." if allowed else "Match the policy."
    if name == "enabled":
        return "The protection flag does not match the policy.", desc.replace("must be", "Set it to").rstrip(".") + "."
    if desc.startswith("Parameter '"):
        return "A required parameter does not match the policy.", desc.replace("must be", "Set it to").replace("is required", "Add it") 
    if name == "origin-match":
        return (
            f"The origin '{actual}' is not among the allowed origins.",
            f"Return only an allowed origin ({expected}), or update the policy if this origin is intended.",
        )
    if name == "wildcard":
        return (
            "The response allows any origin with '*'.",
            "Return a specific allowed origin instead of '*', or allow '*' in the policy if that is intended.",
        )
    if "allowlist must equal the policy" in desc:
        return f"The '{name}' allowlist differs from the policy.", f"Set {name} to match the policy: {expected}."
    # Unknown check: say what failed, never invent a fix.
    return desc, "Update the header so its value complies with the configured policy."


def explain_failure(
    header: str,
    expected: str | None,
    actual: str | None,
    present: bool,
    checks: list[CheckResult],
) -> tuple[str, str]:
    """(issue, remediation) for a header that did not pass its policy check."""
    if not present:
        value = f" with the value '{expected}'" if expected else ""
        return (
            f"The response does not include the {header} header.",
            f"Add the {header} header{value}.",
        )
    failing = [c for c in checks if c.status == Status.FAIL]
    if not failing:
        return (
            f"The {header} value does not comply with the configured policy.",
            "Update the header so its value complies with the configured policy.",
        )
    pairs = [_explain_check(c, expected, actual) for c in failing]
    return _join([i for i, _ in pairs]), _join([r for _, r in pairs])

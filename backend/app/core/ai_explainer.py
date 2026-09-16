"""AI explanation layer (spec sections 12-13).

The deterministic policy engine has ALREADY decided PASS/FAIL/WARNING before
anything here runs. This module never re-judges a verdict - it only explains
a single already-computed finding: what the header/directive does, why the
current configuration doesn't comply, a concrete remediation, and realistic
tradeoffs of applying it. If this call fails for any reason, the caller's
deterministic scan report must remain fully intact and unaffected.
"""
from __future__ import annotations

from google import genai
from google.genai import types

from app.config import GEMINI_API_KEY, GEMINI_MODEL
from app.schemas import ExplainCheckIn, ExplainRequest, ExplainResponse, Status

SYSTEM_INSTRUCTION = """\
You are a web application security expert who explains findings produced by \
Hedr, a deterministic HTTP security header policy scanner.

You will be given exactly ONE finding: a header or Content-Security-Policy \
directive, the value the security policy expects, the actual value observed \
on the target, and a numbered list of its FAILING or WARNING sub-checks \
(passing checks are omitted - they need no fix).

Critical rule: the PASS/FAIL/WARNING verdict has ALREADY been decided by a \
deterministic rule engine before you see it. Do NOT re-judge, second-guess, \
or contradict that verdict. Your only job is to explain it clearly and give \
practical advice, per these four things:

1. what_it_does - In 1-3 sentences, explain what this header or directive \
   does and what security purpose it serves. Write for a developer who may \
   not be a security specialist.
2. why_it_matters - In 1-3 sentences, explain concretely why the CURRENT \
   configuration is a problem, referencing the specific failing/warning \
   checks given - not generic advice.
3. recommendations - Return exactly ONE item per numbered check listed \
   below, in the same order. "check" must be ONLY the short check name that \
   appears right after the status tag on that line (e.g. for the line \
   "1. [FAIL] max-age: max-age must be >= 31536000. (expected: ..., actual: \
   ...)", check is exactly "max-age" - never the full sentence, the status, \
   or the expected/actual values). Each item's "fix" must be a single \
   precise, imperative instruction that:
     - States the CURRENT (wrong) value/state and the EXACT corrected \
       value/state, e.g. "Change max-age from 100 to at least 31536000." or \
       "Add the missing 'object-src' directive: object-src 'none'."
     - Is specific to what THIS check's expected/actual fields show - never \
       generic advice like "improve your security posture" or "follow best \
       practices" with no concrete value.
     - Is one sentence. No preamble, no restating what the header does \
       (that belongs in what_it_does).
4. tradeoffs - Realistic caveats or risks of applying the fix(es) (e.g. \
   "this may break existing inline scripts - test in Report-Only mode \
   first"). If there is genuinely no meaningful tradeoff, say so briefly \
   rather than inventing one.

Keep what_it_does, why_it_matters, and tradeoffs concise (2-4 sentences \
max each). Never state or imply a different PASS/FAIL/WARNING verdict than \
the one implied by the input.\
"""

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "what_it_does": {"type": "string"},
        "why_it_matters": {"type": "string"},
        "recommendations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "check": {"type": "string"},
                    "fix": {"type": "string"},
                },
                "required": ["check", "fix"],
            },
        },
        "tradeoffs": {"type": "string"},
    },
    "required": ["what_it_does", "why_it_matters", "recommendations", "tradeoffs"],
}


class AIExplainerError(RuntimeError):
    pass


class AIExplainerNotConfigured(AIExplainerError):
    pass


def _failing_checks(req: ExplainRequest) -> list[ExplainCheckIn]:
    non_passing = [c for c in req.checks if c.status != Status.PASS]
    return non_passing or req.checks


def _build_prompt(req: ExplainRequest, checks: list[ExplainCheckIn]) -> str:
    lines = [f"Header / directive: {req.name}"]
    if req.policy_expected:
        lines.append(f"Policy expects: {req.policy_expected}")
    lines.append(f"Actual value: {req.actual_value or '(not present in the response)'}")
    if checks:
        lines.append(f"Failing/warning checks ({len(checks)}):")
        for i, c in enumerate(checks, start=1):
            expected = c.expected if c.expected is not None else "-"
            actual = c.actual if c.actual is not None else "-"
            lines.append(
                f"  {i}. [{c.status.value}] {c.name}: {c.description} "
                f"(expected: {expected}, actual: {actual})"
            )
    else:
        lines.append("No sub-checks were provided - this finding failed on presence alone.")
    return "\n".join(lines)


def explain(req: ExplainRequest) -> ExplainResponse:
    if not GEMINI_API_KEY:
        raise AIExplainerNotConfigured(
            "AI explanations are not configured. Set GEMINI_API_KEY on the backend."
        )

    checks = _failing_checks(req)
    client = genai.Client(
        api_key=GEMINI_API_KEY,
        http_options=types.HttpOptions(timeout=20_000),  # milliseconds
    )

    try:
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=_build_prompt(req, checks),
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                response_mime_type="application/json",
                response_json_schema=RESPONSE_SCHEMA,
                max_output_tokens=1536,
            ),
        )
    except Exception as exc:  # noqa: BLE001 - surface as a clean, user-facing error
        raise AIExplainerError(f"AI request failed: {exc}") from exc

    if not response.text:
        raise AIExplainerError("AI returned an empty response.")

    return ExplainResponse.model_validate_json(response.text)

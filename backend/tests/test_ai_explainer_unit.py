import pytest

from app.core import ai_explainer
from app.core.ai_explainer import AIExplainerNotConfigured, _build_prompt, _failing_checks, explain
from app.schemas import ExplainCheckIn, ExplainRequest, Status


def _check(name, status, description="desc", expected="exp", actual="act"):
    return ExplainCheckIn(name=name, description=description, status=status, expected=expected, actual=actual)


class TestFailingChecks:
    def test_filters_out_passing_checks(self):
        req = ExplainRequest(
            name="H",
            checks=[_check("a", Status.PASS), _check("b", Status.FAIL)],
        )
        result = _failing_checks(req)
        assert [c.name for c in result] == ["b"]

    def test_returns_all_checks_when_everything_passes(self):
        req = ExplainRequest(name="H", checks=[_check("a", Status.PASS)])
        result = _failing_checks(req)
        assert [c.name for c in result] == ["a"]

    def test_empty_checks_returns_empty(self):
        req = ExplainRequest(name="H", checks=[])
        assert _failing_checks(req) == []


class TestBuildPrompt:
    def test_includes_header_name_and_actual_value(self):
        req = ExplainRequest(name="X-Frame-Options", actual_value="SAMEORIGIN", checks=[])
        prompt = _build_prompt(req, [])
        assert "X-Frame-Options" in prompt
        assert "SAMEORIGIN" in prompt

    def test_missing_actual_value_is_labeled(self):
        req = ExplainRequest(name="X-Frame-Options", checks=[])
        prompt = _build_prompt(req, [])
        assert "not present in the response" in prompt

    def test_numbers_failing_checks(self):
        req = ExplainRequest(name="H", checks=[_check("max-age", Status.FAIL)])
        checks = _failing_checks(req)
        prompt = _build_prompt(req, checks)
        assert "1. [FAIL] max-age:" in prompt


def test_explain_raises_when_api_key_missing(monkeypatch):
    monkeypatch.setattr(ai_explainer, "GEMINI_API_KEY", None)
    req = ExplainRequest(name="H", checks=[])
    with pytest.raises(AIExplainerNotConfigured):
        explain(req)

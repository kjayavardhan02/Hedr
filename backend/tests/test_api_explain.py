from app.core.ai_explainer import AIExplainerError, AIExplainerNotConfigured
from app.routers import explain as explain_router
from app.schemas import ExplainResponse, RecommendationItem

REQUEST_PAYLOAD = {
    "name": "X-Frame-Options",
    "policy_expected": "DENY",
    "actual_value": None,
    "checks": [],
}


def test_explain_returns_503_when_not_configured(client, monkeypatch):
    def _raise(req):
        raise AIExplainerNotConfigured("AI explanations are not configured.")

    monkeypatch.setattr(explain_router, "explain", _raise)
    resp = client.post("/api/explain", json=REQUEST_PAYLOAD)
    assert resp.status_code == 503


def test_explain_returns_502_on_ai_error(client, monkeypatch):
    def _raise(req):
        raise AIExplainerError("AI request failed")

    monkeypatch.setattr(explain_router, "explain", _raise)
    resp = client.post("/api/explain", json=REQUEST_PAYLOAD)
    assert resp.status_code == 502


def test_explain_returns_response_on_success(client, monkeypatch):
    fake_response = ExplainResponse(
        what_it_does="Prevents clickjacking.",
        why_it_matters="The header is missing.",
        recommendations=[RecommendationItem(check="presence", fix="Add the header.")],
        tradeoffs="None.",
    )
    monkeypatch.setattr(explain_router, "explain", lambda req: fake_response)
    resp = client.post("/api/explain", json=REQUEST_PAYLOAD)
    assert resp.status_code == 200
    assert resp.json()["what_it_does"] == "Prevents clickjacking."

from fastapi import APIRouter, HTTPException

from app.core.ai_explainer import AIExplainerError, AIExplainerNotConfigured, explain
from app.schemas import ExplainRequest, ExplainResponse

router = APIRouter(prefix="/api/explain", tags=["explain"])


@router.post("", response_model=ExplainResponse)
def explain_finding(payload: ExplainRequest):
    try:
        return explain(payload)
    except AIExplainerNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except AIExplainerError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

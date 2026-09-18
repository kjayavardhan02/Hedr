from fastapi import APIRouter, Depends, HTTPException

from app import models
from app.core.ai_explainer import AIExplainerError, AIExplainerNotConfigured, explain
from app.core.deps import get_current_user
from app.schemas import ExplainRequest, ExplainResponse

router = APIRouter(prefix="/api/explain", tags=["explain"])


@router.post("", response_model=ExplainResponse)
def explain_finding(
    payload: ExplainRequest,
    current_user: models.User = Depends(get_current_user),
):
    try:
        return explain(payload)
    except AIExplainerNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except AIExplainerError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

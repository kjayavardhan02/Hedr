from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models
from app.core.deps import get_current_user
from app.database import get_db
from app.schemas import PolicyCreate, PolicyOut, PolicyUpdate

router = APIRouter(prefix="/api/policies", tags=["policies"])


def _visible_or_404(policy: models.Policy | None, current_user: models.User) -> models.Policy:
    """A policy is visible if it's a shared baseline or owned by the
    caller. Anything else - including another user's custom policy -
    reports as 404 rather than 403, so we never confirm that a given id
    belongs to someone else."""
    if policy is None or not (policy.is_baseline or policy.owner_id == current_user.id):
        raise HTTPException(status_code=404, detail="Policy not found.")
    return policy


@router.get("", response_model=list[PolicyOut])
def list_policies(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return (
        db.query(models.Policy)
        .filter(
            (models.Policy.owner_id == current_user.id) | (models.Policy.is_baseline.is_(True))
        )
        .order_by(models.Policy.created_at.desc())
        .all()
    )


@router.get("/baselines", response_model=list[PolicyOut])
def list_baselines(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return (
        db.query(models.Policy)
        .filter(models.Policy.is_baseline.is_(True))
        .order_by(models.Policy.name)
        .all()
    )


@router.get("/{policy_id}", response_model=PolicyOut)
def get_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    policy = db.get(models.Policy, policy_id)
    return _visible_or_404(policy, current_user)


@router.post("", response_model=PolicyOut, status_code=201)
def create_policy(
    payload: PolicyCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not payload.headers and payload.csp_policy is None:
        raise HTTPException(
            status_code=422, detail="Policy must include at least one header or a CSP policy."
        )
    policy = models.Policy(
        name=payload.name,
        description=payload.description,
        headers=[h.model_dump() for h in payload.headers],
        csp_policy=payload.csp_policy.model_dump() if payload.csp_policy else None,
        owner_id=current_user.id,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


@router.put("/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: str,
    payload: PolicyUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    policy = db.get(models.Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found.")
    if policy.is_baseline:
        raise HTTPException(
            status_code=400,
            detail="Baseline policies cannot be edited directly. Create a copy to customize it.",
        )
    if policy.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Policy not found.")
    if not payload.headers and payload.csp_policy is None:
        raise HTTPException(
            status_code=422, detail="Policy must include at least one header or a CSP policy."
        )
    policy.name = payload.name
    policy.description = payload.description
    policy.headers = [h.model_dump() for h in payload.headers]
    policy.csp_policy = payload.csp_policy.model_dump() if payload.csp_policy else None
    policy.version += 1
    db.commit()
    db.refresh(policy)
    return policy


@router.delete("/{policy_id}", status_code=204)
def delete_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    policy = db.get(models.Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found.")
    if policy.is_baseline:
        raise HTTPException(status_code=400, detail="Baseline policies cannot be deleted.")
    if policy.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Policy not found.")
    db.delete(policy)
    db.commit()
    return None

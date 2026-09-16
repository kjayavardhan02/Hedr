from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.schemas import PolicyCreate, PolicyOut, PolicyUpdate

router = APIRouter(prefix="/api/policies", tags=["policies"])


@router.get("", response_model=list[PolicyOut])
def list_policies(db: Session = Depends(get_db)):
    return db.query(models.Policy).order_by(models.Policy.created_at.desc()).all()


@router.get("/baselines", response_model=list[PolicyOut])
def list_baselines(db: Session = Depends(get_db)):
    return (
        db.query(models.Policy)
        .filter(models.Policy.is_baseline.is_(True))
        .order_by(models.Policy.name)
        .all()
    )


@router.get("/{policy_id}", response_model=PolicyOut)
def get_policy(policy_id: str, db: Session = Depends(get_db)):
    policy = db.get(models.Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found.")
    return policy


@router.post("", response_model=PolicyOut, status_code=201)
def create_policy(payload: PolicyCreate, db: Session = Depends(get_db)):
    if not payload.headers:
        raise HTTPException(status_code=422, detail="Policy must include at least one header.")
    policy = models.Policy(
        name=payload.name,
        description=payload.description,
        headers=[h.model_dump() for h in payload.headers],
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


@router.put("/{policy_id}", response_model=PolicyOut)
def update_policy(policy_id: str, payload: PolicyUpdate, db: Session = Depends(get_db)):
    policy = db.get(models.Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found.")
    if policy.is_baseline:
        raise HTTPException(
            status_code=400,
            detail="Baseline policies cannot be edited directly. Create a copy to customize it.",
        )
    if not payload.headers:
        raise HTTPException(status_code=422, detail="Policy must include at least one header.")
    policy.name = payload.name
    policy.description = payload.description
    policy.headers = [h.model_dump() for h in payload.headers]
    db.commit()
    db.refresh(policy)
    return policy


@router.delete("/{policy_id}", status_code=204)
def delete_policy(policy_id: str, db: Session = Depends(get_db)):
    policy = db.get(models.Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found.")
    if policy.is_baseline:
        raise HTTPException(status_code=400, detail="Baseline policies cannot be deleted.")
    db.delete(policy)
    db.commit()
    return None

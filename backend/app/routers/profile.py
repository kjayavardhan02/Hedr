from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models
from app.core.deps import get_current_user
from app.core.security import hash_password, verify_password
from app.database import get_db
from app.schemas import (
    PasswordChangeRequest,
    PreferencesOut,
    PreferencesUpdate,
    ProfileOut,
    ProfileUpdate,
)

router = APIRouter(prefix="/api/profile", tags=["profile"])


@router.get("", response_model=ProfileOut)
def get_profile(current_user: models.User = Depends(get_current_user)):
    return current_user


@router.patch("", response_model=ProfileOut)
def update_profile(
    payload: ProfileUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    data = payload.model_dump(exclude_unset=True)

    if "username" in data:
        username = data["username"]
        if username is not None:
            duplicate = (
                db.query(models.User)
                .filter(models.User.username == username, models.User.id != current_user.id)
                .first()
            )
            if duplicate:
                raise HTTPException(status_code=409, detail="That username is already taken.")
        current_user.username = username
    if "organization" in data:
        current_user.organization = data["organization"]
    if "job_title" in data:
        current_user.job_title = data["job_title"]
    if "first_name" in data:
        current_user.first_name = data["first_name"]
    if "last_name" in data:
        current_user.last_name = data["last_name"]

    db.commit()
    db.refresh(current_user)
    return current_user


@router.post("/password/change", status_code=204)
def change_password(
    payload: PasswordChangeRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect.")
    if verify_password(payload.new_password, current_user.hashed_password):
        raise HTTPException(
            status_code=422, detail="New password must be different from the current password."
        )
    current_user.hashed_password = hash_password(payload.new_password)
    current_user.password_changed_at = datetime.now(timezone.utc)
    db.commit()
    return None


def _preferences_out(user: models.User) -> PreferencesOut:
    return PreferencesOut(
        default_policy_id=user.default_policy_id,
        theme=user.theme,
        accent_color=user.accent_color,
    )


@router.get("/preferences", response_model=PreferencesOut)
def get_preferences(current_user: models.User = Depends(get_current_user)):
    return _preferences_out(current_user)


@router.patch("/preferences", response_model=PreferencesOut)
def update_preferences(
    payload: PreferencesUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # Only the fields actually present in the request are touched - PATCHing
    # just `theme` must never silently clear `default_policy_id`, or vice versa.
    data = payload.model_dump(exclude_unset=True)

    if "default_policy_id" in data:
        policy_id = data["default_policy_id"]
        if policy_id:
            policy = db.get(models.Policy, policy_id)
            if policy is None or not (policy.is_baseline or policy.owner_id == current_user.id):
                raise HTTPException(status_code=404, detail="Policy not found.")
        current_user.default_policy_id = policy_id

    if "theme" in data:
        current_user.theme = data["theme"]

    if "accent_color" in data:
        current_user.accent_color = data["accent_color"]

    db.commit()
    return _preferences_out(current_user)

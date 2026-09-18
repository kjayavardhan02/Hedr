"""FastAPI dependency that resolves the current authenticated user from the
session cookie. Every route that touches user-owned data (policies, scans,
AI explanations) depends on this - there is no anonymous access.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app import models
from app.config import SESSION_COOKIE_NAME
from app.core.security import TokenError, decode_access_token
from app.database import get_db

_UNAUTHORIZED = HTTPException(status_code=401, detail="Not authenticated.")


def get_current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise _UNAUTHORIZED
    try:
        user_id = decode_access_token(token)
    except TokenError:
        raise _UNAUTHORIZED from None

    user = db.get(models.User, user_id)
    if not user:
        raise _UNAUTHORIZED
    return user

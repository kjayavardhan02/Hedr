"""Multi-factor authentication via email one-time codes (Feature 13).

Routes the spec lists (section 41), grouped by who may call them:
- authenticated: status, enable request/verify, disable request/verify;
- unauthenticated, but only with a login `challenge_id` from the password
  step: login verify / resend. A challenge is NOT a session - the cookie is
  only issued by /login/verify, after the code checks out.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app import config, models
from app.core import rate_limit
from app.core.deps import get_current_user
from app.core.security import verify_password
from app.database import get_db
from app.routers.auth import _set_session_cookie
from app.schemas import (
    MFACodeIn,
    MFACodeIssuedOut,
    MFADisableRequestIn,
    MFALoginChallengeOut,
    MFALoginResendIn,
    MFALoginVerifyIn,
    MFAStatusOut,
    UserOut,
)
from app.services import email_service, otp_service

logger = logging.getLogger("hedr.mfa")

router = APIRouter(prefix="/api/mfa", tags=["mfa"])

_SESSION_EXPIRED = "This sign-in session has expired. Please sign in again."


def _ip_guard(request: Request) -> None:
    """Per-IP cap on every MFA call, on top of the per-code attempt limit."""
    rate_limit.hit(
        f"mfa:{rate_limit.client_ip(request)}",
        limit=config.MFA_IP_MAX_REQUESTS,
        window_seconds=config.MFA_IP_WINDOW_SECONDS,
    )


def raise_http(exc: Exception) -> None:
    """Translate service errors into HTTP errors (never reveals a code)."""
    if isinstance(exc, otp_service.OtpRateLimited):
        raise HTTPException(
            status_code=429, detail=exc.message, headers={"Retry-After": str(max(1, exc.retry_after))}
        ) from exc
    if isinstance(exc, otp_service.OtpAttemptsExceeded):
        raise HTTPException(status_code=429, detail=exc.message) from exc
    if isinstance(exc, otp_service.OtpError):
        raise HTTPException(status_code=400, detail=exc.message) from exc
    if isinstance(exc, email_service.EmailNotConfiguredError):
        raise HTTPException(
            status_code=503, detail="Email delivery isn't set up on this server, so a verification code can't be sent."
        ) from exc
    if isinstance(exc, email_service.EmailDeliveryError):
        raise HTTPException(
            status_code=503, detail="We couldn't send the verification code right now. Please try again shortly."
        ) from exc
    raise exc


def _is_enabled(db: Session, user_id: str) -> bool:
    row = db.query(models.UserMFA).filter(models.UserMFA.user_id == user_id).first()
    return bool(row and row.enabled)


def _set_enabled(db: Session, user_id: str, enabled: bool) -> None:
    row = db.query(models.UserMFA).filter(models.UserMFA.user_id == user_id).first()
    if row is None:
        row = models.UserMFA(user_id=user_id, enabled=enabled)
        db.add(row)
    else:
        row.enabled = enabled
    db.commit()


def _status(db: Session, user: models.User) -> MFAStatusOut:
    return MFAStatusOut(
        enabled=_is_enabled(db, user.id),
        masked_email=otp_service.mask_email(user.email),
        email_configured=email_service.is_configured(),
    )


def _issued(db: Session, user: models.User, challenge: models.EmailOTPChallenge) -> MFACodeIssuedOut:
    return MFACodeIssuedOut(
        masked_email=otp_service.mask_email(user.email),
        expires_in=otp_service.seconds_remaining(challenge),
        resend_available_in=otp_service.seconds_until_resend(db, user.id, challenge.purpose),
    )


def login_challenge_out(db: Session, user: models.User, challenge: models.EmailOTPChallenge) -> MFALoginChallengeOut:
    return MFALoginChallengeOut(
        challenge_id=challenge.id,
        masked_email=otp_service.mask_email(user.email),
        expires_in=otp_service.seconds_remaining(challenge),
        resend_available_in=otp_service.seconds_until_resend(db, user.id, challenge.purpose),
    )


# --- authenticated ------------------------------------------------------------


@router.get("/status", response_model=MFAStatusOut)
def mfa_status(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return _status(db, current_user)


@router.post("/enable/request", response_model=MFACodeIssuedOut, dependencies=[Depends(_ip_guard)])
def request_enable(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    if _is_enabled(db, current_user.id):
        raise HTTPException(status_code=409, detail="Two-factor authentication is already enabled.")
    try:
        challenge = otp_service.issue_and_send(db, current_user, otp_service.PURPOSE_ENABLE)
    except (otp_service.OtpError, email_service.EmailNotConfiguredError, email_service.EmailDeliveryError) as exc:
        raise_http(exc)
    return _issued(db, current_user, challenge)


@router.post("/enable/verify", response_model=MFAStatusOut, dependencies=[Depends(_ip_guard)])
def verify_enable(
    payload: MFACodeIn, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)
):
    challenge = otp_service.get_active_for_user(db, current_user.id, otp_service.PURPOSE_ENABLE)
    try:
        otp_service.verify(db, challenge, payload.code)
    except otp_service.OtpError as exc:
        raise_http(exc)
    _set_enabled(db, current_user.id, True)
    logger.info("MFA enabled (user=%s).", current_user.id)
    return _status(db, current_user)


@router.post("/disable/request", response_model=MFACodeIssuedOut, dependencies=[Depends(_ip_guard)])
def request_disable(
    payload: MFADisableRequestIn,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Turning MFA off needs the current password AND an emailed code - a
    session cookie alone is never enough."""
    if not _is_enabled(db, current_user.id):
        raise HTTPException(status_code=409, detail="Two-factor authentication is not enabled.")
    if not verify_password(payload.password, current_user.hashed_password):
        # 403, not 401: a 401 makes the web client treat the session as gone
        # and sign the user out, which a mistyped password must not do.
        raise HTTPException(status_code=403, detail="Current password is incorrect.")
    try:
        challenge = otp_service.issue_and_send(db, current_user, otp_service.PURPOSE_DISABLE)
    except (otp_service.OtpError, email_service.EmailNotConfiguredError, email_service.EmailDeliveryError) as exc:
        raise_http(exc)
    return _issued(db, current_user, challenge)


@router.post("/disable/verify", response_model=MFAStatusOut, dependencies=[Depends(_ip_guard)])
def verify_disable(
    payload: MFACodeIn, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)
):
    if not _is_enabled(db, current_user.id):
        raise HTTPException(status_code=409, detail="Two-factor authentication is not enabled.")
    challenge = otp_service.get_active_for_user(db, current_user.id, otp_service.PURPOSE_DISABLE)
    try:
        otp_service.verify(db, challenge, payload.code)
    except otp_service.OtpError as exc:
        raise_http(exc)
    _set_enabled(db, current_user.id, False)
    logger.info("MFA disabled (user=%s).", current_user.id)
    return _status(db, current_user)


# --- sign-in (no session yet) -------------------------------------------------


def _login_challenge_or_400(db: Session, challenge_id: str) -> models.EmailOTPChallenge:
    challenge = otp_service.get_live_challenge(db, challenge_id, otp_service.PURPOSE_LOGIN)
    if challenge is None:
        raise HTTPException(status_code=400, detail=_SESSION_EXPIRED)
    started = challenge.chain_started_at or challenge.created_at
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - started > timedelta(seconds=config.MFA_LOGIN_MAX_AGE_SECONDS):
        challenge.used_at = datetime.now(timezone.utc)
        db.commit()
        raise HTTPException(status_code=400, detail=_SESSION_EXPIRED)
    return challenge


@router.post("/login/verify", response_model=UserOut, dependencies=[Depends(_ip_guard)])
def verify_login(payload: MFALoginVerifyIn, response: Response, db: Session = Depends(get_db)):
    challenge = _login_challenge_or_400(db, payload.challenge_id)
    user = db.get(models.User, challenge.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail=_SESSION_EXPIRED)
    try:
        otp_service.verify(db, challenge, payload.code)
    except otp_service.OtpError as exc:
        raise_http(exc)
    # Only now - password AND code both checked - is a session issued.
    _set_session_cookie(response, user.id)
    return user


@router.post("/login/resend", response_model=MFALoginChallengeOut, dependencies=[Depends(_ip_guard)])
def resend_login(payload: MFALoginResendIn, db: Session = Depends(get_db)):
    old = _login_challenge_or_400(db, payload.challenge_id)
    user = db.get(models.User, old.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail=_SESSION_EXPIRED)
    try:
        challenge = otp_service.issue_and_send(
            db, user, otp_service.PURPOSE_LOGIN, chain_started_at=old.chain_started_at
        )
    except (otp_service.OtpError, email_service.EmailNotConfiguredError, email_service.EmailDeliveryError) as exc:
        raise_http(exc)
    return login_challenge_out(db, user, challenge)

"""Email one-time-password (OTP) issuing and verification for MFA.

Security properties (spec section 44):
- codes come from `secrets` (a CSPRNG), 6 digits;
- only a keyed HMAC of the code is stored, bound to challenge id + user +
  purpose, compared in constant time - never the code itself;
- a code expires (5 min), is single-use, and is voided after too many wrong
  guesses;
- issuing is rate limited per user+purpose, with a cooldown between sends;
- the code is never logged. Log lines say what happened, not what the code was.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import math
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app import config, models
from app.services import email_service

logger = logging.getLogger("hedr.mfa")

PURPOSE_ENABLE = "mfa_enable"
PURPOSE_LOGIN = "mfa_login"
PURPOSE_DISABLE = "mfa_disable"
PURPOSES = (PURPOSE_ENABLE, PURPOSE_LOGIN, PURPOSE_DISABLE)

_PURPOSE_COPY = {
    PURPOSE_ENABLE: "enable two-factor authentication on your Hedr account",
    PURPOSE_LOGIN: "sign in to Hedr",
    PURPOSE_DISABLE: "turn off two-factor authentication on your Hedr account",
}


class OtpError(Exception):
    """Base class; `message` is safe to show the user."""

    message = "Verification failed."

    def __init__(self, message: str | None = None):
        super().__init__(message or self.message)
        self.message = message or self.message


class OtpRateLimited(OtpError):
    message = "Too many verification codes requested. Please try again later."

    def __init__(self, message: str | None = None, retry_after: int = 0):
        super().__init__(message)
        self.retry_after = retry_after


class OtpInvalid(OtpError):
    message = "Incorrect verification code."


class OtpExpired(OtpError):
    message = "This verification code has expired. Please request a new code."


class OtpAttemptsExceeded(OtpError):
    message = "Too many incorrect attempts. Please request a new verification code."


class OtpNotFound(OtpError):
    """No usable code/challenge. Deliberately vague: it covers unknown ids,
    used codes and codes for someone else alike."""

    message = "No active verification code. Please request a new code."


def _now() -> datetime:
    return datetime.now(timezone.utc)


def generate_code() -> str:
    return f"{secrets.randbelow(10 ** config.OTP_LENGTH):0{config.OTP_LENGTH}d}"


def hash_code(*, challenge_id: str, user_id: str, purpose: str, code: str) -> str:
    key = (config.JWT_SECRET_KEY or "").encode("utf-8")
    message = f"{challenge_id}:{user_id}:{purpose}:{code}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def mask_email(email: str) -> str:
    """`jane@example.com` -> `j******@example.com`. A fixed run of asterisks, so
    the length of the local part isn't leaked either."""
    local, _, domain = email.partition("@")
    return f"{local[:1]}******@{domain}" if domain else f"{email[:1]}******"


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def seconds_until_resend(db: Session, user_id: str, purpose: str, now: datetime | None = None) -> int:
    now = now or _now()
    latest = (
        db.query(models.EmailOTPChallenge)
        .filter(models.EmailOTPChallenge.user_id == user_id, models.EmailOTPChallenge.purpose == purpose)
        .order_by(models.EmailOTPChallenge.created_at.desc())
        .first()
    )
    if latest is None:
        return 0
    ready_at = _as_utc(latest.created_at) + timedelta(seconds=config.OTP_RESEND_COOLDOWN_SECONDS)
    return max(0, math.ceil((ready_at - now).total_seconds()))


def _check_rate_limits(db: Session, user_id: str, purpose: str, now: datetime) -> None:
    wait = seconds_until_resend(db, user_id, purpose, now)
    if wait > 0:
        raise OtpRateLimited(f"Please wait {wait} seconds before requesting another code.", retry_after=wait)
    window_start = now - timedelta(seconds=config.OTP_REQUEST_WINDOW_SECONDS)
    recent = (
        db.query(models.EmailOTPChallenge)
        .filter(
            models.EmailOTPChallenge.user_id == user_id,
            models.EmailOTPChallenge.purpose == purpose,
            models.EmailOTPChallenge.created_at > window_start,
        )
        .order_by(models.EmailOTPChallenge.created_at.asc())
        .all()
    )
    if len(recent) >= config.OTP_MAX_REQUESTS:
        oldest = _as_utc(recent[0].created_at)
        retry_after = max(1, int((oldest + timedelta(seconds=config.OTP_REQUEST_WINDOW_SECONDS) - now).total_seconds()))
        raise OtpRateLimited(
            "Too many verification codes requested. Please try again later.", retry_after=retry_after
        )


def issue_and_send(
    db: Session,
    user: models.User,
    purpose: str,
    *,
    chain_started_at: datetime | None = None,
) -> models.EmailOTPChallenge:
    """Create a fresh code for (user, purpose), supersede any older live one,
    and email it. Raises OtpRateLimited, email_service.EmailNotConfiguredError
    or email_service.EmailDeliveryError. A code that couldn't be delivered is
    discarded, so it doesn't count against the user's rate limit."""
    assert purpose in PURPOSES
    now = _now()
    _check_rate_limits(db, user.id, purpose, now)

    code = generate_code()
    challenge = models.EmailOTPChallenge(
        user_id=user.id,
        purpose=purpose,
        otp_hash="",
        expires_at=now + timedelta(seconds=config.OTP_TTL_SECONDS),
        created_at=now,
        chain_started_at=chain_started_at or now,
    )
    db.add(challenge)
    db.flush()  # assigns challenge.id, which the hash is bound to
    challenge.otp_hash = hash_code(challenge_id=challenge.id, user_id=user.id, purpose=purpose, code=code)
    db.commit()

    try:
        email_service.send_email(
            to=user.email,
            subject="Your Hedr verification code",
            body=_email_body(code, purpose),
        )
    except (email_service.EmailNotConfiguredError, email_service.EmailDeliveryError):
        db.delete(challenge)
        db.commit()
        raise

    # Delivered: only now retire older live codes, so a failed send never
    # leaves the user without a usable one. Only the newest code works.
    for older in (
        db.query(models.EmailOTPChallenge)
        .filter(
            models.EmailOTPChallenge.user_id == user.id,
            models.EmailOTPChallenge.purpose == purpose,
            models.EmailOTPChallenge.used_at.is_(None),
            models.EmailOTPChallenge.id != challenge.id,
        )
        .all()
    ):
        older.used_at = now
    db.commit()
    logger.info("MFA OTP generated (purpose=%s user=%s).", purpose, user.id)
    return challenge


def _email_body(code: str, purpose: str) -> str:
    minutes = max(1, config.OTP_TTL_SECONDS // 60)
    return (
        "Hello,\n\n"
        f"Your Hedr verification code is:\n\n{code}\n\n"
        f"Use it to {_PURPOSE_COPY[purpose]}. This code expires in {minutes} minute{'s' if minutes != 1 else ''}.\n\n"
        "If you did not attempt this, you can safely ignore this email.\n\n"
        "Do not share this code with anyone.\n\n"
        "- Hedr Security\n"
    )


def get_active_for_user(db: Session, user_id: str, purpose: str) -> models.EmailOTPChallenge | None:
    return (
        db.query(models.EmailOTPChallenge)
        .filter(
            models.EmailOTPChallenge.user_id == user_id,
            models.EmailOTPChallenge.purpose == purpose,
            models.EmailOTPChallenge.used_at.is_(None),
        )
        .order_by(models.EmailOTPChallenge.created_at.desc())
        .first()
    )


def get_live_challenge(db: Session, challenge_id: str, purpose: str) -> models.EmailOTPChallenge | None:
    challenge = db.get(models.EmailOTPChallenge, challenge_id)
    if challenge is None or challenge.purpose != purpose or challenge.used_at is not None:
        return None
    return challenge


def verify(db: Session, challenge: models.EmailOTPChallenge | None, code: str) -> None:
    """Check `code` against `challenge`, consuming the challenge on success.
    Every failure path commits what it changed (attempt count / voiding)
    before raising."""
    if challenge is None:
        raise OtpNotFound()
    now = _now()

    if _as_utc(challenge.expires_at) <= now:
        raise OtpExpired()
    if challenge.attempt_count >= config.OTP_MAX_ATTEMPTS:
        challenge.used_at = now
        db.commit()
        raise OtpAttemptsExceeded()

    expected = hash_code(
        challenge_id=challenge.id, user_id=challenge.user_id, purpose=challenge.purpose, code=(code or "").strip()
    )
    if not hmac.compare_digest(expected, challenge.otp_hash):
        challenge.attempt_count += 1
        voided = challenge.attempt_count >= config.OTP_MAX_ATTEMPTS
        if voided:
            challenge.used_at = now
        db.commit()
        logger.warning("MFA OTP verification failed (purpose=%s user=%s).", challenge.purpose, challenge.user_id)
        raise OtpAttemptsExceeded() if voided else OtpInvalid()

    # Single use: consume immediately.
    challenge.used_at = now
    db.commit()
    logger.info("MFA OTP verification succeeded (purpose=%s user=%s).", challenge.purpose, challenge.user_id)


def seconds_remaining(challenge: models.EmailOTPChallenge, now: datetime | None = None) -> int:
    now = now or _now()
    return max(0, int((_as_utc(challenge.expires_at) - now).total_seconds()))

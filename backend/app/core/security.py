"""Password hashing and session-token helpers.

Sessions are a JWT stored in an httpOnly cookie (see routers/auth.py for
where the cookie itself is set/cleared) - stateless, so no server-side
session store is needed, but still can't be read or exfiltrated by
client-side JavaScript (mitigates session-cookie theft via XSS).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.config import JWT_ALGORITHM, JWT_EXPIRE_MINUTES, JWT_SECRET_KEY

# A fixed, valid bcrypt hash of a random string that no real password will
# ever match. Used to run a dummy verification when a login email isn't
# found, so login takes the same amount of time either way and an attacker
# can't use response timing to enumerate registered emails.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt())


class TokenError(ValueError):
    pass


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))


def verify_password_or_dummy(password: str, hashed_password: str | None) -> bool:
    """Like verify_password, but if there's no real hash to check against
    (email not found), still runs bcrypt against a dummy hash so the two
    code paths take about the same time."""
    if hashed_password is None:
        bcrypt.checkpw(password.encode("utf-8"), _DUMMY_HASH)
        return False
    return verify_password(password, hashed_password)


def create_access_token(*, user_id: str) -> str:
    if not JWT_SECRET_KEY:
        raise RuntimeError("JWT_SECRET_KEY is not configured.")
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> str:
    """Returns the user id encoded in the token, or raises TokenError."""
    if not JWT_SECRET_KEY:
        raise RuntimeError("JWT_SECRET_KEY is not configured.")
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    user_id = payload.get("sub")
    if not user_id:
        raise TokenError("Token missing subject.")
    return user_id

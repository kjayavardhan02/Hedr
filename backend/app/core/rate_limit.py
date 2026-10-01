"""A tiny in-memory sliding-window limiter, keyed by an arbitrary string
(here: client IP + action). Process-local - good enough to blunt guessing
against the MFA endpoints; the per-code attempt limit and the per-user OTP
issue limit (see app.services.otp_service) are the durable defences."""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

_hits: dict[str, deque[float]] = defaultdict(deque)


def reset() -> None:
    _hits.clear()


def hit(key: str, *, limit: int, window_seconds: int) -> None:
    """Record a call; raise 429 once `limit` calls land inside the window."""
    now = time.monotonic()
    bucket = _hits[key]
    while bucket and now - bucket[0] > window_seconds:
        bucket.popleft()
    if len(bucket) >= limit:
        retry_after = max(1, int(window_seconds - (now - bucket[0])))
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
    bucket.append(now)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"

import time

import jwt
import pytest

from app.config import JWT_ALGORITHM, JWT_SECRET_KEY
from app.core.security import (
    TokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
    verify_password_or_dummy,
)


class TestPasswordHashing:
    def test_hash_is_not_the_plaintext(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert hashed != "correct-horse-battery-staple"

    def test_verify_correct_password(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("correct-horse-battery-staple", hashed) is True

    def test_verify_wrong_password(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("wrong-password", hashed) is False

    def test_same_password_hashes_differently_each_time(self):
        # bcrypt salts automatically - two hashes of the same password must
        # never be identical (rules out a broken/missing salt).
        h1 = hash_password("same-password")
        h2 = hash_password("same-password")
        assert h1 != h2
        assert verify_password("same-password", h1)
        assert verify_password("same-password", h2)


class TestVerifyPasswordOrDummy:
    def test_returns_false_for_missing_hash_without_raising(self):
        assert verify_password_or_dummy("anything", None) is False

    def test_still_checks_real_hash_when_present(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password_or_dummy("correct-horse-battery-staple", hashed) is True
        assert verify_password_or_dummy("wrong", hashed) is False

    def test_dummy_path_takes_comparable_time_to_real_path(self):
        # Not a precise timing-attack test (too flaky for CI), just a sanity
        # check that the dummy path actually does bcrypt work rather than
        # returning instantly (which would reintroduce the timing gap).
        hashed = hash_password("correct-horse-battery-staple")

        start = time.perf_counter()
        verify_password_or_dummy("guess", hashed)
        real_elapsed = time.perf_counter() - start

        start = time.perf_counter()
        verify_password_or_dummy("guess", None)
        dummy_elapsed = time.perf_counter() - start

        # Both should be on the order of a bcrypt round (tens of ms), not
        # microseconds - loose bound to avoid CI flakiness.
        assert dummy_elapsed > real_elapsed / 5


class TestAccessTokens:
    def test_round_trip(self):
        token = create_access_token(user_id="user-123")
        assert decode_access_token(token) == "user-123"

    def test_tampered_signature_rejected(self):
        token = create_access_token(user_id="user-123")
        forged = jwt.encode({"sub": "user-123"}, "some-other-secret", algorithm=JWT_ALGORITHM)
        assert token != forged
        with pytest.raises(TokenError):
            decode_access_token(forged)

    def test_expired_token_rejected(self):
        expired = jwt.encode({"sub": "user-123", "exp": 1}, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        with pytest.raises(TokenError):
            decode_access_token(expired)

    def test_garbage_token_rejected(self):
        with pytest.raises(TokenError):
            decode_access_token("not-a-jwt-at-all")

    def test_token_without_subject_rejected(self):
        token = jwt.encode({"foo": "bar"}, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        with pytest.raises(TokenError):
            decode_access_token(token)

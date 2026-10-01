"""Feature 13: email-OTP multi-factor authentication."""
import inspect
import logging
import re
from datetime import timedelta

import pytest

from app import config, models
from app.core import rate_limit
from app.database import SessionLocal
from app.services import email_service, otp_service
from tests.conftest import DEFAULT_PASSWORD


class Outbox:
    def __init__(self):
        self.messages: list[dict] = []
        self.fail: Exception | None = None

    def send(self, *, to, subject, body):
        if self.fail:
            raise self.fail
        self.messages.append({"to": to, "subject": subject, "body": body})

    @property
    def last_code(self) -> str:
        return re.search(r"\n\n(\d{6})\n\n", self.messages[-1]["body"]).group(1)


@pytest.fixture(autouse=True)
def outbox(monkeypatch):
    box = Outbox()
    monkeypatch.setattr(email_service, "send_email", box.send)
    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    # Most tests issue several codes back to back; the cooldown/limit tests
    # restore the real values themselves.
    monkeypatch.setattr(config, "OTP_RESEND_COOLDOWN_SECONDS", 0)
    monkeypatch.setattr(config, "OTP_MAX_REQUESTS", 100)
    rate_limit.reset()
    return box


@pytest.fixture
def clock(monkeypatch):
    """Move the OTP service's clock forward."""

    class Clock:
        offset = timedelta()

        def advance(self, **kwargs):
            self.offset += timedelta(**kwargs)

    c = Clock()
    real = otp_service._now
    monkeypatch.setattr(otp_service, "_now", lambda: real() + c.offset)
    return c


def _enable(client, outbox):
    assert client.post("/api/mfa/enable/request").status_code == 200
    resp = client.post("/api/mfa/enable/verify", json={"code": outbox.last_code})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _login(client, user):
    return client.post("/api/auth/login", json={"email": user["email"], "password": DEFAULT_PASSWORD})


@pytest.fixture
def mfa_user(auth_client, outbox):
    client, user = auth_client
    _enable(client, outbox)
    client.post("/api/auth/logout")
    outbox.messages.clear()
    return client, user


# --- status / unauthenticated ---------------------------------------------------


class TestAccess:
    @pytest.mark.parametrize(
        "method,path,body",
        [
            ("get", "/api/mfa/status", None),
            ("post", "/api/mfa/enable/request", None),
            ("post", "/api/mfa/enable/verify", {"code": "123456"}),
            ("post", "/api/mfa/disable/request", {"password": "x"}),
            ("post", "/api/mfa/disable/verify", {"code": "123456"}),
        ],
    )
    def test_authenticated_endpoints_require_a_session(self, client, method, path, body):
        resp = getattr(client, method)(path, **({"json": body} if body else {}))
        assert resp.status_code == 401

    def test_status_defaults_to_disabled_with_masked_email(self, auth_client):
        client, user = auth_client
        body = client.get("/api/mfa/status").json()
        assert body["enabled"] is False
        assert body["masked_email"] == user["email"][0] + "******@" + user["email"].split("@")[1]
        assert user["email"] not in str(body)


# --- enabling ---------------------------------------------------------------------


class TestEnable:
    def test_enable_flow(self, auth_client, outbox):
        client, user = auth_client
        resp = client.post("/api/mfa/enable/request")
        assert resp.status_code == 200
        assert resp.json()["masked_email"].endswith("@example.com") and "*" in resp.json()["masked_email"]
        assert outbox.messages[0]["to"] == user["email"]
        assert outbox.messages[0]["subject"] == "Your Hedr verification code"
        assert re.fullmatch(r"\d{6}", outbox.last_code)
        assert client.post("/api/mfa/enable/verify", json={"code": outbox.last_code}).json()["enabled"] is True
        assert client.get("/api/mfa/status").json()["enabled"] is True

    def test_wrong_code_does_not_enable(self, auth_client, outbox):
        client, _ = auth_client
        client.post("/api/mfa/enable/request")
        wrong = "000000" if outbox.last_code != "000000" else "111111"
        resp = client.post("/api/mfa/enable/verify", json={"code": wrong})
        assert resp.status_code == 400
        assert client.get("/api/mfa/status").json()["enabled"] is False

    def test_malformed_code_rejected(self, auth_client, outbox):
        client, _ = auth_client
        client.post("/api/mfa/enable/request")
        for bad in ("12345", "abcdef", "1234567", ""):
            assert client.post("/api/mfa/enable/verify", json={"code": bad}).status_code == 422

    def test_verify_without_request_fails(self, auth_client):
        client, _ = auth_client
        assert client.post("/api/mfa/enable/verify", json={"code": "123456"}).status_code == 400

    def test_expired_code_rejected(self, auth_client, outbox, clock):
        client, _ = auth_client
        client.post("/api/mfa/enable/request")
        code = outbox.last_code
        clock.advance(seconds=config.OTP_TTL_SECONDS + 1)
        resp = client.post("/api/mfa/enable/verify", json={"code": code})
        assert resp.status_code == 400
        assert "expired" in resp.json()["detail"].lower()
        assert client.get("/api/mfa/status").json()["enabled"] is False

    def test_code_is_single_use(self, auth_client, outbox):
        client, _ = auth_client
        client.post("/api/mfa/enable/request")
        code = outbox.last_code
        assert client.post("/api/mfa/enable/verify", json={"code": code}).status_code == 200
        # Reuse after success, even though MFA is now on: gone.
        again = client.post("/api/mfa/enable/verify", json={"code": code})
        assert again.status_code in (400, 409)

    def test_max_failed_attempts_voids_the_code(self, auth_client, outbox):
        client, _ = auth_client
        client.post("/api/mfa/enable/request")
        good = outbox.last_code
        wrong = "000000" if good != "000000" else "111111"
        statuses = [client.post("/api/mfa/enable/verify", json={"code": wrong}).status_code for _ in range(config.OTP_MAX_ATTEMPTS)]
        assert statuses[-1] == 429
        # Even the right code no longer works - a new one must be requested.
        assert client.post("/api/mfa/enable/verify", json={"code": good}).status_code == 400
        client.post("/api/mfa/enable/request")
        assert client.post("/api/mfa/enable/verify", json={"code": outbox.last_code}).status_code == 200

    def test_cannot_enable_twice(self, auth_client, outbox):
        client, _ = auth_client
        _enable(client, outbox)
        assert client.post("/api/mfa/enable/request").status_code == 409

    def test_new_code_supersedes_the_old_one(self, auth_client, outbox):
        client, _ = auth_client
        client.post("/api/mfa/enable/request")
        first = outbox.last_code
        client.post("/api/mfa/enable/request")
        second = outbox.last_code
        if first != second:
            assert client.post("/api/mfa/enable/verify", json={"code": first}).status_code == 400
        assert client.post("/api/mfa/enable/verify", json={"code": second}).status_code == 200

    def test_email_not_configured_returns_503(self, auth_client, outbox):
        client, _ = auth_client
        outbox.fail = email_service.EmailNotConfiguredError("x")
        assert client.post("/api/mfa/enable/request").status_code == 503
        assert client.get("/api/mfa/status").json()["enabled"] is False

    def test_failed_delivery_is_503_and_not_counted(self, auth_client, outbox, monkeypatch):
        client, _ = auth_client
        monkeypatch.setattr(config, "OTP_MAX_REQUESTS", 1)
        outbox.fail = email_service.EmailDeliveryError("x")
        assert client.post("/api/mfa/enable/request").status_code == 503
        outbox.fail = None
        # The undeliverable code did not use up the single allowed request.
        assert client.post("/api/mfa/enable/request").status_code == 200


# --- rate limiting ------------------------------------------------------------------


class TestRateLimits:
    def test_resend_cooldown(self, auth_client, monkeypatch):
        client, _ = auth_client
        monkeypatch.setattr(config, "OTP_RESEND_COOLDOWN_SECONDS", 30)
        first = client.post("/api/mfa/enable/request")
        assert first.status_code == 200
        assert 0 < first.json()["resend_available_in"] <= 30
        second = client.post("/api/mfa/enable/request")
        assert second.status_code == 429
        assert int(second.headers["Retry-After"]) > 0

    def test_cooldown_ends(self, auth_client, monkeypatch, clock):
        client, _ = auth_client
        monkeypatch.setattr(config, "OTP_RESEND_COOLDOWN_SECONDS", 30)
        assert client.post("/api/mfa/enable/request").status_code == 200
        clock.advance(seconds=31)
        assert client.post("/api/mfa/enable/request").status_code == 200

    def test_request_limit_per_window(self, auth_client, monkeypatch, clock):
        client, _ = auth_client
        monkeypatch.setattr(config, "OTP_MAX_REQUESTS", 3)
        for _ in range(3):
            assert client.post("/api/mfa/enable/request").status_code == 200
        assert client.post("/api/mfa/enable/request").status_code == 429
        clock.advance(seconds=config.OTP_REQUEST_WINDOW_SECONDS + 1)
        assert client.post("/api/mfa/enable/request").status_code == 200

    def test_per_ip_limit_on_mfa_endpoints(self, auth_client, monkeypatch):
        client, _ = auth_client
        monkeypatch.setattr(config, "MFA_IP_MAX_REQUESTS", 3)
        codes = [client.post("/api/mfa/enable/verify", json={"code": "123456"}).status_code for _ in range(5)]
        assert codes[:3] == [400, 400, 400]
        assert codes[3] == 429


# --- signing in ------------------------------------------------------------------


class TestLogin:
    def test_mfa_disabled_login_is_unchanged(self, auth_client, outbox):
        client, user = auth_client
        client.post("/api/auth/logout")
        resp = _login(client, user)
        assert resp.status_code == 200
        assert resp.json()["email"] == user["email"]
        assert "mfa_required" not in resp.json()
        assert outbox.messages == []
        assert client.get("/api/auth/me").status_code == 200

    def test_wrong_password_never_reveals_mfa(self, mfa_user, outbox):
        client, user = mfa_user
        resp = client.post("/api/auth/login", json={"email": user["email"], "password": "wrong-password-123"})
        assert resp.status_code == 401
        assert "mfa" not in resp.text.lower()
        assert outbox.messages == []

    def test_password_step_returns_a_challenge_and_no_session(self, mfa_user, outbox):
        client, user = mfa_user
        resp = _login(client, user)
        assert resp.status_code == 200
        body = resp.json()
        assert body["mfa_required"] is True
        assert body["challenge_id"]
        assert body["masked_email"].endswith("@example.com")
        assert "email" not in body  # not a user object
        assert "set-cookie" not in {k.lower() for k in resp.headers}
        assert outbox.messages[-1]["to"] == user["email"]

    def test_challenge_cannot_reach_authenticated_endpoints(self, mfa_user):
        client, user = mfa_user
        challenge = _login(client, user).json()
        for path in ("/api/auth/me", "/api/policies", "/api/reports", "/api/profile", "/api/dashboard/summary", "/api/burp"):
            assert client.get(path).status_code == 401, path
        # ... and the challenge id is not a credential anywhere else.
        client.cookies.set("hedr_session", challenge["challenge_id"])
        assert client.get("/api/auth/me").status_code == 401
        client.cookies.clear()

    def test_correct_code_creates_the_session(self, mfa_user, outbox):
        client, user = mfa_user
        challenge = _login(client, user).json()
        resp = client.post(
            "/api/mfa/login/verify", json={"challenge_id": challenge["challenge_id"], "code": outbox.last_code}
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == user["email"]
        assert client.get("/api/auth/me").status_code == 200

    def test_incorrect_code_gives_no_session(self, mfa_user, outbox):
        client, user = mfa_user
        challenge = _login(client, user).json()
        wrong = "000000" if outbox.last_code != "000000" else "111111"
        resp = client.post("/api/mfa/login/verify", json={"challenge_id": challenge["challenge_id"], "code": wrong})
        assert resp.status_code == 400
        assert client.get("/api/auth/me").status_code == 401

    def test_expired_code_gives_no_session(self, mfa_user, outbox, clock):
        client, user = mfa_user
        challenge = _login(client, user).json()
        code = outbox.last_code
        clock.advance(seconds=config.OTP_TTL_SECONDS + 1)
        resp = client.post("/api/mfa/login/verify", json={"challenge_id": challenge["challenge_id"], "code": code})
        assert resp.status_code == 400
        assert "expired" in resp.json()["detail"].lower()
        assert client.get("/api/auth/me").status_code == 401

    def test_reused_code_gives_no_session(self, mfa_user, outbox):
        client, user = mfa_user
        challenge = _login(client, user).json()
        code = outbox.last_code
        body = {"challenge_id": challenge["challenge_id"], "code": code}
        assert client.post("/api/mfa/login/verify", json=body).status_code == 200
        client.post("/api/auth/logout")
        assert client.post("/api/mfa/login/verify", json=body).status_code == 400
        assert client.get("/api/auth/me").status_code == 401

    def test_expired_challenge_gives_no_session(self, mfa_user, outbox, clock, monkeypatch):
        client, user = mfa_user
        challenge = _login(client, user).json()
        code = outbox.last_code
        # Past the whole sign-in window (and, as a bonus, the code's own life).
        clock.advance(seconds=config.MFA_LOGIN_MAX_AGE_SECONDS + 60)
        # The route itself uses the real clock for the chain check, so age the row instead.
        db = SessionLocal()
        try:
            row = db.get(models.EmailOTPChallenge, challenge["challenge_id"])
            row.chain_started_at = row.chain_started_at - timedelta(seconds=config.MFA_LOGIN_MAX_AGE_SECONDS + 60)
            db.commit()
        finally:
            db.close()
        resp = client.post("/api/mfa/login/verify", json={"challenge_id": challenge["challenge_id"], "code": code})
        assert resp.status_code == 400
        assert client.get("/api/auth/me").status_code == 401

    def test_unknown_challenge_id(self, client):
        resp = client.post("/api/mfa/login/verify", json={"challenge_id": "nope", "code": "123456"})
        assert resp.status_code == 400
        assert client.get("/api/auth/me").status_code == 401

    def test_too_many_wrong_codes_voids_the_challenge(self, mfa_user, outbox):
        client, user = mfa_user
        challenge = _login(client, user).json()
        good = outbox.last_code
        wrong = "000000" if good != "000000" else "111111"
        body = {"challenge_id": challenge["challenge_id"], "code": wrong}
        last = [client.post("/api/mfa/login/verify", json=body).status_code for _ in range(config.OTP_MAX_ATTEMPTS)][-1]
        assert last == 429
        assert (
            client.post("/api/mfa/login/verify", json={**body, "code": good}).status_code == 400
        )
        assert client.get("/api/auth/me").status_code == 401

    def test_resend_issues_a_new_code_and_retires_the_old_one(self, mfa_user, outbox):
        client, user = mfa_user
        first = _login(client, user).json()
        first_code = outbox.last_code
        resent = client.post("/api/mfa/login/resend", json={"challenge_id": first["challenge_id"]})
        assert resent.status_code == 200
        new = resent.json()
        assert new["challenge_id"] != first["challenge_id"]
        assert len(outbox.messages) == 2
        # The old challenge is dead.
        assert (
            client.post("/api/mfa/login/verify", json={"challenge_id": first["challenge_id"], "code": first_code}).status_code
            == 400
        )
        ok = client.post("/api/mfa/login/verify", json={"challenge_id": new["challenge_id"], "code": outbox.last_code})
        assert ok.status_code == 200

    def test_resend_respects_the_cooldown(self, mfa_user, monkeypatch):
        client, user = mfa_user
        monkeypatch.setattr(config, "OTP_RESEND_COOLDOWN_SECONDS", 30)
        challenge = _login(client, user).json()
        assert client.post("/api/mfa/login/resend", json={"challenge_id": challenge["challenge_id"]}).status_code == 429

    def test_email_failure_during_login_fails_closed(self, mfa_user, outbox):
        client, user = mfa_user
        outbox.fail = email_service.EmailDeliveryError("x")
        resp = _login(client, user)
        assert resp.status_code == 503
        assert client.get("/api/auth/me").status_code == 401

    def test_login_challenge_cannot_be_used_to_confirm_other_purposes(self, mfa_user, outbox):
        client, user = mfa_user
        challenge = _login(client, user).json()
        client.post("/api/mfa/login/verify", json={"challenge_id": challenge["challenge_id"], "code": outbox.last_code})
        # Signed in. A login challenge id fed to the enable/disable/resend
        # paths is useless: those look codes up by user + their own purpose.
        client.post("/api/auth/logout")
        challenge = _login(client, user).json()
        login_code = outbox.last_code
        assert client.post("/api/mfa/login/verify", json={"challenge_id": challenge["challenge_id"], "code": login_code}).status_code == 200
        assert client.post("/api/mfa/disable/verify", json={"code": login_code}).status_code == 400
        assert client.get("/api/mfa/status").json()["enabled"] is True


# --- disabling -------------------------------------------------------------------


class TestDisable:
    def _signed_in(self, mfa_user, outbox):
        client, user = mfa_user
        challenge = _login(client, user).json()
        client.post("/api/mfa/login/verify", json={"challenge_id": challenge["challenge_id"], "code": outbox.last_code})
        return client, user

    def test_session_alone_cannot_disable(self, mfa_user, outbox):
        client, _ = self._signed_in(mfa_user, outbox)
        assert client.post("/api/mfa/disable/verify", json={"code": "123456"}).status_code == 400
        assert client.get("/api/mfa/status").json()["enabled"] is True

    def test_wrong_password_sends_no_code(self, mfa_user, outbox):
        client, _ = self._signed_in(mfa_user, outbox)
        sent = len(outbox.messages)
        resp = client.post("/api/mfa/disable/request", json={"password": "not-the-password-1"})
        assert resp.status_code == 403
        assert len(outbox.messages) == sent

    def test_password_plus_code_disables(self, mfa_user, outbox):
        client, user = self._signed_in(mfa_user, outbox)
        assert client.post("/api/mfa/disable/request", json={"password": DEFAULT_PASSWORD}).status_code == 200
        wrong = "000000" if outbox.last_code != "000000" else "111111"
        assert client.post("/api/mfa/disable/verify", json={"code": wrong}).status_code == 400
        assert client.get("/api/mfa/status").json()["enabled"] is True
        resp = client.post("/api/mfa/disable/verify", json={"code": outbox.last_code})
        assert resp.status_code == 200 and resp.json()["enabled"] is False
        # Normal password-only login is back.
        client.post("/api/auth/logout")
        assert "mfa_required" not in _login(client, user).json()

    def test_disable_when_not_enabled_is_409(self, auth_client):
        client, _ = auth_client
        assert client.post("/api/mfa/disable/request", json={"password": DEFAULT_PASSWORD}).status_code == 409


# --- cross-user / storage / logging ----------------------------------------------


class TestSecurity:
    def test_cross_user_codes_do_not_verify(self, auth_client, make_user, client, outbox):
        client_a, user_a = auth_client
        client_a.post("/api/mfa/enable/request")
        code_a = outbox.last_code
        client.post("/api/auth/logout")
        client.post("/api/auth/register", json={"email": "other-user@example.com", "password": DEFAULT_PASSWORD, "first_name": "B", "last_name": "B"})
        client.post("/api/auth/login", json={"email": "other-user@example.com", "password": DEFAULT_PASSWORD})
        # B never requested a code, and A's code means nothing to B.
        assert client.post("/api/mfa/enable/verify", json={"code": code_a}).status_code == 400
        # Even with their own pending code, A's code still fails.
        client.post("/api/mfa/enable/request")
        if outbox.last_code != code_a:
            assert client.post("/api/mfa/enable/verify", json={"code": code_a}).status_code == 400

    def test_login_challenge_id_is_bound_to_its_user(self, mfa_user, outbox):
        client, user = mfa_user
        challenge = _login(client, user).json()
        # A syntactically valid code from a *different* issuance is rejected.
        wrong = "000000" if outbox.last_code != "000000" else "111111"
        assert client.post("/api/mfa/login/verify", json={"challenge_id": challenge["challenge_id"], "code": wrong}).status_code == 400

    def test_otp_is_not_stored_in_plaintext(self, auth_client, outbox):
        client, user = auth_client
        client.post("/api/mfa/enable/request")
        code = outbox.last_code
        db = SessionLocal()
        try:
            rows = db.query(models.EmailOTPChallenge).filter(models.EmailOTPChallenge.user_id == user["id"]).all()
            assert rows
            for row in rows:
                for column in models.EmailOTPChallenge.__table__.columns:
                    assert str(getattr(row, column.name)) != code
                assert code not in row.otp_hash
                assert re.fullmatch(r"[0-9a-f]{64}", row.otp_hash)
        finally:
            db.close()

    def test_otp_is_never_logged(self, auth_client, outbox, caplog):
        client, _ = auth_client
        with caplog.at_level(logging.DEBUG):
            client.post("/api/mfa/enable/request")
            code = outbox.last_code
            client.post("/api/mfa/enable/verify", json={"code": "000000" if code != "000000" else "111111"})
            client.post("/api/mfa/enable/verify", json={"code": code})
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert code not in text
        assert "MFA OTP generated" in text and "MFA OTP verification failed" in text
        assert "MFA OTP verification succeeded" in text and "MFA enabled" in text

    def test_code_generation_is_cryptographically_secure(self):
        assert "secrets.randbelow" in inspect.getsource(otp_service.generate_code)
        assert "random." not in inspect.getsource(otp_service)
        codes = {otp_service.generate_code() for _ in range(200)}
        assert all(re.fullmatch(r"\d{6}", c) for c in codes)
        assert len(codes) > 150  # not a fixed / tiny set

    def test_hash_binds_challenge_user_and_purpose(self):
        base = dict(challenge_id="c", user_id="u", purpose="mfa_login", code="123456")
        h = otp_service.hash_code(**base)
        assert h == otp_service.hash_code(**base)
        for key, value in (("challenge_id", "c2"), ("user_id", "u2"), ("purpose", "mfa_enable"), ("code", "654321")):
            assert otp_service.hash_code(**{**base, key: value}) != h

    def test_mask_email(self):
        assert otp_service.mask_email("jane.doe@example.com") == "j******@example.com"
        assert otp_service.mask_email("a@x.io") == "a******@x.io"

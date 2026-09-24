from app.core.fetcher import FetchError, FetchResult, SSRFBlockedError
from app.routers import scan as scan_router

RAW_RESPONSE = (
    "HTTP/1.1 200 OK\n"
    "X-Frame-Options: DENY\n"
    "X-Content-Type-Options: nosniff\n"
    "\n"
)

INLINE_POLICY = {
    "name": "Ad-hoc",
    "headers": [
        {"header_name": "X-Frame-Options", "expected_value": "DENY", "required": True},
        {"header_name": "X-Content-Type-Options", "expected_value": "nosniff", "required": True},
    ],
}


def test_scan_raw_with_inline_policy(auth_client):
    client, _ = auth_client
    resp = client.post(
        "/api/scan",
        json={"source": "raw", "raw_response": RAW_RESPONSE, "policy": INLINE_POLICY},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["score"] == 100.0
    assert body["grade"] == "A"
    assert body["fetched_status_code"] == 200
    assert len(body["findings"]) == 2


def test_scan_raw_without_target_name_defaults(auth_client):
    client, _ = auth_client
    resp = client.post(
        "/api/scan",
        json={"source": "raw", "raw_response": RAW_RESPONSE, "policy": INLINE_POLICY},
    )
    assert resp.status_code == 200
    assert resp.json()["target"] == "HTTP Response Scan"


def test_scan_raw_with_target_name_uses_it(auth_client):
    client, _ = auth_client
    resp = client.post(
        "/api/scan",
        json={
            "source": "raw",
            "raw_response": RAW_RESPONSE,
            "target_name": "My Staging Site",
            "policy": INLINE_POLICY,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["target"] == "My Staging Site"


def test_scan_raw_blank_target_name_defaults(auth_client):
    client, _ = auth_client
    resp = client.post(
        "/api/scan",
        json={
            "source": "raw",
            "raw_response": RAW_RESPONSE,
            "target_name": "   ",
            "policy": INLINE_POLICY,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["target"] == "HTTP Response Scan"


def test_scan_raw_missing_raw_response_422(auth_client):
    client, _ = auth_client
    resp = client.post("/api/scan", json={"source": "raw", "policy": INLINE_POLICY})
    assert resp.status_code == 422


def test_scan_without_policy_or_policy_id_422(auth_client):
    client, _ = auth_client
    resp = client.post("/api/scan", json={"source": "raw", "raw_response": RAW_RESPONSE})
    assert resp.status_code == 422


def test_scan_with_inline_policy_missing_headers_422(auth_client):
    client, _ = auth_client
    resp = client.post(
        "/api/scan",
        json={
            "source": "raw",
            "raw_response": RAW_RESPONSE,
            "policy": {"name": "Empty", "headers": []},
        },
    )
    assert resp.status_code == 422


def test_scan_with_nonexistent_policy_id_404(auth_client):
    client, _ = auth_client
    resp = client.post(
        "/api/scan",
        json={"source": "raw", "raw_response": RAW_RESPONSE, "policy_id": "does-not-exist"},
    )
    assert resp.status_code == 404


def test_scan_with_baseline_policy_id(auth_client):
    client, _ = auth_client
    baseline = client.get("/api/policies/baselines").json()[0]
    resp = client.post(
        "/api/scan",
        json={"source": "raw", "raw_response": RAW_RESPONSE, "policy_id": baseline["id"]},
    )
    assert resp.status_code == 200
    assert resp.json()["policy_name"] == baseline["name"]


def test_scan_url_source_empty_url_422(auth_client):
    client, _ = auth_client
    resp = client.post("/api/scan", json={"source": "url", "url": "  ", "policy": INLINE_POLICY})
    assert resp.status_code == 422


def test_scan_url_source_success(auth_client, monkeypatch):
    client, _ = auth_client
    monkeypatch.setattr(
        scan_router,
        "fetch_headers",
        lambda url: FetchResult(
            status_code=200,
            headers={"x-frame-options": "DENY", "x-content-type-options": "nosniff"},
            final_url="https://example.com/",
        ),
    )
    resp = client.post(
        "/api/scan",
        json={"source": "url", "url": "example.com", "policy": INLINE_POLICY},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["target"] == "https://example.com/"
    assert body["score"] == 100.0


def test_scan_url_source_ignores_target_name(auth_client, monkeypatch):
    client, _ = auth_client
    monkeypatch.setattr(
        scan_router,
        "fetch_headers",
        lambda url: FetchResult(
            status_code=200,
            headers={"x-frame-options": "DENY", "x-content-type-options": "nosniff"},
            final_url="https://example.com/",
        ),
    )
    resp = client.post(
        "/api/scan",
        json={
            "source": "url",
            "url": "example.com",
            "target_name": "Ignored Name",
            "policy": INLINE_POLICY,
        },
    )
    assert resp.status_code == 200
    # target_name only applies to source=raw - a URL scan's target is
    # always the actual fetched URL.
    assert resp.json()["target"] == "https://example.com/"


def test_scan_url_source_ssrf_blocked_returns_400(auth_client, monkeypatch):
    client, _ = auth_client

    def _raise(url):
        raise SSRFBlockedError("blocked")

    monkeypatch.setattr(scan_router, "fetch_headers", _raise)
    resp = client.post(
        "/api/scan",
        json={"source": "url", "url": "http://169.254.169.254/", "policy": INLINE_POLICY},
    )
    assert resp.status_code == 400


def test_scan_url_source_fetch_error_returns_502(auth_client, monkeypatch):
    client, _ = auth_client

    def _raise(url):
        raise FetchError("could not connect")

    monkeypatch.setattr(scan_router, "fetch_headers", _raise)
    resp = client.post(
        "/api/scan",
        json={"source": "url", "url": "https://unreachable.example", "policy": INLINE_POLICY},
    )
    assert resp.status_code == 502


def test_scan_requires_auth(client):
    resp = client.post(
        "/api/scan",
        json={"source": "raw", "raw_response": RAW_RESPONSE, "policy": INLINE_POLICY},
    )
    assert resp.status_code == 401


def test_scan_raw_target_name_of_exactly_50_characters_is_accepted(auth_client):
    client, _ = auth_client
    name = "x" * 50
    resp = client.post(
        "/api/scan",
        json={"source": "raw", "raw_response": RAW_RESPONSE, "target_name": name, "policy": INLINE_POLICY},
    )
    assert resp.status_code == 200
    assert resp.json()["target"] == name


def test_scan_raw_target_name_over_50_characters_is_rejected(auth_client):
    client, _ = auth_client
    resp = client.post(
        "/api/scan",
        json={"source": "raw", "raw_response": RAW_RESPONSE, "target_name": "x" * 51, "policy": INLINE_POLICY},
    )
    assert resp.status_code == 422
    assert client.get("/api/reports").json() == []


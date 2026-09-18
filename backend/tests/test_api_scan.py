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


def test_scan_raw_with_inline_policy(client):
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


def test_scan_raw_missing_raw_response_422(client):
    resp = client.post("/api/scan", json={"source": "raw", "policy": INLINE_POLICY})
    assert resp.status_code == 422


def test_scan_without_policy_or_policy_id_422(client):
    resp = client.post("/api/scan", json={"source": "raw", "raw_response": RAW_RESPONSE})
    assert resp.status_code == 422


def test_scan_with_inline_policy_missing_headers_422(client):
    resp = client.post(
        "/api/scan",
        json={
            "source": "raw",
            "raw_response": RAW_RESPONSE,
            "policy": {"name": "Empty", "headers": []},
        },
    )
    assert resp.status_code == 422


def test_scan_with_nonexistent_policy_id_404(client):
    resp = client.post(
        "/api/scan",
        json={"source": "raw", "raw_response": RAW_RESPONSE, "policy_id": "does-not-exist"},
    )
    assert resp.status_code == 404


def test_scan_with_baseline_policy_id(client):
    baseline = client.get("/api/policies/baselines").json()[0]
    resp = client.post(
        "/api/scan",
        json={"source": "raw", "raw_response": RAW_RESPONSE, "policy_id": baseline["id"]},
    )
    assert resp.status_code == 200
    assert resp.json()["policy_name"] == baseline["name"]


def test_scan_url_source_empty_url_422(client):
    resp = client.post("/api/scan", json={"source": "url", "url": "  ", "policy": INLINE_POLICY})
    assert resp.status_code == 422


def test_scan_url_source_success(client, monkeypatch):
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


def test_scan_url_source_ssrf_blocked_returns_400(client, monkeypatch):
    def _raise(url):
        raise SSRFBlockedError("blocked")

    monkeypatch.setattr(scan_router, "fetch_headers", _raise)
    resp = client.post(
        "/api/scan",
        json={"source": "url", "url": "http://169.254.169.254/", "policy": INLINE_POLICY},
    )
    assert resp.status_code == 400


def test_scan_url_source_fetch_error_returns_502(client, monkeypatch):
    def _raise(url):
        raise FetchError("could not connect")

    monkeypatch.setattr(scan_router, "fetch_headers", _raise)
    resp = client.post(
        "/api/scan",
        json={"source": "url", "url": "https://unreachable.example", "policy": INLINE_POLICY},
    )
    assert resp.status_code == 502

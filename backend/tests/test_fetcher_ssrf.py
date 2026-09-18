import socket

import pytest

from app.core import fetcher
from app.core.fetcher import FetchError, SSRFBlockedError, _is_blocked_ip, _validate_url, fetch_headers


class TestIsBlockedIp:
    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.5",
            "192.168.1.1",
            "169.254.1.1",  # link-local
            "224.0.0.1",  # multicast
            "0.0.0.0",
            "::1",  # IPv6 loopback
            "fe80::1",  # IPv6 link-local
            "::ffff:127.0.0.1",  # IPv4-mapped loopback
        ],
    )
    def test_blocked_addresses(self, ip):
        assert _is_blocked_ip(ip) is True

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
    def test_public_addresses_not_blocked(self, ip):
        assert _is_blocked_ip(ip) is False


class TestValidateUrl:
    def test_disallowed_scheme_blocked(self):
        with pytest.raises(SSRFBlockedError):
            _validate_url("ftp://example.com")

    def test_missing_hostname_blocked(self):
        with pytest.raises(SSRFBlockedError):
            _validate_url("http://")

    def test_localhost_hostname_blocked(self):
        with pytest.raises(SSRFBlockedError):
            _validate_url("http://localhost/")

    def test_metadata_hostname_blocked(self):
        with pytest.raises(SSRFBlockedError):
            _validate_url("http://metadata.google.internal/")

    def test_resolves_to_private_ip_blocked(self, monkeypatch):
        monkeypatch.setattr(
            fetcher.socket,
            "getaddrinfo",
            lambda host, port: [(socket.AF_INET, None, None, "", ("10.1.2.3", 0))],
        )
        with pytest.raises(SSRFBlockedError):
            _validate_url("http://internal.example.com/")

    def test_resolves_to_public_ip_allowed(self, monkeypatch):
        monkeypatch.setattr(
            fetcher.socket,
            "getaddrinfo",
            lambda host, port: [(socket.AF_INET, None, None, "", ("93.184.216.34", 0))],
        )
        result = _validate_url("http://example.com/")
        assert result.url == "http://example.com/"
        assert result.hostname == "example.com"
        assert result.ip == "93.184.216.34"

    def test_dns_resolution_failure_raises_fetch_error(self, monkeypatch):
        def _raise(host, port):
            raise socket.gaierror("name resolution failed")

        monkeypatch.setattr(fetcher.socket, "getaddrinfo", _raise)
        with pytest.raises(FetchError):
            _validate_url("http://does-not-exist.invalid/")


class _FakeResponse:
    def __init__(self, status_code, headers, is_redirect=False):
        self.status_code = status_code
        self.headers = headers
        self.is_redirect = is_redirect

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.last_call: dict | None = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def stream(self, method, url, **kwargs):
        self.last_call = {"method": method, "url": url, **kwargs}
        return self._responses.pop(0)


class TestFetchHeaders:
    def _allow_public_ip(self, monkeypatch):
        monkeypatch.setattr(
            fetcher.socket,
            "getaddrinfo",
            lambda host, port: [(socket.AF_INET, None, None, "", ("93.184.216.34", 0))],
        )

    def test_pins_connection_to_resolved_ip_with_host_header_and_sni(self, monkeypatch):
        self._allow_public_ip(monkeypatch)
        response = _FakeResponse(200, {})
        created: dict = {}

        def _make_client(**kw):
            created["client"] = _FakeClient([response])
            return created["client"]

        monkeypatch.setattr(fetcher.httpx, "Client", _make_client)

        fetch_headers("https://example.com/path")

        call = created["client"].last_call
        # The client must connect to the already-validated IP, never let it
        # re-resolve "example.com" itself (that's the DNS-rebinding gap).
        assert call["url"].host == "93.184.216.34"
        assert call["headers"]["Host"] == "example.com"
        assert call["extensions"]["sni_hostname"] == "example.com"

    def test_getaddrinfo_called_once_per_hop_not_reused_by_client(self, monkeypatch):
        """The whole point of pinning: after our one validated resolution,
        nothing else in fetch_headers may re-resolve the hostname."""
        call_count = {"n": 0}

        def fake_getaddrinfo(host, port):
            call_count["n"] += 1
            return [(socket.AF_INET, None, None, "", ("93.184.216.34", 0))]

        monkeypatch.setattr(fetcher.socket, "getaddrinfo", fake_getaddrinfo)
        response = _FakeResponse(200, {})
        monkeypatch.setattr(fetcher.httpx, "Client", lambda **kw: _FakeClient([response]))

        fetch_headers("https://example.com")
        assert call_count["n"] == 1

    def test_returns_lowercased_headers_on_direct_200(self, monkeypatch):
        self._allow_public_ip(monkeypatch)
        response = _FakeResponse(200, {"X-Frame-Options": "DENY"})
        monkeypatch.setattr(fetcher.httpx, "Client", lambda **kw: _FakeClient([response]))

        result = fetch_headers("https://example.com")
        assert result.status_code == 200
        assert result.headers == {"x-frame-options": "DENY"}
        assert result.final_url == "https://example.com"

    def test_follows_redirect_and_revalidates_target(self, monkeypatch):
        self._allow_public_ip(monkeypatch)
        redirect = _FakeResponse(
            301, {"location": "https://example.com/final"}, is_redirect=True
        )
        final = _FakeResponse(200, {"x-content-type-options": "nosniff"})
        monkeypatch.setattr(fetcher.httpx, "Client", lambda **kw: _FakeClient([redirect, final]))

        result = fetch_headers("https://example.com")
        assert result.status_code == 200
        assert result.final_url == "https://example.com/final"

    def test_redirect_to_private_ip_is_blocked(self, monkeypatch):
        call_count = {"n": 0}

        def fake_getaddrinfo(host, port):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return [(socket.AF_INET, None, None, "", ("93.184.216.34", 0))]
            return [(socket.AF_INET, None, None, "", ("127.0.0.1", 0))]

        monkeypatch.setattr(fetcher.socket, "getaddrinfo", fake_getaddrinfo)
        redirect = _FakeResponse(302, {"location": "http://internal.local/"}, is_redirect=True)
        monkeypatch.setattr(fetcher.httpx, "Client", lambda **kw: _FakeClient([redirect]))

        with pytest.raises(SSRFBlockedError):
            fetch_headers("https://example.com")

    def test_adds_https_scheme_when_missing(self, monkeypatch):
        self._allow_public_ip(monkeypatch)
        response = _FakeResponse(200, {})
        monkeypatch.setattr(fetcher.httpx, "Client", lambda **kw: _FakeClient([response]))

        result = fetch_headers("example.com")
        assert result.final_url == "https://example.com"

    def test_stops_after_max_redirects_without_infinite_loop(self, monkeypatch):
        self._allow_public_ip(monkeypatch)
        responses = [
            _FakeResponse(301, {"location": f"https://example.com/{i}"}, is_redirect=True)
            for i in range(fetcher.MAX_REDIRECTS + 1)
        ]
        monkeypatch.setattr(fetcher.httpx, "Client", lambda **kw: _FakeClient(responses))

        result = fetch_headers("https://example.com")
        assert result.status_code == 301

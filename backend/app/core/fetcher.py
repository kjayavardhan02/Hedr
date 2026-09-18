"""Server-side URL fetcher with basic SSRF guardrails.

Blocks requests to loopback / private / link-local / multicast / reserved
IP ranges and non-http(s) schemes. DNS is resolved once per hop and
validated, and the actual connection is pinned to that validated IP
address instead of letting the HTTP client re-resolve the hostname itself.
Without this, a very-short-TTL DNS record could resolve to a public IP
during our check and to a private one microseconds later when the HTTP
client opens its own connection (a DNS-rebinding bypass). The Host header
and TLS SNI/certificate-hostname check still use the original hostname, so
virtual hosting and certificate validation behave exactly as if we had
connected by hostname.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

ALLOWED_SCHEMES = {"http", "https"}
MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 10.0


class SSRFBlockedError(ValueError):
    pass


class FetchError(ValueError):
    pass


@dataclass
class FetchResult:
    status_code: int
    headers: dict[str, str]
    final_url: str


@dataclass
class _ValidatedTarget:
    """A URL whose hostname has already been resolved and checked, pinned
    to one specific validated IP address to connect to."""

    url: str
    hostname: str
    ip: str


def _is_blocked_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (ip.version == 6 and ip.ipv4_mapped and _is_blocked_ip(str(ip.ipv4_mapped)))
    )


def _resolve_pinned_ip(hostname: str) -> str:
    """Resolve `hostname`, reject it if ANY resolved address is blocked,
    and return one validated address to actually connect to."""
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise FetchError(f"Could not resolve host '{hostname}': {exc}") from exc

    ips: list[str] = []
    for _family, _type, _proto, _canonname, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            blocked = _is_blocked_ip(ip_str)
        except ValueError:
            raise SSRFBlockedError(f"Could not parse resolved address '{ip_str}'.")
        if blocked:
            raise SSRFBlockedError(
                f"URL resolves to a blocked/private address ({ip_str})."
            )
        ips.append(ip_str)

    if not ips:
        raise FetchError(f"Could not resolve host '{hostname}'.")
    return ips[0]


def _validate_url(url: str) -> _ValidatedTarget:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFBlockedError(
            f"URL scheme '{parsed.scheme}' is not allowed. Use http or https."
        )
    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("URL has no hostname.")
    if hostname.lower() in {"localhost", "metadata.google.internal"}:
        raise SSRFBlockedError("Requests to this host are blocked.")

    ip = _resolve_pinned_ip(hostname)
    return _ValidatedTarget(url=url, hostname=hostname, ip=ip)


def _host_header(hostname: str, port: int | None) -> str:
    return hostname if port is None else f"{hostname}:{port}"


def fetch_headers(url: str) -> FetchResult:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    target = _validate_url(url)
    redirects_left = MAX_REDIRECTS

    status_code = 0
    headers: dict[str, str] = {}

    with httpx.Client(follow_redirects=False, timeout=REQUEST_TIMEOUT) as client:
        while True:
            hostname_url = httpx.URL(target.url)
            # Connect to the already-validated IP directly - never let the
            # client re-resolve DNS for `target.hostname` itself. The Host
            # header and SNI extension keep TLS/vhost behavior identical to
            # connecting by hostname.
            pinned_url = hostname_url.copy_with(host=target.ip)
            request_headers = {"Host": _host_header(target.hostname, hostname_url.port)}
            extensions = {"sni_hostname": target.hostname}

            try:
                # Stream instead of .get() - we only ever need the headers, so
                # never buffer/download a (possibly huge) response body.
                with client.stream(
                    "GET", pinned_url, headers=request_headers, extensions=extensions
                ) as response:
                    status_code = response.status_code
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    is_redirect = response.is_redirect
                    location = response.headers.get("location")
            except httpx.ConnectError as exc:
                cause = exc.__cause__ or exc.__context__
                if isinstance(cause, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(exc):
                    reason = str(cause) if cause else str(exc)
                    if "expired" in reason.lower():
                        raise FetchError(
                            "This site's TLS certificate has expired. Hedr does not bypass "
                            "certificate validation, since doing so would defeat the purpose "
                            "of a security scan - the site owner needs to renew it."
                        ) from exc
                    raise FetchError(
                        f"This site's TLS certificate could not be verified ({reason}). "
                        "Hedr does not bypass certificate validation."
                    ) from exc
                raise FetchError(f"Could not connect: {exc}") from exc
            except httpx.HTTPError as exc:
                raise FetchError(f"Request failed: {exc}") from exc

            if is_redirect and redirects_left > 0 and location:
                next_url = str(hostname_url.join(location))
                target = _validate_url(next_url)
                redirects_left -= 1
                continue
            break

    return FetchResult(status_code=status_code, headers=headers, final_url=target.url)

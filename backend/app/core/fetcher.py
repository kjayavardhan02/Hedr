"""Server-side URL fetcher with basic SSRF guardrails.

Blocks requests to loopback / private / link-local / multicast / reserved
IP ranges and non-http(s) schemes, resolves DNS before connecting so a
hostname can't be used to bypass the IP check, and re-validates on every
redirect hop.
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


def _is_blocked_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (ip.version == 6 and ip.ipv4_mapped and _is_blocked_ip(str(ip.ipv4_mapped)))
    )


def _validate_url(url: str) -> str:
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

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise FetchError(f"Could not resolve host '{hostname}': {exc}") from exc

    for family, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            blocked = _is_blocked_ip(ip_str)
        except ValueError:
            raise SSRFBlockedError(f"Could not parse resolved address '{ip_str}'.")
        if blocked:
            raise SSRFBlockedError(
                f"URL resolves to a blocked/private address ({ip_str})."
            )
    return url


def fetch_headers(url: str) -> FetchResult:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    current_url = _validate_url(url)
    redirects_left = MAX_REDIRECTS

    with httpx.Client(follow_redirects=False, timeout=REQUEST_TIMEOUT) as client:
        while True:
            try:
                response = client.get(current_url)
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

            if response.is_redirect and redirects_left > 0:
                next_url = response.headers.get("location")
                if not next_url:
                    break
                next_url = str(httpx.URL(current_url).join(next_url))
                current_url = _validate_url(next_url)
                redirects_left -= 1
                continue
            break

    return FetchResult(
        status_code=response.status_code,
        headers={k.lower(): v for k, v in response.headers.items()},
        final_url=current_url,
    )

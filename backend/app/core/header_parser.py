"""Parses raw HTTP response text pasted by the user into a normalized
header dict, and normalizes header dicts coming back from an HTTP fetch.
"""
from __future__ import annotations

import re

_STATUS_LINE_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})")


class RawResponseParseError(ValueError):
    pass


def parse_raw_response(raw: str) -> tuple[int | None, dict[str, str]]:
    """Parse a raw HTTP response (status line + headers, body optional).

    Also tolerates input that is just a bare list of "Header: value" lines
    with no status line, since users may paste only the headers.
    """
    if not raw or not raw.strip():
        raise RawResponseParseError("Raw response text is empty.")

    # Normalize line endings, split headers from body (headers end at the
    # first blank line), and only look at the header block.
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    header_block = text.split("\n\n", 1)[0]
    lines = [line for line in header_block.split("\n") if line.strip() != ""]

    if not lines:
        raise RawResponseParseError("No headers found in input.")

    status_code: int | None = None
    start_idx = 0
    m = _STATUS_LINE_RE.match(lines[0].strip())
    if m:
        status_code = int(m.group(1))
        start_idx = 1

    headers = normalize_headers(_parse_header_lines(lines[start_idx:]))
    if not headers:
        raise RawResponseParseError("No valid 'Header: value' lines found.")
    return status_code, headers


def _parse_header_lines(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    last_key: str | None = None
    for line in lines:
        # Continuation line (obsolete folding) - starts with whitespace.
        if line[:1] in (" ", "\t") and last_key is not None:
            headers[last_key] = headers[last_key] + " " + line.strip()
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if key in headers:
            # Multiple headers with the same name (e.g. Set-Cookie) are
            # joined with a comma per HTTP semantics.
            headers[key] = headers[key] + ", " + value
        else:
            headers[key] = value
        last_key = key
    return headers


def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Lower-case header names for internal lookups while preserving the
    original casing is not required for our purposes - we standardize on
    lower-case keys everywhere internally."""
    return {k.strip().lower(): v.strip() for k, v in headers.items()}

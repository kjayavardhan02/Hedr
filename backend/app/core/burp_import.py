"""Parses a Burp Suite "Save items" HTTP-history XML export into normalized
entries, then filters/deduplicates them ahead of policy analysis.

See `Feature Docs/hedr-burp-history-import-feature.md` for the full spec.
Two principles from that spec drive this module's shape:

- Encoding is read from the export's own metadata (the `base64` attribute on
  `<request>`/`<response>`), never guessed by sniffing the content - see
  section 7 ("Do not blindly Base64-detect").
- Every entry ends up with a processing status (parsed/partial/failed/
  skipped) and, when not fully parsed, a human-readable reason - nothing is
  silently dropped (section 12).
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from enum import Enum

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from app.core.header_parser import RawResponseParseError, parse_raw_response

MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024  # 25MB

STATIC_EXTENSIONS = {
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm",
}

_WHITESPACE_RE = re.compile(r"\s+")

_MIMETYPE_HINT_MAP = {
    "html": "text/html",
    "script": "application/javascript",
    "json": "application/json",
    "xml": "application/xml",
    "css": "text/css",
}


class BurpParseError(ValueError):
    """The uploaded file isn't a supported/valid Burp history export."""


class BurpDecodeError(ValueError):
    """A single entry's request/response representation couldn't be decoded."""


class EntryStatus(str, Enum):
    PARSED = "parsed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class BurpEntryRequest:
    method: str | None = None
    url: str | None = None
    host: str | None = None
    port: int | None = None
    path: str | None = None


@dataclass
class BurpEntryResponse:
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str | None = None


@dataclass
class BurpEntry:
    # 1-based position in the original file - used for user-facing "Entry #N".
    index: int
    request: BurpEntryRequest
    response: BurpEntryResponse | None = None
    status: EntryStatus = EntryStatus.FAILED
    error: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def is_https(self) -> bool:
        return (self.request.url or "").lower().startswith("https://")


@dataclass
class BurpFilters:
    """`None` on a set field means "no filter on this dimension" - distinct
    from an empty set, which would exclude everything."""
    hosts: set[str] | None = None
    methods: set[str] | None = None  # uppercase, e.g. {"GET", "POST"}
    status_buckets: set[str] | None = None  # subset of {"2xx","3xx","4xx","5xx"}
    content_types: set[str] | None = None  # subset of {"html","json","javascript","css","images","fonts"}
    https_only: bool = False
    exclude_static: bool = False
    deduplicate: bool = True


def parse_burp_export(data: bytes) -> list[BurpEntry]:
    """Parses the whole export into normalized entries. Raises BurpParseError
    for problems with the file as a whole (not a supported format, too large,
    disallowed XML constructs); per-entry problems never raise - they're
    recorded on that entry's `status`/`error` instead."""
    if not data:
        raise BurpParseError("The file is empty.")
    if len(data) > MAX_FILE_SIZE_BYTES:
        limit_mb = MAX_FILE_SIZE_BYTES // (1024 * 1024)
        raise BurpParseError(f"File exceeds the {limit_mb}MB import limit.")

    try:
        root = SafeET.fromstring(data)
    except DefusedXmlException as exc:
        raise BurpParseError(
            "The file contains a disallowed XML construct (e.g. external entities) and was rejected."
        ) from exc
    except Exception as exc:  # noqa: BLE001 - any XML syntax error becomes one clear message
        raise BurpParseError("The file isn't valid XML - is this a Burp Suite HTTP history export?") from exc

    if root.tag != "items":
        raise BurpParseError(
            "This doesn't look like a Burp Suite HTTP history export (expected an <items> root element)."
        )

    items = root.findall("item")
    if not items:
        raise BurpParseError("No HTTP history entries found in this file.")

    return [_parse_item(index, item) for index, item in enumerate(items, start=1)]


def _text(el, tag: str) -> str | None:
    child = el.find(tag)
    if child is None or child.text is None:
        return None
    return child.text


def _parse_item(index: int, item) -> BurpEntry:
    method = _text(item, "method")
    url = _text(item, "url")
    host_el = item.find("host")
    host = host_el.text if host_el is not None else None
    port_text = _text(item, "port")
    port = int(port_text) if port_text and port_text.strip().isdigit() else None
    path = _text(item, "path")

    entry = BurpEntry(index=index, request=BurpEntryRequest(method=method, url=url, host=host, port=port, path=path))

    response_el = item.find("response")
    if response_el is None or not (response_el.text or "").strip():
        entry.status = EntryStatus.SKIPPED
        entry.error = "No HTTP response available."
        return entry

    is_base64 = (response_el.get("base64") or "").strip().lower() == "true"
    try:
        response_bytes = _decode_representation(response_el.text, is_base64)
    except BurpDecodeError as exc:
        entry.status = EntryStatus.FAILED
        entry.error = str(exc)
        return entry

    # Body is intentionally never retained past this point - only used
    # (implicitly, by parse_raw_response splitting at the first blank line)
    # to locate the end of the header block.
    response_text = response_bytes.decode("utf-8", errors="replace")
    try:
        status_code, headers = parse_raw_response(response_text)
    except RawResponseParseError as exc:
        entry.status = EntryStatus.FAILED
        entry.error = f"Unable to parse HTTP response: {exc}"
        return entry

    status_text = _text(item, "status")
    fallback_status = int(status_text) if status_text and status_text.strip().isdigit() else None
    final_status_code = status_code if status_code is not None else fallback_status

    partial = final_status_code is None
    if partial:
        entry.warnings.append("Status code could not be determined; response headers were still extracted.")

    content_type = headers.get("content-type") or _mimetype_hint_to_content_type(_text(item, "mimetype"))

    entry.response = BurpEntryResponse(status_code=final_status_code, headers=headers, content_type=content_type)
    entry.status = EntryStatus.PARTIAL if partial else EntryStatus.PARSED
    return entry


def _decode_representation(raw_text: str, is_base64: bool) -> bytes:
    if not is_base64:
        return raw_text.encode("utf-8", errors="replace")
    # Burp wraps long Base64 blobs across lines - strip whitespace before
    # validating, so line breaks aren't mistaken for corruption.
    cleaned = _WHITESPACE_RE.sub("", raw_text)
    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BurpDecodeError("Unable to decode Base64-encoded HTTP response.") from exc


def _mimetype_hint_to_content_type(hint: str | None) -> str | None:
    """Burp's own coarse `<mimetype>` field (e.g. "HTML", "script", "JSON"),
    used only as a fallback when the response has no Content-Type header."""
    if not hint:
        return None
    key = hint.strip().lower()
    if key.startswith("image"):
        return "image/*"
    return _MIMETYPE_HINT_MAP.get(key)


def _status_bucket(status_code: int | None) -> str | None:
    if status_code is None:
        return None
    return f"{status_code // 100}xx"


def _content_type_bucket(content_type: str | None) -> str | None:
    if not content_type:
        return None
    ct = content_type.split(";", 1)[0].strip().lower()
    if ct == "text/html":
        return "html"
    if ct == "application/json":
        return "json"
    if ct in ("application/javascript", "text/javascript"):
        return "javascript"
    if ct == "text/css":
        return "css"
    if ct.startswith("image/"):
        return "images"
    if ct.startswith("font/") or ct in ("application/font-woff", "application/font-woff2"):
        return "fonts"
    return None


def _looks_static(entry: BurpEntry) -> bool:
    content_type = entry.response.content_type if entry.response else None
    if _content_type_bucket(content_type) in ("images", "fonts", "css", "javascript"):
        return True
    path = (entry.request.path or "").lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


def _filter_exclusion_reason(entry: BurpEntry, filters: BurpFilters) -> str | None:
    if filters.https_only and not entry.is_https:
        return "Excluded: HTTPS-only filter."
    if filters.hosts is not None and (entry.request.host or "") not in filters.hosts:
        return "Excluded by host filter."
    if filters.methods is not None and (entry.request.method or "").upper() not in filters.methods:
        return "Excluded by method filter."
    status_code = entry.response.status_code if entry.response else None
    if filters.status_buckets is not None:
        bucket = _status_bucket(status_code)
        if bucket is None or bucket not in filters.status_buckets:
            return "Excluded by status-code filter."
    if filters.exclude_static and _looks_static(entry):
        return "Excluded: static resource."
    if filters.content_types is not None:
        content_type = entry.response.content_type if entry.response else None
        bucket = _content_type_bucket(content_type)
        if bucket is None or bucket not in filters.content_types:
            return "Excluded by content-type filter."
    return None


def _normalize_headers_for_identity(headers: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((k.lower(), v.strip()) for k, v in headers.items()))


def _dedup_key(entry: BurpEntry) -> tuple:
    method = (entry.request.method or "").upper()
    url = entry.request.url or ""
    status_code = entry.response.status_code if entry.response else None
    headers_key = _normalize_headers_for_identity(entry.response.headers) if entry.response else ()
    return (method, url, status_code, headers_key)


def _mark_duplicates(entries: list[BurpEntry]) -> None:
    seen: set[tuple] = set()
    for entry in entries:
        if entry.status not in (EntryStatus.PARSED, EntryStatus.PARTIAL):
            continue
        key = _dedup_key(entry)
        if key in seen:
            entry.status = EntryStatus.SKIPPED
            entry.error = "Excluded: duplicate of an earlier identical response."
        else:
            seen.add(key)


def apply_filters(entries: list[BurpEntry], filters: BurpFilters) -> list[BurpEntry]:
    """Mutates entries excluded by a filter to status=SKIPPED with a reason,
    and returns the same list in the same order - every entry stays visible
    for the Import Issues view. Callers select the survivors with
    `entry.status in (EntryStatus.PARSED, EntryStatus.PARTIAL)`."""
    for entry in entries:
        if entry.status not in (EntryStatus.PARSED, EntryStatus.PARTIAL):
            continue
        reason = _filter_exclusion_reason(entry, filters)
        if reason:
            entry.status = EntryStatus.SKIPPED
            entry.error = reason
    if filters.deduplicate:
        _mark_duplicates(entries)
    return entries


def entry_to_dict(entry: BurpEntry) -> dict:
    """JSON-safe representation for BurpImport.parsed_entries - round-trips
    through entry_from_dict so /analyze can re-filter/re-score without
    re-uploading the file."""
    return {
        "index": entry.index,
        "request": {
            "method": entry.request.method,
            "url": entry.request.url,
            "host": entry.request.host,
            "port": entry.request.port,
            "path": entry.request.path,
        },
        "response": (
            {
                "status_code": entry.response.status_code,
                "headers": entry.response.headers,
                "content_type": entry.response.content_type,
            }
            if entry.response is not None
            else None
        ),
        "status": entry.status.value,
        "error": entry.error,
        "warnings": entry.warnings,
    }


def entry_from_dict(data: dict) -> BurpEntry:
    response_data = data.get("response")
    return BurpEntry(
        index=data["index"],
        request=BurpEntryRequest(**data["request"]),
        response=BurpEntryResponse(**response_data) if response_data else None,
        status=EntryStatus(data["status"]),
        error=data.get("error"),
        warnings=list(data.get("warnings") or []),
    )


def discover_facets(entries: list[BurpEntry]) -> dict[str, list[str]]:
    """Distinct hosts/methods/status-buckets/content-type-buckets seen across
    the entries that actually parsed - used to render filter checkboxes
    without the frontend guessing what's in the file."""
    hosts: set[str] = set()
    methods: set[str] = set()
    status_buckets: set[str] = set()
    content_types: set[str] = set()

    for entry in entries:
        if entry.status not in (EntryStatus.PARSED, EntryStatus.PARTIAL):
            continue
        if entry.request.host:
            hosts.add(entry.request.host)
        if entry.request.method:
            methods.add(entry.request.method.upper())
        bucket = _status_bucket(entry.response.status_code if entry.response else None)
        if bucket:
            status_buckets.add(bucket)
        content_bucket = _content_type_bucket(entry.response.content_type if entry.response else None)
        if content_bucket:
            content_types.add(content_bucket)

    return {
        "hosts": sorted(hosts),
        "methods": sorted(methods),
        "status_buckets": sorted(status_buckets),
        "content_types": sorted(content_types),
    }

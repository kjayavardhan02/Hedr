import base64

import pytest

from app.core.burp_import import (
    BurpFilters,
    BurpParseError,
    EntryStatus,
    apply_filters,
    parse_burp_export,
)

RAW_RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Strict-Transport-Security: max-age=31536000\r\n"
    "\r\n"
    "<html>body</html>"
)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _items_xml(*items: str) -> bytes:
    return ("<?xml version=\"1.0\"?>\n<items>" + "".join(items) + "</items>").encode()


def _item(
    *,
    method: str = "GET",
    url: str = "https://example.com/path",
    host: str = "example.com",
    port: str = "443",
    path: str = "/path",
    status: str = "200",
    mimetype: str = "HTML",
    response: str | None = RAW_RESPONSE,
    response_base64: bool = True,
    include_response_tag: bool = True,
) -> str:
    response_tag = ""
    if include_response_tag:
        value = _b64(response) if (response_base64 and response is not None) else (response or "")
        base64_attr = "true" if response_base64 else "false"
        response_tag = f'<response base64="{base64_attr}">{value}</response>'
    return (
        "<item>"
        f"<url><![CDATA[{url}]]></url>"
        f"<host ip=\"1.2.3.4\">{host}</host>"
        f"<port>{port}</port>"
        f"<method>{method}</method>"
        f"<path><![CDATA[{path}]]></path>"
        f"<status>{status}</status>"
        f"<mimetype>{mimetype}</mimetype>"
        f"{response_tag}"
        "</item>"
    )


class TestParseBurpExport:
    def test_parses_base64_response(self):
        entries = parse_burp_export(_items_xml(_item()))
        assert len(entries) == 1
        entry = entries[0]
        assert entry.status == EntryStatus.PARSED
        assert entry.request.method == "GET"
        assert entry.request.host == "example.com"
        assert entry.response.status_code == 200
        # Header names are normalized to lower-case internally.
        assert entry.response.headers["content-type"] == "text/html"
        assert entry.response.headers["strict-transport-security"] == "max-age=31536000"

    def test_parses_plain_non_base64_response(self):
        entries = parse_burp_export(_items_xml(_item(response_base64=False, response=RAW_RESPONSE)))
        assert entries[0].status == EntryStatus.PARSED
        assert entries[0].response.headers["content-type"] == "text/html"

    def test_missing_response_element_is_skipped(self):
        entries = parse_burp_export(_items_xml(_item(include_response_tag=False)))
        assert entries[0].status == EntryStatus.SKIPPED
        assert "No HTTP response" in entries[0].error

    def test_empty_response_element_is_skipped(self):
        entries = parse_burp_export(_items_xml(_item(response=None, response_base64=False)))
        assert entries[0].status == EntryStatus.SKIPPED

    def test_malformed_base64_marks_entry_failed_without_crashing(self):
        xml = _items_xml(_item(), '<item><response base64="true">not-valid-base64!!!</response></item>')
        entries = parse_burp_export(xml)
        assert entries[0].status == EntryStatus.PARSED
        assert entries[1].status == EntryStatus.FAILED
        assert "decode" in entries[1].error.lower()

    def test_unparseable_http_response_marks_entry_failed(self):
        entries = parse_burp_export(_items_xml(_item(response="not an http response at all", response_base64=False)))
        assert entries[0].status == EntryStatus.FAILED

    def test_content_type_falls_back_to_mimetype_hint(self):
        raw_no_ct = "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\nbody"
        entries = parse_burp_export(_items_xml(_item(response=raw_no_ct, mimetype="JSON")))
        assert entries[0].response.content_type == "application/json"

    def test_empty_file_raises(self):
        with pytest.raises(BurpParseError):
            parse_burp_export(b"")

    def test_invalid_xml_raises(self):
        with pytest.raises(BurpParseError):
            parse_burp_export(b"not xml at all")

    def test_wrong_root_element_raises(self):
        with pytest.raises(BurpParseError):
            parse_burp_export(b"<?xml version=\"1.0\"?><notitems></notitems>")

    def test_no_items_raises(self):
        with pytest.raises(BurpParseError):
            parse_burp_export(b"<?xml version=\"1.0\"?><items></items>")

    def test_oversized_file_raises(self, monkeypatch):
        import app.core.burp_import as burp_import

        monkeypatch.setattr(burp_import, "MAX_FILE_SIZE_BYTES", 10)
        with pytest.raises(BurpParseError):
            parse_burp_export(_items_xml(_item()))

    def test_xxe_external_entity_is_rejected_not_resolved(self):
        malicious = (
            b'<?xml version="1.0"?>'
            b'<!DOCTYPE items [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            b"<items><item><url>&xxe;</url></item></items>"
        )
        with pytest.raises(BurpParseError):
            parse_burp_export(malicious)


class TestApplyFilters:
    def _entries(self):
        not_found = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<html/>"
        return parse_burp_export(
            _items_xml(
                _item(method="GET", url="https://example.com/a", host="example.com"),
                _item(
                    method="POST",
                    url="http://other.com/b",
                    host="other.com",
                    response=not_found,
                    response_base64=False,
                ),
            )
        )

    def test_host_filter_excludes_non_matching(self):
        entries = self._entries()
        apply_filters(entries, BurpFilters(hosts={"example.com"}, deduplicate=False))
        assert entries[0].status == EntryStatus.PARSED
        assert entries[1].status == EntryStatus.SKIPPED

    def test_https_only_filter(self):
        entries = self._entries()
        apply_filters(entries, BurpFilters(https_only=True, deduplicate=False))
        assert entries[0].status == EntryStatus.PARSED
        assert entries[1].status == EntryStatus.SKIPPED

    def test_status_bucket_filter(self):
        entries = self._entries()
        apply_filters(entries, BurpFilters(status_buckets={"2xx"}, deduplicate=False))
        assert entries[0].status == EntryStatus.PARSED
        assert entries[1].status == EntryStatus.SKIPPED

    def test_method_filter(self):
        entries = self._entries()
        apply_filters(entries, BurpFilters(methods={"GET"}, deduplicate=False))
        assert entries[0].status == EntryStatus.PARSED
        assert entries[1].status == EntryStatus.SKIPPED

    def test_content_type_filter_and_exclude_static(self):
        css_response = "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\nbody{}"
        entries = parse_burp_export(
            _items_xml(
                _item(response=RAW_RESPONSE, path="/page.html"),
                _item(response=css_response, response_base64=False, path="/style.css"),
            )
        )
        apply_filters(entries, BurpFilters(exclude_static=True, deduplicate=False))
        assert entries[0].status == EntryStatus.PARSED
        assert entries[1].status == EntryStatus.SKIPPED
        assert "static" in entries[1].error.lower()

    def test_deduplicates_identical_responses(self):
        entries = parse_burp_export(_items_xml(_item(), _item()))
        apply_filters(entries, BurpFilters(deduplicate=True))
        assert entries[0].status == EntryStatus.PARSED
        assert entries[1].status == EntryStatus.SKIPPED
        assert "duplicate" in entries[1].error.lower()

    def test_does_not_deduplicate_when_headers_differ(self):
        other_response = (
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Security-Policy: default-src 'self'\r\n\r\n<html/>"
        )
        entries = parse_burp_export(
            _items_xml(_item(response=RAW_RESPONSE), _item(response=other_response, response_base64=False))
        )
        apply_filters(entries, BurpFilters(deduplicate=True))
        assert entries[0].status == EntryStatus.PARSED
        assert entries[1].status == EntryStatus.PARSED

    def test_deduplicate_false_leaves_duplicates(self):
        entries = parse_burp_export(_items_xml(_item(), _item()))
        apply_filters(entries, BurpFilters(deduplicate=False))
        assert entries[0].status == EntryStatus.PARSED
        assert entries[1].status == EntryStatus.PARSED

    def test_never_touches_already_failed_or_skipped_entries(self):
        entries = parse_burp_export(_items_xml(_item(include_response_tag=False), _item()))
        apply_filters(entries, BurpFilters(hosts={"nomatch.com"}, deduplicate=False))
        # Entry 0 was already SKIPPED (no response) for its own reason -
        # filtering must not overwrite that with a filter-exclusion reason.
        assert entries[0].status == EntryStatus.SKIPPED
        assert "No HTTP response" in entries[0].error

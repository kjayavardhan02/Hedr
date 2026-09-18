import pytest

from app.core.header_parser import RawResponseParseError, normalize_headers, parse_raw_response


def test_parses_status_line_and_headers_with_body():
    raw = (
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/html\n"
        "X-Frame-Options: DENY\n"
        "\n"
        "<html>ignored body</html>"
    )
    status, headers = parse_raw_response(raw)
    assert status == 200
    assert headers == {"content-type": "text/html", "x-frame-options": "DENY"}


def test_bare_header_lines_without_status_line():
    raw = "Content-Type: text/html\nX-Content-Type-Options: nosniff\n"
    status, headers = parse_raw_response(raw)
    assert status is None
    assert headers["x-content-type-options"] == "nosniff"


def test_crlf_line_endings_are_normalized():
    raw = "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\n"
    status, headers = parse_raw_response(raw)
    assert status == 200
    assert headers["x-frame-options"] == "DENY"


def test_empty_input_raises():
    with pytest.raises(RawResponseParseError):
        parse_raw_response("")
    with pytest.raises(RawResponseParseError):
        parse_raw_response("   \n  ")


def test_no_valid_header_lines_raises():
    with pytest.raises(RawResponseParseError):
        parse_raw_response("HTTP/1.1 200 OK\njust some text with no colon\n")


def test_obsolete_line_folding_continuation():
    raw = "X-Custom: first-part\n continued-part\nY-Header: value\n"
    _, headers = parse_raw_response(raw)
    assert headers["x-custom"] == "first-part continued-part"


def test_duplicate_headers_joined_with_comma():
    raw = "Set-Cookie: a=1\nSet-Cookie: b=2\n"
    _, headers = parse_raw_response(raw)
    assert headers["set-cookie"] == "a=1, b=2"


def test_status_line_requires_http_prefix():
    raw = "GET / HTTP/1.1\nHost: example.com\n"
    status, headers = parse_raw_response(raw)
    assert status is None
    assert headers["host"] == "example.com"


def test_normalize_headers_lowercases_keys_and_strips():
    result = normalize_headers({" X-Foo ": " bar "})
    assert result == {"x-foo": "bar"}

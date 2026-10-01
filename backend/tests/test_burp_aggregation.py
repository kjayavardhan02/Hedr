from app.core.burp_aggregation import build_analysis
from app.core.burp_import import BurpEntry, BurpEntryRequest, BurpEntryResponse, EntryStatus
from app.core.policy_resolution import ResolvedPolicy
from app.schemas import CSPPolicy, PolicyHeaderIn


def _entry(
    index: int,
    *,
    url: str,
    host: str,
    path: str = "/",
    method: str = "GET",
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    content_type: str = "text/html",
    entry_status: EntryStatus = EntryStatus.PARSED,
    error: str | None = None,
) -> BurpEntry:
    request = BurpEntryRequest(method=method, url=url, host=host, port=443, path=path)
    response = None
    if entry_status in (EntryStatus.PARSED, EntryStatus.PARTIAL):
        response = BurpEntryResponse(status_code=status_code, headers=headers or {}, content_type=content_type)
    return BurpEntry(index=index, request=request, response=response, status=entry_status, error=error)


def _policy(headers: list[PolicyHeaderIn], csp_policy: CSPPolicy | None = None) -> ResolvedPolicy:
    return ResolvedPolicy(
        policy=None,  # type: ignore[arg-type]  - unused by the aggregation layer
        policy_headers=headers,
        policy_name="Test Policy",
        policy_version="v1",
        csp_policy=csp_policy,
    )


HSTS_HEADER = PolicyHeaderIn(header_name="Strict-Transport-Security", expected_value="max-age=31536000", required=True)
XFO_HEADER = PolicyHeaderIn(header_name="X-Frame-Options", expected_value="DENY", required=True)


def test_all_headers_present_and_compliant():
    entry = _entry(
        1,
        url="https://example.com/",
        host="example.com",
        headers={
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
        },
    )
    result = build_analysis([entry], _policy([HSTS_HEADER, XFO_HEADER]))

    assert result.summary.responses_analyzed == 1
    assert result.summary.unique_hosts == 1
    assert result.summary.overall_score == 100.0
    assert result.summary.responses_with_findings == 0
    assert result.endpoints[0].policy_score == 100.0
    assert {hr.header: hr.status for hr in result.endpoints[0].header_results} == {
        "Strict-Transport-Security": "present",
        "X-Frame-Options": "present",
    }
    assert result.findings == []
    assert result.inconsistencies == []


def test_missing_required_header_becomes_a_finding():
    entry = _entry(1, url="https://example.com/", host="example.com", headers={})
    result = build_analysis([entry], _policy([HSTS_HEADER]))

    assert result.summary.responses_with_findings == 1
    assert result.endpoints[0].header_results[0].status == "missing"
    assert len(result.findings) == 1
    assert result.findings[0].header == "Strict-Transport-Security"
    assert result.findings[0].status == "missing"
    assert result.findings[0].affected_count == 1
    assert result.findings[0].affected_endpoints == ["example.com/"]


def test_hsts_not_applicable_over_plain_http():
    entry = _entry(1, url="http://example.com/", host="example.com", headers={})
    result = build_analysis([entry], _policy([HSTS_HEADER]))

    assert result.endpoints[0].header_results[0].status == "not_applicable"
    # Not-applicable never becomes a finding, and never counts toward coverage's denominator.
    assert result.findings == []
    coverage = result.header_coverage[0]
    assert coverage.not_applicable == 1
    assert coverage.present == 0
    assert coverage.missing == 0
    assert coverage.coverage == 0.0


def test_header_coverage_percentage():
    e1 = _entry(1, url="https://a.com/", host="a.com", headers={"strict-transport-security": "max-age=31536000"})
    e2 = _entry(2, url="https://b.com/", host="b.com", headers={})
    result = build_analysis([e1, e2], _policy([HSTS_HEADER]))

    coverage = result.header_coverage[0]
    assert coverage.present == 1
    assert coverage.missing == 1
    assert coverage.coverage == 50.0


def test_host_summary_groups_and_averages():
    e1 = _entry(1, url="https://a.com/x", host="a.com", path="/x", headers={"strict-transport-security": "max-age=31536000"})
    e2 = _entry(2, url="https://a.com/y", host="a.com", path="/y", headers={})
    e3 = _entry(3, url="https://b.com/", host="b.com", headers={"strict-transport-security": "max-age=31536000"})
    result = build_analysis([e1, e2, e3], _policy([HSTS_HEADER]))

    by_host = {row.host: row for row in result.host_summary}
    assert by_host["a.com"].responses == 2
    assert by_host["a.com"].unique_paths == 2
    assert by_host["a.com"].score == 50.0  # (100 + 0) / 2
    assert by_host["b.com"].responses == 1
    assert by_host["b.com"].score == 100.0


def test_inconsistency_detection_across_distinct_values():
    e1 = _entry(1, url="https://a.com/", host="a.com", headers={"strict-transport-security": "max-age=31536000"})
    e2 = _entry(2, url="https://b.com/", host="b.com", headers={"strict-transport-security": "max-age=86400"})
    e3 = _entry(3, url="https://c.com/", host="c.com", headers={})
    result = build_analysis([e1, e2, e3], _policy([HSTS_HEADER]))

    assert len(result.inconsistencies) == 1
    inconsistency = result.inconsistencies[0]
    assert inconsistency.header == "Strict-Transport-Security"
    values = {c.value: c.count for c in inconsistency.configurations}
    assert values == {"max-age=31536000": 1, "max-age=86400": 1, "(missing)": 1}


def test_no_inconsistency_when_uniform():
    e1 = _entry(1, url="https://a.com/", host="a.com", headers={"strict-transport-security": "max-age=31536000"})
    e2 = _entry(2, url="https://b.com/", host="b.com", headers={"strict-transport-security": "max-age=31536000"})
    result = build_analysis([e1, e2], _policy([HSTS_HEADER]))
    assert result.inconsistencies == []


def test_csp_present_when_policy_rules_satisfied_despite_best_practice_advisories():
    entry = _entry(
        1,
        url="https://example.com/",
        host="example.com",
        headers={"content-security-policy": "default-src 'self'"},
        content_type="text/html",
    )
    result = build_analysis([entry], _policy([], csp_policy=CSPPolicy(required=True)))
    csp_result = next(hr for hr in result.endpoints[0].header_results if hr.header == "Content-Security-Policy")
    assert csp_result.status == "present"


def test_csp_not_applicable_on_json_response():
    entry = _entry(
        1,
        url="https://example.com/api",
        host="example.com",
        headers={},
        content_type="application/json",
    )
    result = build_analysis([entry], _policy([], csp_policy=CSPPolicy(required=True)))
    csp_result = next(hr for hr in result.endpoints[0].header_results if hr.header == "Content-Security-Policy")
    assert csp_result.status == "not_applicable"


def test_failed_and_skipped_entries_become_import_issues_not_endpoints():
    good = _entry(1, url="https://a.com/", host="a.com", headers={})
    failed = _entry(2, url="https://b.com/", host="b.com", entry_status=EntryStatus.FAILED, error="Unable to decode.")
    skipped = _entry(3, url="https://c.com/", host="c.com", entry_status=EntryStatus.SKIPPED, error="Excluded by filter.")

    result = build_analysis([good, failed, skipped], _policy([HSTS_HEADER]))

    assert len(result.endpoints) == 1
    assert result.summary.responses_analyzed == 1
    assert len(result.import_issues) == 2
    issues_by_index = {issue.index: issue for issue in result.import_issues}
    assert issues_by_index[2].status == "failed"
    assert issues_by_index[2].reason == "Unable to decode."
    assert issues_by_index[3].status == "skipped"


def test_empty_survivor_list_gives_zeroed_summary_not_a_crash():
    failed = _entry(1, url="https://a.com/", host="a.com", entry_status=EntryStatus.FAILED, error="oops")
    result = build_analysis([failed], _policy([HSTS_HEADER]))
    assert result.summary.responses_analyzed == 0
    assert result.summary.overall_score == 0.0
    assert result.endpoints == []
    assert result.host_summary == []


# --- Target type & applicability ------------------------------------------


def test_rest_api_target_type_marks_browser_headers_na_and_keeps_them_out_of_the_score():
    from app.schemas import TargetType

    entry = _entry(
        1,
        url="https://api.example.com/users",
        host="api.example.com",
        content_type="application/json",
        headers={"strict-transport-security": "max-age=31536000"},
    )
    policy = _policy([HSTS_HEADER, XFO_HEADER])

    web = build_analysis([entry], policy, TargetType.WEB_APPLICATION)
    api = build_analysis([entry], policy, TargetType.REST_API)

    # Same response: as a web app the missing X-Frame-Options is a finding...
    assert web.endpoints[0].policy_score < 100.0
    # ...as a REST API it is N/A, so the endpoint scores 100 on what applies.
    assert api.target_type == TargetType.REST_API
    assert api.endpoints[0].policy_score == 100.0
    assert api.endpoints[0].has_findings is False
    xfo = next(hr for hr in api.endpoints[0].header_results if hr.header == "X-Frame-Options")
    assert xfo.status == "not_applicable"
    assert xfo.applicability_reason
    assert xfo.severity is None
    assert api.findings == []
    assert api.summary.checks.model_dump() == {"applicable": 1, "passed": 1, "failed": 0, "not_applicable": 1}
    coverage = next(c for c in api.header_coverage if c.header == "X-Frame-Options")
    assert (coverage.present, coverage.missing, coverage.not_applicable) == (0, 0, 1)


def test_burp_defaults_to_web_application_target_type():
    from app.schemas import TargetType

    entry = _entry(1, url="https://example.com/", host="example.com", headers={})
    assert build_analysis([entry], _policy([XFO_HEADER])).target_type == TargetType.WEB_APPLICATION

"""Runs each surviving Burp entry through the existing policy engine and
rolls the per-response results up into one normalized analysis result.

This is the layer the spec calls the "Aggregation Layer" (see
hedr-burp-history-import-feature.md section 36) - it is deliberately the
*only* place that knows about hosts, coverage, or inconsistencies. Nothing
in app.core.policy_engine changes: every entry is scored by the exact same
run_scan() a normal URL/raw scan uses.
"""
from __future__ import annotations

from collections import defaultdict

from app.core.applicability import DEFAULT_TARGET_TYPE
from app.core.burp_import import BurpEntry, EntryStatus
from app.core.policy_engine import run_scan
from app.core.policy_resolution import ResolvedPolicy
from app.core.scoring import get_severity
from app.schemas import (
    BurpAnalysisResult,
    BurpAnalysisSummaryOut,
    EndpointAnalysisOut,
    FindingGroupOut,
    HeaderCoverageRow,
    HeaderInconsistencyOut,
    HeaderResultOut,
    HostSummaryRow,
    ImportIssueOut,
    InconsistencyConfigOut,
    ScanSource,
    ScoreBreakdown,
    TargetType,
)

CSP_HEADER_NAME = "Content-Security-Policy"

# How many affected-endpoint identifiers to embed directly in a findings/
# inconsistency group. The group's own count field always reflects the true
# total, so large findings are never lied about - just not fully inlined.
MAX_AFFECTED_ENDPOINTS_PREVIEW = 50

_MISSING_CONFIG_LABEL = "(missing)"


def _classify(*, present: bool, ok: bool, applicable: bool) -> str:
    if not applicable:
        return "not_applicable"
    if not present:
        return "missing"
    return "present" if ok else "invalid"


def _endpoint_label(domain: str, path: str) -> str:
    return f"{domain}{path}"


def _build_header_results(scan_result, resolved_policy: ResolvedPolicy) -> list[HeaderResultOut]:
    """One result per policy header, read straight from the scan's findings -
    applicability was already decided once, centrally, by the policy engine
    (see app.core.applicability), so Burp has no applicability rules of its own."""
    results: list[HeaderResultOut] = []
    findings_by_name = {f.header.lower(): f for f in scan_result.findings}

    for policy_header in resolved_policy.policy_headers:
        finding = findings_by_name.get(policy_header.header_name.lower())
        if finding is None:
            continue
        status = _classify(
            present=finding.present, ok=finding.status == "PASS", applicable=finding.applicable
        )
        results.append(
            HeaderResultOut(
                header=finding.header,
                status=status,
                applicability_reason=finding.applicability_reason,
                actual_value=finding.actual_value,
                expected_value=policy_header.expected_value or None,
                severity=finding.severity,
            )
        )

    if resolved_policy.csp_policy is not None:
        csp = scan_result.csp_finding
        reason = None
        if csp is None:
            status = "missing"
            actual_value = None
        elif not csp.applicable:
            status = "not_applicable"
            reason = csp.applicability_reason
            actual_value = csp.actual_value
        else:
            # Judge "ok" purely on policy-rule compliance, not the blended
            # overall_score - a CSP that satisfies the policy but trips a
            # best-practice advisory (e.g. an 'unsafe-inline' warning) is
            # still POLICY-compliant, which is what Invalid vs Present means
            # here.
            policy_ok = csp.policy_checks_passed == csp.policy_checks_total
            status = _classify(present=csp.present, ok=policy_ok, applicable=True)
            actual_value = csp.actual_value
        results.append(
            HeaderResultOut(
                header=CSP_HEADER_NAME,
                status=status,
                applicability_reason=reason,
                actual_value=actual_value,
                expected_value=None,
                severity=None if status == "not_applicable" else get_severity(CSP_HEADER_NAME),
            )
        )

    return results


def build_analysis(
    entries: list[BurpEntry],
    resolved_policy: ResolvedPolicy,
    target_type: TargetType = DEFAULT_TARGET_TYPE,
) -> BurpAnalysisResult:
    survivors = [e for e in entries if e.status in (EntryStatus.PARSED, EntryStatus.PARTIAL)]
    issues = [e for e in entries if e.status in (EntryStatus.FAILED, EntryStatus.SKIPPED)]

    endpoints: list[EndpointAnalysisOut] = []
    for entry in survivors:
        raw_headers = entry.response.headers
        scan_result = run_scan(
            raw_headers=raw_headers,
            policy_name=resolved_policy.policy_name,
            policy_headers=resolved_policy.policy_headers,
            source=ScanSource.burp,
            target=entry.request.url,
            fetched_status_code=entry.response.status_code,
            csp_policy=resolved_policy.csp_policy,
            target_url=None,
            target_type=target_type,
            is_https=entry.is_https,
            content_type=entry.response.content_type,
        )
        header_results = _build_header_results(scan_result, resolved_policy)
        has_findings = any(hr.status in ("missing", "invalid") for hr in header_results)
        endpoints.append(
            EndpointAnalysisOut(
                domain=entry.request.host or "",
                path=entry.request.path or "/",
                raw_url=entry.request.url or "",
                method=(entry.request.method or "").upper(),
                status_code=entry.response.status_code,
                content_type=entry.response.content_type,
                header_results=header_results,
                policy_score=scan_result.score,
                has_findings=has_findings,
            )
        )

    summary = _build_summary(endpoints)
    host_summary = _build_host_summary(endpoints)
    header_coverage = _build_header_coverage(endpoints)
    findings = _build_findings(endpoints)
    inconsistencies = _build_inconsistencies(endpoints)
    import_issues = _build_import_issues(issues)

    return BurpAnalysisResult(
        target_type=target_type,
        summary=summary,
        host_summary=host_summary,
        header_coverage=header_coverage,
        findings=findings,
        inconsistencies=inconsistencies,
        endpoints=endpoints,
        import_issues=import_issues,
    )


def _build_summary(endpoints: list[EndpointAnalysisOut]) -> BurpAnalysisSummaryOut:
    unique_hosts = {e.domain for e in endpoints}
    unique_paths = {(e.domain, e.path) for e in endpoints}
    overall_score = round(sum(e.policy_score for e in endpoints) / len(endpoints), 1) if endpoints else 0.0
    responses_with_findings = sum(1 for e in endpoints if e.has_findings)

    severity_counts: dict[str, int] = defaultdict(int)
    for endpoint in endpoints:
        for hr in endpoint.header_results:
            if hr.status in ("missing", "invalid") and hr.severity:
                severity_counts[hr.severity] += 1

    statuses = [hr.status for e in endpoints for hr in e.header_results]
    passed = statuses.count("present")
    failed = statuses.count("missing") + statuses.count("invalid")
    checks = ScoreBreakdown(
        applicable=passed + failed,
        passed=passed,
        failed=failed,
        not_applicable=statuses.count("not_applicable"),
    )

    return BurpAnalysisSummaryOut(
        checks=checks,
        responses_analyzed=len(endpoints),
        unique_hosts=len(unique_hosts),
        unique_paths=len(unique_paths),
        overall_score=overall_score,
        responses_with_findings=responses_with_findings,
        severity_counts=dict(severity_counts),
    )


def _build_host_summary(endpoints: list[EndpointAnalysisOut]) -> list[HostSummaryRow]:
    by_host: dict[str, list[EndpointAnalysisOut]] = defaultdict(list)
    for endpoint in endpoints:
        by_host[endpoint.domain].append(endpoint)

    rows = [
        HostSummaryRow(
            host=host,
            responses=len(group),
            unique_paths=len({e.path for e in group}),
            score=round(sum(e.policy_score for e in group) / len(group), 1),
        )
        for host, group in by_host.items()
    ]
    rows.sort(key=lambda r: r.responses, reverse=True)
    return rows


def _build_header_coverage(endpoints: list[EndpointAnalysisOut]) -> list[HeaderCoverageRow]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"present": 0, "missing": 0, "invalid": 0, "not_applicable": 0})
    for endpoint in endpoints:
        for hr in endpoint.header_results:
            counts[hr.header][hr.status] += 1

    rows: list[HeaderCoverageRow] = []
    for header, tally in counts.items():
        applicable_total = tally["present"] + tally["missing"] + tally["invalid"]
        coverage = round(tally["present"] / applicable_total * 100, 1) if applicable_total else 0.0
        rows.append(
            HeaderCoverageRow(
                header=header,
                present=tally["present"],
                missing=tally["missing"],
                invalid=tally["invalid"],
                not_applicable=tally["not_applicable"],
                coverage=coverage,
            )
        )
    rows.sort(key=lambda r: r.header)
    return rows


def _build_findings(endpoints: list[EndpointAnalysisOut]) -> list[FindingGroupOut]:
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    severities: dict[tuple[str, str], str] = {}
    for endpoint in endpoints:
        label = _endpoint_label(endpoint.domain, endpoint.path)
        for hr in endpoint.header_results:
            if hr.status not in ("missing", "invalid"):
                continue
            key = (hr.header, hr.status)
            groups[key].append(label)
            severities[key] = hr.severity or "medium"

    results = [
        FindingGroupOut(
            header=header,
            status=status,  # type: ignore[arg-type]
            severity=severities[(header, status)],  # type: ignore[arg-type]
            affected_count=len(labels),
            affected_endpoints=labels[:MAX_AFFECTED_ENDPOINTS_PREVIEW],
        )
        for (header, status), labels in groups.items()
    ]
    results.sort(key=lambda f: f.affected_count, reverse=True)
    return results


def _build_inconsistencies(endpoints: list[EndpointAnalysisOut]) -> list[HeaderInconsistencyOut]:
    by_header: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for endpoint in endpoints:
        label = _endpoint_label(endpoint.domain, endpoint.path)
        for hr in endpoint.header_results:
            if hr.status == "not_applicable":
                continue
            value = hr.actual_value if hr.status != "missing" else None
            by_header[hr.header][value or _MISSING_CONFIG_LABEL].append(label)

    results: list[HeaderInconsistencyOut] = []
    for header, configs in by_header.items():
        if len(configs) < 2:
            continue  # a single uniform configuration isn't an inconsistency
        config_rows = [
            InconsistencyConfigOut(value=value, count=len(labels), affected_endpoints=labels[:MAX_AFFECTED_ENDPOINTS_PREVIEW])
            for value, labels in configs.items()
        ]
        config_rows.sort(key=lambda c: c.count, reverse=True)
        results.append(HeaderInconsistencyOut(header=header, configurations=config_rows))

    results.sort(key=lambda h: sum(c.count for c in h.configurations), reverse=True)
    return results


def _build_import_issues(issues: list[BurpEntry]) -> list[ImportIssueOut]:
    return [
        ImportIssueOut(
            index=entry.index,
            url=entry.request.url,
            host=entry.request.host,
            path=entry.request.path,
            status=entry.status.value,  # type: ignore[arg-type]
            reason=entry.error,
        )
        for entry in issues
    ]

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app import models
from app.core import scan_comparison
from app.database import SessionLocal


def _header_finding(
    header="Strict-Transport-Security",
    present=True,
    status="PASS",
    severity="high",
    actual_value="max-age=31536000",
):
    return {
        "header": header,
        "required": True,
        "present": present,
        "status": status,
        "severity": severity,
        "weight": 10.0,
        "score_earned": 10.0 if status == "PASS" else 0.0,
        "score_possible": 10.0,
        "policy_expected": None,
        "actual_value": actual_value if present else None,
        "checks": [],
        "recommendation": None,
    }


def _csp_check(id, directive, status="PASS", severity="medium", description="check", category="policy"):
    return {
        "name": id,
        "description": description,
        "status": status,
        "expected": None,
        "actual": None,
        "id": id,
        "severity": severity,
        "directive": directive,
        "evidence": None,
    }


def _csp_finding(policy_checks=None, security_checks=None, directives=None, overall_score=100.0):
    policy_checks = policy_checks or []
    security_checks = security_checks or []
    return {
        "present": True,
        "actual_value": "default-src 'self'",
        "policy_checks": policy_checks,
        "security_checks": security_checks,
        "directives": directives or {},
        "policy_checks_passed": sum(1 for c in policy_checks if c["status"] == "PASS"),
        "policy_checks_total": len(policy_checks),
        "best_practice_passed": sum(1 for c in security_checks if c["status"] == "PASS"),
        "best_practice_total": len(security_checks),
        "overall_score": overall_score,
    }


def _report(
    score=80.0,
    grade="B",
    findings=None,
    csp_finding=None,
    scan_number=1,
    owner_id="owner-1",
    target="https://example.com",
    policy_id="policy-1",
    policy_version="v1",
    scanned_at=None,
):
    return models.ScanReport(
        id=str(uuid.uuid4()),
        owner_id=owner_id,
        scan_number=scan_number,
        policy_id=policy_id,
        policy_name="Test Policy",
        policy_version=policy_version,
        source="raw",
        target=target,
        fetched_status_code=200,
        score=score,
        grade=grade,
        findings=findings if findings is not None else [_header_finding()],
        csp_finding=csp_finding,
        scanned_at=scanned_at or datetime.now(timezone.utc),
    )


class TestCompareReportsScoreAndGrade:
    def test_basic_score_delta(self):
        previous = _report(score=80.0, grade="B")
        latest = _report(score=90.0, grade="A")

        result = scan_comparison.compare_reports(previous, latest)

        assert result.has_comparison is True
        assert result.summary.score_delta == 10.0
        assert result.summary.previous_grade == "B"
        assert result.summary.latest_grade == "A"

    def test_score_unchanged_but_findings_changed_still_reported(self):
        previous = _report(score=90.0, findings=[_header_finding(status="PASS")])
        latest = _report(
            score=90.0,
            findings=[_header_finding(status="FAIL", actual_value="max-age=100")],
        )

        result = scan_comparison.compare_reports(previous, latest)

        assert result.summary.score_delta == 0.0
        assert result.summary.findings_new == 1


class TestHeaderDiff:
    def test_header_added(self):
        previous = _report(findings=[_header_finding(present=False, status="FAIL", actual_value=None)])
        latest = _report(findings=[_header_finding(present=True, status="PASS")])

        result = scan_comparison.compare_reports(previous, latest)

        assert len(result.changes.headers_added) == 1
        assert result.changes.headers_added[0].header == "Strict-Transport-Security"
        assert result.changes.headers_added[0].latest_value == "max-age=31536000"

    def test_header_removed(self):
        previous = _report(findings=[_header_finding(present=True, status="PASS")])
        latest = _report(findings=[_header_finding(present=False, status="FAIL", actual_value=None)])

        result = scan_comparison.compare_reports(previous, latest)

        assert len(result.changes.headers_removed) == 1
        assert result.changes.headers_removed[0].previous_value == "max-age=31536000"

    def test_header_value_changed(self):
        previous = _report(findings=[_header_finding(actual_value="max-age=31536000")])
        latest = _report(findings=[_header_finding(actual_value="max-age=86400")])

        result = scan_comparison.compare_reports(previous, latest)

        assert len(result.changes.headers_changed) == 1
        change = result.changes.headers_changed[0]
        assert change.previous_value == "max-age=31536000"
        assert change.latest_value == "max-age=86400"

    def test_no_change_when_value_identical(self):
        previous = _report(findings=[_header_finding()])
        latest = _report(findings=[_header_finding()])

        result = scan_comparison.compare_reports(previous, latest)

        assert result.changes.headers_added == []
        assert result.changes.headers_removed == []
        assert result.changes.headers_changed == []


class TestFindingDiff:
    def test_finding_resolved(self):
        previous = _report(findings=[_header_finding(status="FAIL")])
        latest = _report(findings=[_header_finding(status="PASS")])

        result = scan_comparison.compare_reports(previous, latest)

        assert len(result.changes.findings_resolved) == 1
        assert result.changes.findings_resolved[0].header == "Strict-Transport-Security"

    def test_new_finding(self):
        previous = _report(findings=[_header_finding(status="PASS")])
        latest = _report(findings=[_header_finding(status="FAIL")])

        result = scan_comparison.compare_reports(previous, latest)

        assert len(result.changes.findings_new) == 1
        assert result.changes.findings_new[0].header == "Strict-Transport-Security"

    def test_severity_change(self):
        previous = _report(findings=[_header_finding(status="FAIL", severity="medium")])
        latest = _report(findings=[_header_finding(status="FAIL", severity="high")])

        result = scan_comparison.compare_reports(previous, latest)

        assert len(result.changes.severity_changes) == 1
        change = result.changes.severity_changes[0]
        assert change.previous_severity == "medium"
        assert change.latest_severity == "high"


class TestCspDiff:
    def test_csp_finding_resolved(self):
        previous = _report(
            csp_finding=_csp_finding(security_checks=[_csp_check("CSP-004", "script-src", status="FAIL")])
        )
        latest = _report(
            csp_finding=_csp_finding(security_checks=[_csp_check("CSP-004", "script-src", status="PASS")])
        )

        result = scan_comparison.compare_reports(previous, latest)

        assert len(result.changes.csp_changes.resolved) == 1
        assert result.changes.csp_changes.resolved[0].id == "CSP-004"

    def test_csp_finding_new(self):
        previous = _report(
            csp_finding=_csp_finding(security_checks=[_csp_check("CSP-004", "script-src", status="PASS")])
        )
        latest = _report(
            csp_finding=_csp_finding(security_checks=[_csp_check("CSP-004", "script-src", status="FAIL")])
        )

        result = scan_comparison.compare_reports(previous, latest)

        assert len(result.changes.csp_changes.new) == 1

    def test_csp_severity_change(self):
        previous = _report(
            csp_finding=_csp_finding(
                security_checks=[_csp_check("CSP-003", "script-src", status="FAIL", severity="medium")]
            )
        )
        latest = _report(
            csp_finding=_csp_finding(
                security_checks=[_csp_check("CSP-003", "script-src", status="FAIL", severity="high")]
            )
        )

        result = scan_comparison.compare_reports(previous, latest)

        assert len(result.changes.csp_changes.severity_changed) == 1

    def test_composite_id_directive_identity_does_not_collapse(self):
        """CSP-003 (wildcard) failing on script-src only, previously; latest
        additionally fails on style-src. The script-src instance is
        unchanged (still failing) and must not mask the new style-src one."""
        previous = _report(
            csp_finding=_csp_finding(
                security_checks=[
                    _csp_check("CSP-003", "script-src", status="FAIL"),
                    _csp_check("CSP-003", "style-src", status="PASS"),
                ]
            )
        )
        latest = _report(
            csp_finding=_csp_finding(
                security_checks=[
                    _csp_check("CSP-003", "script-src", status="FAIL"),
                    _csp_check("CSP-003", "style-src", status="FAIL"),
                ]
            )
        )

        result = scan_comparison.compare_reports(previous, latest)

        assert len(result.changes.csp_changes.new) == 1
        assert result.changes.csp_changes.new[0].directive == "style-src"
        assert result.changes.csp_changes.resolved == []

    def test_csp_directive_value_changed(self):
        previous = _report(
            csp_finding=_csp_finding(directives={"script-src": ["'self'", "https://cdn.example.com"]})
        )
        latest = _report(csp_finding=_csp_finding(directives={"script-src": ["'self'"]}))

        result = scan_comparison.compare_reports(previous, latest)

        assert len(result.changes.csp_changes.directive_changes) == 1
        change = result.changes.csp_changes.directive_changes[0]
        assert change.directive == "script-src"
        assert change.previous_value == ["'self'", "https://cdn.example.com"]
        assert change.latest_value == ["'self'"]

    def test_csp_score_breakdown_delta(self):
        previous = _report(csp_finding=_csp_finding(overall_score=62.0))
        latest = _report(csp_finding=_csp_finding(overall_score=87.0))

        result = scan_comparison.compare_reports(previous, latest)

        assert result.changes.csp_changes.previous_overall_score == 62.0
        assert result.changes.csp_changes.latest_overall_score == 87.0

    def test_no_csp_on_either_side_yields_no_csp_changes(self):
        previous = _report(csp_finding=None)
        latest = _report(csp_finding=None)

        result = scan_comparison.compare_reports(previous, latest)

        assert result.changes.csp_changes is None


class TestFindPreviousComparableReport:
    @pytest.fixture(autouse=True)
    def _setup(self, client):
        # Depending on `client` triggers the app's lifespan startup (table
        # creation) before these DB-only tests run standalone.
        self.db = SessionLocal()
        self.owner_id = f"owner-{uuid.uuid4().hex}"
        yield
        self.db.close()

    def _save(self, **overrides):
        report = _report(owner_id=self.owner_id, **overrides)
        self.db.add(report)
        self.db.commit()
        return report

    def test_finds_exact_match_most_recent_first(self):
        now = datetime.now(timezone.utc)
        older = self._save(scan_number=1, scanned_at=now - timedelta(hours=2))
        newer = self._save(scan_number=2, scanned_at=now - timedelta(hours=1))
        current = self._save(scan_number=3, scanned_at=now)

        found = scan_comparison.find_previous_comparable_report(self.db, current)

        assert found.id == newer.id
        assert found.id != older.id

    def test_no_match_when_policy_version_differs(self):
        now = datetime.now(timezone.utc)
        self._save(scan_number=1, policy_version="v1", scanned_at=now - timedelta(hours=1))
        current = self._save(scan_number=2, policy_version="v2", scanned_at=now)

        found = scan_comparison.find_previous_comparable_report(self.db, current)

        assert found is None

    def test_no_match_when_target_differs(self):
        now = datetime.now(timezone.utc)
        self._save(scan_number=1, target="https://a.example.com", scanned_at=now - timedelta(hours=1))
        current = self._save(scan_number=2, target="https://b.example.com", scanned_at=now)

        found = scan_comparison.find_previous_comparable_report(self.db, current)

        assert found is None

    def test_ad_hoc_report_never_matches(self):
        current = self._save(scan_number=1, policy_id=None, policy_version="ad-hoc")

        found = scan_comparison.find_previous_comparable_report(self.db, current)

        assert found is None

    def test_default_raw_target_name_never_matches(self):
        now = datetime.now(timezone.utc)
        self._save(scan_number=1, target="HTTP Response Scan", scanned_at=now - timedelta(hours=1))
        current = self._save(scan_number=2, target="HTTP Response Scan", scanned_at=now)

        assert scan_comparison.find_previous_comparable_report(self.db, current) is None

    def test_different_owner_never_matches(self):
        now = datetime.now(timezone.utc)
        other_report = _report(owner_id="someone-else", scanned_at=now - timedelta(hours=1))
        self.db.add(other_report)
        self.db.commit()
        current = self._save(scan_number=1, scanned_at=now)

        found = scan_comparison.find_previous_comparable_report(self.db, current)

        assert found is None

    def test_falls_back_to_next_older_when_immediate_previous_deleted(self):
        now = datetime.now(timezone.utc)
        oldest = self._save(scan_number=1, scanned_at=now - timedelta(hours=2))
        middle = self._save(scan_number=2, scanned_at=now - timedelta(hours=1))
        current = self._save(scan_number=3, scanned_at=now)

        self.db.delete(middle)
        self.db.commit()

        found = scan_comparison.find_previous_comparable_report(self.db, current)

        assert found.id == oldest.id


class TestBuildComparisonForReport:
    @pytest.fixture(autouse=True)
    def _setup(self, client):
        self.db = SessionLocal()
        self.owner_id = f"owner-{uuid.uuid4().hex}"
        yield
        self.db.close()

    def _save(self, **overrides):
        report = _report(owner_id=self.owner_id, **overrides)
        self.db.add(report)
        self.db.commit()
        return report

    def test_ad_hoc_reason(self):
        report = self._save(policy_id=None, policy_version="ad-hoc")

        result = scan_comparison.build_comparison_for_report(self.db, report)

        assert result.has_comparison is False
        assert result.reason == "ad_hoc_policy"

    def test_default_raw_target_reason(self):
        now = datetime.now(timezone.utc)
        self._save(target="HTTP Response Scan", scanned_at=now - timedelta(hours=1))
        report = self._save(target="HTTP Response Scan", scanned_at=now)

        result = scan_comparison.build_comparison_for_report(self.db, report)

        assert result.has_comparison is False
        assert result.reason == "raw_default_target"

    def test_default_name_on_a_url_scan_is_not_anonymous(self):
        """Only raw-response scans get the anonymous-target treatment."""
        now = datetime.now(timezone.utc)
        prior = _report(owner_id=self.owner_id, target="HTTP Response Scan", scanned_at=now)
        prior.source = "url"

        assert scan_comparison.is_anonymous_raw_target(prior) is False

    def test_no_previous_scan_reason(self):
        report = self._save()

        result = scan_comparison.build_comparison_for_report(self.db, report)

        assert result.has_comparison is False
        assert result.reason == "no_previous_scan"

    def test_policy_version_changed_reason(self):
        now = datetime.now(timezone.utc)
        self._save(policy_version="v1", scanned_at=now - timedelta(hours=1))
        report = self._save(policy_version="v2", scanned_at=now)

        result = scan_comparison.build_comparison_for_report(self.db, report)

        assert result.has_comparison is False
        assert result.reason == "policy_version_changed"

    def test_returns_full_comparison_when_match_found(self):
        now = datetime.now(timezone.utc)
        self._save(score=80.0, grade="B", scanned_at=now - timedelta(hours=1))
        report = self._save(score=90.0, grade="A", scanned_at=now)

        result = scan_comparison.build_comparison_for_report(self.db, report)

        assert result.has_comparison is True
        assert result.summary.score_delta == 10.0

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


class TestTargetNameNormalization:
    @pytest.mark.parametrize(
        "name", ["Production API", " production api ", "PRODUCTION API", "Production    API", "\tProduction \n API"]
    )
    def test_equivalent_names_normalize_identically(self, name):
        assert scan_comparison.normalize_target_name(name) == "production api"

    def test_different_names_stay_different(self):
        assert scan_comparison.normalize_target_name("Production API") != scan_comparison.normalize_target_name(
            "Staging API"
        )

    def test_none_and_blank_are_empty(self):
        assert scan_comparison.normalize_target_name(None) == ""
        assert scan_comparison.normalize_target_name("   ") == ""

    @pytest.mark.parametrize("name", ["HTTP Response Scan", "http response scan", "  HTTP   RESPONSE  SCAN "])
    def test_anonymous_default_is_detected_in_any_form(self, name):
        assert scan_comparison.is_anonymous_raw_target(_report(target=name)) is True

    def test_only_raw_scans_can_be_anonymous(self):
        report = _report(target="HTTP Response Scan")
        report.source = "url"
        assert scan_comparison.is_anonymous_raw_target(report) is False


class TestTargetMatchingRules:
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

    def test_raw_names_match_loosely(self):
        now = datetime.now(timezone.utc)
        earlier = self._save(target="Production API", scanned_at=now - timedelta(hours=1))
        current = self._save(target="  production   api", scanned_at=now)

        assert scan_comparison.find_previous_comparable_report(self.db, current).id == earlier.id

    def test_url_targets_match_exactly_only(self):
        now = datetime.now(timezone.utc)
        for target in ("https://Example.com/Path", "https://example.com/path"):
            report = _report(owner_id=self.owner_id, target=target, scanned_at=now - timedelta(hours=1))
            report.source = "url"
            self.db.add(report)
        self.db.commit()
        current = _report(owner_id=self.owner_id, target="https://example.com/PATH", scanned_at=now)
        current.source = "url"
        self.db.add(current)
        self.db.commit()

        assert scan_comparison.find_previous_comparable_report(self.db, current) is None

    def test_a_typed_name_never_matches_a_fetched_url(self):
        now = datetime.now(timezone.utc)
        fetched = _report(owner_id=self.owner_id, target="https://example.com", scanned_at=now - timedelta(hours=1))
        fetched.source = "url"
        self.db.add(fetched)
        self.db.commit()
        current = self._save(target="https://example.com", scanned_at=now)

        assert scan_comparison.find_previous_comparable_report(self.db, current) is None

    def test_selects_the_immediately_preceding_of_several(self):
        now = datetime.now(timezone.utc)
        self._save(scan_number=1, scanned_at=now - timedelta(hours=3))
        second = self._save(scan_number=2, scanned_at=now - timedelta(hours=2))
        third = self._save(scan_number=3, scanned_at=now - timedelta(hours=1))
        current = self._save(scan_number=4, scanned_at=now)

        assert scan_comparison.find_previous_comparable_report(self.db, current).id == third.id
        assert scan_comparison.find_previous_comparable_report(self.db, third).id == second.id

    def test_reasons_distinguish_policy_from_version(self):
        now = datetime.now(timezone.utc)
        self._save(policy_id="policy-A", policy_version="v1", scanned_at=now - timedelta(hours=2))
        other_policy = self._save(policy_id="policy-B", policy_version="v1", scanned_at=now - timedelta(hours=1))
        assert scan_comparison.build_comparison_for_report(self.db, other_policy).reason == "different_policy"

        new_version = self._save(policy_id="policy-B", policy_version="v2", scanned_at=now)
        assert scan_comparison.build_comparison_for_report(self.db, new_version).reason == "policy_version_changed"

    def test_reason_describes_the_most_recent_scan_of_the_target(self):
        now = datetime.now(timezone.utc)
        self._save(target="Staging API", policy_id="policy-Z", scanned_at=now - timedelta(hours=2))
        current = self._save(target="Production API", scanned_at=now)

        assert scan_comparison.build_comparison_for_report(self.db, current).reason == "no_previous_scan"

    def test_stored_previous_that_no_longer_exists_is_unavailable(self):
        now = datetime.now(timezone.utc)
        older = self._save(scanned_at=now - timedelta(hours=2))
        current = self._save(scanned_at=now)
        current.previous_report_id = "deleted-report-id"
        self.db.commit()

        result = scan_comparison.build_comparison_for_report(self.db, current)

        assert result.has_comparison is False
        assert result.reason == "previous_report_unavailable"
        assert older.id != current.previous_report_id  # not re-pointed at the older scan

    def test_stored_previous_owned_by_someone_else_is_treated_as_unavailable(self):
        now = datetime.now(timezone.utc)
        foreign = _report(owner_id="someone-else", scanned_at=now - timedelta(hours=1))
        self.db.add(foreign)
        self.db.commit()
        current = self._save(scanned_at=now)
        current.previous_report_id = foreign.id
        self.db.commit()

        assert scan_comparison.build_comparison_for_report(self.db, current).reason == "previous_report_unavailable"


class TestSemanticChangeDetection:
    def _headers(self, name, value):
        return [_header_finding(header=name, actual_value=value, status="PASS")]

    @pytest.mark.parametrize(
        "header, before, after",
        [
            ("Cache-Control", "private, no-store", "no-store,   private"),
            ("Cache-Control", "PRIVATE, No-Store", "private, no-store"),
            ("Access-Control-Allow-Origin", "https://Example.com", "https://example.com/"),
            ("X-XSS-Protection", "1; mode=block", "1;mode=block"),
            ("Permissions-Policy", "geolocation=(), camera=()", "camera=(),  geolocation=()"),
            ("Strict-Transport-Security", "max-age=100; includeSubDomains", "includeSubDomains;max-age=100"),
            ("X-Frame-Options", "DENY", "  deny "),
            ("Referrer-Policy", "unsafe-url, strict-origin", "strict-origin"),
        ],
    )
    def test_formatting_only_differences_are_not_changes(self, header, before, after):
        result = scan_comparison.compare_reports(
            _report(findings=self._headers(header, before)), _report(findings=self._headers(header, after))
        )
        assert result.changes.headers_changed == [], (before, after)

    @pytest.mark.parametrize(
        "header, before, after",
        [
            ("Cache-Control", "private, no-store", "private, no-store, max-age=60"),
            ("Cache-Control", "private, no-store", "public, no-store"),
            ("Strict-Transport-Security", "max-age=100", "max-age=200"),
            ("Access-Control-Allow-Origin", "https://a.com", "https://b.com"),
            ("Access-Control-Allow-Origin", "https://a.com", "*"),
            ("X-XSS-Protection", "1; mode=block", "0"),
            ("X-XSS-Protection", "1; mode=block", "1; mode=block; report=/r"),
            ("Permissions-Policy", "camera=()", "camera=(self)"),
            ("X-Frame-Options", "DENY", "SAMEORIGIN"),
            ("Referrer-Policy", "strict-origin", "unsafe-url"),
            ("X-Content-Type-Options", "nosniff", "sniff"),
        ],
    )
    def test_real_differences_are_still_changes(self, header, before, after):
        result = scan_comparison.compare_reports(
            _report(findings=self._headers(header, before)), _report(findings=self._headers(header, after))
        )
        assert len(result.changes.headers_changed) == 1, (before, after)

    def test_unknown_header_compares_by_normalised_text(self):
        same = scan_comparison.compare_reports(
            _report(findings=self._headers("X-Custom", "a  b")), _report(findings=self._headers("X-Custom", "A b"))
        )
        different = scan_comparison.compare_reports(
            _report(findings=self._headers("X-Custom", "a b")), _report(findings=self._headers("X-Custom", "a c"))
        )
        assert same.changes.headers_changed == []
        assert len(different.changes.headers_changed) == 1

    def test_csp_source_order_and_case_are_not_a_directive_change(self):
        before = _report(csp_finding=_csp_finding(directives={"script-src": ["'self'", "https://A.com"]}))
        after = _report(csp_finding=_csp_finding(directives={"script-src": ["https://a.com", "'self'"]}))
        assert scan_comparison.compare_reports(before, after).changes.csp_changes.directive_changes == []

    def test_csp_a_different_source_is_a_directive_change(self):
        before = _report(csp_finding=_csp_finding(directives={"script-src": ["'self'"]}))
        after = _report(csp_finding=_csp_finding(directives={"script-src": ["'self'", "https://cdn.com"]}))
        assert len(scan_comparison.compare_reports(before, after).changes.csp_changes.directive_changes) == 1


class TestEnsureSchema:
    def test_adds_the_column_to_an_older_database_and_is_idempotent(self, tmp_path):
        from sqlalchemy import create_engine, inspect, text

        from app.database import ensure_schema

        engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE scan_reports (id VARCHAR PRIMARY KEY, owner_id VARCHAR)"))
            conn.execute(text("INSERT INTO scan_reports (id, owner_id) VALUES ('r1', 'u1')"))

        ensure_schema(engine)
        ensure_schema(engine)  # running it again must be harmless

        columns = {c["name"] for c in inspect(engine).get_columns("scan_reports")}
        assert "previous_report_id" in columns
        with engine.connect() as conn:
            assert conn.execute(text("SELECT previous_report_id FROM scan_reports")).scalar() is None

    def test_does_nothing_when_the_table_does_not_exist_yet(self, tmp_path):
        from sqlalchemy import create_engine

        from app.database import ensure_schema

        ensure_schema(create_engine(f"sqlite:///{tmp_path / 'empty.db'}"))

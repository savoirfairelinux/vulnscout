# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Integration tests for the scc-scan bulk persistence writer.

These run against a live in-memory SQLite database (the real models, real
foreign-key relationships and the real priority write lock) — only the engine
*output* objects are constructed as lightweight value carriers, mirroring the
``ComputedVulnInfo`` instances ``SccEngine.applicable_vulns`` yields.
"""

import os
from datetime import datetime, timezone
import pytest

from src.bin.webapp import create_app
from src.bin.cmd_vuln_scan import _SccBulkWriter
from src.extensions import db as _db
from src.models.project import Project
from src.models.variant import Variant
from src.models.scan import Scan
from src.models.package import Package
from src.models.finding import Finding
from src.models.observation import Observation
from src.models.assessment import Assessment
from src.models.vulnerability import Vulnerability
from src.models.metrics import Metrics


# ---------------------------------------------------------------------------
# Engine-output value carriers (shape of sbom_cve_check ComputedVulnInfo)
# ---------------------------------------------------------------------------

class _Ref:
    def __init__(self, url):
        self.url = url


class _CvssVer:
    def __init__(self, value):
        self.value = value


class _Metric:
    def __init__(self, score, version=(3, 1), vector="AV:N/AC:L", source="nvd"):
        self.score = score
        self.cvss_ver = _CvssVer(version)
        self.vector_str = vector
        self.source = source


class _VexAssessment:
    def __init__(self, notes):
        self.status_notes = notes


class _Computed:
    """Mirrors the attributes _SccBulkWriter reads from a ComputedVulnInfo."""

    def __init__(self, cve_id, description="desc", score=7.5, notes="note"):
        self._cve_id = cve_id
        self.description = description
        self.date_published = datetime(2023, 1, 2, tzinfo=timezone.utc)
        self.date_modified = datetime(2023, 6, 1, tzinfo=timezone.utc)
        self.external_refs = [_Ref(f"https://example/{cve_id}")]
        self.cvss_metrics = [_Metric(score)]
        self.vex_assessment = _VexAssessment(notes)

    @property
    def identifier(self):
        return self._cve_id


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True})
        with application.app_context():
            _db.drop_all()
            _db.create_all()
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


def _make_packages(names):
    pkgs = []
    for name, version in names:
        pkgs.append(Package.find_or_create(name, version))
    _db.session.commit()
    return pkgs


def _scan_pkg(writer, pkg, computed_status_pairs):
    """Feed one package's engine output through the writer.

    Every verdict is forwarded — including ``not_affected`` and ``fixed`` — so
    the full VEX picture reaches persistence, mirroring the scc-scan callers.
    """
    seen = set()
    for computed, status in computed_status_pairs:
        writer.add(pkg, computed, status, seen)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSccBulkWriter:

    def test_kernel_explosion_persists_once_per_package_cve(self, app):
        """Many sibling packages sharing the same CVE set each get their own
        finding/observation/assessment, while each CVE row is inserted once."""
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")

            # 5 kernel-module siblings, all carrying the same 2 CVEs.
            pkgs = _make_packages([(f"kernel-module-{i}", "6.6") for i in range(5)])
            shared = [
                (_Computed("CVE-2023-0001", score=9.8), "affected"),
                (_Computed("CVE-2023-0002", score=5.0), "under_investigation"),
            ]

            writer = _SccBulkWriter(scan.id, variant.id, pkgs)
            writer.FLUSH_THRESHOLD = 3  # force several chunked flushes
            for pkg in pkgs:
                # Fresh _Computed per package (engine yields per-package instances).
                pairs = [(_Computed(c.identifier, score=float(c.cvss_metrics[0].score)), s)
                         for c, s in shared]
                _scan_pkg(writer, pkg, pairs)
            writer.flush()

            # 2 distinct vulnerabilities, each with exactly one metric row.
            assert _db.session.query(Vulnerability).count() == 2
            assert _db.session.query(Metrics).count() == 2

            # 5 packages x 2 CVEs = 10 findings / observations / assessments.
            assert _db.session.query(Finding).count() == 10
            assert _db.session.query(Observation).count() == 10
            assert _db.session.query(Assessment).count() == 10

            # Every observation belongs to this scan; every assessment to variant.
            assert all(o.scan_id == scan.id
                       for o in _db.session.query(Observation).all())
            assert all(a.variant_id == variant.id and a.origin == "scc"
                       for a in _db.session.query(Assessment).all())
            assert writer.cves_found == {"CVE-2023-0001", "CVE-2023-0002"}

    def test_existing_finding_is_reused_not_duplicated(self, app):
        """A finding from a prior scan must be reused (no duplicate row), and its
        already-present assessment must not be duplicated."""
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("openssl", "1.1.1")])[0]

            # Pre-existing finding + assessment for (pkg, CVE) from an earlier run.
            existing = Finding.create(pkg.id, "CVE-2023-0001", commit=False)
            Assessment.create(
                status="affected", finding_id=existing.id, variant_id=variant.id,
                origin="nvd", commit=False,
            )
            _db.session.commit()
            existing_fid = existing.id

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
            writer.flush()

            # No duplicate finding: still exactly one for this (pkg, CVE).
            findings = _db.session.query(Finding).filter_by(
                package_id=pkg.id, vulnerability_id="CVE-2023-0001").all()
            assert len(findings) == 1
            assert findings[0].id == existing_fid

            # The existing assessment is reused (not duplicated).
            assert _db.session.query(Assessment).filter_by(
                finding_id=existing_fid, variant_id=variant.id).count() == 1
            # One observation recorded for this scan against the reused finding.
            assert _db.session.query(Observation).filter_by(
                finding_id=existing_fid, scan_id=scan.id).count() == 1

    def test_existing_vulnerability_not_reinserted(self, app):
        """A CVE already present in the vulnerabilities table is left intact and
        not re-inserted (no primary-key collision)."""
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("curl", "8.0")])[0]

            Vulnerability.create_record(
                id="CVE-2023-0001", description="pre-existing")

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001", description="new"),
                                     "affected")])
            writer.flush()

            vulns = _db.session.query(Vulnerability).filter_by(
                id="CVE-2023-0001").all()
            assert len(vulns) == 1
            # Original description preserved (writer does not overwrite existing).
            assert vulns[0].description == "pre-existing"
            # Finding for the existing vuln was still created.
            assert _db.session.query(Finding).filter_by(
                package_id=pkg.id, vulnerability_id="CVE-2023-0001").count() == 1

    def test_not_affected_and_fixed_are_persisted(self, app):
        """Every engine verdict — including not_affected and fixed — is recorded."""
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("zlib", "1.3")])[0]

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            _scan_pkg(writer, pkg, [
                (_Computed("CVE-2023-0001"), "affected"),
                (_Computed("CVE-2023-0002"), "not_affected"),
                (_Computed("CVE-2023-0003"), "fixed"),
            ])
            writer.flush()

            ids = {f.vulnerability_id for f in _db.session.query(Finding).all()}
            assert ids == {"CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"}

            statuses = {
                a.finding.vulnerability_id: a.status
                for a in _db.session.query(Assessment).all()
            }
            # All new findings start as under_investigation regardless of the
            # engine verdict; a human must triage before a verdict is recorded.
            assert statuses == {
                "CVE-2023-0001": "under_investigation",
                "CVE-2023-0002": "under_investigation",
                "CVE-2023-0003": "under_investigation",
            }

    def test_matching_last_assessment_writes_no_new_one(self, app):
        """When the engine confirms a finding's current state (even via an
        equivalent CDX-VEX synonym) no new assessment is recorded."""
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("openssl", "1.1.1")])[0]

            existing = Finding.create(pkg.id, "CVE-2023-0001", commit=False)
            # CDX-VEX "exploitable" is the synonym of OpenVEX "affected".
            Assessment.create(
                status="exploitable", finding_id=existing.id,
                variant_id=variant.id, origin="manual", commit=False,
            )
            _db.session.commit()

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
            writer.flush()

            # No new assessment: the engine verdict matches the recorded state.
            assert _db.session.query(Assessment).filter_by(
                finding_id=existing.id, variant_id=variant.id).count() == 1
            # The scan still observed the finding.
            assert _db.session.query(Observation).filter_by(
                finding_id=existing.id, scan_id=scan.id).count() == 1

    def test_existing_finding_without_assessment_not_given_pending(self, app):
        """A pre-existing finding that has no assessment must not receive a new
        'Pending Assessment' from the scc-scan (only brand-new findings should)."""
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("curl", "8.0")])[0]

            # Pre-existing finding with NO assessment.
            existing = Finding.create(pkg.id, "CVE-2023-0001", commit=False)
            _db.session.commit()
            existing_fid = existing.id

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
            writer.flush()

            # The finding is reused, no new one created.
            findings = _db.session.query(Finding).filter_by(
                package_id=pkg.id, vulnerability_id="CVE-2023-0001").all()
            assert len(findings) == 1
            assert findings[0].id == existing_fid

            # No assessment added — the pre-existing finding had none and the
            # scc-scan must not inject a "Pending Assessment" for it.
            assert _db.session.query(Assessment).filter_by(
                finding_id=existing_fid, variant_id=variant.id).count() == 0
            # The scan still recorded the observation.
            assert _db.session.query(Observation).filter_by(
                finding_id=existing_fid, scan_id=scan.id).count() == 1

    def test_changed_status_writes_no_new_assessment_if_one_exists(self, app):
        """When a finding already has an assessment the scc-scan leaves it
        untouched, regardless of the engine's current verdict."""
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("curl", "8.0")])[0]

            existing = Finding.create(pkg.id, "CVE-2023-0001", commit=False)
            Assessment.create(
                status="not_affected", finding_id=existing.id,
                variant_id=variant.id, origin="manual", commit=False,
            )
            _db.session.commit()

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
            writer.flush()

            # Assessment count must remain 1 — the existing one is preserved.
            assessments = _db.session.query(Assessment).filter_by(
                finding_id=existing.id, variant_id=variant.id).all()
            assert len(assessments) == 1
            assert assessments[0].status == "not_affected"
            # The scan still observed the finding.
            assert _db.session.query(Observation).filter_by(
                finding_id=existing.id, scan_id=scan.id).count() == 1

    def test_duplicate_cve_within_package_deduped(self, app):
        """If the same CVE is offered twice for one package it yields one finding."""
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("bash", "5.2")])[0]

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            _scan_pkg(writer, pkg, [
                (_Computed("CVE-2023-0001"), "affected"),
                (_Computed("CVE-2023-0001"), "affected"),
            ])
            writer.flush()

            assert _db.session.query(Finding).filter_by(
                package_id=pkg.id, vulnerability_id="CVE-2023-0001").count() == 1
            assert _db.session.query(Observation).count() == 1
            assert _db.session.query(Assessment).count() == 1


# ---------------------------------------------------------------------------
# Pure-function helper coverage (no DB needed)
# ---------------------------------------------------------------------------

class TestTsKey:
    """Cover all branches of _ts_key (line 370 area)."""

    def test_none_returns_empty_string(self):
        from src.bin.cmd_vuln_scan import _ts_key
        assert _ts_key(None) == ""

    def test_string_returned_unchanged(self):
        from src.bin.cmd_vuln_scan import _ts_key
        assert _ts_key("2023-01-01T00:00:00") == "2023-01-01T00:00:00"

    def test_datetime_uses_isoformat(self):
        from src.bin.cmd_vuln_scan import _ts_key
        dt = datetime(2023, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        assert _ts_key(dt) == dt.isoformat()

    def test_object_without_isoformat_uses_str(self):
        from src.bin.cmd_vuln_scan import _ts_key

        class _Bad:
            def isoformat(self):
                raise RuntimeError("no isoformat")

            def __str__(self):
                return "fallback"

        assert _ts_key(_Bad()) == "fallback"


class TestSccCvssVersion:
    """Cover error and edge branches of _scc_cvss_version (line 382 area)."""

    def _metric(self, ver_value):
        class _CV:
            value = ver_value

        class _M:
            cvss_ver = _CV()

        return _M()

    def test_valid_version_returns_string(self):
        from src.bin.cmd_vuln_scan import _scc_cvss_version
        assert _scc_cvss_version(self._metric((3, 1))) == "3.1"

    def test_zero_major_returns_empty(self):
        from src.bin.cmd_vuln_scan import _scc_cvss_version
        assert _scc_cvss_version(self._metric((0, 1))) == ""

    def test_non_iterable_value_returns_empty(self):
        from src.bin.cmd_vuln_scan import _scc_cvss_version
        # None cannot be unpacked → TypeError → ""
        assert _scc_cvss_version(self._metric(None)) == ""

    def test_wrong_length_tuple_returns_empty(self):
        from src.bin.cmd_vuln_scan import _scc_cvss_version
        # ValueError: not enough values to unpack
        assert _scc_cvss_version(self._metric((3,))) == ""


class TestBuildVulnEdgeCases:
    """Cover skipped-metric branches inside _SccBulkWriter._build_vuln."""

    def test_metric_with_none_score_skipped(self):
        from src.bin.cmd_vuln_scan import _SccBulkWriter

        class _CV:
            value = (3, 1)

        class _M:
            score = None
            cvss_ver = _CV()
            vector_str = ""
            source = "nvd"

        class _Computed:
            description = "d"
            date_published = None
            date_modified = None
            external_refs = []
            cvss_metrics = [_M()]

        vuln_row, metric_rows = _SccBulkWriter._build_vuln("CVE-2099-0001", _Computed())
        assert metric_rows == []

    def test_duplicate_version_score_deduped(self):
        from src.bin.cmd_vuln_scan import _SccBulkWriter

        class _CV:
            value = (3, 1)

        class _M:
            score = 7.5
            cvss_ver = _CV()
            vector_str = "AV:N"
            source = "nvd"

        class _Computed:
            description = "d"
            date_published = None
            date_modified = None
            external_refs = []
            # Two metrics with the same (version, score) → only one inserted.
            cvss_metrics = [_M(), _M()]

        vuln_row, metric_rows = _SccBulkWriter._build_vuln("CVE-2099-0002", _Computed())
        assert len(metric_rows) == 1


class TestMaybeFlushAndEarlyReturn:
    """Cover maybe_flush() and the early-return path of flush()."""

    def test_maybe_flush_does_not_flush_below_threshold(self, app):
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("curl", "8.0")])[0]

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            # Below threshold — maybe_flush must be a no-op (nothing committed).
            writer.maybe_flush()
            assert _db.session.query(Finding).count() == 0

    def test_maybe_flush_triggers_flush_at_threshold(self, app):
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("curl", "8.0")])[0]

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            writer.FLUSH_THRESHOLD = 0  # force flush on any count
            writer._buffered_findings = 1
            writer.maybe_flush()
            # flush() ran — row buffers are cleared.
            assert writer._vuln_rows == []

    def test_flush_with_empty_rows_returns_early(self, app):
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("curl", "8.0")])[0]

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            # All row lists are empty → flush() must return without DB writes.
            writer.flush()
            assert _db.session.query(Finding).count() == 0


class TestAddExceptionInStatusNotes:
    """Cover the except branch when vex_assessment.status_notes raises."""

    def test_status_notes_exception_records_none(self, app):
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("bash", "5.2")])[0]

            class _BadAssessment:
                @property
                def status_notes(self):
                    raise RuntimeError("status_notes unavailable")

            class _ComputedNoNotes:
                _cve_id = "CVE-2099-NOTES"
                description = "test"
                date_published = None
                date_modified = None
                external_refs = []
                cvss_metrics = []
                vex_assessment = _BadAssessment()

                @property
                def identifier(self):
                    return self._cve_id

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            seen: set = set()
            writer.add(pkg, _ComputedNoNotes(), "affected", seen)
            writer.flush()

            # Assessment row should exist with status_notes=None (no crash).
            assessments = _db.session.query(Assessment).all()
            assert len(assessments) == 1
            assert assessments[0].status_notes is None

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Integration tests for the sbom-cve-check-scan bulk persistence writer.

These run against a live in-memory SQLite database (the real models, real
foreign-key relationships and the real priority write lock) — only the engine
*output* objects are constructed as lightweight value carriers, mirroring the
``ComputedVulnInfo`` instances ``SccEngine.applicable_vulns`` yields.
"""

import gc
import os
import tracemalloc
from datetime import datetime, timezone
import pytest

from src.bin.webapp import create_app
from src.bin.cmd_vuln_scan import _SccBulkWriter, _persist_finding
from src.extensions import db as _db
from src.models.project import Project
from src.models.variant import Variant
from src.models.scan import Scan
from src.models.package import Package
from src.models.finding import Finding
from src.models.observation import Observation
from src.models.assessment import Assessment
from src.models.assessment_target import AssessmentTarget
from src.models.vulnerability import Vulnerability
from src.models.metrics import Metrics
from src.helpers.scan_runs import tool_scan


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
    the full VEX picture reaches persistence, mirroring the sbom-cve-check-scan callers.
    """
    seen = set()
    for computed, status in computed_status_pairs:
        writer.add(pkg, computed, status, seen)


def _assessments_for(finding_id, variant_id):
    """Return the query for assessments targeting (finding_id, variant_id).

    An assessment states what it applies to through its target rows, so the
    filter joins ``AssessmentTarget``.
    """
    return _db.session.query(Assessment).join(
        AssessmentTarget, AssessmentTarget.assessment_id == Assessment.id
    ).filter(
        AssessmentTarget.finding_id == finding_id,
        AssessmentTarget.variant_id == variant_id,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSccBulkWriter:

    def test_failure_cleanup_preserves_new_finding_adopted_by_another_scan(self, app):
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            pkg = _make_packages([("openssl", "1.1.1")])[0]
            variant_id, package_id = variant.id, pkg.id
            failure_cleanups = []

            with pytest.raises(KeyboardInterrupt):
                with tool_scan(variant_id, "scc", failure_cleanups=failure_cleanups) as scan:
                    writer = _SccBulkWriter(
                        scan.id, variant_id, [pkg], failure_cleanups=failure_cleanups,
                    )
                    _scan_pkg(writer, pkg, [
                        (_Computed("CVE-2023-0001"), "affected"),
                        (_Computed("CVE-2023-0002"), "affected"),
                    ])
                    writer.flush()

                    # A separate session adopts one of the newly committed
                    # findings before the original producer is interrupted.
                    with app.app_context():
                        adopted = _db.session.scalar(_db.select(Finding).where(
                            Finding.package_id == package_id,
                            Finding.vulnerability_id == "CVE-2023-0001",
                        ))
                        adopted_id = adopted.id
                        other_scan = Scan.create("completed", variant_id, scan_type="tool")
                        other_scan_id = other_scan.id
                        Observation.create(finding_id=adopted_id, scan_id=other_scan_id)
                        custom = Assessment.create(
                            status="not_affected", origin="custom",
                            targets=[(variant_id, adopted_id)],
                        )
                        custom_id = custom.id
                    raise KeyboardInterrupt

            assert list(_db.session.scalars(_db.select(Finding.id))) == [adopted_id]
            assert list(_db.session.scalars(_db.select(Scan.id))) == [other_scan_id]
            assert list(_db.session.scalars(_db.select(Assessment.id))) == [custom_id]
            assert _db.session.query(AssessmentTarget).count() == 1
            observation = _db.session.query(Observation).one()
            assert (observation.finding_id, observation.scan_id) == (adopted_id, other_scan_id)

    def test_failure_cleanup_keeps_pending_assessment_reused_by_another_scan(self, app):
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            pkg = _make_packages([("openssl", "1.1.1")])[0]
            variant_id, package_id = variant.id, pkg.id
            failure_cleanups = []

            with pytest.raises(KeyboardInterrupt):
                with tool_scan(variant_id, "scc", failure_cleanups=failure_cleanups) as scan:
                    writer = _SccBulkWriter(
                        scan.id, variant_id, [pkg], failure_cleanups=failure_cleanups,
                    )
                    _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
                    writer.flush()

                    # A concurrent scan of the same variant observes the new
                    # finding, reuses its pending assessment, and completes.
                    with app.app_context():
                        with tool_scan(variant_id, "osv") as other_scan:
                            other_scan_id = other_scan.id
                            _persist_finding(
                                package_id, "CVE-2023-0001", other_scan_id, variant_id,
                                "osv", set(), set(),
                            )
                    raise KeyboardInterrupt

            finding = _db.session.query(Finding).one()
            assert list(_db.session.scalars(_db.select(Scan.id))) == [other_scan_id]
            observation = _db.session.query(Observation).one()
            assert (observation.finding_id, observation.scan_id) == (finding.id, other_scan_id)
            pending = _assessments_for(finding.id, variant_id).one()
            assert pending.status == "under_investigation"

    @pytest.mark.parametrize("first_source", ["nvd", "scc"])
    @pytest.mark.parametrize("second_source", ["nvd", "scc"])
    @pytest.mark.parametrize("failure_order", [(0, 1), (1, 0), (0, 1, 2), (0, 2, 1), (2, 1, 0)])
    def test_overlapping_failed_scans_remove_their_shared_pending_assessment(
        self, app, monkeypatch, first_source, second_source, failure_order,
    ):
        monkeypatch.setattr(_SccBulkWriter, "_SELECT_CHUNK", 2)
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            pkg = _make_packages([("openssl", "1.1.1")])[0]
            variant_id, package_id = variant.id, pkg.id

        steps = []
        for source in (first_source, second_source, first_source)[:len(failure_order)]:
            with app.app_context():
                failure_cleanups = []
                step = tool_scan(variant_id, source, failure_cleanups=failure_cleanups)
                scan = step.__enter__()
                pkg = _db.session.get(Package, package_id)
                writer = _SccBulkWriter(
                    scan.id, variant_id, [pkg], failure_cleanups=failure_cleanups,
                )
                for index in range(3):
                    _scan_pkg(writer, pkg, [(_Computed(f"CVE-2023-{index:04d}"), "affected")])
                    writer.flush()
                steps.append(step)

        with app.app_context():
            assert _db.session.query(Scan).count() == len(steps)
            assert _db.session.query(Observation).count() == 3 * len(steps)
            pending_ids = set(_db.session.scalars(_db.select(Assessment.id)))
            assert len(pending_ids) == 3

        for remaining, index in zip(reversed(range(len(steps))), failure_order):
            with app.app_context():
                error = KeyboardInterrupt()
                assert steps[index].__exit__(type(error), error, None) is False
                assert _db.session.query(Scan).count() == remaining
                assert _db.session.query(Observation).count() == 3 * remaining
                if remaining:
                    assert set(_db.session.scalars(_db.select(Assessment.id))) == pending_ids
                    surviving_ids = set(_db.session.scalars(_db.select(Scan.id)))
                    assert set(_db.session.scalars(_db.select(Assessment.provisional_scan_id))) <= surviving_ids
                else:
                    assert _db.session.query(Assessment).count() == 0
                    assert _db.session.query(AssessmentTarget).count() == 0

    @pytest.mark.parametrize("completion", ["before_overlap", "after_overlap", "adopter"])
    def test_failed_scan_preserves_assessment_after_completed_scan_is_deleted(self, app, tmp_path, completion):
        status_file = tmp_path / "status.txt"
        status_file.write_text("__END_OF_SCAN_SCRIPT__")
        app.config["SCAN_FILE"] = str(status_file)
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            pkg = _make_packages([("openssl", "1.1.1")])[0]
            variant_id, package_id = variant.id, pkg.id

        steps, scan_ids = [], []
        for index, source in enumerate(("nvd", "scc")):
            with app.app_context():
                failure_cleanups = []
                step = tool_scan(variant_id, source, failure_cleanups=failure_cleanups)
                scan = step.__enter__()
                scan_ids.append(scan.id)
                pkg = _db.session.get(Package, package_id)
                writer = _SccBulkWriter(
                    scan.id, variant_id, [pkg], failure_cleanups=failure_cleanups,
                )
                _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
                writer.flush()
                steps.append(step)
                if index == 0 and completion == "before_overlap":
                    step.__exit__(None, None, None)

        completed = int(completion == "adopter")
        with app.app_context():
            if completion != "before_overlap":
                steps[completed].__exit__(None, None, None)
            pending_id = _db.session.query(Assessment).one().id

        response = app.test_client().delete(f"/api/scans/{scan_ids[completed]}")
        assert response.status_code == 200
        assert response.json["orphaned_findings_removed"] == 0

        with app.app_context():
            assert _db.session.query(Assessment).one().id == pending_id
            error = KeyboardInterrupt()
            assert steps[1 - completed].__exit__(type(error), error, None) is False
            assert _db.session.query(Scan).count() == 0
            assert _db.session.query(Observation).count() == 0
            assert _db.session.query(Assessment).one().id == pending_id
            assert _db.session.query(AssessmentTarget).count() == 1

    @pytest.mark.parametrize("origin", ["scc", "custom"])
    @pytest.mark.parametrize("observed", [False, True])
    @pytest.mark.parametrize("has_custom_assessment", [False, True])
    def test_failure_cleanup_preserves_preexisting_pending_assessments(
        self, app, origin, observed, has_custom_assessment,
    ):
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            pkg = _make_packages([("openssl", "1.1.1")])[0]
            vuln = Vulnerability.create_record(id="CVE-2023-0001", description="existing")
            finding = Finding.get_or_create(pkg.id, vuln.id)
            pending = Assessment.create(
                status="under_investigation", origin=origin,
                targets=[(variant.id, finding.id)],
            )
            expected_ids = {pending.id}
            if observed:
                completed = Scan.create("completed", variant.id, scan_type="tool")
                Observation.create(finding_id=finding.id, scan_id=completed.id)
            if has_custom_assessment:
                custom = Assessment.create(
                    status="not_affected", origin="custom",
                    targets=[(variant.id, finding.id)],
                )
                expected_ids.add(custom.id)
            _db.session.commit()
            failure_cleanups = []

            with pytest.raises(KeyboardInterrupt):
                with tool_scan(variant.id, "nvd", failure_cleanups=failure_cleanups) as scan:
                    writer = _SccBulkWriter(
                        scan.id, variant.id, [pkg], failure_cleanups=failure_cleanups,
                    )
                    _scan_pkg(writer, pkg, [(_Computed(vuln.id), "affected")])
                    writer.flush()
                    raise KeyboardInterrupt

            assert set(_db.session.scalars(_db.select(Assessment.id))) == expected_ids
            assert _db.session.query(AssessmentTarget).count() == len(expected_ids)
            assert _db.session.query(Finding).count() == 1
            assert _db.session.query(Observation).count() == int(observed)
            assert _db.session.query(Scan).count() == int(observed)

    @pytest.mark.parametrize("origin,status", [
        ("custom", "under_investigation"),
        ("scc", "fixed"),
    ])
    def test_failure_cleanup_preserves_edited_adopted_assessment(self, app, origin, status):
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            pkg = _make_packages([("openssl", "1.1.1")])[0]
            variant_id, package_id = variant.id, pkg.id
            failure_cleanups = []
            first = tool_scan(variant_id, "scc", failure_cleanups=failure_cleanups)
            scan = first.__enter__()
            writer = _SccBulkWriter(
                scan.id, variant_id, [pkg], failure_cleanups=failure_cleanups,
            )
            _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
            writer.flush()
            pending_id = _db.session.query(Assessment).one().id

        with app.app_context():
            failure_cleanups = []
            with pytest.raises(KeyboardInterrupt):
                with tool_scan(variant_id, "nvd", failure_cleanups=failure_cleanups) as scan:
                    pkg = _db.session.get(Package, package_id)
                    writer = _SccBulkWriter(
                        scan.id, variant_id, [pkg], failure_cleanups=failure_cleanups,
                    )
                    _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
                    writer.flush()
                    with app.app_context():
                        error = KeyboardInterrupt()
                        assert first.__exit__(type(error), error, None) is False
                    pending = _db.session.get(Assessment, pending_id)
                    pending.origin, pending.status = origin, status
                    _db.session.commit()
                    raise KeyboardInterrupt

            retained = _db.session.query(Assessment).one()
            assert (retained.id, retained.origin, retained.status) == (pending_id, origin, status)
            assert retained.provisional_scan_id is None
            assert _db.session.query(AssessmentTarget).count() == 1
            assert _db.session.query(Observation).count() == 0
            assert _db.session.query(Scan).count() == 0

    def test_failure_cleanup_removes_pending_assessment_seen_only_by_other_variant(self, app):
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            other_variant = Variant.create("W", project.id)
            pkg = _make_packages([("openssl", "1.1.1")])[0]
            variant_id, other_variant_id = variant.id, other_variant.id
            failure_cleanups = []

            with pytest.raises(KeyboardInterrupt):
                with tool_scan(variant_id, "scc", failure_cleanups=failure_cleanups) as scan:
                    writer = _SccBulkWriter(
                        scan.id, variant_id, [pkg], failure_cleanups=failure_cleanups,
                    )
                    _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
                    writer.flush()
                    finding_id = _db.session.query(Finding).one().id

                    with app.app_context():
                        with tool_scan(other_variant_id, "osv") as other_scan:
                            _persist_finding(
                                pkg.id, "CVE-2023-0001", other_scan.id, other_variant_id,
                                "osv", set(), set(),
                            )
                    raise KeyboardInterrupt

            assert _assessments_for(finding_id, variant_id).count() == 0
            assert _assessments_for(finding_id, other_variant_id).count() == 1

    def test_failure_cleanup_ownership_memory_stays_bounded_across_flushes(self, app, monkeypatch):
        monkeypatch.setattr(_SccBulkWriter, "FLUSH_THRESHOLD", 1000)
        cves = [_Computed(f"CVE-2023-{i:04d}") for i in range(100)]
        findings_per_run = 100 * len(cves)

        def run(variant_id, scan_id, prefix, track, writers):
            pkgs = _make_packages([(f"{prefix}-{i}", "1.0") for i in range(100)])
            gc.collect()
            before = tracemalloc.get_traced_memory()[0]
            writer = _SccBulkWriter(
                scan_id, variant_id, pkgs, failure_cleanups=[] if track else None,
            )
            for pkg in pkgs:
                _scan_pkg(writer, pkg, [(computed, "affected") for computed in cves])
                writer.maybe_flush()
            writer.flush()
            writers.append(writer)
            gc.collect()
            return tracemalloc.get_traced_memory()[0] - before

        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("s", variant.id, scan_type="tool")
            writers = []
            tracemalloc.start()
            try:
                run(variant.id, scan.id, "warmup", True, writers)
                untracked = run(variant.id, scan.id, "untracked", False, writers)
                tracked = run(variant.id, scan.id, "tracked", True, writers)
            finally:
                tracemalloc.stop()

            assert _db.session.query(Finding).count() == 3 * findings_per_run
            # In-memory ownership lists would retain at least one pointer, and
            # a UUID object per created assessment, for every created row.
            assert tracked - untracked < findings_per_run * 8

    def test_failure_cleanup_removes_rows_from_every_flushed_chunk(self, app, monkeypatch):
        monkeypatch.setattr(_SccBulkWriter, "FLUSH_THRESHOLD", 3)
        monkeypatch.setattr(_SccBulkWriter, "_SELECT_CHUNK", 4)
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            pkgs = _make_packages([(f"pkg-{i}", "1.0") for i in range(10)])
            variant_id = variant.id
            failure_cleanups = []

            with pytest.raises(KeyboardInterrupt):
                with tool_scan(variant_id, "scc", failure_cleanups=failure_cleanups) as scan:
                    writer = _SccBulkWriter(
                        scan.id, variant_id, pkgs, failure_cleanups=failure_cleanups,
                    )
                    for pkg in pkgs:
                        _scan_pkg(writer, pkg, [
                            (_Computed("CVE-2023-0001"), "affected"),
                            (_Computed("CVE-2023-0002"), "affected"),
                        ])
                        writer.maybe_flush()
                    assert _db.session.query(Finding).count() > 2 * _SccBulkWriter._SELECT_CHUNK
                    raise KeyboardInterrupt

            assert _db.session.query(Finding).count() == 0
            assert _db.session.query(Assessment).count() == 0
            assert _db.session.query(AssessmentTarget).count() == 0
            assert _db.session.query(Observation).count() == 0
            assert _db.session.query(Scan).count() == 0

    def test_kernel_explosion_persists_once_per_package_cve(self, app):
        """Many sibling packages sharing the same CVE set each get their own
        finding, observation, and exact-target pending assessment."""
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

            # 5 packages x 2 CVEs = 10 findings / observations.
            assert _db.session.query(Finding).count() == 10
            assert _db.session.query(Observation).count() == 10
            # Every discovered package/CVE target starts pending, otherwise the
            # unassessed package rows would remain unknown in this variant.
            assert _db.session.query(Assessment).count() == 10

            # Every observation belongs to this scan; every assessment to variant.
            assert all(o.scan_id == scan.id
                       for o in _db.session.query(Observation).all())
            assert all(
                all(t.variant_id == variant.id for t in a.target_rows) and a.origin == "scc"
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
                status="affected", targets=[(variant.id, existing.id)],
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
            assert _assessments_for(existing_fid, variant.id).count() == 1
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

    def test_existing_variant_cve_gets_pending_on_new_package_finding(self, app):
        """A new package finding gets pending even when its CVE is already known
        in the variant through another package."""
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)

            old_scan = Scan.create("old", variant.id, scan_type="tool")
            new_scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg_old, pkg_new = _make_packages([
                ("openssl", "1.1.1"),
                ("openssl", "3.0.0"),
            ])

            # Existing CVE already present in this variant via an older package.
            old_finding = Finding.create(pkg_old.id, "CVE-2023-0001", commit=False)
            Observation.create(finding_id=old_finding.id, scan_id=old_scan.id, commit=False)
            Assessment.create(
                status="not_affected",
                targets=[(variant.id, old_finding.id)],
                origin="manual",
                commit=False,
            )
            _db.session.commit()

            writer = _SccBulkWriter(new_scan.id, variant.id, [pkg_new])
            _scan_pkg(writer, pkg_new, [(_Computed("CVE-2023-0001"), "affected")])
            writer.flush()

            # New finding for the second package exists.
            new_finding = _db.session.query(Finding).filter_by(
                package_id=pkg_new.id,
                vulnerability_id="CVE-2023-0001",
            ).one()

            assessment = _assessments_for(new_finding.id, variant.id).one()
            assert assessment.status == "under_investigation"
            assert assessment.simplified_status == "Pending Assessment"
            assert assessment.origin == "scc"

    def test_not_affected_and_fixed_are_persisted_as_pending_for_new_cves(self, app):
        """For new CVEs, one pending assessment is created per new vulnerability
        regardless of the engine verdict."""
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
                a.target_rows[0].finding.vulnerability_id: a.status
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
                status="exploitable", targets=[(variant.id, existing.id)],
                origin="manual", commit=False,
            )
            _db.session.commit()

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
            writer.flush()

            # No new assessment: the engine verdict matches the recorded state.
            assert _assessments_for(existing.id, variant.id).count() == 1
            # The scan still observed the finding.
            assert _db.session.query(Observation).filter_by(
                finding_id=existing.id, scan_id=scan.id).count() == 1

    def test_existing_finding_without_assessment_gets_pending(self, app):
        """A reused global finding gets pending when this variant has no status."""
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

            assessment = _assessments_for(existing_fid, variant.id).one()
            assert assessment.status == "under_investigation"
            assert assessment.simplified_status == "Pending Assessment"
            assert assessment.origin == "scc"
            # The scan still recorded the observation.
            assert _db.session.query(Observation).filter_by(
                finding_id=existing_fid, scan_id=scan.id).count() == 1

    def test_finding_assessed_in_another_variant_gets_pending(self, app):
        """A globally reused finding still gets a target assessment in a newly
        scanned variant.

        Findings are shared by package/CVE. Assessment targets are not: an
        assessment for v1 must never suppress the fallback status for v2.
        """
        with app.app_context():
            project = Project.create("P")
            variant_1 = Variant.create("V1", project.id)
            variant_2 = Variant.create("V2", project.id)
            old_scan = Scan.create("scc", variant_1.id, scan_type="tool")
            new_scan = Scan.create("scc", variant_2.id, scan_type="tool")
            pkg = _make_packages([("curl", "8.0")])[0]

            finding = Finding.create(pkg.id, "CVE-2023-0001", commit=False)
            Observation.create(
                finding_id=finding.id, scan_id=old_scan.id, commit=False)
            Assessment.create(
                status="under_investigation",
                simplified_status="Pending Assessment",
                targets=[(variant_1.id, finding.id)],
                origin="scc",
                commit=False,
            )
            _db.session.commit()

            writer = _SccBulkWriter(new_scan.id, variant_2.id, [pkg])
            _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
            writer.flush()

            assert _assessments_for(finding.id, variant_1.id).count() == 1
            assessment_v2 = _assessments_for(finding.id, variant_2.id).one()
            assert assessment_v2.status == "under_investigation"
            assert assessment_v2.simplified_status == "Pending Assessment"
            assert assessment_v2.origin == "scc"
            assert [(target.variant_id, target.finding_id)
                    for target in assessment_v2.target_rows] == [
                        (variant_2.id, finding.id)
                    ]

    def test_changed_status_writes_no_new_assessment_if_one_exists(self, app):
        """When a finding already has an assessment the sbom-cve-check-scan leaves it
        untouched, regardless of the engine's current verdict."""
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("curl", "8.0")])[0]

            existing = Finding.create(pkg.id, "CVE-2023-0001", commit=False)
            Assessment.create(
                status="not_affected", targets=[(variant.id, existing.id)],
                origin="manual", commit=False,
            )
            _db.session.commit()

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
            writer.flush()

            # Assessment count must remain 1 — the existing one is preserved.
            assessments = list(_assessments_for(existing.id, variant.id))
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

    def test_new_pending_assessment_gets_an_assessment_target_row(self, app):
        """The bulk-inserted 'Pending Assessment' must carry its own
        assessment_targets row.

        ``bulk_insert_mappings`` bypasses ``Assessment.create()``'s dual
        write entirely, so without an explicit insert here the new
        assessment would be invisible to every target-based query (scan
        diffs, outdated-assessment cleanup, ...).
        """
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("openssl", "1.1.1")])[0]

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
            writer.flush()

            assessment = _db.session.query(Assessment).one()
            target = _db.session.query(AssessmentTarget).one()
            assert target.assessment_id == assessment.id
            assert target.variant_id == variant.id
            assert target.finding_id == assessment.target_rows[0].finding_id

    def test_new_pending_assessment_preserves_creation_timestamp(self, app):
        with app.app_context():
            project = Project.create("P")
            variant = Variant.create("V", project.id)
            scan = Scan.create("scc", variant.id, scan_type="tool")
            pkg = _make_packages([("openssl", "1.1.1")])[0]

            writer = _SccBulkWriter(scan.id, variant.id, [pkg])
            _scan_pkg(writer, pkg, [(_Computed("CVE-2023-0001"), "affected")])
            writer.flush()

            assessment = _db.session.query(Assessment).one()
            assert assessment.created_at == assessment.timestamp


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

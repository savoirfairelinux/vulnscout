# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests covering uncovered lines in _scan_cache.py and _scan_diff.py.

Targets:
  _scan_cache.py  lines 43, 49, 56-58, 83-88, 126-128, 152-154
  _scan_diff.py   lines 119, 126, 262, 327, 357, 392-393, 444-445
"""

import json
import uuid
import pytest
from unittest.mock import patch, MagicMock

from sqlalchemy.exc import OperationalError

from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_db(app):
    """Populate DB with two SBOM scans + one tool scan.

    Layout
    ------
    Project / Variant
        sbom_scan_a  (first SBOM)
            openssl@1.1.0  → CVE-2020-0001
            kernel@6.12    → (SBOM package, will be removed in sbom B)
        tool_scan    (tool scan, source=nvd, BETWEEN the two SBOMs)
            kernel@6.12    → CVE-2021-8888  (tool finding on soon-removed pkg)
            openssl@1.1.1  → CVE-2021-9999  (tool finding on new-version pkg)
        sbom_scan_b  (second SBOM – upgrades openssl, removes kernel)
            openssl@1.1.1  → CVE-2020-0001  (same vuln, upgraded pkg)
    """
    import time
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    from src.models.observation import Observation

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        project = Project.create("CacheProject")
        variant = Variant.create("CacheVariant", project.id)

        # --- First SBOM scan ---
        sbom_a = Scan.create("sbom A", variant.id, scan_type="sbom")
        pkg_old = Package.find_or_create("openssl", "1.1.0")
        pkg_removed = Package.find_or_create("kernel", "6.12")
        vuln = Vulnerability.create_record(
            id="CVE-2020-0001", description="test vuln"
        )
        finding_old = Finding.get_or_create(pkg_old.id, vuln.id)
        _db.session.commit()

        doc_a = SBOMDocument.create("/a/sbom.json", "spdx", sbom_a.id)
        SBOMPackage.create(doc_a.id, pkg_old.id)
        SBOMPackage.create(doc_a.id, pkg_removed.id)
        Observation.create(finding_id=finding_old.id, scan_id=sbom_a.id)
        _db.session.commit()

        # Small delay so tool_scan.timestamp > sbom_a.timestamp
        time.sleep(0.05)

        # --- Tool scan (between the two SBOMs) ---
        tool_scan = Scan.create("NVD scan", variant.id, scan_type="tool")
        tool_scan.scan_source = "nvd"
        vuln_tool = Vulnerability.create_record(
            id="CVE-2021-9999", description="tool vuln"
        )
        vuln_tool_removed = Vulnerability.create_record(
            id="CVE-2021-8888", description="tool vuln on removed pkg"
        )
        pkg_new = Package.find_or_create("openssl", "1.1.1")
        finding_tool = Finding.get_or_create(pkg_new.id, vuln_tool.id)
        finding_tool_removed = Finding.get_or_create(
            pkg_removed.id, vuln_tool_removed.id)
        _db.session.commit()

        Observation.create(finding_id=finding_tool.id, scan_id=tool_scan.id)
        Observation.create(
            finding_id=finding_tool_removed.id, scan_id=tool_scan.id)
        _db.session.commit()

        # Small delay so sbom_b.timestamp > tool_scan.timestamp
        time.sleep(0.05)

        # --- Second SBOM scan (package upgrade, kernel removed) ---
        sbom_b = Scan.create("sbom B", variant.id, scan_type="sbom")
        finding_new = Finding.get_or_create(pkg_new.id, vuln.id)
        _db.session.commit()

        doc_b = SBOMDocument.create("/b/sbom.json", "spdx", sbom_b.id)
        SBOMPackage.create(doc_b.id, pkg_new.id)
        Observation.create(finding_id=finding_new.id, scan_id=sbom_b.id)
        _db.session.commit()

        return {
            "project_id": str(project.id),
            "variant_id": str(variant.id),
            "sbom_a_id": str(sbom_a.id),
            "sbom_b_id": str(sbom_b.id),
            "tool_scan_id": str(tool_scan.id),
            "pkg_old_id": str(pkg_old.id),
            "pkg_new_id": str(pkg_new.id),
            "pkg_removed_id": str(pkg_removed.id),
        }


@pytest.fixture()
def app(tmp_path):
    import os
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True, "SCAN_FILE": str(scan_file),
        })
        ids = _build_db(application)
        application._test_ids = ids
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def ids(app):
    return app._test_ids


# ===================================================================
# _scan_cache.py — OperationalError fallback paths
# ===================================================================

class TestScanCacheErrorPaths:
    """Cover OperationalError handlers and edge cases in _scan_cache.py."""

    def test_store_cache_empty(self, app):
        """_store_cache([]) returns immediately (line 49)."""
        from src.routes._scan_cache import _store_cache
        with app.app_context():
            _store_cache([])  # no-op, no error

    def test_store_cache_operational_error_recreates_table(self, app, ids):
        """When _store_cache hits OperationalError it recreates the table (lines 56-58)."""
        from src.routes._scan_cache import _store_cache, _ensure_cache_table
        from src.models.scan_diff_cache import ScanDiffCache

        with app.app_context():
            # Drop the cache table to force OperationalError
            ScanDiffCache.__table__.drop(_db.engine, checkfirst=True)  # type: ignore[attr-defined]
            # _store_cache should recover by recreating the table
            _store_cache([{
                "id": ids["sbom_a_id"],
                "finding_count": 1,
                "package_count": 1,
                "vuln_count": 1,
                "is_first": True,
            }])
            # Verify the row was inserted after table recreation
            row = _db.session.execute(
                _db.select(ScanDiffCache)
                .where(ScanDiffCache.scan_id == uuid.UUID(ids["sbom_a_id"]))
            ).scalar_one_or_none()
            assert row is not None
            assert row.finding_count == 1

    def test_read_cache_operational_error_recreates_table(self, app, ids):
        """When _read_cache hits OperationalError it recreates table & returns None (lines 83-88)."""
        from src.routes._scan_cache import _read_cache
        from src.models.scan import Scan
        from src.models.scan_diff_cache import ScanDiffCache

        with app.app_context():
            # Drop cache table
            ScanDiffCache.__table__.drop(_db.engine, checkfirst=True)  # type: ignore[attr-defined]
            scans = Scan.get_by_variant_id(uuid.UUID(ids["variant_id"]))
            result = _read_cache(scans)
            # Should return None (cache miss) and not crash
            assert result is None

    def test_recompute_empty_variant_operational_error(self, app):
        """recompute_variant_cache handles OperationalError for empty variant (lines 126-128)."""
        from src.routes._scan_cache import recompute_variant_cache
        from src.models.scan_diff_cache import ScanDiffCache

        fake_variant = uuid.uuid4()
        with app.app_context():
            # Drop cache table to trigger OperationalError
            ScanDiffCache.__table__.drop(_db.engine, checkfirst=True)  # type: ignore[attr-defined]
            # Should not crash
            recompute_variant_cache(fake_variant)

    def test_invalidate_variant_cache_operational_error(self, app, ids):
        """invalidate_variant_cache handles OperationalError (lines 152-154)."""
        from src.routes._scan_cache import invalidate_variant_cache
        from src.models.scan_diff_cache import ScanDiffCache

        with app.app_context():
            # Drop cache table to trigger OperationalError
            ScanDiffCache.__table__.drop(_db.engine, checkfirst=True)  # type: ignore[attr-defined]
            # Should not crash
            invalidate_variant_cache(uuid.UUID(ids["variant_id"]))

    def test_ensure_cache_table_called(self, app):
        """_ensure_cache_table creates the table without error (line 43)."""
        from src.routes._scan_cache import _ensure_cache_table
        from src.models.scan_diff_cache import ScanDiffCache

        with app.app_context():
            # Ensure table exists (idempotent)
            _ensure_cache_table()
            # Drop and recreate
            ScanDiffCache.__table__.drop(_db.engine, checkfirst=True)  # type: ignore[attr-defined]
            _ensure_cache_table()
            # Table should be usable now
            rows = _db.session.execute(
                _db.select(ScanDiffCache)
            ).scalars().all()
            assert rows == []


# ===================================================================
# _scan_diff.py — _classify_finding_changes with upgrade matches
# ===================================================================

class TestClassifyFindingChangesUpgrade:
    """Cover lines 119 and 126 in _scan_diff.py — finding upgrade matching."""

    def test_finding_upgraded_via_package_upgrade(self, app, ids):
        """When a finding moves from old_pkg to new_pkg for the same vuln, it's upgraded."""
        from src.routes._scan_diff import _classify_finding_changes
        from src.models.package import Package

        with app.app_context():
            old_pkg = _db.session.get(Package, uuid.UUID(ids["pkg_old_id"]))
            new_pkg = _db.session.get(Package, uuid.UUID(ids["pkg_new_id"]))

            findings_added = [{
                "finding_id": "f-new",
                "package_id": str(new_pkg.id),
                "package_name": "openssl",
                "package_version": "1.1.1",
                "vulnerability_id": "CVE-2020-0001",
                "origin": "SBOM",
            }]
            findings_removed = [{
                "finding_id": "f-old",
                "package_id": str(old_pkg.id),
                "package_name": "openssl",
                "package_version": "1.1.0",
                "vulnerability_id": "CVE-2020-0001",
                "origin": "SBOM",
            }]
            upgraded_pairs = [(old_pkg, new_pkg)]

            truly_add, truly_rem, upgraded, upgraded_keys = _classify_finding_changes(
                findings_added, findings_removed, upgraded_pairs,
            )
            assert len(upgraded) == 1
            assert upgraded[0]["vulnerability_id"] == "CVE-2020-0001"
            assert upgraded[0]["old_version"] == "1.1.0"
            assert upgraded[0]["new_version"] == "1.1.1"
            assert len(truly_add) == 0
            assert len(truly_rem) == 0
            assert ("CVE-2020-0001", str(old_pkg.id)) in upgraded_keys


# ===================================================================
# _scan_diff.py — _global_result_id_sets with sbom_scan=None
# ===================================================================

class TestGlobalResultIdSetsNone:
    """Cover line 262: _global_result_id_sets returns empty when sbom is None."""

    def test_returns_empty_when_sbom_none(self, app):
        from src.routes._scan_diff import _global_result_id_sets
        with app.app_context():
            fids, vids, pkg_ids = _global_result_id_sets(None, {})
            assert fids == set()
            assert vids == set()
            assert pkg_ids == set()


# ===================================================================
# _scan_diff.py — _contributing_scans_before for tool scan (line 327)
# ===================================================================

class TestContributingScansBefore:
    """Cover line 327: _contributing_scans_before for a tool scan."""

    def test_tool_scan_before(self, app, ids):
        """_contributing_scans_before on a tool scan yields the SBOM active at that time."""
        from src.routes._scan_diff import _contributing_scans_before
        from src.models.scan import Scan
        from src.controllers.scans import ScanController

        with app.app_context():
            tool_scan = _db.session.get(Scan, uuid.UUID(ids["tool_scan_id"]))
            all_scans = ScanController.get_all()
            sbom_before, tools_before = _contributing_scans_before(tool_scan, all_scans)
            # Should find the latest SBOM at or before tool scan's timestamp
            assert sbom_before is not None
            assert (sbom_before.scan_type or "sbom") == "sbom"
            # tools_before dict should NOT include the tool_scan itself
            for t in tools_before.values():
                assert t.id != tool_scan.id


# ===================================================================
# _scan_diff.py — _global_result_full with sbom_scan=None (line 357)
# ===================================================================

class TestGlobalResultFullNone:
    """Cover line 357: _global_result_full returns empty when no SBOM baseline."""

    def test_returns_empty_when_no_sbom(self, app):
        """A scan on a variant with no SBOM scan returns empty global result."""
        from src.routes._scan_diff import _global_result_full
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan

        with app.app_context():
            project = Project.create("EmptyProject")
            variant = Variant.create("EmptyVariant", project.id)
            tool_scan = Scan.create("empty description", variant.id, scan_type="tool")
            tool_scan.scan_source = "nvd"
            _db.session.commit()

            result = _global_result_full(tool_scan, [tool_scan])
            assert result["packages"] == []
            assert result["findings"] == []
            assert result["vulnerabilities"] == []
            assert result["package_count"] == 0


# ===================================================================
# _scan_diff.py — _global_result_full source labels (lines 392-393, 444-445)
# ===================================================================

class TestGlobalResultFullSources:
    """Cover source-label logic in _global_result_full."""

    def test_source_labels_on_findings(self, app, ids):
        """Findings in global result carry source labels (lines 392-393, 444-445)."""
        from src.routes._scan_diff import _global_result_full
        from src.models.scan import Scan
        from src.controllers.scans import ScanController

        with app.app_context():
            # Get the tool scan and compute its global result
            tool_scan = _db.session.get(Scan, uuid.UUID(ids["tool_scan_id"]))
            all_scans = ScanController.get_all()
            result = _global_result_full(tool_scan, all_scans)

            # Should have both SBOM and tool findings
            assert result["finding_count"] >= 2
            assert result["vuln_count"] >= 2

            # Each finding should have a "sources" list
            for f in result["findings"]:
                assert "sources" in f
                assert len(f["sources"]) >= 1

            # Each vulnerability should have a "sources" list
            for v in result["vulnerabilities"]:
                assert "sources" in v
                assert len(v["sources"]) >= 1

            # Packages should have "sources" containing the SBOM format
            for p in result["packages"]:
                assert "sources" in p
                assert len(p["sources"]) >= 1

    def test_sbom_source_label_contains_format(self, app, ids):
        """SBOM packages show 'source_name (format)' label (line 392-393)."""
        from src.routes._scan_diff import _global_result_full
        from src.models.scan import Scan
        from src.controllers.scans import ScanController

        with app.app_context():
            sbom_b = _db.session.get(Scan, uuid.UUID(ids["sbom_b_id"]))
            all_scans = ScanController.get_all()
            result = _global_result_full(sbom_b, all_scans)

            # At least one package source label should contain the format
            pkg_sources = []
            for p in result["packages"]:
                pkg_sources.extend(p["sources"])
            # Our SBOMDocument was created with format="spdx"
            assert any("spdx" in s for s in pkg_sources)


# ===================================================================
# _scan_diff.py — tool findings on removed packages must be "removed"
# ===================================================================

class TestToolFindingsOnRemovedPackages:
    """Regression: when an SBOM removes a package, tool-scan findings for
    that package must move to 'removed findings', not stay 'unchanged'.

    Scenario:
      SBOM A: pkg_old (kernel-image 6.12) → CVE-X
      NVD tool scan: pkg_old → CVE-X  (tool finding)
      SBOM B: pkg_new (linux-yocto 6.18) → CVE-X  (same vuln, new pkg)
              pkg_old is removed

    Expected diff on SBOM B:
      - CVE-X via pkg_new: Added finding
      - CVE-X via pkg_old (NVD): Removed finding  (NOT unchanged)
    """

    def test_tool_finding_for_removed_pkg_is_removed(self, app, ids):
        from src.routes._scan_diff import _serialize_list_with_diff
        from src.models.scan import Scan
        from src.controllers.scans import ScanController

        with app.app_context():
            scans = ScanController.get_all()  # chronological
            result = _serialize_list_with_diff(scans)

            # Find the second SBOM scan entry (sbom_b)
            sbom_b_entry = None
            for r in result:
                if r["id"] == ids["sbom_b_id"]:
                    sbom_b_entry = r
                    break
            assert sbom_b_entry is not None, "sbom_b not found in results"

            # The NVD tool finding for the removed package should NOT be in
            # unchanged — it should contribute to findings_removed.
            # Before fix: findings_removed was 0 and findings_unchanged
            # included the tool finding.
            assert sbom_b_entry["findings_removed"] >= 1, (
                f"Expected at least 1 removed finding (tool finding for "
                f"removed pkg), got {sbom_b_entry['findings_removed']}"
            )

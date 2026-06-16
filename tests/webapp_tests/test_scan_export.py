# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for scan export endpoints in src/routes/scans.py."""

import pytest
import json
import os
import uuid
from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_export_db(app):
    """Populate a Project → Variant → 2 SBOM Scans chain for export tests.

    Layout
    ------
    ExportProject / ExportVariant
        ScanA  (first SBOM, cairo@1.16.0, CVE-2020-35492)
        ScanB  (second SBOM, cairo@1.16.0 + libpng@1.6.37, CVE-2020-35492 + CVE-2019-7317)

    Returns UUID strings safe outside app context.
    """
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

        project = Project.create("ExportProject")
        variant = Variant.create("ExportVariant", project.id)

        scan_a = Scan.create("first scan", variant.id)
        scan_b = Scan.create("second scan", variant.id)

        pkg1 = Package.find_or_create("cairo", "1.16.0")
        pkg2 = Package.find_or_create("libpng", "1.6.37")
        vuln1 = Vulnerability.create_record(id="CVE-2020-35492", description="cairo vuln")
        vuln2 = Vulnerability.create_record(id="CVE-2019-7317", description="libpng vuln")
        finding1 = Finding.get_or_create(pkg1.id, vuln1.id)
        finding2 = Finding.get_or_create(pkg2.id, vuln2.id)
        _db.session.commit()

        # ScanA: one package, one finding
        sbom_a = SBOMDocument.create("/scan_a/sbom.json", "spdx", scan_a.id)
        SBOMPackage.create(sbom_a.id, pkg1.id)
        Observation.create(finding_id=finding1.id, scan_id=scan_a.id)

        # ScanB: two packages, two findings
        sbom_b = SBOMDocument.create("/scan_b/sbom.json", "spdx", scan_b.id)
        SBOMPackage.create(sbom_b.id, pkg1.id)
        SBOMPackage.create(sbom_b.id, pkg2.id)
        Observation.create(finding_id=finding1.id, scan_id=scan_b.id)
        Observation.create(finding_id=finding2.id, scan_id=scan_b.id)
        _db.session.commit()

        return {
            "project_id": str(project.id),
            "variant_id": str(variant.id),
            "scan_a_id": str(scan_a.id),
            "scan_b_id": str(scan_b.id),
        }


@pytest.fixture()
def app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        ids = _build_export_db(application)
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


# ---------------------------------------------------------------------------
# Export helper unit tests
# ---------------------------------------------------------------------------

class TestExportHelpers:

    def test_extract_supplier_name_strips_prefix_and_suffix(self):
        from src.routes.scans import _extract_supplier_name

        assert _extract_supplier_name("SPDX: Example Corp (contact@example.com)") == "Example Corp"

    def test_strip_helpers_include_supplier_when_present(self):
        from src.routes.scans import (
            _strip_finding,
            _strip_package,
            _strip_package_upgrade,
            _strip_finding_upgrade,
            _strip_assessment,
        )

        finding = _strip_finding({
            "vulnerability_id": "CVE-1",
            "package_name": "pkg",
            "package_version": "1.0",
            "package_supplier": "SPDX: Vendor (x)",
        })
        package = _strip_package({
            "package_name": "pkg",
            "package_version": "1.0",
            "package_supplier": "SPDX: Vendor (x)",
        })
        package_upgrade = _strip_package_upgrade({
            "package_name": "pkg",
            "old_version": "1.0",
            "new_version": "2.0",
            "package_supplier": "SPDX: Vendor (x)",
        })
        finding_upgrade = _strip_finding_upgrade({
            "vulnerability_id": "CVE-1",
            "package_name": "pkg",
            "old_version": "1.0",
            "new_version": "2.0",
            "package_supplier": "SPDX: Vendor (x)",
        })
        assessment = _strip_assessment({
            "vulnerability_id": "CVE-1",
            "status": "fixed",
            "simplified_status": "Done",
            "justification": "mitigated",
            "impact_statement": "none",
            "status_notes": "ok",
        })

        assert finding["supplier"] == "Vendor"
        assert package["supplier"] == "Vendor"
        assert package_upgrade["supplier"] == "Vendor"
        assert finding_upgrade["supplier"] == "Vendor"
        assert assessment["status"] == "fixed"

    def test_format_timestamp_for_filename_accepts_string(self):
        from src.routes.scans import _format_timestamp_for_filename

        assert _format_timestamp_for_filename("2025-01-02T03:04:05+00:00") == "20250102_030405"


# ---------------------------------------------------------------------------
# GET /api/scans/<scan_id>/export-diff
# ---------------------------------------------------------------------------

class TestExportScanDiff:
    def test_export_first_scan_diff(self, client, ids):
        """First scan export has no diff section, just current state."""
        r = client.get(f"/api/scans/{ids['scan_a_id']}/export-diff")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["scan_id"] == ids["scan_a_id"]
        assert data["scan_type"] == "import_sbom"
        assert data["project_name"] == "ExportProject"
        assert data["variant_name"] == "ExportVariant"
        assert "diff" not in data
        assert "vulnerabilities" in data
        assert "findings" in data
        assert "packages" in data

    def test_export_second_scan_diff(self, client, ids):
        """Second scan export includes a diff section."""
        r = client.get(f"/api/scans/{ids['scan_b_id']}/export-diff")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["scan_id"] == ids["scan_b_id"]
        assert "diff" in data
        diff = data["diff"]
        # libpng was added in scan_b
        added_pkgs = diff["packages_added"]
        added_pkg_names = [p["package_name"] for p in added_pkgs]
        assert "libpng" in added_pkg_names

    def test_export_diff_strips_internal_ids(self, client, ids):
        """Export should not contain package_id or finding_id fields."""
        r = client.get(f"/api/scans/{ids['scan_a_id']}/export-diff")
        data = json.loads(r.data)
        for f in data.get("findings", []):
            assert "finding_id" not in f
            assert "package_id" not in f

    def test_export_diff_has_content_disposition(self, client, ids):
        """Response includes Content-Disposition header for download."""
        r = client.get(f"/api/scans/{ids['scan_a_id']}/export-diff")
        assert r.status_code == 200
        cd = r.headers.get("Content-Disposition", "")
        assert "attachment" in cd
        assert "scan_diff_" in cd
        assert ".json" in cd

    def test_export_diff_invalid_id(self, client):
        """Invalid UUID returns 400."""
        r = client.get("/api/scans/not-a-uuid/export-diff")
        assert r.status_code == 400

    def test_export_diff_not_found(self, client):
        """Non-existent scan returns 404."""
        r = client.get(f"/api/scans/{uuid.uuid4()}/export-diff")
        assert r.status_code == 404

    def test_export_diff_includes_metadata(self, client, ids):
        """Export includes scan_source, variant_id, timestamp."""
        r = client.get(f"/api/scans/{ids['scan_a_id']}/export-diff")
        data = json.loads(r.data)
        assert "timestamp" in data
        assert data["variant_id"] == ids["variant_id"]


# ---------------------------------------------------------------------------
# GET /api/scans/<scan_id>/export-result
# ---------------------------------------------------------------------------

class TestExportScanResult:
    def test_export_result_basic(self, client, ids):
        """Export global result includes packages, findings, vulns."""
        r = client.get(f"/api/scans/{ids['scan_b_id']}/export-result")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["scan_id"] == ids["scan_b_id"]
        assert data["scan_type"] == "import_sbom"
        assert "packages" in data
        assert "findings" in data
        assert "vulnerabilities" in data
        assert "assessments" in data

    def test_export_result_strips_ids(self, client, ids):
        """Export should not contain internal IDs in packages/findings."""
        r = client.get(f"/api/scans/{ids['scan_b_id']}/export-result")
        data = json.loads(r.data)
        for p in data.get("packages", []):
            assert "package_id" not in p
        for f in data.get("findings", []):
            assert "finding_id" not in f
            assert "package_id" not in f

    def test_export_result_has_sources(self, client, ids):
        """Global result export includes source attribution."""
        r = client.get(f"/api/scans/{ids['scan_b_id']}/export-result")
        data = json.loads(r.data)
        for p in data.get("packages", []):
            assert "sources" in p
        for f in data.get("findings", []):
            assert "sources" in f

    def test_export_result_has_content_disposition(self, client, ids):
        """Response includes Content-Disposition header."""
        r = client.get(f"/api/scans/{ids['scan_b_id']}/export-result")
        assert r.status_code == 200
        cd = r.headers.get("Content-Disposition", "")
        assert "attachment" in cd
        assert "scan_total_" in cd

    def test_export_result_invalid_id(self, client):
        r = client.get("/api/scans/not-a-uuid/export-result")
        assert r.status_code == 400

    def test_export_result_not_found(self, client):
        r = client.get(f"/api/scans/{uuid.uuid4()}/export-result")
        assert r.status_code == 404

    def test_export_result_metadata(self, client, ids):
        """Export result has project/variant metadata."""
        r = client.get(f"/api/scans/{ids['scan_b_id']}/export-result")
        data = json.loads(r.data)
        assert data["project_name"] == "ExportProject"
        assert data["variant_name"] == "ExportVariant"


# ---------------------------------------------------------------------------
# GET /api/scans/export (batch)
# ---------------------------------------------------------------------------

class TestExportAllScans:
    def test_export_all_diff(self, client, ids):
        """Export all diffs returns a list with entries for each scan."""
        r = client.get("/api/scans/export?type=diff")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert isinstance(data, list)
        assert len(data) >= 2
        scan_ids = {d["scan_id"] for d in data}
        assert ids["scan_a_id"] in scan_ids
        assert ids["scan_b_id"] in scan_ids

    def test_export_all_total(self, client, ids):
        """Export all results returns a list."""
        r = client.get("/api/scans/export?type=total")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert isinstance(data, list)
        assert len(data) >= 2

    def test_export_all_by_variant(self, client, ids):
        """Filter by variant_id."""
        r = client.get(f"/api/scans/export?type=diff&variant_id={ids['variant_id']}")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert len(data) >= 2
        for d in data:
            assert d["variant_id"] == ids["variant_id"]

    def test_export_all_by_project(self, client, ids):
        """Filter by project_id."""
        r = client.get(f"/api/scans/export?type=diff&project_id={ids['project_id']}")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert len(data) >= 2

    def test_export_all_invalid_type(self, client):
        """Invalid type parameter returns 400."""
        r = client.get("/api/scans/export?type=invalid")
        assert r.status_code == 400

    def test_export_all_invalid_variant(self, client):
        """Invalid variant_id returns 400."""
        r = client.get("/api/scans/export?type=diff&variant_id=bad")
        assert r.status_code == 400

    def test_export_all_has_content_disposition(self, client):
        """Batch export includes Content-Disposition header."""
        r = client.get("/api/scans/export?type=diff")
        assert r.status_code == 200
        cd = r.headers.get("Content-Disposition", "")
        assert "attachment" in cd
        assert "scans_diff_" in cd

    def test_export_all_entries_have_no_internal_ids(self, client, ids):
        """Entries in batch export should not contain internal IDs."""
        r = client.get("/api/scans/export?type=diff")
        data = json.loads(r.data)
        for entry in data:
            for f in entry.get("findings", []):
                assert "finding_id" not in f
                assert "package_id" not in f

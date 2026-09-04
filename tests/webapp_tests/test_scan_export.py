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
        assert data["export_format"] == "scan-diff"
        assert data["export_version"] == 1
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
        assert data["export_format"] == "full-result"
        assert data["export_version"] == 1
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
# POST /api/scans/import
# ---------------------------------------------------------------------------

class TestImportScan:
    @staticmethod
    def _set_fresh_destination(app, *payloads):
        from src.models.project import Project
        from src.models.variant import Variant

        project_name = f"DestinationProject-{uuid.uuid4()}"
        variant_name = "DestinationVariant"
        with app.app_context():
            project = Project.create(project_name)
            Variant.create(variant_name, project.id)
        for payload in payloads:
            payload.update({
                "project_name": project_name,
                "variant_name": variant_name,
            })

    def test_imports_full_result(self, app, client, ids):
        from src.models.project import Project
        from src.models.variant import Variant

        payload = json.loads(client.get(
            f"/api/scans/{ids['scan_b_id']}/export-result"
        ).data)
        payload.update({
            "scan_id": str(uuid.uuid4()),
            "project_name": "DestinationProject",
            "variant_name": "DestinationVariant",
        })
        with app.app_context():
            project = Project.create("DestinationProject")
            Variant.create("DestinationVariant", project.id)

        response = client.post("/api/scans/import", json=payload)

        assert response.status_code == 201
        assert response.get_json()["format"] == "full"

    def test_imports_legacy_full_result(self, app, client, ids):
        payload = json.loads(client.get(
            f"/api/scans/{ids['scan_b_id']}/export-result"
        ).data)
        payload.pop("export_version")
        payload.pop("export_format")
        payload["scan_id"] = str(uuid.uuid4())
        self._set_fresh_destination(app, payload)

        response = client.post("/api/scans/import", json=payload)

        assert response.status_code == 201
        assert response.get_json()["format"] == "full"

    def test_imports_non_first_diff_from_its_top_level_state(self, app, client, ids):
        """A later scan's diff export carries its full state and imports fine.

        The ``diff`` block describes the *source* variant's history and is
        ignored: the destination recomputes its own diff.
        """
        from src.models.scan import Scan

        payload = json.loads(client.get(
            f"/api/scans/{ids['scan_b_id']}/export-diff"
        ).data)
        assert "diff" in payload  # precondition: this is not a first-scan export
        self._set_fresh_destination(app, payload)

        response = client.post("/api/scans/import", json=payload)

        assert response.status_code == 201
        body = response.get_json()
        assert body["format"] == "diff"
        # scan_b holds cairo + libpng, both of which must land in the copy.
        assert body["package_count"] == 2
        assert body["finding_count"] == 2
        assert body["is_first"] is True  # first scan in the empty destination
        with app.app_context():
            imported = _db.session.get(Scan, uuid.UUID(body["scan_id"]))
            assert {o.finding.package.name for o in imported.observations} == {
                "cairo", "libpng",
            }

    def test_imports_export_all_diffs(self, app, client, ids):
        """The Export All (diff) file round-trips through import as a whole."""
        payload = json.loads(client.get("/api/scans/export?type=diff").data)
        assert len(payload) >= 2
        self._set_fresh_destination(app, *payload)

        response = client.post("/api/scans/import", json=payload)

        assert response.status_code == 201
        assert response.get_json()["imported_count"] == len(payload)

    def test_import_diff_uses_current_state_and_skips_duplicate(self, app, client, ids):
        payload = json.loads(client.get(
            f"/api/scans/{ids['scan_a_id']}/export-diff"
        ).data)
        payload["scan_id"] = str(uuid.uuid4())
        self._set_fresh_destination(app, payload)

        response = client.post("/api/scans/import", json=payload)
        duplicate = client.post("/api/scans/import", json=payload)

        assert response.status_code == 201
        assert json.loads(response.data)["format"] == "diff"
        assert duplicate.status_code == 201
        assert json.loads(duplicate.data)["imported_count"] == 0
        assert json.loads(duplicate.data)["skipped_count"] == 1

    def test_imports_export_all_results(self, app, client, ids):
        payload = json.loads(client.get("/api/scans/export?type=total").data)
        for export in payload:
            export["scan_id"] = str(uuid.uuid4())
            export["assessments"] = []
        self._set_fresh_destination(app, *payload)

        response = client.post("/api/scans/import", json=payload)

        assert response.status_code == 201
        assert response.get_json()["imported_count"] == len(payload)

    def test_import_allows_json_larger_than_default_request_limit(self, app, client, ids):
        payload = json.loads(client.get(
            f"/api/scans/{ids['scan_a_id']}/export-diff"
        ).data)
        payload["scan_id"] = str(uuid.uuid4())
        payload["padding"] = "x" * app.config["MAX_CONTENT_LENGTH"]
        self._set_fresh_destination(app, payload)

        response = client.post("/api/scans/import", json=payload)

        assert response.status_code == 201

    def test_import_rejects_request_larger_than_import_limit(self, app, client):
        app.config["MAX_SCAN_IMPORT_CONTENT_LENGTH"] = 1

        response = client.post("/api/scans/import", json={})

        assert response.status_code == 413
        # The message reports the limit actually configured, not a constant.
        assert response.get_json() == {
            "error": "Scan import exceeds the 1 B size limit",
        }

    def test_import_needs_no_schema_change(self, app):
        """Import works against the schema as it already exists on disk.

        The importer identifies scans by their own content, so it must not
        depend on any column added for its benefit.
        """
        from src.models.scan import Scan

        with app.app_context():
            columns = set(Scan.__table__.columns.keys())
        assert columns == {
            "id", "description", "scan_type", "scan_source", "timestamp",
            "variant_id",
        }

    def test_import_rejects_malformed_json_body(self, client):
        response = client.post(
            "/api/scans/import",
            data="{not json",
            content_type="application/json",
        )

        assert response.status_code == 400
        assert "valid JSON" in response.get_json()["error"]

    def test_import_rolls_back_when_persistence_fails(
        self, app, client, ids, monkeypatch
    ):
        from src.models.scan import Scan

        payload = json.loads(client.get(
            f"/api/scans/{ids['scan_a_id']}/export-diff"
        ).data)
        self._set_fresh_destination(app, payload)

        def fail_persist(_item):
            raise RuntimeError("persistence failure")

        monkeypatch.setattr("src.routes.scans._persist_scan_import", fail_persist)

        with app.app_context():
            before = len(Scan.get_all())

        response = client.post("/api/scans/import", json=payload)

        assert response.status_code == 500
        assert response.get_json() == {"error": "Failed to import scan data"}
        with app.app_context():
            assert len(Scan.get_all()) == before

    def test_import_rejects_whole_batch_when_one_entry_is_invalid(self, app, client, ids):
        """A bad entry aborts the request and names its position."""
        from src.models.scan import Scan

        good = json.loads(client.get(
            f"/api/scans/{ids['scan_a_id']}/export-diff"
        ).data)
        other = json.loads(client.get(
            f"/api/scans/{ids['scan_b_id']}/export-diff"
        ).data)
        self._set_fresh_destination(app, good, other)
        broken = dict(other, timestamp="not-a-timestamp")

        with app.app_context():
            before = len(Scan.get_all())

        response = client.post("/api/scans/import", json=[good, broken])

        assert response.status_code == 400
        assert "Export #2 of 2" in response.get_json()["error"]
        with app.app_context():
            assert len(Scan.get_all()) == before

    def test_import_rejects_duplicate_entries_within_one_request(self, app, client, ids):
        payload = json.loads(client.get(
            f"/api/scans/{ids['scan_a_id']}/export-diff"
        ).data)
        self._set_fresh_destination(app, payload)

        response = client.post("/api/scans/import", json=[payload, payload])

        assert response.status_code == 409
        assert "appears more than once" in response.get_json()["error"]

    def test_import_rejects_too_many_exports(self, app, client, ids):
        payload = json.loads(client.get(
            f"/api/scans/{ids['scan_a_id']}/export-diff"
        ).data)
        self._set_fresh_destination(app, payload)

        response = client.post("/api/scans/import", json=[payload] * 201)

        assert response.status_code == 400
        assert "Too many exports" in response.get_json()["error"]

    def test_import_persists_assessments_without_duplicating_them(
        self, app, client, ids
    ):
        """Assessments are imported, and re-importing them adds no copies."""
        from src.models.assessment import Assessment
        from src.models.project import Project
        from src.models.variant import Variant

        payload = json.loads(client.get(
            f"/api/scans/{ids['scan_b_id']}/export-result"
        ).data)
        payload["assessments"] = [{
            "vulnerability_id": "CVE-2020-35492",
            "status": "fixed",
            "simplified_status": "fixed",
            "justification": "patched upstream",
            "impact_statement": "",
            "status_notes": "",
        }]
        self._set_fresh_destination(app, payload)

        first = client.post("/api/scans/import", json=payload)
        assert first.status_code == 201
        assert first.get_json()["assessment_count"] == 1

        def variant_assessments():
            from src.models.assessment_target import AssessmentTarget

            with app.app_context():
                project = Project.get_by_name(payload["project_name"])
                variant = Variant.get_by_name_and_project(
                    payload["variant_name"], project.id
                )
                return _db.session.execute(
                    _db.select(Assessment)
                    .join(AssessmentTarget, AssessmentTarget.assessment_id == Assessment.id)
                    .where(AssessmentTarget.variant_id == variant.id)
                ).scalars().unique().all()

        assert len(variant_assessments()) == 1

        # A genuinely different scan that re-states the same assessment: the
        # scan is new, the assessment is not, so only the scan is stored.
        second_payload = dict(
            payload, scan_id=str(uuid.uuid4()), timestamp="2027-03-04T05:06:07+00:00",
        )
        second = client.post("/api/scans/import", json=second_payload)

        assert second.status_code == 201
        assert second.get_json()["assessment_count"] == 0
        assert len(variant_assessments()) == 1

    def test_import_reuses_existing_packages_and_findings(self, app, client, ids):
        """Importing into a populated DB links to existing rows, not copies."""
        from src.models.finding import Finding
        from src.models.package import Package

        payload = json.loads(client.get(
            f"/api/scans/{ids['scan_b_id']}/export-result"
        ).data)
        self._set_fresh_destination(app, payload)
        with app.app_context():
            packages_before = len(Package.get_all())
            findings_before = len(Finding.get_all())

        assert client.post("/api/scans/import", json=payload).status_code == 201

        with app.app_context():
            assert len(Package.get_all()) == packages_before
            assert len(Finding.get_all()) == findings_before

    @pytest.mark.parametrize("payload, status", [
        ({}, 400),
        ({"scan_id": "not-a-uuid"}, 400),
        ({
            "export_format": "scan-diff",
            "export_version": 1,
            "scan_id": "00000000-0000-0000-0000-000000000001",
            "project_name": "Missing",
            "variant_name": "Missing",
            "scan_type": "import_sbom",
            "timestamp": "2026-01-01T00:00:00Z",
            "packages": [],
            "findings": [],
        }, 404),
    ])
    def test_import_rejects_invalid_payloads(self, client, payload, status):
        response = client.post("/api/scans/import", json=payload)

        assert response.status_code == status
        assert json.loads(response.data)["error"]

    def test_import_rejects_malformed_state_arrays_and_assessments(
        self, app, client, ids
    ):
        payload = json.loads(client.get(
            f"/api/scans/{ids['scan_a_id']}/export-diff"
        ).data)
        self._set_fresh_destination(app, payload)

        # An assessment missing its status, and one whose vulnerability has no
        # finding in this scan, are both rejected.
        no_status = dict(payload, assessments=[{"vulnerability_id": "CVE-1"}])
        unmatched = dict(payload, assessments=[
            {"vulnerability_id": "CVE-1", "status": "fixed"},
        ])
        missing_findings = dict(payload)
        del missing_findings["findings"]
        missing_packages = dict(payload)
        del missing_packages["packages"]

        assert client.post("/api/scans/import", json=no_status).status_code == 400
        unmatched_response = client.post("/api/scans/import", json=unmatched)
        assert unmatched_response.status_code == 400
        assert "no matching finding" in unmatched_response.get_json()["error"]
        assert client.post("/api/scans/import", json=missing_findings).status_code == 400
        assert client.post("/api/scans/import", json=missing_packages).status_code == 400


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

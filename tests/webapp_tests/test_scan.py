# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for src/routes/scans.py — covering all routes and helpers."""

import pytest
import json
import uuid
from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_scan_db(app):
    """Populate a full Project → Variant → Scan → Observation chain.

    Layout
    ------
    ProjectA / VariantA
        ScanA  (first, no prev)
        ScanB  (second, prev=ScanA)

    Each scan has:
      - One SBOMDocument with one SBOMPackage  (cairo@1.16.0)
      - One Observation → Finding → CVE-2020-35492

    Returns plain Python primitives (UUID strings) that survive outside the
    app context without DetachedInstanceError.
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

        project = Project.create("ScanTestProject")
        variant = Variant.create("ScanTestVariant", project.id)

        # Two sequential scans on the same variant
        scan_a = Scan.create("first scan", variant.id)
        scan_b = Scan.create("second scan", variant.id)

        # Package + vulnerability + finding (shared)
        pkg = Package.find_or_create("cairo", "1.16.0")
        vuln = Vulnerability.create_record(id="CVE-2020-35492", description="cairo vuln")
        finding = Finding.get_or_create(pkg.id, vuln.id)
        _db.session.commit()

        # SBOMDocument + SBOMPackage for each scan
        sbom_a = SBOMDocument.create("/scan_a/sbom.json", "grype", scan_a.id)
        SBOMPackage.create(sbom_a.id, pkg.id)
        sbom_b = SBOMDocument.create("/scan_b/sbom.json", "grype", scan_b.id)
        SBOMPackage.create(sbom_b.id, pkg.id)
        _db.session.commit()

        # Observations (link findings to scans)
        Observation.create(finding_id=finding.id, scan_id=scan_a.id)
        Observation.create(finding_id=finding.id, scan_id=scan_b.id)
        _db.session.commit()

        return {
            "project_id": str(project.id),
            "variant_id": str(variant.id),
            "scan_a_id": str(scan_a.id),
            "scan_b_id": str(scan_b.id),
        }


@pytest.fixture()
def app(tmp_path):
    import os
    # The middleware checks SCAN_FILE for '__END_OF_SCAN_SCRIPT__' before
    # forwarding any /api request; write the sentinel so routes are reachable.
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        ids = _build_scan_db(application)
        # Store IDs on the app so they're accessible in tests
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
# GET /api/scans
# ---------------------------------------------------------------------------

class TestListAllScans:
    def test_returns_list(self, client, ids):
        """GET /api/scans returns a JSON list with at least our two scans."""
        response = client.get("/api/scans")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert len(data) >= 2

    def test_scan_has_diff_fields(self, client, ids):
        """Scans include diff fields (finding_count, packages_added, etc.)."""
        response = client.get("/api/scans")
        data = json.loads(response.data)
        scan_ids = {d["id"] for d in data}
        assert ids["scan_a_id"] in scan_ids
        assert ids["scan_b_id"] in scan_ids

        # The second scan should have diff info (not is_first)
        scan_b = next(d for d in data if d["id"] == ids["scan_b_id"])
        assert "finding_count" in scan_b
        assert "package_count" in scan_b
        assert "vuln_count" in scan_b
        assert "findings_added" in scan_b

    def test_first_scan_is_first(self, client, ids):
        """The first scan has is_first=True and None diffs."""
        response = client.get("/api/scans")
        data = json.loads(response.data)
        scan_a = next(d for d in data if d["id"] == ids["scan_a_id"])
        assert scan_a["is_first"] is True
        assert scan_a["findings_added"] is None
        assert scan_a["findings_removed"] is None

    def test_second_scan_not_first(self, client, ids):
        """The second scan has integer diff values."""
        response = client.get("/api/scans")
        data = json.loads(response.data)
        scan_b = next(d for d in data if d["id"] == ids["scan_b_id"])
        assert scan_b["is_first"] is False
        assert isinstance(scan_b["findings_added"], int)
        assert isinstance(scan_b["findings_removed"], int)

    def test_scan_has_variant_and_project_name(self, client, ids):
        """Scans include variant_name and project_name populated from DB."""
        response = client.get("/api/scans")
        data = json.loads(response.data)
        scan_a = next(d for d in data if d["id"] == ids["scan_a_id"])
        assert scan_a["variant_name"] == "ScanTestVariant"
        assert scan_a["project_name"] == "ScanTestProject"

    def test_empty_db_returns_empty_list(self, app, client):
        """When no scans exist, GET /api/scans returns []."""
        with app.app_context():
            from src.models.scan import Scan
            from src.models.observation import Observation
            # Remove all observations first (FK), then scans
            for obs in _db.session.execute(_db.select(Observation)).scalars().all():
                _db.session.delete(obs)
            for scan in _db.session.execute(_db.select(Scan)).scalars().all():
                _db.session.delete(scan)
            _db.session.commit()
        response = client.get("/api/scans")
        assert response.status_code == 200
        assert json.loads(response.data) == []


# ---------------------------------------------------------------------------
# GET /api/projects/<project_id>/scans
# ---------------------------------------------------------------------------

class TestListScansByProject:
    def test_returns_scans_for_project(self, client, ids):
        """GET /api/projects/<id>/scans returns scans in that project."""
        response = client.get(f"/api/projects/{ids['project_id']}/scans")
        assert response.status_code == 200
        data = json.loads(response.data)
        scan_ids = {d["id"] for d in data}
        assert ids["scan_a_id"] in scan_ids

    def test_404_for_nonexistent_project(self, client):
        """GET /api/projects/<missing-id>/scans returns 404."""
        unknown = str(uuid.uuid4())
        response = client.get(f"/api/projects/{unknown}/scans")
        assert response.status_code == 404
        data = json.loads(response.data)
        assert "error" in data


# ---------------------------------------------------------------------------
# GET /api/variants/<variant_id>/scans
# ---------------------------------------------------------------------------

class TestListScansByVariant:
    def test_returns_scans_for_variant(self, client, ids):
        """GET /api/variants/<id>/scans returns scans in that variant."""
        response = client.get(f"/api/variants/{ids['variant_id']}/scans")
        assert response.status_code == 200
        data = json.loads(response.data)
        scan_ids = {d["id"] for d in data}
        assert ids["scan_a_id"] in scan_ids
        assert ids["scan_b_id"] in scan_ids

    def test_404_for_nonexistent_variant(self, client):
        """GET /api/variants/<missing-id>/scans returns 404."""
        unknown = str(uuid.uuid4())
        response = client.get(f"/api/variants/{unknown}/scans")
        assert response.status_code == 404
        data = json.loads(response.data)
        assert "error" in data


# ---------------------------------------------------------------------------
# PATCH /api/scans/<scan_id>
# ---------------------------------------------------------------------------

class TestUpdateScan:
    def test_update_description(self, client, ids):
        """PATCH /api/scans/<id> updates the description."""
        response = client.patch(
            f"/api/scans/{ids['scan_a_id']}",
            json={"description": "updated description"},
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["description"] == "updated description"

    def test_invalid_scan_id(self, client):
        """PATCH with a non-UUID scan_id returns 400."""
        response = client.patch("/api/scans/not-a-uuid", json={"description": "x"})
        assert response.status_code == 400
        assert "Invalid scan id" in json.loads(response.data)["error"]

    def test_missing_description_field(self, client, ids):
        """PATCH without 'description' in payload returns 400."""
        response = client.patch(
            f"/api/scans/{ids['scan_a_id']}",
            json={"other": "value"},
        )
        assert response.status_code == 400
        assert "description" in json.loads(response.data)["error"]

    def test_non_string_description(self, client, ids):
        """PATCH with non-string description returns 400."""
        response = client.patch(
            f"/api/scans/{ids['scan_a_id']}",
            json={"description": 42},
        )
        assert response.status_code == 400
        assert "description" in json.loads(response.data)["error"]

    def test_scan_not_found(self, client):
        """PATCH on a valid UUID that doesn't exist returns 404."""
        unknown = str(uuid.uuid4())
        response = client.patch(f"/api/scans/{unknown}", json={"description": "x"})
        assert response.status_code == 404
        assert "Scan not found" in json.loads(response.data)["error"]

    def test_no_body(self, client, ids):
        """PATCH with no JSON body returns 400."""
        response = client.patch(
            f"/api/scans/{ids['scan_a_id']}",
            data=b"",
            content_type="text/plain",
        )
        assert response.status_code in (400, 415)


# ---------------------------------------------------------------------------
# GET /api/scans/<scan_id>/diff
# ---------------------------------------------------------------------------

class TestGetScanDiff:
    def test_first_scan_diff(self, client, ids):
        """GET diff for the first scan: is_first=True, no removed."""
        response = client.get(f"/api/scans/{ids['scan_a_id']}/diff")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["is_first"] is True
        assert data["previous_scan_id"] is None
        assert isinstance(data["findings_added"], list)
        assert data["findings_removed"] == []
        assert isinstance(data["vulns_added"], list)
        assert data["vulns_removed"] == []

    def test_second_scan_diff(self, client, ids):
        """GET diff for the second scan: is_first=False, has previous_scan_id."""
        response = client.get(f"/api/scans/{ids['scan_b_id']}/diff")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["is_first"] is False
        assert data["previous_scan_id"] == ids["scan_a_id"]
        assert "findings_added" in data
        assert "findings_removed" in data
        assert "packages_added" in data
        assert "packages_removed" in data
        assert "vulns_added" in data
        assert "vulns_removed" in data

    def test_diff_finding_fields(self, client, ids):
        """Findings in diff have required keys."""
        response = client.get(f"/api/scans/{ids['scan_a_id']}/diff")
        data = json.loads(response.data)
        if data["findings_added"]:
            f = data["findings_added"][0]
            assert "finding_id" in f
            assert "package_name" in f
            assert "vulnerability_id" in f

    def test_diff_package_fields(self, client, ids):
        """Packages in diff have required keys."""
        response = client.get(f"/api/scans/{ids['scan_a_id']}/diff")
        data = json.loads(response.data)
        # First scan has all packages in packages_added
        if data["packages_added"]:
            p = data["packages_added"][0]
            assert "package_id" in p
            assert "package_name" in p
            assert "package_version" in p

    def test_diff_count_fields(self, client, ids):
        """Diff response includes finding_count, package_count, vuln_count."""
        response = client.get(f"/api/scans/{ids['scan_a_id']}/diff")
        data = json.loads(response.data)
        assert "finding_count" in data
        assert "package_count" in data
        assert "vuln_count" in data
        assert data["finding_count"] >= 0

    def test_invalid_scan_id(self, client):
        """GET diff with non-UUID scan_id returns 400."""
        response = client.get("/api/scans/not-a-uuid/diff")
        assert response.status_code == 400
        assert "Invalid scan id" in json.loads(response.data)["error"]

    def test_scan_not_found(self, client):
        """GET diff for a valid UUID that doesn't exist returns 404."""
        unknown = str(uuid.uuid4())
        response = client.get(f"/api/scans/{unknown}/diff")
        assert response.status_code == 404
        assert "Scan not found" in json.loads(response.data)["error"]

    def test_scan_id_in_response(self, client, ids):
        """The scan_id field in the response matches the requested scan."""
        response = client.get(f"/api/scans/{ids['scan_a_id']}/diff")
        data = json.loads(response.data)
        assert data["scan_id"] == ids["scan_a_id"]


# ---------------------------------------------------------------------------
# Helpers — standalone unit tests within app context
# ---------------------------------------------------------------------------

class TestHelperFunctions:
    def test_findings_by_scan_ids_empty(self, app):
        """_findings_by_scan_ids([]) returns empty dict."""
        from src.routes.scans import _findings_by_scan_ids
        with app.app_context():
            assert _findings_by_scan_ids([]) == {}

    def test_vulns_by_scan_ids_empty(self, app):
        """_vulns_by_scan_ids([]) returns empty dict."""
        from src.routes.scans import _vulns_by_scan_ids
        with app.app_context():
            assert _vulns_by_scan_ids([]) == {}

    def test_packages_by_scan_ids_empty(self, app):
        """_packages_by_scan_ids([]) returns empty dict."""
        from src.routes.scans import _packages_by_scan_ids
        with app.app_context():
            assert _packages_by_scan_ids([]) == {}

    def test_variant_info_empty(self, app):
        """_variant_info([]) returns empty dict."""
        from src.routes.scans import _variant_info
        with app.app_context():
            assert _variant_info([]) == {}

    def test_package_rows_empty(self, app):
        """_package_rows(set()) returns empty dict."""
        from src.routes.scans import _package_rows
        with app.app_context():
            assert _package_rows(set()) == {}

    def test_serialize_list_empty(self, app):
        """_serialize_list_with_diff([]) returns []."""
        from src.routes.scans import _serialize_list_with_diff
        with app.app_context():
            assert _serialize_list_with_diff([]) == []

    def test_prev_scan_map_single_scan(self, app, ids):
        """_prev_scan_map for a single scan returns {scan_id: None}."""
        from src.routes.scans import _prev_scan_map
        from src.models.scan import Scan
        with app.app_context():
            scan = _db.session.get(Scan, uuid.UUID(ids["scan_a_id"]))
            mapping = _prev_scan_map([scan])
            assert mapping[scan.id] is None

    def test_prev_scan_map_two_scans(self, app, ids):
        """_prev_scan_map for two scans links second to first."""
        from src.routes.scans import _prev_scan_map
        from src.models.scan import Scan
        from src.controllers.scans import ScanController
        with app.app_context():
            scans = ScanController.get_all()
            mapping = _prev_scan_map(scans)
            # One of them should have None (first) and one should point to the first
            has_none = any(v is None for v in mapping.values())
            has_prev = any(v is not None for v in mapping.values())
            assert has_none
            assert has_prev

    def test_findings_by_scan_ids_returns_data(self, app, ids):
        """_findings_by_scan_ids returns entries for known scan IDs."""
        from src.routes.scans import _findings_by_scan_ids
        with app.app_context():
            result = _findings_by_scan_ids([uuid.UUID(ids["scan_a_id"])])
            assert uuid.UUID(ids["scan_a_id"]) in result

    def test_vulns_by_scan_ids_returns_data(self, app, ids):
        """_vulns_by_scan_ids returns vuln IDs linked to observations."""
        from src.routes.scans import _vulns_by_scan_ids
        with app.app_context():
            result = _vulns_by_scan_ids([uuid.UUID(ids["scan_a_id"])])
            assert uuid.UUID(ids["scan_a_id"]) in result
            assert "CVE-2020-35492" in result[uuid.UUID(ids["scan_a_id"])]

    def test_packages_by_scan_ids_returns_data(self, app, ids):
        """_packages_by_scan_ids returns package IDs from sbom documents."""
        from src.routes.scans import _packages_by_scan_ids
        with app.app_context():
            result = _packages_by_scan_ids([uuid.UUID(ids["scan_a_id"])])
            assert uuid.UUID(ids["scan_a_id"]) in result
            assert len(result[uuid.UUID(ids["scan_a_id"])]) >= 1

    def test_variant_info_returns_names(self, app, ids):
        """_variant_info returns variant and project names."""
        from src.routes.scans import _variant_info
        with app.app_context():
            variant_uuid = uuid.UUID(ids["variant_id"])
            result = _variant_info([variant_uuid])
            assert variant_uuid in result
            vname, pname = result[variant_uuid]
            assert vname == "ScanTestVariant"
            assert pname == "ScanTestProject"

    def test_load_scan_with_findings(self, app, ids):
        """_load_scan_with_findings loads a scan with eager observations."""
        from src.routes.scans import _load_scan_with_findings
        with app.app_context():
            scan = _load_scan_with_findings(uuid.UUID(ids["scan_a_id"]))
            assert scan is not None
            assert len(list(scan.observations)) >= 1

    def test_load_scan_with_findings_not_found(self, app):
        """_load_scan_with_findings returns None for missing scan."""
        from src.routes.scans import _load_scan_with_findings
        with app.app_context():
            result = _load_scan_with_findings(uuid.uuid4())
            assert result is None

    def test_obs_to_dict(self, app, ids):
        """_obs_to_dict builds a dict with the right keys."""
        from src.routes.scans import _obs_to_dict, _load_scan_with_findings
        with app.app_context():
            scan = _load_scan_with_findings(uuid.UUID(ids["scan_a_id"]))
            obs = list(scan.observations)[0]
            d = _obs_to_dict(obs)
            assert "finding_id" in d
            assert "package_name" in d
            assert "package_version" in d
            assert "package_id" in d
            assert "vulnerability_id" in d

    def test_pkg_to_dict(self, app):
        """_pkg_to_dict serialises a Package into the expected shape."""
        from src.routes.scans import _pkg_to_dict
        from src.models.package import Package
        with app.app_context():
            pkg = Package("testpkg", "9.9.9")
            d = _pkg_to_dict(pkg)
            assert d["package_name"] == "testpkg"
            assert d["package_version"] == "9.9.9"
            assert "package_id" in d

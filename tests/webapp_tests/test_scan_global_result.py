# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for GET /api/scans/<scan_id>/global-result endpoint."""

import json
import uuid
import pytest

from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_global_result_db(app):
    """Populate DB with SBOM + tool scan for global-result testing."""
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

        project = Project.create("GlobalProject")
        variant = Variant.create("GlobalVariant", project.id)

        # SBOM scan with a package and a finding
        sbom_scan = Scan.create("SBOM scan", variant.id, scan_type="sbom")
        pkg = Package.find_or_create("openssl", "1.1.1")
        vuln_sbom = Vulnerability.create_record(
            id="CVE-2020-1111", description="sbom vuln"
        )
        finding_sbom = Finding.get_or_create(pkg.id, vuln_sbom.id)
        _db.session.commit()

        sbom_doc = SBOMDocument.create("/sbom/file.json", "spdx", sbom_scan.id)
        SBOMPackage.create(sbom_doc.id, pkg.id)
        Observation.create(finding_id=finding_sbom.id, scan_id=sbom_scan.id)
        _db.session.commit()

        # Tool scan with a different finding + reuses the same pkg
        tool_scan = Scan.create("empty description", variant.id, scan_type="tool")
        vuln_tool = Vulnerability.create_record(
            id="CVE-2021-2222", description="tool vuln"
        )
        finding_tool = Finding.get_or_create(pkg.id, vuln_tool.id)
        _db.session.commit()

        Observation.create(
            finding_id=finding_tool.id, scan_id=tool_scan.id
        )
        _db.session.commit()

        return {
            "project_id": str(project.id),
            "variant_id": str(variant.id),
            "sbom_scan_id": str(sbom_scan.id),
            "tool_scan_id": str(tool_scan.id),
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
        ids = _build_global_result_db(application)
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
# Tests
# ---------------------------------------------------------------------------

class TestGetScanGlobalResult:
    def test_invalid_scan_id(self, client):
        resp = client.get("/api/scans/not-a-uuid/global-result")
        assert resp.status_code == 400
        assert b"Invalid scan id" in resp.data

    def test_scan_not_found(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/scans/{fake_id}/global-result")
        assert resp.status_code == 404
        assert b"Scan not found" in resp.data

    def test_sbom_scan_global_result(self, client, ids):
        """For SBOM scan, merge result is just that scan's own data."""
        resp = client.get(
            f"/api/scans/{ids['sbom_scan_id']}/global-result"
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["scan_type"] == "sbom"
        assert data["package_count"] >= 1
        assert data["finding_count"] >= 1
        assert data["vuln_count"] >= 1
        # Should contain the SBOM finding
        vuln_ids = [v["vulnerability_id"] for v in data["vulnerabilities"]]
        assert "CVE-2020-1111" in vuln_ids

    def test_tool_scan_global_result(self, client, ids):
        """For tool scan, merge result = SBOM + tool scan union."""
        resp = client.get(
            f"/api/scans/{ids['tool_scan_id']}/global-result"
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["scan_type"] == "tool"
        # Should have union of both SBOM and tool findings
        vuln_ids = [v["vulnerability_id"] for v in data["vulnerabilities"]]
        assert "CVE-2020-1111" in vuln_ids
        assert "CVE-2021-2222" in vuln_ids
        # Packages should come from SBOM
        assert data["package_count"] >= 1

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for Grype / NVD / OSV scan trigger & status endpoints in scans.py."""

import pytest
import json
import uuid
from unittest.mock import patch, MagicMock

from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_scan_trigger_db(app):
    """Populate DB with packages that have CPE and PURL identifiers."""
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.package import Package

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        project = Project.create("TriggerProject")
        variant = Variant.create("TriggerVariant", project.id)

        scan = Scan.create("initial scan", variant.id, scan_type="sbom")

        # Package with valid CPE (vendor:product:version all non-*)
        pkg_with_cpe = Package.find_or_create(
            "openssl", "1.1.1",
            cpe=["cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"],
            purl=["pkg:generic/openssl/openssl@1.1.1"],
        )
        # Package with valid PURL (ecosystem-specific)
        pkg_with_purl = Package.find_or_create(
            "requests", "2.28.0",
            cpe=[],
            purl=["pkg:pypi/requests@2.28.0"],
        )
        # Package with no CPE or PURL
        pkg_plain = Package.find_or_create("mylib", "0.1.0")
        _db.session.commit()

        sbom = SBOMDocument.create("/test/sbom.json", "spdx", scan.id)
        SBOMPackage.create(sbom.id, pkg_with_cpe.id)
        SBOMPackage.create(sbom.id, pkg_with_purl.id)
        SBOMPackage.create(sbom.id, pkg_plain.id)
        _db.session.commit()

        return {
            "project_id": str(project.id),
            "variant_id": str(variant.id),
            "scan_id": str(scan.id),
            "pkg_cpe_id": str(pkg_with_cpe.id),
            "pkg_purl_id": str(pkg_with_purl.id),
            "pkg_plain_id": str(pkg_plain.id),
        }


@pytest.fixture()
def app(tmp_path):
    import os
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        ids = _build_scan_trigger_db(application)
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
# Grype scan — trigger
# ---------------------------------------------------------------------------

class TestTriggerGrypeScan:
    def test_invalid_variant_id(self, client):
        resp = client.post("/api/variants/not-a-uuid/grype-scan")
        assert resp.status_code == 400
        assert b"Invalid variant id" in resp.data

    def test_variant_not_found(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.post(f"/api/variants/{fake_id}/grype-scan")
        assert resp.status_code == 404
        assert b"Variant not found" in resp.data

    @patch("shutil.which", return_value=None)
    def test_grype_not_installed(self, mock_which, client, ids):
        resp = client.post(f"/api/variants/{ids['variant_id']}/grype-scan")
        assert resp.status_code == 503
        assert b"grype binary not found" in resp.data

    @patch("threading.Thread")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_scan_starts_successfully(self, mock_which, mock_thread, client, ids):
        mock_t = MagicMock()
        mock_thread.return_value = mock_t
        resp = client.post(f"/api/variants/{ids['variant_id']}/grype-scan")
        assert resp.status_code == 202
        data = json.loads(resp.data)
        assert data["status"] == "started"
        assert data["variant_id"] == ids["variant_id"]
        mock_t.start.assert_called_once()

    @patch("threading.Thread")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_scan_already_running(self, mock_which, mock_thread, client, ids):
        mock_t = MagicMock()
        mock_thread.return_value = mock_t
        # First scan starts
        resp1 = client.post(f"/api/variants/{ids['variant_id']}/grype-scan")
        assert resp1.status_code == 202
        # Second scan blocked
        resp2 = client.post(f"/api/variants/{ids['variant_id']}/grype-scan")
        assert resp2.status_code == 409
        assert b"already in progress" in resp2.data


# ---------------------------------------------------------------------------
# Grype scan — status
# ---------------------------------------------------------------------------

class TestGrypeScanStatus:
    def test_invalid_variant_id(self, client):
        resp = client.get("/api/variants/not-a-uuid/grype-scan/status")
        assert resp.status_code == 400
        assert b"Invalid variant id" in resp.data

    def test_idle_when_never_started(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/variants/{fake_id}/grype-scan/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "idle"

    @patch("threading.Thread")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_running_after_trigger(self, mock_which, mock_thread, client, ids):
        mock_t = MagicMock()
        mock_thread.return_value = mock_t
        client.post(f"/api/variants/{ids['variant_id']}/grype-scan")
        resp = client.get(f"/api/variants/{ids['variant_id']}/grype-scan/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "running"
        assert data["progress"] == "starting"
        assert data["logs"] == []
        assert data["total"] == 4
        assert data["done_count"] == 0


# ---------------------------------------------------------------------------
# NVD scan — trigger
# ---------------------------------------------------------------------------

class TestTriggerNvdScan:
    def test_invalid_variant_id(self, client):
        resp = client.post("/api/variants/not-a-uuid/nvd-scan")
        assert resp.status_code == 400
        assert b"Invalid variant id" in resp.data

    def test_variant_not_found(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.post(f"/api/variants/{fake_id}/nvd-scan")
        assert resp.status_code == 404
        assert b"Variant not found" in resp.data

    @patch("threading.Thread")
    def test_scan_starts_successfully(self, mock_thread, client, ids):
        mock_t = MagicMock()
        mock_thread.return_value = mock_t
        resp = client.post(f"/api/variants/{ids['variant_id']}/nvd-scan")
        assert resp.status_code == 202
        data = json.loads(resp.data)
        assert data["status"] == "started"
        assert data["variant_id"] == ids["variant_id"]
        mock_t.start.assert_called_once()

    @patch("threading.Thread")
    def test_scan_already_running(self, mock_thread, client, ids):
        mock_t = MagicMock()
        mock_thread.return_value = mock_t
        resp1 = client.post(f"/api/variants/{ids['variant_id']}/nvd-scan")
        assert resp1.status_code == 202
        resp2 = client.post(f"/api/variants/{ids['variant_id']}/nvd-scan")
        assert resp2.status_code == 409
        assert b"already in progress" in resp2.data


# ---------------------------------------------------------------------------
# NVD scan — status
# ---------------------------------------------------------------------------

class TestNvdScanStatus:
    def test_invalid_variant_id(self, client):
        resp = client.get("/api/variants/not-a-uuid/nvd-scan/status")
        assert resp.status_code == 400
        assert b"Invalid variant id" in resp.data

    def test_idle_when_never_started(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/variants/{fake_id}/nvd-scan/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "idle"

    @patch("threading.Thread")
    def test_running_after_trigger(self, mock_thread, client, ids):
        mock_t = MagicMock()
        mock_thread.return_value = mock_t
        client.post(f"/api/variants/{ids['variant_id']}/nvd-scan")
        resp = client.get(f"/api/variants/{ids['variant_id']}/nvd-scan/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "running"


# ---------------------------------------------------------------------------
# OSV scan — trigger
# ---------------------------------------------------------------------------

class TestTriggerOsvScan:
    def test_invalid_variant_id(self, client):
        resp = client.post("/api/variants/not-a-uuid/osv-scan")
        assert resp.status_code == 400
        assert b"Invalid variant id" in resp.data

    def test_variant_not_found(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.post(f"/api/variants/{fake_id}/osv-scan")
        assert resp.status_code == 404
        assert b"Variant not found" in resp.data

    @patch("threading.Thread")
    def test_scan_starts_successfully(self, mock_thread, client, ids):
        mock_t = MagicMock()
        mock_thread.return_value = mock_t
        resp = client.post(f"/api/variants/{ids['variant_id']}/osv-scan")
        assert resp.status_code == 202
        data = json.loads(resp.data)
        assert data["status"] == "started"
        assert data["variant_id"] == ids["variant_id"]
        mock_t.start.assert_called_once()

    @patch("threading.Thread")
    def test_scan_already_running(self, mock_thread, client, ids):
        mock_t = MagicMock()
        mock_thread.return_value = mock_t
        resp1 = client.post(f"/api/variants/{ids['variant_id']}/osv-scan")
        assert resp1.status_code == 202
        resp2 = client.post(f"/api/variants/{ids['variant_id']}/osv-scan")
        assert resp2.status_code == 409
        assert b"already in progress" in resp2.data


# ---------------------------------------------------------------------------
# OSV scan — status
# ---------------------------------------------------------------------------

class TestOsvScanStatus:
    def test_invalid_variant_id(self, client):
        resp = client.get("/api/variants/not-a-uuid/osv-scan/status")
        assert resp.status_code == 400
        assert b"Invalid variant id" in resp.data

    def test_idle_when_never_started(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/variants/{fake_id}/osv-scan/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "idle"

    @patch("threading.Thread")
    def test_running_after_trigger(self, mock_thread, client, ids):
        mock_t = MagicMock()
        mock_thread.return_value = mock_t
        client.post(f"/api/variants/{ids['variant_id']}/osv-scan")
        resp = client.get(f"/api/variants/{ids['variant_id']}/osv-scan/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "running"

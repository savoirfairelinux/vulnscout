# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests exercising the NVD and OSV scan *logic* (``_do_nvd_scan`` / ``_do_osv_scan``).

The inner helper functions are closures inside ``init_app``, so the cleanest
way to test them is to let the trigger endpoint run the thread target
synchronously (by making ``Thread.start()`` call ``target()`` immediately).
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from src.bin.webapp import create_app
from src.controllers.nvd_db import NVD_DB as _RealNvdDb
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_nvd_osv_db(app):
    """DB with packages carrying CPE and PURL identifiers."""
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.package import Package

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        project = Project.create("NvdOsvProject")
        variant = Variant.create("NvdOsvVariant", project.id)
        scan = Scan.create("base scan", variant.id, scan_type="sbom")

        pkg_cpe = Package.find_or_create(
            "openssl", "1.1.1",
            cpe=["cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"],
            purl=["pkg:pypi/openssl@1.1.1"],
        )
        pkg_purl = Package.find_or_create(
            "requests", "2.28.0",
            cpe=[],
            purl=["pkg:pypi/requests@2.28.0"],
        )
        pkg_neither = Package.find_or_create("bare", "0.1.0")
        _db.session.commit()

        sbom = SBOMDocument.create("/test/base.json", "spdx", scan.id)
        SBOMPackage.create(sbom.id, pkg_cpe.id)
        SBOMPackage.create(sbom.id, pkg_purl.id)
        SBOMPackage.create(sbom.id, pkg_neither.id)
        _db.session.commit()

        # Also create an empty variant (no scans) for error-path tests
        variant_empty = Variant.create("EmptyVariant", project.id)
        _db.session.commit()

        return {
            "project_id": str(project.id),
            "variant_id": str(variant.id),
            "variant_empty_id": str(variant_empty.id),
            "scan_id": str(scan.id),
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
        ids = _build_nvd_osv_db(application)
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


def _make_sync_thread_patch():
    """Return a patch that makes Thread.start() run target synchronously."""
    return patch(
        "threading.Thread",
        side_effect=lambda **kwargs: type(
            "SyncThread", (), {
                "_target": kwargs.get("target"),
                "start": lambda self: kwargs.get("target")(),
                "daemon": True,
            }
        )(),
    )


# ---------------------------------------------------------------------------
# _do_nvd_scan — full logic
# ---------------------------------------------------------------------------

class TestDoNvdScan:
    """Test the NVD scan logic end-to-end via synchronous thread execution."""

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_nvd_scan_finds_cves(self, MockNvdDb, app, client, ids):
        """Scan completes and creates findings for discovered CVEs."""
        mock_nvd = MagicMock()
        MockNvdDb.return_value = mock_nvd
        MockNvdDb.extract_cve_details = _RealNvdDb.extract_cve_details
        mock_nvd.api_get_cves_by_cpe.return_value = [
            {"cve": {"id": "CVE-2023-0001"}},
            {"cve": {"id": "CVE-2023-0002"}},
        ]

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{ids['variant_id']}/nvd-scan")
        assert resp.status_code == 202

        # Check the scan status was set to done
        resp_status = client.get(
            f"/api/variants/{ids['variant_id']}/nvd-scan/status"
        )
        data = json.loads(resp_status.data)
        assert data["status"] == "done"
        assert data["error"] is None
        assert data["total"] >= 1
        assert data["done_count"] >= 1

        # Verify CVEs were actually created in DB
        with app.app_context():
            from src.models.vulnerability import Vulnerability
            v1 = _db.session.get(Vulnerability, "CVE-2023-0001")
            v2 = _db.session.get(Vulnerability, "CVE-2023-0002")
            assert v1 is not None
            assert v2 is not None

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_nvd_scan_no_cves(self, MockNvdDb, app, client, ids):
        """No CVEs found — scan completes successfully with 0 CVEs."""
        mock_nvd = MagicMock()
        MockNvdDb.return_value = mock_nvd
        mock_nvd.api_get_cves_by_cpe.return_value = []

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{ids['variant_id']}/nvd-scan")
        assert resp.status_code == 202

        resp_status = client.get(
            f"/api/variants/{ids['variant_id']}/nvd-scan/status"
        )
        data = json.loads(resp_status.data)
        assert data["status"] == "done"
        assert "0 CVEs" in data["progress"]

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_nvd_scan_api_error_continues(self, MockNvdDb, app, client, ids):
        """API error on one CPE doesn't crash the whole scan."""
        mock_nvd = MagicMock()
        MockNvdDb.return_value = mock_nvd
        mock_nvd.api_get_cves_by_cpe.side_effect = Exception("NVD timeout")

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{ids['variant_id']}/nvd-scan")
        assert resp.status_code == 202

        resp_status = client.get(
            f"/api/variants/{ids['variant_id']}/nvd-scan/status"
        )
        data = json.loads(resp_status.data)
        # Should complete (done) — errors per CPE are logged but don't fail
        assert data["status"] == "done"
        any_error_log = any("ERROR" in log for log in data.get("logs", []))
        assert any_error_log

    def test_nvd_scan_empty_variant(self, app, client, ids):
        """Variant with no scans produces an error."""
        with _make_sync_thread_patch():
            resp = client.post(
                f"/api/variants/{ids['variant_empty_id']}/nvd-scan"
            )
        assert resp.status_code == 202

        resp_status = client.get(
            f"/api/variants/{ids['variant_empty_id']}/nvd-scan/status"
        )
        data = json.loads(resp_status.data)
        assert data["status"] == "error"
        assert "No scans found" in data["error"]


# ---------------------------------------------------------------------------
# _do_osv_scan — full logic
# ---------------------------------------------------------------------------

class TestDoOsvScan:
    """Test the OSV scan logic end-to-end via synchronous thread execution."""

    @patch("src.controllers.osv_client.OSVClient.query_by_purl")
    def test_osv_scan_finds_vulns(self, mock_query, app, client, ids):
        """Scan completes and creates findings for discovered vulns."""
        mock_query.return_value = [
            {"id": "GHSA-1234-5678", "aliases": ["CVE-2023-9999"]},
        ]

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{ids['variant_id']}/osv-scan")
        assert resp.status_code == 202

        resp_status = client.get(
            f"/api/variants/{ids['variant_id']}/osv-scan/status"
        )
        data = json.loads(resp_status.data)
        assert data["status"] == "done"
        assert data["error"] is None
        assert data["total"] >= 1

        # Verify vulns were created in DB
        with app.app_context():
            from src.models.vulnerability import Vulnerability
            v1 = _db.session.get(Vulnerability, "GHSA-1234-5678")
            assert v1 is not None
            # CVE alias should also be created
            v2 = _db.session.get(Vulnerability, "CVE-2023-9999")
            assert v2 is not None

    @patch("src.controllers.osv_client.OSVClient.query_by_purl")
    def test_osv_scan_no_vulns(self, mock_query, app, client, ids):
        """No vulns found — scan completes with 0."""
        mock_query.return_value = []

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{ids['variant_id']}/osv-scan")
        assert resp.status_code == 202

        resp_status = client.get(
            f"/api/variants/{ids['variant_id']}/osv-scan/status"
        )
        data = json.loads(resp_status.data)
        assert data["status"] == "done"
        assert "0 vulnerabilities" in data["progress"]

    @patch("src.controllers.osv_client.OSVClient.query_by_purl")
    def test_osv_scan_api_error_continues(self, mock_query, app, client, ids):
        """API error on one PURL doesn't crash the whole scan."""
        mock_query.side_effect = Exception("OSV timeout")

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{ids['variant_id']}/osv-scan")
        assert resp.status_code == 202

        resp_status = client.get(
            f"/api/variants/{ids['variant_id']}/osv-scan/status"
        )
        data = json.loads(resp_status.data)
        assert data["status"] == "done"
        any_error_log = any("ERROR" in log for log in data.get("logs", []))
        assert any_error_log

    def test_osv_scan_empty_variant(self, app, client, ids):
        """Variant with no scans produces an error."""
        with _make_sync_thread_patch():
            resp = client.post(
                f"/api/variants/{ids['variant_empty_id']}/osv-scan"
            )
        assert resp.status_code == 202

        resp_status = client.get(
            f"/api/variants/{ids['variant_empty_id']}/osv-scan/status"
        )
        data = json.loads(resp_status.data)
        assert data["status"] == "error"
        assert "No scans found" in data["error"]


# ---------------------------------------------------------------------------
# NVD scan — no valid CPEs edge case
# ---------------------------------------------------------------------------

class TestNvdScanNoCpes:
    """Test NVD scan when packages have no CPEs."""

    @pytest.fixture()
    def app_no_cpe(self, tmp_path):
        import os
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.sbom_document import SBOMDocument
        from src.models.sbom_package import SBOMPackage
        from src.models.package import Package

        scan_file = tmp_path / "scan_status.txt"
        scan_file.write_text("__END_OF_SCAN_SCRIPT__")
        os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        try:
            application = create_app()
            application.config.update({
                "TESTING": True, "SCAN_FILE": str(scan_file),
            })
            with application.app_context():
                _db.drop_all()
                _db.create_all()
                project = Project.create("NoCpeProject")
                variant = Variant.create("NoCpeVariant", project.id)
                scan = Scan.create("no-cpe scan", variant.id)
                # Package with only wildcard CPE (invalid for NVD)
                pkg = Package.find_or_create(
                    "plain", "1.0.0",
                    cpe=["cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"],
                )
                _db.session.commit()
                sbom = SBOMDocument.create("/t/sbom.json", "spdx", scan.id)
                SBOMPackage.create(sbom.id, pkg.id)
                _db.session.commit()
                application._test_ids = {
                    "variant_id": str(variant.id),
                }
            yield application
        finally:
            os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_no_valid_cpes(self, MockNvdDb, app_no_cpe):
        client = app_no_cpe.test_client()
        vid = app_no_cpe._test_ids["variant_id"]
        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{vid}/nvd-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{vid}/nvd-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "No packages with valid CPE" in data["error"]


# ---------------------------------------------------------------------------
# OSV scan — no valid PURLs edge case
# ---------------------------------------------------------------------------

class TestOsvScanNoPurls:
    """Test OSV scan when packages have no PURLs."""

    @pytest.fixture()
    def app_no_purl(self, tmp_path):
        import os
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.sbom_document import SBOMDocument
        from src.models.sbom_package import SBOMPackage
        from src.models.package import Package

        scan_file = tmp_path / "scan_status.txt"
        scan_file.write_text("__END_OF_SCAN_SCRIPT__")
        os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        try:
            application = create_app()
            application.config.update({
                "TESTING": True, "SCAN_FILE": str(scan_file),
            })
            with application.app_context():
                _db.drop_all()
                _db.create_all()
                project = Project.create("NoPurlProject")
                variant = Variant.create("NoPurlVariant", project.id)
                scan = Scan.create("no-purl scan", variant.id)
                pkg = Package.find_or_create("bare-pkg", "0.0.1", purl=[])
                _db.session.commit()
                sbom = SBOMDocument.create("/t/sbom.json", "spdx", scan.id)
                SBOMPackage.create(sbom.id, pkg.id)
                _db.session.commit()
                application._test_ids = {
                    "variant_id": str(variant.id),
                }
            yield application
        finally:
            os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)

    def test_no_valid_purls(self, app_no_purl):
        client = app_no_purl.test_client()
        vid = app_no_purl._test_ids["variant_id"]
        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{vid}/osv-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{vid}/osv-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "No packages with valid PURL" in data["error"]


# ---------------------------------------------------------------------------
# NVD scan — variant with no packages
# ---------------------------------------------------------------------------

class TestNvdScanNoPackages:
    """Test NVD scan when variant has scans but no packages."""

    @pytest.fixture()
    def app_no_pkgs(self, tmp_path):
        import os
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan

        scan_file = tmp_path / "scan_status.txt"
        scan_file.write_text("__END_OF_SCAN_SCRIPT__")
        os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        try:
            application = create_app()
            application.config.update({
                "TESTING": True, "SCAN_FILE": str(scan_file),
            })
            with application.app_context():
                _db.drop_all()
                _db.create_all()
                project = Project.create("NoPkgProject")
                variant = Variant.create("NoPkgVariant", project.id)
                # Scan exists but has no SBOM documents → no packages
                Scan.create("empty scan", variant.id)
                _db.session.commit()
                application._test_ids = {
                    "variant_id": str(variant.id),
                }
            yield application
        finally:
            os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_no_packages(self, MockNvdDb, app_no_pkgs):
        client = app_no_pkgs.test_client()
        vid = app_no_pkgs._test_ids["variant_id"]
        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{vid}/nvd-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{vid}/nvd-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "No packages found" in data["error"]


# ---------------------------------------------------------------------------
# OSV scan — variant with no packages
# ---------------------------------------------------------------------------

class TestOsvScanNoPackages:
    """Test OSV scan when variant has scans but no packages."""

    @pytest.fixture()
    def app_no_pkgs(self, tmp_path):
        import os
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan

        scan_file = tmp_path / "scan_status.txt"
        scan_file.write_text("__END_OF_SCAN_SCRIPT__")
        os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        try:
            application = create_app()
            application.config.update({
                "TESTING": True, "SCAN_FILE": str(scan_file),
            })
            with application.app_context():
                _db.drop_all()
                _db.create_all()
                project = Project.create("NoPkgProject2")
                variant = Variant.create("NoPkgVariant2", project.id)
                Scan.create("empty scan", variant.id)
                _db.session.commit()
                application._test_ids = {
                    "variant_id": str(variant.id),
                }
            yield application
        finally:
            os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)

    def test_no_packages(self, app_no_pkgs):
        client = app_no_pkgs.test_client()
        vid = app_no_pkgs._test_ids["variant_id"]
        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{vid}/osv-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{vid}/osv-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "No packages found" in data["error"]


# ---------------------------------------------------------------------------
# NVD scan — existing vulnerability gets add_found_by("nvd")
# ---------------------------------------------------------------------------

class TestNvdScanExistingVuln:
    """NVD scan with a pre-existing vulnerability still completes."""

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_existing_vuln_no_duplicate(self, MockNvdDb, app, client, ids):
        from src.models.vulnerability import Vulnerability

        # Pre-create the vulnerability
        with app.app_context():
            Vulnerability.create_record(
                id="CVE-2023-9876", description="pre-existing"
            )
            _db.session.commit()

        mock_nvd = MagicMock()
        MockNvdDb.return_value = mock_nvd
        MockNvdDb.extract_cve_details = _RealNvdDb.extract_cve_details
        mock_nvd.api_get_cves_by_cpe.return_value = [
            {"cve": {"id": "CVE-2023-9876"}},
        ]

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{ids['variant_id']}/nvd-scan")
        assert resp.status_code == 202

        resp_s = client.get(
            f"/api/variants/{ids['variant_id']}/nvd-scan/status"
        )
        data = json.loads(resp_s.data)
        assert data["status"] == "done"

        # Vulnerability still exists and was not duplicated
        with app.app_context():
            v = _db.session.get(Vulnerability, "CVE-2023-9876")
            assert v is not None


# ---------------------------------------------------------------------------
# OSV scan — existing vulnerability gets add_found_by("osv")
# ---------------------------------------------------------------------------

class TestOsvScanExistingVuln:
    """OSV scan with a pre-existing vulnerability still completes."""

    @patch("src.controllers.osv_client.OSVClient.query_by_purl")
    def test_existing_vuln_no_duplicate(self, mock_query, app, client, ids):
        from src.models.vulnerability import Vulnerability

        with app.app_context():
            Vulnerability.create_record(
                id="GHSA-0000-1111", description="pre"
            )
            _db.session.commit()

        mock_query.return_value = [
            {"id": "GHSA-0000-1111", "aliases": []},
        ]

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{ids['variant_id']}/osv-scan")
        assert resp.status_code == 202

        resp_s = client.get(
            f"/api/variants/{ids['variant_id']}/osv-scan/status"
        )
        data = json.loads(resp_s.data)
        assert data["status"] == "done"

        # Vulnerability still exists and was not duplicated
        with app.app_context():
            v = _db.session.get(Vulnerability, "GHSA-0000-1111")
            assert v is not None


# ---------------------------------------------------------------------------
# NVD scan — multiple CVEs returned (> 10 triggers ellipsis in log)
# ---------------------------------------------------------------------------

class TestNvdScanManyCves:
    """NVD scan with >10 CVEs per CPE shows ellipsis in log."""

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_many_cves_ellipsis(self, MockNvdDb, app, client, ids):
        mock_nvd = MagicMock()
        MockNvdDb.return_value = mock_nvd
        MockNvdDb.extract_cve_details = _RealNvdDb.extract_cve_details
        mock_nvd.api_get_cves_by_cpe.return_value = [
            {"cve": {"id": f"CVE-2023-{i:04d}"}} for i in range(15)
        ]

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{ids['variant_id']}/nvd-scan")
        assert resp.status_code == 202

        resp_s = client.get(
            f"/api/variants/{ids['variant_id']}/nvd-scan/status"
        )
        data = json.loads(resp_s.data)
        assert data["status"] == "done"
        log_text = "\n".join(data.get("logs", []))
        assert "…" in log_text  # ellipsis for >10 CVEs


# ---------------------------------------------------------------------------
# OSV scan — multiple vulns returned (> 10 triggers ellipsis in log)
# ---------------------------------------------------------------------------

class TestOsvScanManyVulns:
    """OSV scan with >10 vulns per PURL shows ellipsis in log."""

    @patch("src.controllers.osv_client.OSVClient.query_by_purl")
    def test_many_vulns_ellipsis(self, mock_query, app, client, ids):
        mock_query.return_value = [
            {"id": f"GHSA-{i:04d}", "aliases": []} for i in range(12)
        ]

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{ids['variant_id']}/osv-scan")
        assert resp.status_code == 202

        resp_s = client.get(
            f"/api/variants/{ids['variant_id']}/osv-scan/status"
        )
        data = json.loads(resp_s.data)
        assert data["status"] == "done"
        log_text = "\n".join(data.get("logs", []))
        assert "…" in log_text

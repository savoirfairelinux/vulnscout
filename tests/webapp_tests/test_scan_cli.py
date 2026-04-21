# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the ``flask nvd-scan`` and ``flask osv-scan`` CLI commands."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

from src.bin.webapp import create_app
from src.controllers.nvd_db import NVD_DB as _RealNvdDb
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_db(app):
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

        project = Project.create("CLIProject")
        variant = Variant.create("CLIVariant", project.id)
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
        _db.session.commit()

        doc = SBOMDocument.create("/sbom.json", "sbom.json", scan.id, format="spdx")
        SBOMPackage.create(doc.id, pkg_cpe.id)
        SBOMPackage.create(doc.id, pkg_purl.id)

        from src.models.observation import Observation
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding

        vuln = Vulnerability.create_record(id="CVE-EXISTING-1", description="existing")
        finding = Finding.get_or_create(pkg_cpe.id, vuln.id)
        _db.session.commit()
        Observation.create(finding_id=finding.id, scan_id=scan.id)
        _db.session.commit()

        return {
            "project_name": "CLIProject",
            "variant_name": "CLIVariant",
            "variant_id": str(variant.id),
        }


@pytest.fixture()
def app(tmp_path):
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
def ids(app):
    return app._test_ids


# ---------------------------------------------------------------------------
# NVD scan CLI tests
# ---------------------------------------------------------------------------

class TestNvdScanCLI:
    """flask nvd-scan CLI command."""

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_nvd_scan_creates_findings(self, MockNvdDb, app, ids):
        """NVD scan via CLI creates findings and a tool scan."""
        mock_instance = MockNvdDb.return_value
        mock_instance.api_get_cves_by_cpe.return_value = [
            {
                "cve": {
                    "id": "CVE-2023-0001",
                    "descriptions": [
                        {"lang": "en", "value": "test vuln"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 5.9,
                        }],
                    },
                    "references": [{"url": "https://example.com"}],
                    "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                    "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2023-06-01T00:00:00.000",
                    "vulnStatus": "Analyzed",
                }
            }
        ]
        MockNvdDb.extract_cve_details = _RealNvdDb.extract_cve_details

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "nvd-scan",
            "--project", ids["project_name"],
            "--variant", ids["variant_name"],
        ])
        assert result.exit_code == 0, result.output
        assert "Scan complete" in result.output
        assert "CVE-2023-0001" in result.output

        # Verify scan was created in DB
        with app.app_context():
            from src.models.scan import Scan
            scans = _db.session.execute(
                _db.select(Scan).where(Scan.scan_source == "nvd")
            ).scalars().all()
            assert len(scans) >= 1

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_nvd_scan_enriches_existing_vuln(self, MockNvdDb, app, ids):
        """NVD scan enriches an existing bare CVE with description/links."""
        mock_instance = MockNvdDb.return_value
        mock_instance.api_get_cves_by_cpe.return_value = [
            {
                "cve": {
                    "id": "CVE-EXISTING-1",
                    "descriptions": [
                        {"lang": "en", "value": "enriched description"}
                    ],
                    "metrics": {},
                    "references": [{"url": "https://nvd.nist.gov"}],
                    "weaknesses": [],
                }
            }
        ]
        MockNvdDb.extract_cve_details = _RealNvdDb.extract_cve_details

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "nvd-scan",
            "--project", ids["project_name"],
            "--variant", ids["variant_name"],
        ])
        assert result.exit_code == 0, result.output
        assert "CVE-EXISTING-1" in result.output

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_nvd_scan_handles_api_error(self, MockNvdDb, app, ids):
        """NVD scan continues when API call raises an exception."""
        mock_instance = MockNvdDb.return_value
        mock_instance.api_get_cves_by_cpe.side_effect = RuntimeError("API timeout")
        MockNvdDb.extract_cve_details = _RealNvdDb.extract_cve_details

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "nvd-scan",
            "--project", ids["project_name"],
            "--variant", ids["variant_name"],
        ])
        assert result.exit_code == 0, result.output
        assert "Scan complete" in result.output
        assert "0 unique CVEs" in result.output

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_nvd_scan_no_cpe_packages(self, MockNvdDb, app):
        """NVD scan on a project with no CPE packages fails gracefully."""
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.sbom_document import SBOMDocument
        from src.models.sbom_package import SBOMPackage
        from src.models.package import Package

        with app.app_context():
            project = Project.create("NoCPE")
            variant = Variant.create("NoCPEVar", project.id)
            scan = Scan.create("scan", variant.id, scan_type="sbom")
            pkg = Package.find_or_create("nocpe-pkg", "1.0", cpe=[], purl=[])
            _db.session.commit()
            doc = SBOMDocument.create("/no.json", "no.json", scan.id)
            SBOMPackage.create(doc.id, pkg.id)
            _db.session.commit()

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "nvd-scan", "--project", "NoCPE", "--variant", "NoCPEVar",
        ])
        assert result.exit_code != 0
        assert "CPE" in result.output

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_nvd_scan_default_variant(self, MockNvdDb, app, ids):
        """NVD scan uses default variant when --variant is omitted."""
        mock_instance = MockNvdDb.return_value
        mock_instance.api_get_cves_by_cpe.return_value = []
        MockNvdDb.extract_cve_details = _RealNvdDb.extract_cve_details

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "nvd-scan", "--project", ids["project_name"],
        ])
        assert result.exit_code != 0
        assert "No scans found" in result.output

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_nvd_scan_no_cves_returned(self, MockNvdDb, app, ids):
        """NVD scan with zero results still completes successfully."""
        mock_instance = MockNvdDb.return_value
        mock_instance.api_get_cves_by_cpe.return_value = []
        MockNvdDb.extract_cve_details = _RealNvdDb.extract_cve_details

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "nvd-scan",
            "--project", ids["project_name"],
            "--variant", ids["variant_name"],
        ])
        assert result.exit_code == 0, result.output
        assert "no CVEs" in result.output
        assert "Scan complete" in result.output


# ---------------------------------------------------------------------------
# OSV scan CLI tests
# ---------------------------------------------------------------------------

class TestOsvScanCLI:
    """flask osv-scan CLI command."""

    @patch("src.controllers.osv_client.OSVClient")
    def test_osv_scan_creates_findings(self, MockOsvClient, app, ids):
        """OSV scan via CLI creates findings and a tool scan."""
        mock_instance = MockOsvClient.return_value
        mock_instance.query_by_purl.return_value = [
            {
                "id": "GHSA-test-0001",
                "summary": "test osv vuln",
                "aliases": ["CVE-2023-9999"],
                "references": [{"url": "https://example.com"}],
            }
        ]

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "osv-scan",
            "--project", ids["project_name"],
            "--variant", ids["variant_name"],
        ])
        assert result.exit_code == 0, result.output
        assert "Scan complete" in result.output

        # Verify scan was created in DB
        with app.app_context():
            from src.models.scan import Scan
            scans = _db.session.execute(
                _db.select(Scan).where(Scan.scan_source == "osv")
            ).scalars().all()
            assert len(scans) >= 1

    @patch("src.controllers.osv_client.OSVClient")
    def test_osv_scan_enriches_existing_vuln(self, MockOsvClient, app, ids):
        """OSV scan enriches an existing bare CVE with description."""
        mock_instance = MockOsvClient.return_value
        # Return a vuln whose alias matches CVE-EXISTING-1 (already in DB)
        mock_instance.query_by_purl.return_value = [
            {
                "id": "GHSA-enrich-001",
                "summary": "enriched from osv",
                "aliases": ["CVE-EXISTING-1"],
                "references": [{"url": "https://osv.dev"}],
            }
        ]

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "osv-scan",
            "--project", ids["project_name"],
            "--variant", ids["variant_name"],
        ])
        assert result.exit_code == 0, result.output
        assert "Scan complete" in result.output

    @patch("src.controllers.osv_client.OSVClient")
    def test_osv_scan_handles_api_error(self, MockOsvClient, app, ids):
        """OSV scan continues when API call raises an exception."""
        mock_instance = MockOsvClient.return_value
        mock_instance.query_by_purl.side_effect = RuntimeError("network error")

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "osv-scan",
            "--project", ids["project_name"],
            "--variant", ids["variant_name"],
        ])
        assert result.exit_code == 0, result.output
        assert "Scan complete" in result.output
        assert "0 unique vulnerabilities" in result.output

    @patch("src.controllers.osv_client.OSVClient")
    def test_osv_scan_no_purl_packages(self, MockOsvClient, app):
        """OSV scan on a project with no PURL packages fails gracefully."""
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.sbom_document import SBOMDocument
        from src.models.sbom_package import SBOMPackage
        from src.models.package import Package

        with app.app_context():
            project = Project.create("NoPURL")
            variant = Variant.create("NoPURLVar", project.id)
            scan = Scan.create("scan", variant.id, scan_type="sbom")
            pkg = Package.find_or_create("nopurl-pkg", "1.0", cpe=[], purl=[])
            _db.session.commit()
            doc = SBOMDocument.create("/no.json", "no2.json", scan.id)
            SBOMPackage.create(doc.id, pkg.id)
            _db.session.commit()

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "osv-scan", "--project", "NoPURL", "--variant", "NoPURLVar",
        ])
        assert result.exit_code != 0
        assert "PURL" in result.output

    @patch("src.controllers.osv_client.OSVClient")
    def test_osv_scan_default_variant(self, MockOsvClient, app, ids):
        """OSV scan uses default variant when --variant is omitted."""
        mock_instance = MockOsvClient.return_value
        mock_instance.query_by_purl.return_value = []

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "osv-scan", "--project", ids["project_name"],
        ])
        # Default variant won't have scans → error
        assert result.exit_code != 0
        assert "No scans found" in result.output

    @patch("src.controllers.osv_client.OSVClient")
    def test_osv_scan_no_vulns_returned(self, MockOsvClient, app, ids):
        """OSV scan with zero results still completes successfully."""
        mock_instance = MockOsvClient.return_value
        mock_instance.query_by_purl.return_value = []

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "osv-scan",
            "--project", ids["project_name"],
            "--variant", ids["variant_name"],
        ])
        assert result.exit_code == 0, result.output
        assert "no vulnerabilities" in result.output
        assert "Scan complete" in result.output

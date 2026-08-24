# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""NVD and OSV scan behaviour, exercised through the queued job entry points.

``run_nvd_scan`` / ``run_osv_scan`` receive a :class:`JobContext` and report
through it, so the assertions read the resulting operation straight from the
registry instead of polling a status endpoint.  A job signals failure by
raising, which is what the queue turns into an ``error`` operation.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from src.bin.webapp import create_app
from src.controllers.job_context import JobContext
from src.controllers.nvd_db import NVD_DB as _RealNvdDb
from src.controllers.operation_registry import KIND_SCAN, LANE_PIPELINE, registry
from src.controllers.scan_jobs import run_nvd_scan, run_osv_scan
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
def ids(app):
    return app._test_ids


@pytest.fixture(autouse=True)
def clean_registry():
    registry.clear()
    yield
    registry.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _context(source, variant_id, **options):
    """Register an operation and return the context its job would receive."""
    op_id = f"scan:{source}:{variant_id}"
    registry.create(
        op_id=op_id, kind=KIND_SCAN, source=source,
        label=f"{source} scan", lane=LANE_PIPELINE,
    )
    return JobContext(op_id, {"variant_id": variant_id, **options})


def _run(app, runner, ctx):
    """Run a scan job the way the queue does, then publish what it buffered."""
    with app.app_context():
        try:
            runner(ctx)
        finally:
            ctx.flush()
    return registry.get(ctx.op_id)


# ---------------------------------------------------------------------------
# NVD scan
# ---------------------------------------------------------------------------

class TestNvdScan:
    """NVD scan against the REST API."""

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_discovered_cves_are_persisted(self, MockNvdDb, app, ids):
        """Every CVE returned for a CPE becomes a vulnerability record."""
        nvd = MagicMock()
        MockNvdDb.return_value = nvd
        MockNvdDb.extract_cve_details = _RealNvdDb.extract_cve_details
        nvd.api_get_cves_by_cpe.return_value = [
            {"cve": {"id": "CVE-2023-0001"}},
            {"cve": {"id": "CVE-2023-0002"}},
        ]

        ctx = _context("nvd", ids["variant_id"], mode="api")
        operation = _run(app, run_nvd_scan, ctx)

        assert operation["error"] is None
        assert operation["progress"]["total"] >= 1
        assert operation["progress"]["current"] >= 1

        with app.app_context():
            from src.models.vulnerability import Vulnerability
            assert _db.session.get(Vulnerability, "CVE-2023-0001") is not None
            assert _db.session.get(Vulnerability, "CVE-2023-0002") is not None

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_scan_without_matches_reports_zero_cves(self, MockNvdDb, app, ids):
        """A scan that matches nothing still completes and says so."""
        nvd = MagicMock()
        MockNvdDb.return_value = nvd
        nvd.api_get_cves_by_cpe.return_value = []

        ctx = _context("nvd", ids["variant_id"], mode="api")
        operation = _run(app, run_nvd_scan, ctx)

        assert "0 CVEs" in operation["progress"]["message"]

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_failed_cpe_query_is_logged_and_scan_continues(
        self, MockNvdDb, app, ids
    ):
        """An API failure on one CPE is recorded without aborting the scan."""
        nvd = MagicMock()
        MockNvdDb.return_value = nvd
        nvd.api_get_cves_by_cpe.side_effect = Exception("NVD timeout")

        ctx = _context("nvd", ids["variant_id"], mode="api")
        operation = _run(app, run_nvd_scan, ctx)

        assert any("ERROR" in line for line in operation["logs"])
        assert any("NVD timeout" in line for line in operation["logs"])
        assert "0 CVEs" in operation["progress"]["message"]

    def test_variant_without_sbom_scan_fails(self, app, ids):
        """A variant that was never imported cannot be scanned."""
        ctx = _context("nvd", ids["variant_empty_id"])
        with pytest.raises(RuntimeError, match="No SBOM scan found"):
            _run(app, run_nvd_scan, ctx)

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_known_vulnerability_is_not_duplicated(self, MockNvdDb, app, ids):
        """Re-discovering a CVE reuses the existing record."""
        from src.models.vulnerability import Vulnerability

        with app.app_context():
            Vulnerability.create_record(
                id="CVE-2023-9876", description="pre-existing"
            )
            _db.session.commit()

        nvd = MagicMock()
        MockNvdDb.return_value = nvd
        MockNvdDb.extract_cve_details = _RealNvdDb.extract_cve_details
        nvd.api_get_cves_by_cpe.return_value = [{"cve": {"id": "CVE-2023-9876"}}]

        ctx = _context("nvd", ids["variant_id"], mode="api")
        operation = _run(app, run_nvd_scan, ctx)

        assert operation["error"] is None
        with app.app_context():
            rows = _db.session.execute(
                _db.select(Vulnerability).where(
                    Vulnerability.id == "CVE-2023-9876"
                )
            ).scalars().all()
            assert len(rows) == 1

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_long_cve_list_is_truncated_in_the_log(self, MockNvdDb, app, ids):
        """Only the first ten CVEs are listed, the rest become an ellipsis."""
        nvd = MagicMock()
        MockNvdDb.return_value = nvd
        MockNvdDb.extract_cve_details = _RealNvdDb.extract_cve_details
        nvd.api_get_cves_by_cpe.return_value = [
            {"cve": {"id": f"CVE-2023-{i:04d}"}} for i in range(15)
        ]

        ctx = _context("nvd", ids["variant_id"], mode="api")
        operation = _run(app, run_nvd_scan, ctx)

        listing = next(line for line in operation["logs"] if "CVE(s):" in line)
        assert listing.count("CVE-2023-") == 10
        assert listing.endswith("…")


# ---------------------------------------------------------------------------
# OSV scan
# ---------------------------------------------------------------------------

class TestOsvScan:
    """OSV scan against osv.dev."""

    @patch("src.controllers.osv_client.OSVClient.query_by_purl")
    def test_advisory_and_its_cve_alias_are_persisted(self, query, app, ids):
        """An advisory is recorded under its own id and under its aliases."""
        query.return_value = [
            {"id": "GHSA-1234-5678", "aliases": ["CVE-2023-9999"]},
        ]

        ctx = _context("osv", ids["variant_id"])
        operation = _run(app, run_osv_scan, ctx)

        assert operation["error"] is None
        assert operation["progress"]["total"] >= 1

        with app.app_context():
            from src.models.vulnerability import Vulnerability
            assert _db.session.get(Vulnerability, "GHSA-1234-5678") is not None
            assert _db.session.get(Vulnerability, "CVE-2023-9999") is not None

    @patch("src.controllers.osv_client.OSVClient.query_by_purl")
    def test_scan_without_matches_reports_zero_vulnerabilities(
        self, query, app, ids
    ):
        query.return_value = []

        ctx = _context("osv", ids["variant_id"])
        operation = _run(app, run_osv_scan, ctx)

        assert "0 vulnerabilities" in operation["progress"]["message"]

    @patch("src.controllers.osv_client.OSVClient.query_by_purl")
    def test_failed_purl_query_is_logged_and_scan_continues(
        self, query, app, ids
    ):
        query.side_effect = Exception("OSV timeout")

        ctx = _context("osv", ids["variant_id"])
        operation = _run(app, run_osv_scan, ctx)

        assert any("ERROR" in line for line in operation["logs"])
        assert any("OSV timeout" in line for line in operation["logs"])
        assert "0 vulnerabilities" in operation["progress"]["message"]

    def test_variant_without_sbom_scan_fails(self, app, ids):
        ctx = _context("osv", ids["variant_empty_id"])
        with pytest.raises(RuntimeError, match="No SBOM scan found"):
            _run(app, run_osv_scan, ctx)

    @patch("src.controllers.osv_client.OSVClient.query_by_purl")
    def test_known_vulnerability_is_not_duplicated(self, query, app, ids):
        from src.models.vulnerability import Vulnerability

        with app.app_context():
            Vulnerability.create_record(id="GHSA-0000-1111", description="pre")
            _db.session.commit()

        query.return_value = [{"id": "GHSA-0000-1111", "aliases": []}]

        ctx = _context("osv", ids["variant_id"])
        operation = _run(app, run_osv_scan, ctx)

        assert operation["error"] is None
        with app.app_context():
            rows = _db.session.execute(
                _db.select(Vulnerability).where(
                    Vulnerability.id == "GHSA-0000-1111"
                )
            ).scalars().all()
            assert len(rows) == 1

    @patch("src.controllers.osv_client.OSVClient.query_by_purl")
    def test_long_advisory_list_is_truncated_in_the_log(self, query, app, ids):
        query.return_value = [
            {"id": f"GHSA-{i:04d}", "aliases": []} for i in range(12)
        ]

        ctx = _context("osv", ids["variant_id"])
        operation = _run(app, run_osv_scan, ctx)

        listing = next(line for line in operation["logs"] if "vuln(s):" in line)
        assert listing.count("GHSA-") == 10
        assert listing.endswith("…")


# ---------------------------------------------------------------------------
# NVD scan — no usable CPE identifiers
# ---------------------------------------------------------------------------

class TestNvdScanNoCpes:
    """NVD needs a CPE carrying a concrete version field."""

    @pytest.fixture()
    def app_no_cpe(self, tmp_path):
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
                application._test_ids = {"variant_id": str(variant.id)}
            yield application
        finally:
            os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_wildcard_only_cpes_fail_the_scan(self, MockNvdDb, app_no_cpe):
        ctx = _context("nvd", app_no_cpe._test_ids["variant_id"], mode="api")
        with pytest.raises(RuntimeError, match="No packages with valid CPE"):
            _run(app_no_cpe, run_nvd_scan, ctx)


# ---------------------------------------------------------------------------
# OSV scan — no usable PURL identifiers
# ---------------------------------------------------------------------------

class TestOsvScanNoPurls:
    """OSV needs at least one ``pkg:`` identifier."""

    @pytest.fixture()
    def app_no_purl(self, tmp_path):
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
                application._test_ids = {"variant_id": str(variant.id)}
            yield application
        finally:
            os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)

    def test_packages_without_purls_fail_the_scan(self, app_no_purl):
        ctx = _context("osv", app_no_purl._test_ids["variant_id"])
        with pytest.raises(RuntimeError, match="No packages with valid PURL"):
            _run(app_no_purl, run_osv_scan, ctx)


# ---------------------------------------------------------------------------
# Scans of a variant whose SBOM scan carries no packages
# ---------------------------------------------------------------------------

@pytest.fixture()
def app_no_packages(tmp_path):
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
            application._test_ids = {"variant_id": str(variant.id)}
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@patch("src.controllers.nvd_db.NVD_DB")
def test_nvd_scan_of_a_packageless_variant_fails(MockNvdDb, app_no_packages):
    ctx = _context("nvd", app_no_packages._test_ids["variant_id"], mode="api")
    with pytest.raises(RuntimeError, match="No packages found"):
        _run(app_no_packages, run_nvd_scan, ctx)


def test_osv_scan_of_a_packageless_variant_fails(app_no_packages):
    ctx = _context("osv", app_no_packages._test_ids["variant_id"])
    with pytest.raises(RuntimeError, match="No packages found"):
        _run(app_no_packages, run_osv_scan, ctx)

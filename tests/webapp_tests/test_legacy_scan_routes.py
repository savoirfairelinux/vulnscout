"""Legacy scan endpoints exercised through Flask and an in-memory SQLite DB."""

import os
import subprocess
import threading

import pytest

from src.bin.webapp import create_app
from src.extensions import db
from src.models.package import Package
from src.models.project import Project
from src.models.sbom_document import SBOMDocument
from src.models.sbom_package import SBOMPackage
from src.models.scan import Scan
from src.models.variant import Variant
from src.models.vulnerability import Vulnerability


class _ComputedVulnerability:
    identifier = "CVE-2024-SCCTEST-01"
    description = "test vulnerability"
    date_published = None
    date_modified = None
    external_refs = []
    cvss_metrics = []
    vex_assessment = None


class _LocalEngine:
    def __init__(self, results=(), error=None):
        self.results = results
        self.error = error

    def applicable_vulns(self, package):
        if self.error:
            raise self.error
        return iter(self.results)


@pytest.fixture
def app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    previous_uri = os.environ.get("FLASK_SQLALCHEMY_DATABASE_URI")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update(TESTING=True, SCAN_FILE=str(scan_file))
        with application.app_context():
            db.drop_all()
            db.create_all()
            project = Project.create("LegacyRoutes")
            variant = Variant.create("WithSbom", project.id)
            empty_variant = Variant.create("WithoutSbom", project.id)
            scan = Scan.create("base scan", variant.id, scan_type="sbom")
            package = Package.find_or_create(
                "openssl", "1.1.1",
                cpe=["cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"],
                purl=["pkg:pypi/openssl@1.1.1"],
            )
            purl_package = Package.find_or_create(
                "requests", "2.28.0", purl=["pkg:pypi/requests@2.28.0"]
            )
            db.session.commit()
            sbom = SBOMDocument.create("/test/base.json", "spdx", scan.id)
            SBOMPackage.create(sbom.id, package.id)
            SBOMPackage.create(sbom.id, purl_package.id)
            db.session.commit()
            application._test_ids = (str(variant.id), str(empty_variant.id))
        yield application
    finally:
        if previous_uri is None:
            os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)
        else:
            os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = previous_uri


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def variant_ids(app):
    return app._test_ids


@pytest.fixture
def synchronous_scans(monkeypatch):
    monkeypatch.setattr(threading.Thread, "start", lambda thread: thread.run())


def test_legacy_nvd_api_persists_cves(
    app, client, variant_ids, synchronous_scans, monkeypatch
):
    from src.controllers.nvd_db import NVD_DB

    monkeypatch.setattr(
        NVD_DB, "api_get_cves_by_cpe",
        lambda self, *args, **kwargs: [{"cve": {"id": "CVE-2023-0001"}}],
    )
    variant_id, _ = variant_ids
    response = client.post(f"/api/variants/{variant_id}/nvd-scan?mode=api")
    assert response.status_code == 202
    status = client.get(f"/api/variants/{variant_id}/nvd-scan/status").json
    assert status["status"] == "done"
    assert status["error"] is None
    assert status["done_count"] == status["total"] == 1
    with app.app_context():
        assert db.session.get(Vulnerability, "CVE-2023-0001") is not None


@pytest.mark.parametrize("failure", [False, True])
def test_legacy_nvd_api_empty_or_failed_query(
    client, variant_ids, synchronous_scans, monkeypatch, failure
):
    from src.controllers.nvd_db import NVD_DB

    def query(self, *args, **kwargs):
        if failure:
            raise RuntimeError("NVD timeout")
        return []

    monkeypatch.setattr(NVD_DB, "api_get_cves_by_cpe", query)
    variant_id, _ = variant_ids
    assert client.post(f"/api/variants/{variant_id}/nvd-scan?mode=api").status_code == 202
    status = client.get(f"/api/variants/{variant_id}/nvd-scan/status").json
    assert status["status"] == "done"
    assert "0 CVEs" in status["progress"]
    assert any("NVD timeout" in log for log in status["logs"]) == failure


@pytest.mark.parametrize("results", [(), ((_ComputedVulnerability(), "affected"),)])
def test_legacy_nvd_local_scan(
    app, client, variant_ids, synchronous_scans, monkeypatch, results
):
    from src.controllers import scc_engine

    monkeypatch.setattr(scc_engine, "get_engine", lambda **kwargs: _LocalEngine(results))
    variant_id, _ = variant_ids
    assert client.post(f"/api/variants/{variant_id}/nvd-scan").status_code == 202
    status = client.get(f"/api/variants/{variant_id}/nvd-scan/status").json
    assert status["status"] == "done"
    assert status["error"] is None
    assert status["done_count"] == status["total"] == 2
    assert f"Found {len(results) * status['total']} CVEs" in status["progress"]
    if results:
        with app.app_context():
            assert db.session.get(Vulnerability, "CVE-2024-SCCTEST-01") is not None


def test_legacy_nvd_local_engine_unavailable(
    client, variant_ids, synchronous_scans, monkeypatch
):
    from src.controllers import scc_engine

    def unavailable(**kwargs):
        raise RuntimeError("local NVD unavailable")

    monkeypatch.setattr(scc_engine, "get_engine", unavailable)
    variant_id, _ = variant_ids
    assert client.post(f"/api/variants/{variant_id}/nvd-scan").status_code == 202
    status = client.get(f"/api/variants/{variant_id}/nvd-scan/status").json
    assert status["status"] == "error"
    assert "Failed to load local NVD database: local NVD unavailable" in status["error"]


@pytest.mark.parametrize("source", ["nvd", "osv", "sbom-cve-check"])
def test_legacy_scan_without_sbom(client, variant_ids, synchronous_scans, source):
    _, empty_variant_id = variant_ids
    assert client.post(f"/api/variants/{empty_variant_id}/{source}-scan").status_code == 202
    status = client.get(f"/api/variants/{empty_variant_id}/{source}-scan/status").json
    assert status["status"] == "error"
    assert "No SBOM scan found" in status["error"]


def test_legacy_osv_persists_vulnerability_and_cve_alias(
    app, client, variant_ids, synchronous_scans, monkeypatch
):
    from src.controllers.osv_client import OSVClient

    monkeypatch.setattr(
        OSVClient, "query_by_purl",
        lambda self, purl: [
            {
                "id": "GHSA-1234-5678",
                "aliases": ["CVE-2023-9999"],
                "summary": "affected package",
                "references": [{"url": "https://example.org/advisory"}],
            }
        ] if "openssl" in purl else [],
    )
    variant_id, _ = variant_ids
    assert client.post(f"/api/variants/{variant_id}/osv-scan").status_code == 202
    status = client.get(f"/api/variants/{variant_id}/osv-scan/status").json
    assert status["status"] == "done"
    assert status["error"] is None
    assert status["done_count"] == status["total"] == 2
    assert any("no vulnerabilities" in log for log in status["logs"])
    with app.app_context():
        for vuln_id in ("GHSA-1234-5678", "CVE-2023-9999"):
            vuln = db.session.get(Vulnerability, vuln_id)
            assert vuln is not None


def test_legacy_osv_enriches_existing_vulnerability(
    app, client, variant_ids, synchronous_scans, monkeypatch
):
    from src.controllers.osv_client import OSVClient

    with app.app_context():
        Vulnerability.create_record(id="GHSA-1234-5678")
        db.session.commit()
    monkeypatch.setattr(
        OSVClient, "query_by_purl",
        lambda self, purl: [{"id": "GHSA-1234-5678", "summary": "OSV description"}],
    )
    variant_id, _ = variant_ids
    assert client.post(f"/api/variants/{variant_id}/osv-scan").status_code == 202
    assert client.get(f"/api/variants/{variant_id}/osv-scan/status").json["status"] == "done"
    with app.app_context():
        assert db.session.get(Vulnerability, "GHSA-1234-5678").description == "OSV description"


def test_legacy_osv_rejects_sbom_without_valid_purls(
    app, client, variant_ids, synchronous_scans
):
    from src.models.sbom_package import SBOMPackage

    variant_id, _ = variant_ids
    with app.app_context():
        for link in db.session.execute(db.select(SBOMPackage)).scalars():
            db.session.delete(link)
        sbom = db.session.execute(db.select(SBOMDocument)).scalar_one()
        package = Package.find_or_create("without-purl", "1.0")
        db.session.commit()
        SBOMPackage.create(sbom.id, package.id)
        db.session.commit()
    assert client.post(f"/api/variants/{variant_id}/osv-scan").status_code == 202
    status = client.get(f"/api/variants/{variant_id}/osv-scan/status").json
    assert status["status"] == "error"
    assert "No packages with valid PURL identifiers" in status["error"]


@pytest.mark.parametrize("failure", [False, True])
def test_legacy_osv_empty_or_failed_queries(
    client, variant_ids, synchronous_scans, monkeypatch, failure
):
    from src.controllers.osv_client import OSVClient

    def query(self, purl):
        if failure:
            raise RuntimeError("OSV timeout")
        return []

    monkeypatch.setattr(OSVClient, "query_by_purl", query)
    variant_id, _ = variant_ids
    assert client.post(f"/api/variants/{variant_id}/osv-scan").status_code == 202
    status = client.get(f"/api/variants/{variant_id}/osv-scan/status").json
    assert status["status"] == "done"
    assert "0 vulnerabilities" in status["progress"]
    assert any("OSV timeout" in log for log in status["logs"]) == failure


@pytest.mark.parametrize("results", [(), ((_ComputedVulnerability(), "affected"),)])
def test_legacy_scc_scan_results(
    app, client, variant_ids, synchronous_scans, monkeypatch, results
):
    from src.controllers import scc_engine

    monkeypatch.setattr(scc_engine, "get_engine", lambda **kwargs: _LocalEngine(results))
    variant_id, _ = variant_ids
    assert client.post(f"/api/variants/{variant_id}/sbom-cve-check-scan").status_code == 202
    status = client.get(f"/api/variants/{variant_id}/sbom-cve-check-scan/status").json
    assert status["status"] == "done"
    assert status["error"] is None
    assert status["done_count"] == status["total"] == 2
    if results:
        assert any("CVE-2024-SCCTEST-01" in log for log in status["logs"])
        with app.app_context():
            assert db.session.get(Vulnerability, "CVE-2024-SCCTEST-01") is not None
    else:
        assert any("no vulnerabilities" in log for log in status["logs"])


def test_legacy_scc_engine_unavailable(
    client, variant_ids, synchronous_scans, monkeypatch
):
    from src.controllers import scc_engine

    def unavailable(**kwargs):
        raise RuntimeError("engine unavailable")

    monkeypatch.setattr(scc_engine, "get_engine", unavailable)
    variant_id, _ = variant_ids
    assert client.post(f"/api/variants/{variant_id}/sbom-cve-check-scan").status_code == 202
    status = client.get(f"/api/variants/{variant_id}/sbom-cve-check-scan/status").json
    assert status["status"] == "error"
    assert "Failed to load CVE databases: engine unavailable" in status["error"]


def test_legacy_scc_package_failure_continues(
    client, variant_ids, synchronous_scans, monkeypatch
):
    from src.controllers import scc_engine

    monkeypatch.setattr(
        scc_engine, "get_engine",
        lambda **kwargs: _LocalEngine(error=RuntimeError("pkg scan failed")),
    )
    variant_id, _ = variant_ids
    assert client.post(f"/api/variants/{variant_id}/sbom-cve-check-scan").status_code == 202
    status = client.get(f"/api/variants/{variant_id}/sbom-cve-check-scan/status").json
    assert status["status"] == "done"
    assert any("pkg scan failed" in log for log in status["logs"])


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (subprocess.TimeoutExpired(["flask", "export"], 120), "Grype scan timed out"),
        (subprocess.CalledProcessError(1, ["flask", "export"], stderr="export failed"),
         "Command failed: export failed"),
        (OSError("export unavailable"), "export unavailable"),
    ],
)
def test_legacy_grype_export_failure_reports_status(
    client, variant_ids, synchronous_scans, monkeypatch, failure, expected
):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda binary: "/usr/bin/grype")

    def fail_export(*args, **kwargs):
        raise failure

    monkeypatch.setattr(subprocess, "run", fail_export)
    variant_id, _ = variant_ids
    assert client.post(f"/api/variants/{variant_id}/grype-scan").status_code == 202
    status = client.get(f"/api/variants/{variant_id}/grype-scan/status").json
    assert status["status"] == "error"
    assert expected in status["error"]
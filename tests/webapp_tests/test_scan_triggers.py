# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for Grype / NVD / OSV scan trigger & status endpoints in scans.py."""

import pytest
import json
import uuid
from unittest.mock import patch, MagicMock

from src.bin.webapp import create_app
from src.extensions import db as _db


def _sync_thread_patch():
    """Run background scan threads synchronously in tests."""
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

    @patch("shutil.which", return_value="/usr/bin/grype")
    @patch("subprocess.run")
    def test_scan_filters_matches_to_variant_sbom(self, mock_run, mock_which, client, ids):
        """The grype worker filters matches to packages present in the variant SBOM."""
        import json as _json
        from src.models.vulnerability import Vulnerability
        from src.models.package import Package

        with client.application.app_context():
            Vulnerability.create_record(id="CVE-GRYPE-0001", description="seed")
            Package.find_or_create("openssl", "1.1.1")
            _db.session.commit()

        def _fake_run(cmd, **kwargs):
            if isinstance(cmd, list) and "export" in cmd:
                out_dir = cmd[cmd.index("--output-dir") + 1]
                with open(f"{out_dir}/sbom_cyclonedx_v1_6.cdx.json", "w") as f:
                    f.write("{}")
            elif isinstance(cmd, list) and "grype" in cmd:
                stdout_file = kwargs.get("stdout")
                if stdout_file is not None:
                    stdout_file.write(_json.dumps({
                        "matches": [{
                            "artifact": {
                                "name": "openssl",
                                "version": "1.1.1",
                            }
                        }]
                    }))
            return MagicMock(returncode=0)

        mock_run.side_effect = _fake_run

        with _sync_thread_patch():
            resp = client.post(f"/api/variants/{ids['variant_id']}/grype-scan")

        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{ids['variant_id']}/grype-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "done"
        assert any("Filtered: 1/1 matches kept" in line for line in data["logs"])


# ---------------------------------------------------------------------------
# Grype scan — kernel module exclusion
# ---------------------------------------------------------------------------

class TestGrypeKernelModuleExclusion:
    @patch("shutil.which", return_value="/usr/bin/grype")
    @patch("subprocess.run")
    def test_kernel_modules_pruned_from_cdx_before_grype(self, mock_run, mock_which, client, ids):
        """Kernel-module components are removed from the CDX handed to Grype."""
        import json as _json

        captured = {}

        def _fake_run(cmd, **kwargs):
            if isinstance(cmd, list) and "export" in cmd:
                out_dir = cmd[cmd.index("--output-dir") + 1]
                with open(f"{out_dir}/sbom_cyclonedx_v1_6.cdx.json", "w") as f:
                    _json.dump({
                        "components": [
                            {"name": "openssl", "version": "1.1.1", "bom-ref": "ref-openssl"},
                            {"name": "kernel-module-ext4", "version": "6.1", "bom-ref": "ref-km1"},
                            {"name": "kernel-module-usbcore", "version": "6.1", "bom-ref": "ref-km2"},
                        ],
                        "dependencies": [
                            {"ref": "ref-openssl"},
                            {"ref": "ref-km1"},
                        ],
                    }, f)
            elif isinstance(cmd, list) and "grype" in cmd:
                # cmd[2] == "sbom:<path>"
                sbom_path = cmd[2].split("sbom:", 1)[1]
                with open(sbom_path) as f:
                    captured["cdx"] = _json.load(f)
                stdout_file = kwargs.get("stdout")
                if stdout_file is not None:
                    stdout_file.write(_json.dumps({"matches": []}))
            return MagicMock(returncode=0)

        mock_run.side_effect = _fake_run

        with _sync_thread_patch():
            resp = client.post(f"/api/variants/{ids['variant_id']}/grype-scan")
        assert resp.status_code == 202

        names = {c["name"] for c in captured["cdx"]["components"]}
        assert names == {"openssl"}
        # Dependency edges referencing dropped kernel modules are pruned too.
        dep_refs = {d["ref"] for d in captured["cdx"]["dependencies"]}
        assert dep_refs == {"ref-openssl"}

        resp_s = client.get(f"/api/variants/{ids['variant_id']}/grype-scan/status")
        data = json.loads(resp_s.data)
        assert any("2 kernel modules excluded" in line for line in data["logs"])


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

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_scan_updates_existing_vuln_and_handles_missing_cve_id(self, mock_nvd, client, ids):
        """The worker skips empty CVE ids and updates an existing vulnerability in place."""
        mock_db = mock_nvd.return_value
        mock_db.api_get_cves_by_cpe.return_value = [
            {"cve": {}},
            {"cve": {"id": "CVE-TRIGGER-0001"}},
        ]
        mock_nvd.extract_cve_details.return_value = {
            "description": "updated desc",
            "status": "high",
            "publish_date": "2025-01-01",
            "attack_vector": "NETWORK",
            "links": ["https://example.org"],
            "weaknesses": ["CWE-79"],
            "nvd_last_modified": "2025-01-02",
            "base_score": 7.5,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_exploitability": 3.2,
            "cvss_impact": 4.3,
        }

        class _ExistingVuln:
            def __init__(self):
                self.id = "CVE-TRIGGER-0001"
                self.description = None
                self.status = None
                self.publish_date = None
                self.attack_vector = None
                self.links = None
                self.weaknesses = None
                self.update_record = MagicMock()
                self.add_found_by = MagicMock()

        fake_vuln = _ExistingVuln()
        original_get = _db.session.get

        def _fake_get(model, identity):
            if getattr(model, "__name__", "") == "Vulnerability" and str(identity) == "CVE-TRIGGER-0001":
                return fake_vuln
            return original_get(model, identity)

        with patch.object(_db.session, "get", side_effect=_fake_get):
            with patch("src.models.metrics.Metrics.from_cvss", side_effect=Exception("boom")):
                with _sync_thread_patch():
                    resp = client.post(f"/api/variants/{ids['variant_id']}/nvd-scan")

        assert resp.status_code == 202

        fake_vuln.update_record.assert_called_once()
        kwargs = fake_vuln.update_record.call_args.kwargs
        assert kwargs["description"] == "updated desc"
        assert kwargs["status"] == "high"

        resp_s = client.get(f"/api/variants/{ids['variant_id']}/nvd-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "done"


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


# ---------------------------------------------------------------------------
# Bulk running-scan discovery
# ---------------------------------------------------------------------------

class TestRunningScans:
    def test_empty_when_nothing_running(self, client):
        resp = client.get("/api/scans/running")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data == {"grype": [], "nvd": [], "osv": [], "sbom-cve-check": []}

    @patch("threading.Thread")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_lists_running_scans_grouped_by_type(self, mock_which, mock_thread, client, ids):
        # Leave the spawned threads unstarted so the scans stay "running".
        mock_thread.return_value = MagicMock()
        vid = ids["variant_id"]
        client.post(f"/api/variants/{vid}/grype-scan")
        client.post(f"/api/variants/{vid}/nvd-scan")

        resp = client.get("/api/scans/running")
        assert resp.status_code == 200
        data = json.loads(resp.data)

        assert len(data["grype"]) == 1
        assert data["grype"][0]["variant_id"] == vid
        assert data["grype"][0]["status"] == "running"
        assert len(data["nvd"]) == 1
        assert data["nvd"][0]["variant_id"] == vid
        assert data["osv"] == []
        assert data["sbom-cve-check"] == []

    @patch("threading.Thread")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_excludes_finished_scans(self, mock_which, mock_thread, client, ids):
        vid = ids["variant_id"]
        # Run the grype scan synchronously so it completes (status -> done).
        with _sync_thread_patch():
            with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout='{"matches": []}')):
                client.post(f"/api/variants/{vid}/grype-scan")

        resp = client.get("/api/scans/running")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["grype"] == []


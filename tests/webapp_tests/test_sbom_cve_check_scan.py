# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the sbom-cve-check scan trigger and status endpoints.

Covers routes/scan_triggers.py lines 744-900, 905.
"""

import json
import os
import uuid
import pytest
from unittest.mock import patch, MagicMock

from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


class _SimpleComputed:
    """Minimal stand-in for sbom_cve_check ComputedVulnInfo."""
    identifier = "CVE-2024-SCCTEST-01"
    description = "test vulnerability"
    date_published = None
    date_modified = None
    external_refs = []
    cvss_metrics = []
    vex_assessment = None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_db(app):
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.package import Package

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        project = Project.create("SccProject")
        variant = Variant.create("SccVariant", project.id)
        scan = Scan.create("initial scan", variant.id, scan_type="sbom")

        pkg = Package.find_or_create("openssl", "1.1.1",
                                     cpe=["cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"])
        _db.session.commit()

        sbom = SBOMDocument.create("/test/sbom.json", "spdx", scan.id)
        SBOMPackage.create(sbom.id, pkg.id)
        _db.session.commit()

        return {
            "variant_id": str(variant.id),
            "pkg_id": str(pkg.id),
        }


@pytest.fixture()
def app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        ids = _build_db(application)
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
# sbom-cve-check scan — status route (line 905)
# ---------------------------------------------------------------------------

class TestSbomCveCheckScanStatus:
    def test_idle_when_never_started(self, client):
        """Covers line 905: return scan_status_response(...)"""
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/variants/{fake_id}/sbom-cve-check-scan/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "idle"

    def test_invalid_variant_id_status(self, client):
        resp = client.get("/api/variants/not-a-uuid/sbom-cve-check-scan/status")
        assert resp.status_code == 400

    @patch("threading.Thread")
    def test_running_after_trigger(self, mock_thread, client, ids):
        mock_t = MagicMock()
        mock_thread.return_value = mock_t
        with patch("src.controllers.scc_engine.get_engine"):
            client.post(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan")
        resp = client.get(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "running"


# ---------------------------------------------------------------------------
# sbom-cve-check scan — trigger route (lines 744-755+)
# ---------------------------------------------------------------------------

class TestTriggerSbomCveCheckScan:
    def test_invalid_variant_id(self, client):
        resp = client.post("/api/variants/not-a-uuid/sbom-cve-check-scan")
        assert resp.status_code == 400
        assert b"Invalid variant id" in resp.data

    def test_variant_not_found(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.post(f"/api/variants/{fake_id}/sbom-cve-check-scan")
        assert resp.status_code == 404
        assert b"Variant not found" in resp.data

    @patch("threading.Thread")
    def test_scan_starts_successfully(self, mock_thread, client, ids):
        """Covers lines 749-755: vid_str, init_progress, thread creation."""
        mock_t = MagicMock()
        mock_thread.return_value = mock_t
        with patch("src.controllers.scc_engine.get_engine"):
            resp = client.post(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan")
        assert resp.status_code == 202
        data = json.loads(resp.data)
        assert data["status"] == "started"
        assert data["variant_id"] == ids["variant_id"]
        mock_t.start.assert_called_once()

    @patch("threading.Thread")
    def test_scan_already_running(self, mock_thread, client, ids):
        """Covers the 409 already-in-progress branch."""
        mock_t = MagicMock()
        mock_thread.return_value = mock_t
        with patch("src.controllers.scc_engine.get_engine"):
            resp1 = client.post(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan")
            assert resp1.status_code == 202
            resp2 = client.post(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan")
            assert resp2.status_code == 409
            assert b"already in progress" in resp2.data

    def test_scan_engine_failure(self, client, ids):
        """Covers lines ~808-812: get_engine() raises → set_error + early return."""
        with patch("src.controllers.scc_engine.get_engine",
                   side_effect=RuntimeError("engine unavailable")):
            with _sync_thread_patch():
                resp = client.post(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "engine unavailable" in data.get("error", "") or any(
            "Failed to load CVE databases" in log
            for log in data.get("logs", [])
        )

    def test_scan_empty_results(self, client, ids):
        """Covers most of _do_sbom_cve_check_scan with an engine that returns no vulns.

        This covers the happy path including:
        - _SccLogForwarder class definition and usage
        - logger level manipulation
        - scan + writer creation
        - per-package loop with 'no vulnerabilities' log
        - writer.flush() call
        - done state update
        """
        mock_engine = MagicMock()
        mock_engine.applicable_vulns.return_value = iter([])

        with patch("src.controllers.scc_engine.get_engine", return_value=mock_engine):
            with _sync_thread_patch():
                resp = client.post(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "done"
        assert any("no vulnerabilities" in log for log in data.get("logs", []))

    def test_scan_with_vulnerabilities_found(self, client, ids):
        """Covers the 'has vulns' log path when persisted_ids is non-empty."""
        computed = _SimpleComputed()
        mock_engine = MagicMock()
        mock_engine.applicable_vulns.return_value = iter([(computed, "affected")])

        with patch("src.controllers.scc_engine.get_engine", return_value=mock_engine):
            with _sync_thread_patch():
                resp = client.post(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "done"
        # The log should mention the CVE found
        all_logs = " ".join(data.get("logs", []))
        assert "CVE-2024-SCCTEST-01" in all_logs or "vuln" in all_logs.lower()

    def test_scan_per_package_exception(self, client, ids):
        """Covers the except block inside the per-package loop."""
        mock_engine = MagicMock()
        mock_engine.applicable_vulns.side_effect = RuntimeError("pkg scan failed")

        with patch("src.controllers.scc_engine.get_engine", return_value=mock_engine):
            with _sync_thread_patch():
                resp = client.post(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan/status")
        data = json.loads(resp_s.data)
        # Status should be done (the outer try/except completes) or error
        assert data["status"] in ("done", "error")
        all_logs = " ".join(data.get("logs", []))
        assert "ERROR" in all_logs or "pkg scan failed" in all_logs

    def test_scan_no_sbom_scan_for_variant(self, app, client):
        """Line 772: pkg_err → early return when variant has no SBOM scan.

        Creates a fresh variant with only a 'tool' scan — so
        active_sbom_scan_ids_for_variant returns empty, pkg_err=True.
        """
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        with app.app_context():
            project = Project.create("NoSbomProj")
            variant = Variant.create("NoSbomVariant", project.id)
            # Only a tool scan — NOT an sbom scan
            Scan.create("tool only", variant.id, scan_type="tool")
            from src.extensions import db as _db
            _db.session.commit()
            vid = str(variant.id)

        with patch("src.controllers.scc_engine.get_engine"):
            with _sync_thread_patch():
                resp = client.post(f"/api/variants/{vid}/sbom-cve-check-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{vid}/sbom-cve-check-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "SBOM" in data.get("error", "") or "packages" in data.get("error", "").lower()

    def test_scan_scc_log_forwarded_to_progress(self, client, ids):
        """Line 792: _SccLogForwarder.emit is exercised when sbom_cve_check logs."""
        mock_engine = MagicMock()
        mock_engine.applicable_vulns.return_value = iter([])

        def _engine_that_logs():
            import logging
            logging.getLogger("sbom_cve_check").info("test-forwarder-msg")
            return mock_engine

        with patch("src.controllers.scc_engine.get_engine", side_effect=_engine_that_logs):
            with _sync_thread_patch():
                resp = client.post(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "done"
        all_logs = " ".join(data.get("logs", []))
        assert "test-forwarder-msg" in all_logs

    def test_scan_outer_exception_handler(self, client, ids):
        """Lines 889-891: outer except block when Scan.create raises unexpectedly."""
        mock_engine = MagicMock()
        mock_engine.applicable_vulns.return_value = iter([])

        with patch("src.controllers.scc_engine.get_engine", return_value=mock_engine):
            with patch("src.routes.scan_triggers.Scan.create",
                       side_effect=RuntimeError("db crashed unexpectedly")):
                with _sync_thread_patch():
                    resp = client.post(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{ids['variant_id']}/sbom-cve-check-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "db crashed" in data.get("error", "")

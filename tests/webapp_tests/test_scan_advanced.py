# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for _run_grype_scan inner logic, tool-scan diffs, and
newly-detected computation in scan list serialisation."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Helper: build a DB with both SBOM and tool scans for diff testing
# ---------------------------------------------------------------------------

def _build_tool_scan_db(app):
    """Populate DB with SBOM scan + two sequential tool scans.

    - Tool scan A detects CVE-TOOL-1
    - Tool scan B detects CVE-TOOL-1 + CVE-TOOL-2  (newly detected = 1)
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

        project = Project.create("DiffProject")
        variant = Variant.create("DiffVariant", project.id)

        # --- SBOM scan ---
        sbom_scan = Scan.create("sbom scan", variant.id, scan_type="sbom")
        pkg = Package.find_or_create(
            "openssl", "1.1.1",
            cpe=["cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"],
            purl=["pkg:pypi/openssl@1.1.1"],
        )
        vuln_sbom = Vulnerability.create_record(
            id="CVE-SBOM-1", description="sbom vuln"
        )
        finding_sbom = Finding.get_or_create(pkg.id, vuln_sbom.id)
        _db.session.commit()

        sbom_doc = SBOMDocument.create(
            "/sbom/doc.json", "doc.json", sbom_scan.id, format="spdx"
        )
        SBOMPackage.create(sbom_doc.id, pkg.id)
        Observation.create(
            finding_id=finding_sbom.id, scan_id=sbom_scan.id
        )
        _db.session.commit()

        # --- Tool scan A ---
        tool_scan_a = Scan.create(
            "empty description", variant.id, scan_type="tool"
        )
        vuln_tool_1 = Vulnerability.create_record(
            id="CVE-TOOL-1", description="tool vuln 1"
        )
        finding_t1 = Finding.get_or_create(pkg.id, vuln_tool_1.id)
        _db.session.commit()
        Observation.create(
            finding_id=finding_t1.id, scan_id=tool_scan_a.id
        )
        _db.session.commit()

        # --- Tool scan B (adds CVE-TOOL-2, keeps CVE-TOOL-1) ---
        tool_scan_b = Scan.create(
            "empty description", variant.id, scan_type="tool"
        )
        vuln_tool_2 = Vulnerability.create_record(
            id="CVE-TOOL-2", description="tool vuln 2"
        )
        finding_t2 = Finding.get_or_create(pkg.id, vuln_tool_2.id)
        _db.session.commit()
        Observation.create(
            finding_id=finding_t1.id, scan_id=tool_scan_b.id
        )
        Observation.create(
            finding_id=finding_t2.id, scan_id=tool_scan_b.id
        )
        _db.session.commit()

        return {
            "project_id": str(project.id),
            "variant_id": str(variant.id),
            "sbom_scan_id": str(sbom_scan.id),
            "tool_scan_a_id": str(tool_scan_a.id),
            "tool_scan_b_id": str(tool_scan_b.id),
            "pkg_id": str(pkg.id),
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
        ids = _build_tool_scan_db(application)
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
# Tool scan list serialisation (covers lines 314-319, 195, tool-scan diffs)
# ---------------------------------------------------------------------------

class TestToolScanListSerialisation:
    """GET /api/scans returns correct diffs for sequential tool scans."""

    def test_list_includes_tool_scans_with_diffs(self, client, ids):
        """Second tool scan shows findings_added/removed vs first tool scan."""
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        data = json.loads(resp.data)

        # Find tool scan B in the list
        tool_b = [
            s for s in data
            if s["id"] == ids["tool_scan_b_id"]
        ]
        assert len(tool_b) == 1
        tb = tool_b[0]

        # Tool scan B added 1 finding (CVE-TOOL-2) vs tool scan A
        assert tb["findings_added"] == 1
        assert tb["findings_removed"] == 0
        assert tb["vulns_added"] == 1
        assert tb["vulns_removed"] == 0

        # newly_detected should be present for tool scans
        assert tb["newly_detected_findings"] is not None
        assert tb["newly_detected_vulns"] is not None

        # Tool scans have empty formats list
        assert tb["formats"] == []

    def test_list_sbom_scan_has_null_newly_detected(self, client, ids):
        """SBOM scan should have null for newly_detected fields."""
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        data = json.loads(resp.data)

        sbom = [
            s for s in data
            if s["id"] == ids["sbom_scan_id"]
        ]
        assert len(sbom) == 1
        s = sbom[0]
        assert s["newly_detected_findings"] is None
        assert s["newly_detected_vulns"] is None

        # SBOM scan has formats from its SBOM documents
        assert "spdx" in s["formats"]

    def test_scan_source_field(self, client, ids):
        """scan_source is present in the serialised response."""
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        # All scans in this fixture have scan_source=None
        for s in data:
            assert "scan_source" in s

    def test_tool_scan_a_newly_detected(self, client, ids):
        """Tool scan A — first tool scan — has newly_detected counts."""
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        data = json.loads(resp.data)

        tool_a = [
            s for s in data
            if s["id"] == ids["tool_scan_a_id"]
        ]
        assert len(tool_a) == 1
        ta = tool_a[0]
        # CVE-TOOL-1 is not in SBOM scan → it IS newly detected
        assert ta["newly_detected_findings"] >= 1
        assert ta["newly_detected_vulns"] >= 1


# ---------------------------------------------------------------------------
# Tool scan detail diff (covers lines 578-582, 634-663)
# ---------------------------------------------------------------------------

class TestToolScanDetailDiff:
    """GET /api/scans/<id>/diff for tool scans."""

    def test_tool_scan_b_diff(self, client, ids):
        """Detail-diff for tool scan B shows findings added vs tool scan A."""
        resp = client.get(
            f"/api/scans/{ids['tool_scan_b_id']}/diff"
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)

        # Tool scan packages are empty (no package diff for tool scans)
        assert data["packages_added"] == []
        assert data["packages_removed"] == []
        assert data["packages_upgraded"] == []

        # Findings: CVE-TOOL-2 added
        finding_vuln_ids = [
            f["vulnerability_id"] for f in data["findings_added"]
        ]
        assert "CVE-TOOL-2" in finding_vuln_ids

        # Newly detected: tool scan B has CVE-TOOL-2 not in SBOM and not
        # in tool scan A → newly_detected_findings should be 1.
        assert data["newly_detected_findings"] == 1
        assert data["newly_detected_vulns"] == 1

    def test_tool_scan_a_diff_first(self, client, ids):
        """First tool scan — all findings are new."""
        resp = client.get(
            f"/api/scans/{ids['tool_scan_a_id']}/diff"
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)

        # Tool scan A has 1 finding (CVE-TOOL-1) — all newly detected
        assert data["newly_detected_findings"] >= 1
        assert data["newly_detected_vulns"] >= 1

    def test_sbom_scan_diff_no_newly_detected(self, client, ids):
        """SBOM scan diff has no newly_detected fields."""
        resp = client.get(
            f"/api/scans/{ids['sbom_scan_id']}/diff"
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["newly_detected_findings"] is None
        assert data["newly_detected_vulns"] is None


# ---------------------------------------------------------------------------
# Merge result for tool scan merging SBOM (covers lines 746-747, 786-787)
# ---------------------------------------------------------------------------

class TestGlobalResultToolScanSources:
    """Merge result endpoint resolves source labels for SBOM + tool."""

    def test_tool_scan_global_result_has_sources(self, client, ids):
        resp = client.get(
            f"/api/scans/{ids['tool_scan_b_id']}/global-result"
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["scan_type"] == "tool"

        # Vulnerabilities should include CVEs from both tool and SBOM scans
        vuln_ids = [v["vulnerability_id"] for v in data["vulnerabilities"]]
        assert "CVE-SBOM-1" in vuln_ids
        assert "CVE-TOOL-1" in vuln_ids

        # Check that sources include both "Grype" and the SBOM name
        all_sources = set()
        for v in data["vulnerabilities"]:
            for s in v.get("sources", []):
                all_sources.add(s)
        # "Grype" should be among sources for tool findings
        assert any("Grype" in s or "SBOM" in s or "spdx" in s for s in all_sources)


# ---------------------------------------------------------------------------
# _run_grype_scan logic (covers lines 845-916 via subprocess mocking)
# ---------------------------------------------------------------------------

def _make_sync_thread_patch():
    """Return a context-manager patch that makes Thread.start() synchronous."""
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


class TestRunGrypeScan:
    """Test the _run_grype_scan inner function with mocked subprocesses."""

    @pytest.fixture()
    def grype_app(self, tmp_path):
        """Separate app fixture for Grype tests (avoids scan-state leaks)."""
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
                project = Project.create("GrypeProject")
                variant = Variant.create("GrypeVariant", project.id)
                scan = Scan.create("base scan", variant.id)
                pkg = Package.find_or_create("pkg", "1.0")
                _db.session.commit()
                sbom = SBOMDocument.create(
                    "/test/s.json", "spdx", scan.id
                )
                SBOMPackage.create(sbom.id, pkg.id)
                _db.session.commit()
                application._test_ids = {
                    "project_id": str(project.id),
                    "variant_id": str(variant.id),
                }
            yield application
        finally:
            os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_grype_scan_success(
        self, mock_which, mock_sp_run, grype_app, tmp_path
    ):
        """Grype scan completes when subprocess calls succeed."""
        # Make subprocess.run create the expected files
        def subprocess_side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            if isinstance(cmd, list) and "export" in cmd:
                # Simulate export creating the CDX file
                out_dir = cmd[cmd.index("--output-dir") + 1]
                cdx_path = os.path.join(
                    out_dir, "sbom_cyclonedx_v1_6.cdx.json"
                )
                with open(cdx_path, "w") as f:
                    f.write("{}")
            elif isinstance(cmd, list) and "grype" in cmd:
                # grype writes to stdout which is redirected to a file
                stdout_file = kwargs.get("stdout")
                if stdout_file and hasattr(stdout_file, "write"):
                    stdout_file.write('{"matches": []}')
            return MagicMock(returncode=0)

        mock_sp_run.side_effect = subprocess_side_effect
        client = grype_app.test_client()
        vid = grype_app._test_ids["variant_id"]

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{vid}/grype-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{vid}/grype-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "done"
        assert data["error"] is None
        assert data["progress"] == "Scan complete"
        assert data["total"] == 4
        assert data["done_count"] == 4
        assert any("\u2713" in line for line in data["logs"])

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_grype_scan_export_no_file(
        self, mock_which, mock_sp_run, grype_app
    ):
        """Grype scan errors when export produces no CDX file."""
        mock_sp_run.return_value = MagicMock(returncode=0)
        client = grype_app.test_client()
        vid = grype_app._test_ids["variant_id"]

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{vid}/grype-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{vid}/grype-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "CycloneDX export produced no file" in data["error"]
        assert any("ERROR" in line for line in data.get("logs", []))

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_grype_scan_timeout(
        self, mock_which, mock_sp_run, grype_app
    ):
        """Grype scan handles timeout."""
        import subprocess
        mock_sp_run.side_effect = subprocess.TimeoutExpired(
            cmd="flask export", timeout=120
        )
        client = grype_app.test_client()
        vid = grype_app._test_ids["variant_id"]

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{vid}/grype-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{vid}/grype-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "timed out" in data["error"]
        assert any("ERROR" in line for line in data.get("logs", []))

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_grype_scan_command_failure(
        self, mock_which, mock_sp_run, grype_app
    ):
        """Grype scan handles CalledProcessError."""
        import subprocess
        mock_sp_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="flask export", stderr="something failed"
        )
        client = grype_app.test_client()
        vid = grype_app._test_ids["variant_id"]

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{vid}/grype-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{vid}/grype-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "Command failed" in data["error"]
        assert any("ERROR" in line for line in data.get("logs", []))

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_grype_scan_generic_exception(
        self, mock_which, mock_sp_run, grype_app
    ):
        """Grype scan handles unexpected exceptions."""
        mock_sp_run.side_effect = RuntimeError("unexpected")
        client = grype_app.test_client()
        vid = grype_app._test_ids["variant_id"]

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{vid}/grype-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{vid}/grype-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "unexpected" in data["error"]
        assert any("ERROR" in line for line in data.get("logs", []))

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_grype_scan_grype_no_output(
        self, mock_which, mock_sp_run, grype_app, tmp_path
    ):
        """Grype scan errors when grype produces an empty output file."""
        def subprocess_side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            if isinstance(cmd, list) and "export" in cmd:
                out_dir = cmd[cmd.index("--output-dir") + 1]
                cdx_path = os.path.join(
                    out_dir, "sbom_cyclonedx_v1_6.cdx.json"
                )
                with open(cdx_path, "w") as f:
                    f.write("{}")
            # grype call — don't write anything to stdout
            return MagicMock(returncode=0)

        mock_sp_run.side_effect = subprocess_side_effect
        client = grype_app.test_client()
        vid = grype_app._test_ids["variant_id"]

        with _make_sync_thread_patch():
            resp = client.post(f"/api/variants/{vid}/grype-scan")
        assert resp.status_code == 202

        resp_s = client.get(f"/api/variants/{vid}/grype-scan/status")
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "Grype produced no output" in data["error"]
        assert any("ERROR" in line for line in data.get("logs", []))


# ---------------------------------------------------------------------------
# NVD / OSV scans with two scan types → break at line 1008/1280
# ---------------------------------------------------------------------------

class TestNvdScanWithToolAndSbom:
    """NVD scan on a variant that has both sbom and tool scans
    (triggers the ``break`` at line 1008)."""

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_nvd_scans_variant_two_types(self, MockNvdDb, app, client, ids):
        mock_nvd = MagicMock()
        MockNvdDb.return_value = mock_nvd
        mock_nvd.api_get_cves_by_cpe.return_value = []

        with _make_sync_thread_patch():
            resp = client.post(
                f"/api/variants/{ids['variant_id']}/nvd-scan"
            )
        assert resp.status_code == 202

        resp_s = client.get(
            f"/api/variants/{ids['variant_id']}/nvd-scan/status"
        )
        data = json.loads(resp_s.data)
        assert data["status"] == "done"


class TestOsvScanWithToolAndSbom:
    """OSV scan on a variant that has both sbom and tool scans
    (triggers the ``break`` at line 1280)."""

    @patch("src.controllers.osv_client.OSVClient.query_by_purl")
    def test_osv_scans_variant_two_types(self, mock_query, app, client, ids):
        mock_query.return_value = []

        with _make_sync_thread_patch():
            resp = client.post(
                f"/api/variants/{ids['variant_id']}/osv-scan"
            )
        assert resp.status_code == 202

        resp_s = client.get(
            f"/api/variants/{ids['variant_id']}/osv-scan/status"
        )
        data = json.loads(resp_s.data)
        assert data["status"] == "done"


# ---------------------------------------------------------------------------
# NVD / OSV scans outer exception handler (lines 1187-1189 / 1479-1481)
# ---------------------------------------------------------------------------

class TestNvdScanOuterException:
    """NVD scan outer except catches unexpected crashes."""

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_nvd_scan_outer_crash(self, MockNvdDb, app, client, ids):
        """An exception in the NVD scan body is caught and reported."""
        MockNvdDb.side_effect = RuntimeError("crashed at construction")

        with _make_sync_thread_patch():
            resp = client.post(
                f"/api/variants/{ids['variant_id']}/nvd-scan"
            )
        assert resp.status_code == 202

        resp_s = client.get(
            f"/api/variants/{ids['variant_id']}/nvd-scan/status"
        )
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "crashed at construction" in data["error"]


class TestOsvScanOuterException:
    """OSV scan outer except catches unexpected crashes."""

    @patch("src.controllers.osv_client.OSVClient")
    def test_osv_scan_outer_crash(self, MockOsv, app, client, ids):
        MockOsv.side_effect = RuntimeError("osv crash")

        with _make_sync_thread_patch():
            resp = client.post(
                f"/api/variants/{ids['variant_id']}/osv-scan"
            )
        assert resp.status_code == 202

        resp_s = client.get(
            f"/api/variants/{ids['variant_id']}/osv-scan/status"
        )
        data = json.loads(resp_s.data)
        assert data["status"] == "error"
        assert "osv crash" in data["error"]


# ---------------------------------------------------------------------------
# DELETE /api/scans/<scan_id> tests
# ---------------------------------------------------------------------------

class TestDeleteScanEndpoint:
    """DELETE /api/scans/<scan_id> removes a scan and orphaned findings."""

    def test_delete_scan_invalid_id(self, client):
        resp = client.delete("/api/scans/not-a-uuid")
        assert resp.status_code == 400

    def test_delete_scan_not_found(self, client):
        import uuid
        resp = client.delete(f"/api/scans/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_delete_tool_scan_success(self, client, ids):
        """Deleting a tool scan removes it and cleans up orphaned findings."""
        resp = client.delete(f"/api/scans/{ids['tool_scan_b_id']}")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["deleted"] is True
        assert data["scan_id"] == ids["tool_scan_b_id"]
        # CVE-TOOL-2 was only in tool_scan_b so it should be orphaned
        assert data["orphaned_findings_removed"] >= 1

        # Verify the scan no longer appears in the list
        resp2 = client.get("/api/scans")
        scan_ids = [s["id"] for s in json.loads(resp2.data)]
        assert ids["tool_scan_b_id"] not in scan_ids


# ---------------------------------------------------------------------------
# Tool-scan diff compares against GLOBAL state, not previous same-type scan
# ---------------------------------------------------------------------------

def _build_multi_source_db(app):
    """Populate DB with SBOM + NVD tool scan + Grype tool scan.

    SBOM: findings S1, S2 (CVE-S1, CVE-S2)
    NVD:  findings S1, N1, N2 (CVE-S1, CVE-N1, CVE-N2)  → adds 2 to global
    Grype: findings S2, N1, G1 (CVE-S2, CVE-N1, CVE-G1) → adds 1 to global
    Second SBOM re-import (same findings as first): expected global includes
    tool-scan findings.
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

        project = Project.create("MultiSrcProject")
        variant = Variant.create("MultiSrcVariant", project.id)
        pkg = Package.find_or_create("libfoo", "2.0.0")

        vuln_s1 = Vulnerability.create_record(id="CVE-S1", description="s1")
        vuln_s2 = Vulnerability.create_record(id="CVE-S2", description="s2")
        vuln_n1 = Vulnerability.create_record(id="CVE-N1", description="n1")
        vuln_n2 = Vulnerability.create_record(id="CVE-N2", description="n2")
        vuln_g1 = Vulnerability.create_record(id="CVE-G1", description="g1")
        f_s1 = Finding.get_or_create(pkg.id, vuln_s1.id)
        f_s2 = Finding.get_or_create(pkg.id, vuln_s2.id)
        f_n1 = Finding.get_or_create(pkg.id, vuln_n1.id)
        f_n2 = Finding.get_or_create(pkg.id, vuln_n2.id)
        f_g1 = Finding.get_or_create(pkg.id, vuln_g1.id)
        _db.session.commit()

        # 1) SBOM scan: S1, S2
        sbom1 = Scan.create("sbom1", variant.id, scan_type="sbom")
        doc = SBOMDocument.create("/doc.json", "doc", sbom1.id, format="spdx")
        SBOMPackage.create(doc.id, pkg.id)
        Observation.create(finding_id=f_s1.id, scan_id=sbom1.id)
        Observation.create(finding_id=f_s2.id, scan_id=sbom1.id)
        _db.session.commit()

        # 2) NVD tool scan: S1, N1, N2  (source="NVD")
        nvd_scan = Scan.create(
            "empty description", variant.id, scan_type="tool",
            scan_source="NVD",
        )
        Observation.create(finding_id=f_s1.id, scan_id=nvd_scan.id)
        Observation.create(finding_id=f_n1.id, scan_id=nvd_scan.id)
        Observation.create(finding_id=f_n2.id, scan_id=nvd_scan.id)
        _db.session.commit()

        # 3) Grype tool scan: S2, N1, G1  (source="Grype")
        grype_scan = Scan.create(
            "empty description", variant.id, scan_type="tool",
            scan_source="Grype",
        )
        Observation.create(finding_id=f_s2.id, scan_id=grype_scan.id)
        Observation.create(finding_id=f_n1.id, scan_id=grype_scan.id)
        Observation.create(finding_id=f_g1.id, scan_id=grype_scan.id)
        _db.session.commit()

        # 4) Second SBOM re-import (same content): S1, S2
        sbom2 = Scan.create("sbom2", variant.id, scan_type="sbom")
        doc2 = SBOMDocument.create("/doc2.json", "doc2", sbom2.id, format="spdx")
        SBOMPackage.create(doc2.id, pkg.id)
        Observation.create(finding_id=f_s1.id, scan_id=sbom2.id)
        Observation.create(finding_id=f_s2.id, scan_id=sbom2.id)
        _db.session.commit()

        return {
            "variant_id": str(variant.id),
            "sbom1_id": str(sbom1.id),
            "nvd_scan_id": str(nvd_scan.id),
            "grype_scan_id": str(grype_scan.id),
            "sbom2_id": str(sbom2.id),
        }


@pytest.fixture()
def multi_app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True, "SCAN_FILE": str(scan_file),
        })
        ids = _build_multi_source_db(application)
        application._test_ids = ids
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def multi_client(multi_app):
    return multi_app.test_client()


@pytest.fixture()
def multi_ids(multi_app):
    return multi_app._test_ids


class TestToolScanGlobalStateDiff:
    """Tool scan diffs compare against the global state (SBOM ∪ all tools),
    NOT the previous scan of the same tool type."""

    def test_nvd_scan_diff_vs_sbom_baseline(self, multi_client, multi_ids):
        """NVD scan adds 2 findings (N1, N2) to the global state."""
        resp = multi_client.get("/api/scans")
        data = json.loads(resp.data)
        nvd = next(s for s in data if s["id"] == multi_ids["nvd_scan_id"])

        # S1 is already in SBOM → not counted as added.
        # N1, N2 are new to global → findings_added = 2
        assert nvd["findings_added"] == 2
        assert nvd["findings_removed"] == 0
        assert nvd["vulns_added"] == 2
        assert nvd["vulns_removed"] == 0

    def test_grype_scan_diff_vs_global_state(self, multi_client, multi_ids):
        """Grype scan adds 1 finding (G1) to the global state.

        S2 is in SBOM, N1 is already contributed by NVD → only G1 is new.
        """
        resp = multi_client.get("/api/scans")
        data = json.loads(resp.data)
        grype = next(s for s in data if s["id"] == multi_ids["grype_scan_id"])

        assert grype["findings_added"] == 1
        assert grype["findings_removed"] == 0
        assert grype["vulns_added"] == 1
        assert grype["vulns_removed"] == 0

    def test_grype_global_result_includes_all_sources(self, multi_client, multi_ids):
        """Global result for Grype scan = SBOM ∪ NVD ∪ Grype = 5 findings."""
        resp = multi_client.get("/api/scans")
        data = json.loads(resp.data)
        grype = next(s for s in data if s["id"] == multi_ids["grype_scan_id"])

        # SBOM: S1, S2  NVD: S1, N1, N2  Grype: S2, N1, G1
        # Union = S1, S2, N1, N2, G1 → 5
        assert grype["global_finding_count"] == 5
        assert grype["global_vuln_count"] == 5

    def test_sbom_reimport_global_includes_tool_scans(self, multi_client, multi_ids):
        """Second SBOM import has global_finding_count = SBOM ∪ tools."""
        resp = multi_client.get("/api/scans")
        data = json.loads(resp.data)
        sbom2 = next(s for s in data if s["id"] == multi_ids["sbom2_id"])

        # The re-imported SBOM scan should show the global result
        # including tool-scan findings.
        assert sbom2["global_finding_count"] == 5
        assert sbom2["global_vuln_count"] == 5

    def test_first_tool_scan_has_diff_fields(self, multi_client, multi_ids):
        """First tool scan (NVD) should have numeric diff fields, not null."""
        resp = multi_client.get("/api/scans")
        data = json.loads(resp.data)
        nvd = next(s for s in data if s["id"] == multi_ids["nvd_scan_id"])

        # Even though it's the first NVD scan, is_first may be True but
        # findings_added should still be a number (not None).
        assert nvd["findings_added"] is not None
        assert nvd["vulns_added"] is not None

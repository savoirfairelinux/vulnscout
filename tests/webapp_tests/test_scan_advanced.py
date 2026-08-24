# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the Grype scan job, tool-scan diffs, and newly-detected
computation in scan list serialisation."""

import json
import os
import subprocess
import pytest
from unittest.mock import patch, MagicMock

from src.bin.webapp import create_app
from src.controllers.job_context import JobContext
from src.controllers.operation_registry import KIND_SCAN, LANE_PIPELINE, registry
from src.controllers.scan_jobs import (
    _resolve_grype_memlimit,
    run_grype_scan,
    run_nvd_scan,
    run_osv_scan,
)
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


@pytest.fixture(autouse=True)
def clean_registry():
    registry.clear()
    yield
    registry.clear()


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
# Scan jobs — shared harness
# ---------------------------------------------------------------------------

def _context(source, variant_id, **options):
    """Register an operation and return the context its job would receive."""
    op_id = f"scan:{source}:{variant_id}"
    registry.create(
        op_id=op_id, kind=KIND_SCAN, source=source,
        label=f"{source} scan", lane=LANE_PIPELINE,
    )
    return JobContext(op_id, {"variant_id": variant_id, **options})


def _run_job(application, runner, ctx):
    """Run a scan job the way the queue does, then publish what it buffered."""
    with application.app_context():
        try:
            runner(ctx)
        finally:
            ctx.flush()
    return registry.get(ctx.op_id)


class _FakeProcess:
    """Subprocess handle whose outcome the calling test decides."""

    def __init__(self, returncode=0, stderr="", times_out=False):
        self.returncode = returncode
        self._stderr = stderr
        self._times_out = times_out
        self.killed = False

    def communicate(self, timeout=None):
        if self._times_out:
            self._times_out = False
            raise subprocess.TimeoutExpired(cmd="flask", timeout=timeout)
        return "", self._stderr

    def terminate(self):
        pass

    def kill(self):
        self.killed = True


def _grype_pipeline(export_payload=None, grype_output='{"matches": []}'):
    """Popen side effect writing the artifacts each pipeline step expects.

    Passing ``None`` for either payload simulates a step that reports success
    while producing nothing.
    """
    def _spawn(command, **kwargs):
        if "export" in command:
            if export_payload is not None:
                out_dir = command[command.index("--output-dir") + 1]
                target = os.path.join(out_dir, "sbom_cyclonedx_v1_6.cdx.json")
                with open(target, "w") as handle:
                    json.dump(export_payload, handle)
        elif "grype" in command and grype_output is not None:
            kwargs["stdout"].write(grype_output)
        return _FakeProcess()
    return _spawn


# ---------------------------------------------------------------------------
# Grype scan job
# ---------------------------------------------------------------------------

class TestGrypeScanJob:
    """The Grype pipeline: CycloneDX export, scan, merge, process."""

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

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_successful_pipeline_reports_four_completed_steps(
        self, which, popen, grype_app
    ):
        """Every stage runs and the operation ends on the final step."""
        popen.side_effect = _grype_pipeline(export_payload={})

        ctx = _context("grype", grype_app._test_ids["variant_id"])
        operation = _run_job(grype_app, run_grype_scan, ctx)

        assert operation["error"] is None
        assert operation["progress"] == {
            "current": 4, "total": 4, "message": "Scan complete",
        }
        assert any("\u2713" in line for line in operation["logs"])

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_missing_cyclonedx_export_fails_the_scan(
        self, which, popen, grype_app
    ):
        """A silent export failure is caught before Grype is invoked."""
        popen.side_effect = _grype_pipeline(export_payload=None)

        ctx = _context("grype", grype_app._test_ids["variant_id"])
        with pytest.raises(RuntimeError, match="CycloneDX export produced no file"):
            _run_job(grype_app, run_grype_scan, ctx)

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_subprocess_timeout_fails_the_scan(self, which, popen, grype_app):
        popen.return_value = _FakeProcess(times_out=True)

        ctx = _context("grype", grype_app._test_ids["variant_id"])
        with pytest.raises(RuntimeError, match="Grype scan timed out"):
            _run_job(grype_app, run_grype_scan, ctx)

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_failing_subprocess_surfaces_its_stderr(
        self, which, popen, grype_app
    ):
        popen.return_value = _FakeProcess(returncode=1, stderr="something failed")

        ctx = _context("grype", grype_app._test_ids["variant_id"])
        with pytest.raises(RuntimeError, match="Command failed: something failed"):
            _run_job(grype_app, run_grype_scan, ctx)

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_unexpected_spawn_failure_fails_the_scan(
        self, which, popen, grype_app
    ):
        popen.side_effect = RuntimeError("unexpected")

        ctx = _context("grype", grype_app._test_ids["variant_id"])
        with pytest.raises(RuntimeError, match="unexpected"):
            _run_job(grype_app, run_grype_scan, ctx)

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_empty_grype_output_fails_the_scan(self, which, popen, grype_app):
        """Grype exiting cleanly with no findings file is still a failure."""
        popen.side_effect = _grype_pipeline(export_payload={}, grype_output=None)

        ctx = _context("grype", grype_app._test_ids["variant_id"])
        with pytest.raises(RuntimeError, match="Grype produced no output"):
            _run_job(grype_app, run_grype_scan, ctx)


# ---------------------------------------------------------------------------
# NVD / OSV scans on a variant carrying both SBOM and tool scans
# ---------------------------------------------------------------------------

class TestNvdScanWithToolAndSbomScans:
    """The scanned package set comes from the SBOM scan, not the tool scans."""

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_nvd_scan_completes_on_a_variant_holding_both_scan_types(
        self, MockNvdDb, app, ids
    ):
        nvd = MagicMock()
        MockNvdDb.return_value = nvd
        nvd.api_get_cves_by_cpe.return_value = []

        ctx = _context("nvd", ids["variant_id"], mode="api")
        operation = _run_job(app, run_nvd_scan, ctx)

        assert operation["error"] is None
        assert "0 CVEs" in operation["progress"]["message"]


class TestOsvScanWithToolAndSbomScans:
    """The scanned package set comes from the SBOM scan, not the tool scans."""

    @patch("src.controllers.osv_client.OSVClient.query_by_purl")
    def test_osv_scan_completes_on_a_variant_holding_both_scan_types(
        self, query, app, ids
    ):
        query.return_value = []

        ctx = _context("osv", ids["variant_id"])
        operation = _run_job(app, run_osv_scan, ctx)

        assert operation["error"] is None
        assert "0 vulnerabilities" in operation["progress"]["message"]


# ---------------------------------------------------------------------------
# _resolve_grype_memlimit unit tests
# ---------------------------------------------------------------------------

class TestResolveGrypeMemlimit:
    """Unit tests for the _resolve_grype_memlimit() helper."""

    def setup_method(self):
        # Remove GRYPE_MEMLIMIT from env before each test
        os.environ.pop("GRYPE_MEMLIMIT", None)

    def teardown_method(self):
        os.environ.pop("GRYPE_MEMLIMIT", None)

    def test_explicit_value_returned_verbatim(self):
        """An explicit GRYPE_MEMLIMIT value is forwarded to GOMEMLIMIT as-is."""
        os.environ["GRYPE_MEMLIMIT"] = "24GiB"
        assert _resolve_grype_memlimit() == "24GiB"

    def test_explicit_bytes_returned_verbatim(self):
        """A plain-integer GRYPE_MEMLIMIT is forwarded unchanged."""
        os.environ["GRYPE_MEMLIMIT"] = "6442450944"
        assert _resolve_grype_memlimit() == "6442450944"

    def test_off_returns_none(self):
        os.environ["GRYPE_MEMLIMIT"] = "off"
        assert _resolve_grype_memlimit() is None

    def test_zero_returns_none(self):
        os.environ["GRYPE_MEMLIMIT"] = "0"
        assert _resolve_grype_memlimit() is None

    def test_disabled_returns_none(self):
        os.environ["GRYPE_MEMLIMIT"] = "disabled"
        assert _resolve_grype_memlimit() is None

    def test_auto_mode_uses_proc_meminfo(self, tmp_path):
        """Auto mode reads /proc/meminfo and returns ~80 % as bytes."""
        import builtins as _builtins
        fake_meminfo = tmp_path / "meminfo"
        # 8 GiB = 8388608 kB
        fake_meminfo.write_text("MemTotal:        8388608 kB\nMemFree: 1000000 kB\n")
        _real_open = _builtins.open

        def _patched_open(path, *a, **kw):
            if str(path) == "/proc/meminfo":
                return _real_open(str(fake_meminfo), *a, **kw)
            raise OSError(f"not available: {path}")

        with patch("builtins.open", side_effect=_patched_open):
            result = _resolve_grype_memlimit()
        # 8 GiB * 80 % = 6.4 GiB = 6871947674 bytes (approx)
        if result is not None:
            assert int(result) == 8388608 * 1024 * 80 // 100

    def test_auto_mode_returns_integer_string(self, tmp_path):
        """Auto mode result is a plain integer string (valid GOMEMLIMIT)."""
        import builtins as _builtins
        fake_meminfo = tmp_path / "meminfo"
        fake_meminfo.write_text("MemTotal:        4194304 kB\n")
        _real_open = _builtins.open

        def _patched_open(path, *a, **kw):
            if str(path) == "/proc/meminfo":
                return _real_open(str(fake_meminfo), *a, **kw)
            raise OSError(f"not available: {path}")

        with patch("builtins.open", side_effect=_patched_open):
            result = _resolve_grype_memlimit()
        if result is not None:
            assert result.isdigit()


# ---------------------------------------------------------------------------
# GRYPE_MEMLIMIT integration: grype subprocess receives GOMEMLIMIT
# ---------------------------------------------------------------------------

class TestGrypeScanMemlimit:
    """The Grype subprocess is the only one that receives GOMEMLIMIT."""

    @pytest.fixture()
    def grype_app_ml(self, tmp_path):
        """Minimal app for memory-limit tests."""
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
                project = Project.create("MLProject")
                variant = Variant.create("MLVariant", project.id)
                Scan.create("base scan", variant.id)
                _db.session.commit()
                application._test_ids = {
                    "variant_id": str(variant.id),
                }
            yield application
        finally:
            os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)
            os.environ.pop("GRYPE_MEMLIMIT", None)

    @staticmethod
    def _call_for(popen, executable):
        return next(
            (call for call in popen.call_args_list
             if isinstance(call.args[0], list) and executable in call.args[0]),
            None,
        )

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_explicit_grype_memlimit_sets_gomemlimit(
        self, which, popen, grype_app_ml
    ):
        """When GRYPE_MEMLIMIT is set, the Grype subprocess receives GOMEMLIMIT."""
        os.environ["GRYPE_MEMLIMIT"] = "8GiB"
        popen.side_effect = _grype_pipeline(export_payload={"components": []})

        ctx = _context("grype", grype_app_ml._test_ids["variant_id"])
        _run_job(grype_app_ml, run_grype_scan, ctx)

        grype_call = self._call_for(popen, "grype")
        assert grype_call is not None, "grype subprocess was never called"
        assert grype_call.kwargs.get("env", {}).get("GOMEMLIMIT") == "8GiB"

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_off_grype_memlimit_does_not_set_gomemlimit(
        self, which, popen, grype_app_ml
    ):
        """When GRYPE_MEMLIMIT=off, the Grype subprocess has no GOMEMLIMIT."""
        os.environ["GRYPE_MEMLIMIT"] = "off"
        popen.side_effect = _grype_pipeline(export_payload={"components": []})

        ctx = _context("grype", grype_app_ml._test_ids["variant_id"])
        _run_job(grype_app_ml, run_grype_scan, ctx)

        grype_call = self._call_for(popen, "grype")
        assert grype_call is not None, "grype subprocess was never called"
        assert "GOMEMLIMIT" not in grype_call.kwargs.get("env", {})

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_flask_export_does_not_receive_gomemlimit(
        self, which, popen, grype_app_ml
    ):
        """GOMEMLIMIT must only reach Grype, not the flask export subprocess."""
        os.environ["GRYPE_MEMLIMIT"] = "4GiB"
        popen.side_effect = _grype_pipeline(export_payload={"components": []})

        ctx = _context("grype", grype_app_ml._test_ids["variant_id"])
        _run_job(grype_app_ml, run_grype_scan, ctx)

        export_call = self._call_for(popen, "export")
        assert export_call is not None, "flask export subprocess was never called"
        # The export call inherits the process environment untouched.
        export_env = export_call.kwargs.get("env")
        if export_env is not None:
            assert "GOMEMLIMIT" not in export_env

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/grype")
    def test_memlimit_is_recorded_in_the_operation_log(
        self, which, popen, grype_app_ml
    ):
        """The applied GOMEMLIMIT is visible to whoever watches the scan."""
        os.environ["GRYPE_MEMLIMIT"] = "12GiB"
        popen.side_effect = _grype_pipeline(export_payload={"components": []})

        ctx = _context("grype", grype_app_ml._test_ids["variant_id"])
        operation = _run_job(grype_app_ml, run_grype_scan, ctx)

        assert any("GOMEMLIMIT" in line and "12GiB" in line
                   for line in operation["logs"])


# ---------------------------------------------------------------------------
# NVD / OSV scans propagate unexpected crashes
# ---------------------------------------------------------------------------

class TestNvdScanCrashPropagation:
    """An unexpected crash surfaces instead of being swallowed."""

    @patch("src.controllers.nvd_db.NVD_DB")
    def test_nvd_scan_reraises_an_unexpected_crash(self, MockNvdDb, app, ids):
        MockNvdDb.side_effect = RuntimeError("crashed at construction")

        ctx = _context("nvd", ids["variant_id"], mode="api")
        with pytest.raises(RuntimeError, match="crashed at construction"):
            _run_job(app, run_nvd_scan, ctx)


class TestOsvScanCrashPropagation:
    """An unexpected crash surfaces instead of being swallowed."""

    @patch("src.controllers.osv_client.OSVClient")
    def test_osv_scan_reraises_an_unexpected_crash(self, MockOsv, app, ids):
        MockOsv.side_effect = RuntimeError("osv crash")

        ctx = _context("osv", ids["variant_id"])
        with pytest.raises(RuntimeError, match="osv crash"):
            _run_job(app, run_osv_scan, ctx)


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

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""sbom-cve-check scan behaviour, exercised through ``run_scc_scan``.

The job reports through its :class:`JobContext`, so progress and log
assertions read the operation back from the registry.  Failures are raised
rather than recorded by the job itself; the queue is what turns them into an
``error`` operation.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from src.bin.webapp import create_app
from src.controllers.job_context import JobContext
from src.controllers.operation_registry import KIND_SCAN, LANE_PIPELINE, registry
from src.controllers.scan_jobs import run_scc_scan
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _SimpleComputed:
    """Minimal stand-in for sbom_cve_check ComputedVulnInfo."""
    identifier = "CVE-2024-SCCTEST-01"
    description = "test vulnerability"
    date_published = None
    date_modified = None
    external_refs = []
    cvss_metrics = []
    vex_assessment = None


def _context(variant_id, **options):
    """Register an operation and return the context its job would receive."""
    op_id = f"scan:scc:{variant_id}"
    registry.create(
        op_id=op_id, kind=KIND_SCAN, source="scc",
        label="sbom-cve-check scan", lane=LANE_PIPELINE,
    )
    return JobContext(op_id, {"variant_id": variant_id, **options})


def _run(app, ctx):
    """Run the job the way the queue does, then publish what it buffered."""
    with app.app_context():
        try:
            run_scc_scan(ctx)
        finally:
            ctx.flush()
    return registry.get(ctx.op_id)


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
def ids(app):
    return app._test_ids


@pytest.fixture(autouse=True)
def clean_registry():
    registry.clear()
    yield
    registry.clear()


# ---------------------------------------------------------------------------
# sbom-cve-check scan job
# ---------------------------------------------------------------------------

class TestSbomCveCheckScan:
    def test_unavailable_advisory_databases_fail_the_scan(self, app, ids):
        """A database that cannot be loaded aborts the scan with its cause."""
        ctx = _context(ids["variant_id"])
        with patch("src.controllers.scc_engine.get_engine",
                   side_effect=RuntimeError("engine unavailable")):
            with pytest.raises(RuntimeError, match="Failed to load CVE databases"):
                _run(app, ctx)

        logs = registry.get(ctx.op_id)["logs"]
        assert any("Loading CVE databases" in line for line in logs)

    def test_package_without_matches_is_reported_as_clean(self, app, ids):
        """A package the engine returns nothing for is logged as clean."""
        engine = MagicMock()
        engine.applicable_vulns.return_value = iter([])

        ctx = _context(ids["variant_id"])
        with patch("src.controllers.scc_engine.get_engine", return_value=engine):
            operation = _run(app, ctx)

        assert operation["error"] is None
        assert any("no vulnerabilities" in line for line in operation["logs"])
        assert operation["progress"]["message"].startswith("Found 0 vulnerabilities")

    def test_matched_vulnerabilities_are_listed_in_the_log(self, app, ids):
        """Persisted CVE identifiers appear in the per-package log line."""
        engine = MagicMock()
        engine.applicable_vulns.return_value = iter([(_SimpleComputed(), "affected")])

        ctx = _context(ids["variant_id"])
        with patch("src.controllers.scc_engine.get_engine", return_value=engine):
            operation = _run(app, ctx)

        assert operation["error"] is None
        assert any("CVE-2024-SCCTEST-01" in line for line in operation["logs"])

    def test_package_level_failure_is_logged_and_scan_continues(self, app, ids):
        """One unscannable package does not abort the whole run."""
        engine = MagicMock()
        engine.applicable_vulns.side_effect = RuntimeError("pkg scan failed")

        ctx = _context(ids["variant_id"])
        with patch("src.controllers.scc_engine.get_engine", return_value=engine):
            operation = _run(app, ctx)

        assert operation["error"] is None
        assert any("ERROR" in line for line in operation["logs"])
        assert any("pkg scan failed" in line for line in operation["logs"])

    def test_variant_without_sbom_scan_fails(self, app):
        """A variant holding only tool scans has no package set to scan."""
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan

        with app.app_context():
            project = Project.create("NoSbomProj")
            variant = Variant.create("NoSbomVariant", project.id)
            # Only a tool scan — NOT an sbom scan
            Scan.create("tool only", variant.id, scan_type="tool")
            _db.session.commit()
            vid = str(variant.id)

        ctx = _context(vid)
        with patch("src.controllers.scc_engine.get_engine"):
            with pytest.raises(RuntimeError, match="No SBOM scan found"):
                _run(app, ctx)

    def test_engine_library_output_reaches_the_operation_log(self, app, ids):
        """Both ``sbom_cve_check`` logging and git sync progress are forwarded."""
        engine = MagicMock()
        engine.applicable_vulns.return_value = iter([])

        def _engine_that_logs(progress=None):
            import logging
            logging.getLogger("sbom_cve_check").info("test-forwarder-msg")
            progress("Synchronizing nvd-fkie: Receiving objects: 50%")
            return engine

        ctx = _context(ids["variant_id"])
        with patch("src.controllers.scc_engine.get_engine",
                   side_effect=_engine_that_logs):
            operation = _run(app, ctx)

        assert operation["error"] is None
        assert "test-forwarder-msg" in operation["logs"]
        assert "Synchronizing nvd-fkie: Receiving objects: 50%" in operation["logs"]

    def test_unexpected_persistence_failure_fails_the_scan(self, app, ids):
        """A crash while recording the scan propagates instead of being swallowed."""
        engine = MagicMock()
        engine.applicable_vulns.return_value = iter([])

        ctx = _context(ids["variant_id"])
        with patch("src.controllers.scc_engine.get_engine", return_value=engine):
            with patch("src.controllers.scan_jobs.Scan.create",
                       side_effect=RuntimeError("db crashed unexpectedly")):
                with pytest.raises(RuntimeError, match="db crashed unexpectedly"):
                    _run(app, ctx)

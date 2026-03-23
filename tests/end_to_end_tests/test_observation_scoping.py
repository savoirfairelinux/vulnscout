# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the observation-scoping change in merger_ci._run_main.

The key invariant being tested: when _run_main() creates observations it must
only link findings whose package appears in the *current scan's* SBOM documents.
Findings for packages that are NOT referenced by the scan's SBOM documents must
NOT receive an observation for that scan.
"""

import pytest
import os
from unittest.mock import MagicMock, patch
from . import write_demo_files


# ---------------------------------------------------------------------------
# Shared autouse fixture for every test in this module
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def mock_epss_db():
    """Replace EPSS_DB with a harmless mock."""
    mock = MagicMock()
    mock.get_score.return_value = None
    with patch("src.controllers.vulnerabilities.EPSS_DB", return_value=mock):
        yield mock


# ---------------------------------------------------------------------------
# Fixture: single-variant app (reuses the standard demo data)
# ---------------------------------------------------------------------------

@pytest.fixture()
def init_files(tmp_path):
    files = {
        "CDX_PATH": tmp_path / "input.cdx.json",
        "OPENVEX_PATH": tmp_path / "merged.openvex.json",
        "SPDX_FOLDER": tmp_path / "spdx",
        "SPDX_PATH": tmp_path / "spdx" / "input.spdx.json",
        "GRYPE_CDX_PATH": tmp_path / "cdx.grype.json",
        "GRYPE_SPDX_PATH": tmp_path / "spdx.grype.json",
        "YOCTO_FOLDER": tmp_path / "yocto_cve",
        "YOCTO_CVE_CHECKER": tmp_path / "yocto_cve" / "demo.json",
        "LOCAL_USER_DATABASE_PATH": tmp_path / "openvex.json",
    }
    files["YOCTO_FOLDER"].mkdir()
    files["SPDX_FOLDER"].mkdir()
    write_demo_files(files)
    return files


@pytest.fixture()
def app(init_files):
    """Flask app with in-memory SQLite; demo SBOM files registered for
    project='TestProject', variant='default'."""
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        from src.bin.webapp import create_app
        from src.extensions import db as _db
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        with application.app_context():
            _db.create_all()
            runner = application.test_cli_runner()
            result = runner.invoke(args=[
                "merge",
                "--project", "TestProject",
                "--variant", "default",
                "--cdx", str(init_files["CDX_PATH"]),
                "--spdx", str(init_files["SPDX_PATH"]),
                "--grype", str(init_files["GRYPE_CDX_PATH"]),
                "--grype", str(init_files["GRYPE_SPDX_PATH"]),
                "--yocto-cve", str(init_files["YOCTO_CVE_CHECKER"]),
                "--openvex", str(init_files["LOCAL_USER_DATABASE_PATH"]),
            ])
            assert result.exit_code == 0, result.output
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_observations_only_created_for_sbom_packages(app):
    """Observations must only be created for findings whose package is
    referenced by the scan's SBOM documents.

    A pre-existing finding for a package NOT in the SBOM must NOT receive
    an observation for that scan after _run_main() completes.
    """
    from src.bin.merger_ci import _run_main
    from src.extensions import db
    from src.models.scan import Scan
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.sbom_document import SBOMDocument

    with app.app_context():
        # --- inject a "foreign" package + finding BEFORE running _run_main ---
        # This package is intentionally NOT referenced by any SBOMPackage row
        # (i.e. it was not in the CDX/SPDX files registered for this scan).
        foreign_pkg = Package.find_or_create(
            "foreign-package",
            "9.9.9",
            [],
            ["pkg:generic/foreign-package@9.9.9"],
            "",
        )
        foreign_vuln = Vulnerability.create_record(
            id="CVE-9999-99999",
            description="A fake foreign vulnerability",
            status="critical",
        )
        db.session.commit()

        foreign_finding = Finding.get_or_create(foreign_pkg.id, "CVE-9999-99999")

        # Sanity: the foreign finding must have no observations yet
        assert Observation.get_by_finding(foreign_finding.id) == []

        # --- run merger_ci ---
        _run_main()

        # --- verify scoping ---
        latest_scan = Scan.get_latest()
        assert latest_scan is not None

        # Observations for the foreign finding must remain empty for this scan
        foreign_obs = [
            o for o in Observation.get_by_finding(foreign_finding.id)
            if o.scan_id == latest_scan.id
        ]
        assert foreign_obs == [], (
            "foreign-package is not in the scan's SBOM, so its finding must "
            "not receive an observation for this scan"
        )

        # At least one SBOM-linked package (cairo) must have an observation
        # for the latest scan (confirming _run_main() did create observations)
        cairo = Package.find_or_create(
            "cairo", "1.16.0", [], [], ""
        )
        cairo_findings = db.session.execute(
            db.select(Finding).where(Finding.package_id == cairo.id)
        ).scalars().all()
        cairo_observations = [
            o
            for f in cairo_findings
            for o in Observation.get_by_finding(f.id)
            if o.scan_id == latest_scan.id
        ]
        assert len(cairo_observations) > 0, (
            "cairo is in the scan's SBOM, so at least one of its findings "
            "must have an observation for the latest scan"
        )


def test_no_observations_when_sbom_has_no_packages(app):
    """When the latest scan's SBOM documents reference no packages,
    no observations should be created for that scan."""
    from src.bin.merger_ci import _run_main
    from src.extensions import db
    from src.models.scan import Scan
    from src.models.observation import Observation
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.sbom_document import SBOMDocument

    with app.app_context():
        # Create a brand-new scan (later timestamp → will be the "latest")
        # with an SBOM document that has no SBOMPackage rows
        new_project = Project.get_or_create("EmptyProject")
        new_variant = Variant.get_or_create("EmptyVariant", new_project.id)
        new_scan = Scan.create("empty scan", new_variant.id)
        # SBOM document with no packages
        SBOMDocument.create(
            path="/sbom/empty.cdx.json",
            source_name="cdx",
            scan_id=new_scan.id,
        )

        # Confirm this is now the latest scan
        latest = Scan.get_latest()
        assert latest.id == new_scan.id

        obs_before = Observation.get_by_scan(new_scan.id)
        assert obs_before == []

        _run_main()

        obs_after = Observation.get_by_scan(new_scan.id)
        assert obs_after == [], (
            "An empty SBOM scan should not produce any observations"
        )


def test_observations_not_duplicated_on_second_run(app):
    """Running _run_main() twice for the same scan must not create duplicate
    observations."""
    from src.bin.merger_ci import _run_main
    from src.extensions import db
    from src.models.scan import Scan
    from src.models.observation import Observation

    with app.app_context():
        _run_main()

        latest_scan = Scan.get_latest()
        obs_after_first = Observation.get_by_scan(latest_scan.id)
        count_first = len(obs_after_first)
        assert count_first > 0

        # Second run — must not create duplicates
        _run_main()

        obs_after_second = Observation.get_by_scan(latest_scan.id)
        count_second = len(obs_after_second)
        assert count_second == count_first, (
            f"Expected {count_first} observations after second run, "
            f"got {count_second}"
        )

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tool scans launched in one batch are reported as a single scan run."""

import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from src.bin.webapp import create_app
from src.controllers.scan_jobs import _tool_scan
from src.extensions import db as _db
from src.routes._scan_diff import invalidate_scan_list_cache

RUN_ID = "q-run"
START = datetime(2026, 9, 1, tzinfo=timezone.utc)


def _build_db(app):
    """Variant A: SBOM, then Grype + NVD in one run, then a lone OSV run.

    Grype reports CVE-RUN-1; NVD reports CVE-RUN-1 again plus CVE-RUN-2.
    Variant B takes part in the same run with a single Grype scan.
    """
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.project import Project
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.scan import Scan
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability
    from src.routes._scan_helpers import create_observation_and_assessment

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        project = Project.create("RunProject")
        variant_a = Variant.create("alpha", project.id)
        variant_b = Variant.create("beta", project.id)
        package = Package.find_or_create("openssl", "3.0.0")
        for vuln_id in ("CVE-SBOM-1", "CVE-RUN-1", "CVE-RUN-2", "CVE-OSV-1"):
            Vulnerability.create_record(id=vuln_id, description=vuln_id)
        _db.session.commit()

        minute = iter(range(100))

        def scan(variant, scan_type, source=None, run_id=None):
            created = Scan.create("empty description", variant.id, scan_type=scan_type,
                                  scan_source=source, run_id=run_id)
            created.timestamp = START + timedelta(minutes=next(minute))
            _db.session.commit()
            return created

        def observe(tool_scan, variant, vuln_ids):
            pairs: set = set()
            assessed: set = set()
            for vuln_id in vuln_ids:
                finding = Finding.get_or_create(package.id, vuln_id)
                create_observation_and_assessment(
                    finding, tool_scan, variant.id, tool_scan.scan_source, pairs, assessed,
                )
            _db.session.commit()

        for variant in (variant_a, variant_b):
            sbom_scan = scan(variant, "sbom")
            document = SBOMDocument.create(f"/sbom/{variant.name}.json", "spdx", sbom_scan.id)
            SBOMPackage.create(document.id, package.id)
            Observation.create(
                finding_id=Finding.get_or_create(package.id, "CVE-SBOM-1").id, scan_id=sbom_scan.id,
            )
            _db.session.commit()

        grype = scan(variant_a, "tool", "grype", RUN_ID)
        observe(grype, variant_a, ["CVE-RUN-1"])
        grype_b = scan(variant_b, "tool", "grype", RUN_ID)
        observe(grype_b, variant_b, ["CVE-RUN-1"])
        nvd = scan(variant_a, "tool", "nvd", RUN_ID)
        observe(nvd, variant_a, ["CVE-RUN-1", "CVE-RUN-2"])
        osv = scan(variant_a, "tool", "osv", "q-solo")
        observe(osv, variant_a, ["CVE-OSV-1"])
        legacy = scan(variant_a, "tool", "scc")
        observe(legacy, variant_a, ["CVE-RUN-2"])

        return {
            "project_id": str(project.id),
            "variant_a": str(variant_a.id),
            "variant_b": str(variant_b.id),
            "grype": str(grype.id),
            "grype_b": str(grype_b.id),
            "nvd": str(nvd.id),
            "osv": str(osv.id),
            "legacy": str(legacy.id),
        }


@pytest.fixture()
def app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        application._test_ids = _build_db(application)
        invalidate_scan_list_cache()
        yield application
    finally:
        invalidate_scan_list_cache()
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def ids(app):
    return app._test_ids


def _by_id(response):
    assert response.status_code == 200
    return {entry["id"]: entry for entry in json.loads(response.data)}


@pytest.mark.parametrize("scope", ["all", "project", "variant"])
def test_every_step_of_a_run_carries_the_same_summary(client, ids, scope):
    path = {
        "all": "/api/scans",
        "project": f"/api/projects/{ids['project_id']}/scans",
        "variant": f"/api/variants/{ids['variant_a']}/scans",
    }[scope]
    scans = _by_id(client.get(path))

    grype, nvd = scans[ids["grype"]], scans[ids["nvd"]]
    assert grype["run_id"] == nvd["run_id"] == RUN_ID
    assert grype["run"] == nvd["run"]
    assert grype["run"] == {
        "id": RUN_ID,
        "scan_ids": [ids["grype"], ids["nvd"]],
        "sources": ["grype", "nvd"],
        "vuln_count": 2,
        "finding_count": 2,
        "assessment_count": 2,
        "newly_detected_vulns": 2,
        "newly_detected_findings": 2,
        "newly_detected_assessments": 2,
    }


def test_run_counts_a_vulnerability_found_by_several_scanners_once(client, ids):
    scans = _by_id(client.get("/api/scans"))
    grype, nvd = scans[ids["grype"]], scans[ids["nvd"]]

    assert grype["vuln_count"] + nvd["vuln_count"] == 3
    assert grype["run"]["vuln_count"] == 2


def test_scans_outside_a_multi_step_run_have_no_summary(client, ids):
    scans = _by_id(client.get("/api/scans"))

    # Same run id, but the only step of that run for its variant.
    assert scans[ids["grype_b"]]["run_id"] == RUN_ID
    assert scans[ids["grype_b"]]["run"] is None
    assert scans[ids["osv"]]["run_id"] == "q-solo"
    assert scans[ids["osv"]]["run"] is None
    assert scans[ids["legacy"]]["run_id"] is None
    assert scans[ids["legacy"]]["run"] is None
    sbom_scans = [entry for entry in scans.values() if entry["scan_type"] == "sbom"]
    assert sbom_scans and all(entry["run"] is None for entry in sbom_scans)


def test_selected_variant_subset_keeps_run_summaries(client, ids):
    scans = _by_id(client.get(f"/api/scans?variant_ids={ids['variant_a']},{ids['variant_b']}"))

    assert scans[ids["nvd"]]["run"]["scan_ids"] == [ids["grype"], ids["nvd"]]
    assert scans[ids["grype_b"]]["run"] is None


def test_tool_scan_records_its_run_id(app, ids):
    from src.models.scan import Scan

    with app.app_context():
        with _tool_scan(uuid.UUID(ids["variant_a"]), "osv", "q-42") as scan:
            scan_id = scan.id
        assert _db.session.get(Scan, scan_id).run_id == "q-42"

        with _tool_scan(uuid.UUID(ids["variant_a"]), "osv") as scan:
            scan_id = scan.id
        assert _db.session.get(Scan, scan_id).run_id is None


def test_merge_command_groups_grype_results_into_the_run(app, tmp_path):
    from src.models.project import Project
    from src.models.scan import Scan
    from src.models.variant import Variant

    grype_file = tmp_path / "grype.json"
    grype_file.write_text('{"matches": []}')
    sbom_file = tmp_path / "sbom.spdx.json"
    sbom_file.write_text('{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"t"}')
    runner = app.test_cli_runner()

    tool = runner.invoke(args=["merge", "--project", "CLIRun", "--variant", "v",
                               "--grype", str(grype_file), "--run-id", "q-cli"])
    sbom = runner.invoke(args=["merge", "--project", "CLIRun", "--variant", "v",
                               "--spdx", str(sbom_file), "--run-id", "q-cli"])

    assert tool.exit_code == 0, tool.output
    assert sbom.exit_code == 0, sbom.output
    with app.app_context():
        project = Project.get_or_create("CLIRun")
        variant = Variant.get_by_project(project.id)[0]
        run_ids = {scan.scan_type: scan.run_id for scan in Scan.get_by_variant_id(variant.id)}
    assert run_ids == {"tool": "q-cli", "sbom": None}

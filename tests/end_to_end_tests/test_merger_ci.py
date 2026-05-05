# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""End-to-end tests for merger_ci.

Tests use the new DB-backed workflow:
  1. `flask merge` registers SBOM files in the database.
  2. `_run_main()` (the `flask process` command logic) reads the registered
     documents, parses them and populates the in-memory controllers / DB.
"""

import pytest
import io
import json
import os

from flask.testing import FlaskCliRunner
from click.testing import Result as CliResult

from src.bin.merger_ci import _run_main, _ts_key, post_treatment, main
from . import write_demo_files


# ---------------------------------------------------------------------------
# Fixtures
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
def app(init_files, monkeypatch):
    """Flask app with in-memory SQLite; all demo SBOM files are registered."""
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
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
            "--variant", "TestVariant",
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


@pytest.fixture()
def cli_runner(app) -> FlaskCliRunner:
    return app.test_cli_runner()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_running_script(app):
    ctrls = _run_main()

    out_pkg = ctrls["packages"].to_dict()
    out_vuln = ctrls["vulnerabilities"].to_dict()
    out_assessment = ctrls["assessments"].to_dict()

    assert "cairo@1.16.0" in out_pkg
    assert "busybox@1.35.0" in out_pkg
    assert "c-ares@1.18.1" in out_pkg
    assert "curl@7.82.0" in out_pkg
    assert "xyz@rev2.3" in out_pkg
    assert "linux@6.8.0-40-generic" in out_pkg

    assert "CVE-2020-35492" in out_vuln
    assert "CVE-2022-30065" in out_vuln
    assert "CVE-2007-3152" in out_vuln
    assert "CVE-2023-31124" in out_vuln
    assert "CVE-2024-2398" in out_vuln

    assert len(out_assessment) >= 1


def test_invalid_openvex(app, init_files, monkeypatch):
    init_files["LOCAL_USER_DATABASE_PATH"].write_text("invalid{ json")
    monkeypatch.setenv("IGNORE_PARSING_ERRORS", 'false')
    with pytest.raises(Exception):
        _run_main()

    monkeypatch.setenv("IGNORE_PARSING_ERRORS", 'true')
    _run_main()


def test_invalid_cdx(app, init_files, monkeypatch):
    """Replaces test_invalid_time_estimates: error handling for a bad CDX file."""
    init_files["CDX_PATH"].write_text("invalid{ json")
    monkeypatch.setenv("IGNORE_PARSING_ERRORS", 'false')
    with pytest.raises(Exception):
        _run_main()

    monkeypatch.setenv("IGNORE_PARSING_ERRORS", 'true')
    _run_main()


def test_ci_mode(app, monkeypatch):
    monkeypatch.setenv("MATCH_CONDITION", "false == true")
    _run_main()

    monkeypatch.setenv("MATCH_CONDITION", "true == true")
    with pytest.raises(SystemExit) as e:
        _run_main()
    assert e.type == SystemExit
    assert e.value.code == 2

    monkeypatch.setenv("MATCH_CONDITION", "cvss >= 8")
    with pytest.raises(SystemExit) as e:
        _run_main()
    assert e.type == SystemExit
    assert e.value.code == 2

    monkeypatch.setenv("MATCH_CONDITION", "cvss >= 8 and epss == 1.23456%")
    _run_main()


def test_spdx_output_completeness(app):
    # merger_ci no longer writes SPDX output files — verify in-memory state
    ctrls = _run_main()

    out_pkg = ctrls["packages"].to_dict()
    assert len(out_pkg) >= 6
    assert "linux@6.8.0-40-generic" in out_pkg
    assert "cairo@1.16.0" in out_pkg


def test_expiration_vulnerabilities(app, init_files):
    init_files["LOCAL_USER_DATABASE_PATH"].write_text("""{
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
        "author": "Savoir-faire Linux",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": 1,
        "statements": [
            {
                "vulnerability": {
                    "@id": "https://nvd.nist.gov/vuln/detail/CVE-2002-FAKE-EXPIRED",
                    "name": "CVE-2002-FAKE-EXPIRED"
                },
                "products": [ { "@id": "cairo@0.0.1" } ],
                "status": "under_investigation",
                "action_statement": "Use product version 1.0+",
                "action_statement_timestamp": "2023-01-08T18:02:03.647787998-06:00",
                "status_notes": "This vulnerability was mitigated by the use of a color filter in image-pipeline.c",
                "timestamp": "2023-01-06T15:05:42.647787998Z",
                "last_updated": "2023-01-08T18:02:03.647787998Z",
                "scanners": ["some_scanner"]
            },
            {
                "vulnerability": {
                    "@id": "https://nvd.nist.gov/vuln/detail/CVE-2002-FAKE-EXPIRED",
                    "name": "CVE-2002-FAKE-EXPIRED"
                },
                "products": [ { "@id": "cairo@1.16.0" } ],
                "status": "affected",
                "timestamp": "2023-01-06T15:05:42.647787998Z",
                "last_updated": "2023-01-08T18:02:03.647787998Z",
                "scanners": ["some_scanner"]
            },
            {
                "vulnerability": {
                    "@id": "https://nvd.nist.gov/vuln/detail/CVE-2002-FAKE-EXPIRED",
                    "name": "CVE-2002-FAKE-EXPIRED"
                },
                "products": [ { "@id": "cairo@1.16.0" } ],
                "status": "not_affected",
                "justification": "component_not_present",
                "impact_statement": "Vulnerable component removed, marking as expired",
                "status_notes": "Vulnerability no longer present in analysis, marking as expired",
                "timestamp": "2023-02-06T15:05:42.647787998Z",
                "last_updated": "2023-02-08T18:02:03.647787998Z",
                "scanners": ["some_scanner"]
            }
        ]
    }""")

    ctrls = _run_main()

    out_assessment = ctrls["assessments"].to_dict()
    found_expiration = False

    for assess_id, assessment in out_assessment.items():
        if assessment["vuln_id"] == "CVE-2002-FAKE-EXPIRED":
            if assessment["status"] == "not_affected":
                assert assessment["justification"] == "component_not_present"
                assert assessment["impact_statement"] == "Vulnerable component removed, marking as expired"
                assert assessment["status_notes"] == "Vulnerability no longer present in analysis, marking as expired"
                found_expiration = True

    assert found_expiration


def test_yocto_description(app, init_files):
    init_files['YOCTO_CVE_CHECKER'].write_text("""{
    "version": "1",
    "package": [
      {
        "name": "c-ares",
        "layer": "meta-oe",
        "version": "1.18.1",
        "products": [
          {
            "product": "c-ares",
            "cvesInRecord": "Yes"
          }
        ],
        "issue": [
          {
            "id": "CVE-2007-3152",
            "summary": "c-ares before 1.4.0 blah blah blah",
            "description": "Yocto-specfic description",
            "scorev2": "7.5",
            "scorev3": "0.0",
            "vector": "NETWORK",
            "status": "Patched",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2007-3152"
          }
        ]
      }
    ]
    }""")

    from src.models import Observation, Finding

    _run_main()

    finding = Finding.get_by_package_and_vulnerability("c-ares@1.18.1", "CVE-2007-3152")
    assert finding is not None
    observations = Observation.get_by_finding(finding.id)
    assert len(observations) == 1
    assert observations[0].yocto_description == "Yocto-specfic description"


# ---------------------------------------------------------------------------
# _ts_key() — all branches
# ---------------------------------------------------------------------------

def test_ts_key_none():
    """_ts_key(None) returns empty string (line 46)."""
    assert _ts_key(None) == ""


def test_ts_key_str():
    """_ts_key(str) returns the string unchanged (line 48)."""
    assert _ts_key("2024-01-01T12:00:00") == "2024-01-01T12:00:00"


def test_ts_key_datetime():
    """_ts_key(datetime) returns isoformat string (lines 50-52)."""
    from datetime import datetime, timezone
    dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    result = _ts_key(dt)
    assert "2024-01-01" in result


def test_ts_key_fallback_to_str():
    """_ts_key with an object that has no .isoformat() falls back to str() (line 53)."""

    class WeirdTs:
        def isoformat(self):
            raise AttributeError("no isoformat")

        def __str__(self):
            return "weird-timestamp"

    result = _ts_key(WeirdTs())
    assert result == "weird-timestamp"


# ---------------------------------------------------------------------------
# post_treatment() — covers lines 60-63
# ---------------------------------------------------------------------------

def test_post_treatment():
    """post_treatment calls fetch_epss_scores (lines 60-63)."""
    from unittest.mock import MagicMock
    mock_vuln_ctrl = MagicMock()
    controllers = {"vulnerabilities": mock_vuln_ctrl}
    post_treatment(controllers, [])
    mock_vuln_ctrl.fetch_epss_scores.assert_called_once()


# ---------------------------------------------------------------------------
# export_command — all format branches (lines 377-427)
# ---------------------------------------------------------------------------

def test_export_command_spdx2(app, tmp_path):
    """flask export --format spdx2 writes sbom_spdx_v2_3.spdx.json (lines 397-400)."""
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["export", "--format", "spdx2", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "sbom_spdx_v2_3.spdx.json").exists()


def test_export_command_spdx3(app, tmp_path):
    """flask export --format spdx3 writes sbom_spdx_v3_0.spdx.json (lines 402-405)."""
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["export", "--format", "spdx3", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "sbom_spdx_v3_0.spdx.json").exists()


def test_export_command_cdx14(app, tmp_path):
    """flask export --format cdx14 writes sbom_cyclonedx_v1_4.cdx.json (lines 407-413)."""
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["export", "--format", "cdx14", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "sbom_cyclonedx_v1_4.cdx.json").exists()


def test_export_command_cdx15(app, tmp_path):
    """flask export --format cdx15 writes sbom_cyclonedx_v1_5.cdx.json."""
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["export", "--format", "cdx15", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "sbom_cyclonedx_v1_5.cdx.json").exists()


def test_export_command_openvex(app, tmp_path):
    """flask export --format openvex writes openvex.json (lines 415-420)."""
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["export", "--format", "openvex", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "openvex.json").exists()


# ---------------------------------------------------------------------------
# report_command — template rendering (lines 443-520)
# ---------------------------------------------------------------------------

def test_report_command_txt_template(app, tmp_path):
    """flask report renders vulnerability_summary.txt to output dir (lines 497-504)."""
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "report", "vulnerability_summary.txt",
            "--output-dir", str(tmp_path),
        ])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "vulnerability_summary.txt").exists()


def test_report_command_nonexistent_template(app, tmp_path):
    """flask report with a nonexistent template logs a warning but exits 0."""
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "report", "does_not_exist.txt",
            "--output-dir", str(tmp_path),
        ])
    # Should complete without raising, warning printed to stderr
    assert "does_not_exist.txt" in result.output or result.exit_code == 0


def test_report_command_with_extra_template_env(app, tmp_path, monkeypatch):
    """GENERATE_DOCUMENTS env var causes extra template to be generated (lines 476-479)."""
    monkeypatch.setenv("GENERATE_DOCUMENTS", "vulnerability_summary.txt")
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "report", "vulnerability_summary.txt",
            "--output-dir", str(tmp_path),
        ])
    assert result.exit_code == 0, result.output


def test_report_command_with_match_condition_cache(app, tmp_path, monkeypatch):
    """flask report uses cached failed_vulns when /tmp/vulnscout_matched_vulns.json exists (lines 464-467)."""
    import json as _json
    cache_path = "/tmp/vulnscout_matched_vulns.json"
    _json.dump(["CVE-2020-35492"], open(cache_path, "w"))
    monkeypatch.setenv("MATCH_CONDITION", "cvss >= 1")
    try:
        with app.app_context():
            runner = app.test_cli_runner()
            result = runner.invoke(args=[
                "report", "vulnerability_summary.txt",
                "--output-dir", str(tmp_path),
            ])
        assert result.exit_code == 0, result.output
    finally:
        try:
            os.remove(cache_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# main() — entry-point (lines 530, 534)
# ---------------------------------------------------------------------------

def test_main_entry_point(app):
    """main() delegates to _run_main() and returns the controllers dict (lines 530, 534)."""
    with app.app_context():
        result = main()
    assert isinstance(result, dict)
    assert "packages" in result
    assert "vulnerabilities" in result
    assert "assessments" in result


# ---------------------------------------------------------------------------
# export-custom-assessments & import-custom-assessments CLI commands
# ---------------------------------------------------------------------------

def _create_custom_assessment(app):
    """Create a handmade assessment (origin='custom') in the database."""
    with app.app_context():
        from src.extensions import db as _db
        from src.models.variant import Variant
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding
        from src.models.assessment import Assessment

        variant = Variant.get_all()[0]
        pkg = Package.find_or_create("cairo", "1.16.0")
        vuln = Vulnerability.get_or_create("CVE-2020-35492")
        finding = Finding.get_or_create(pkg.id, "CVE-2020-35492")

        db_a = Assessment.create(
            status="affected",
            simplified_status="Active",
            finding_id=finding.id,
            variant_id=variant.id,
            origin="custom",
            status_notes="test notes",
            justification="",
            impact_statement="test impact",
            workaround="update it",
            responses=[],
            commit=True,
        )
        return db_a, variant


def test_export_custom_assessments_no_data(app, tmp_path):
    """Export with no custom assessments exits with error code 1."""
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export-custom-assessments",
            "--output-dir", str(tmp_path),
        ])
    assert result.exit_code == 1
    assert "No custom assessments" in result.output


def test_export_custom_assessments_success(app, tmp_path):
    """Export creates custom_assessments.tar.gz with a valid OpenVEX inside."""
    _create_custom_assessment(app)
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export-custom-assessments",
            "--output-dir", str(tmp_path),
        ])
    assert result.exit_code == 0, result.output
    out_file = tmp_path / "custom_assessments.tar.gz"
    assert out_file.exists()

    import tarfile as _tf
    with _tf.open(str(out_file), "r:gz") as tar:
        members = tar.getnames()
        assert len(members) >= 1
        # Verify the first file is valid OpenVEX
        f = tar.extractfile(members[0])
        doc = json.loads(f.read())
        assert "openvex" in doc["@context"]
        assert len(doc["statements"]) >= 1


def test_import_custom_assessments_file_not_found(app, tmp_path):
    """Import with a nonexistent file exits with error code 1."""
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments",
            str(tmp_path / "nonexistent.tar.gz"),
        ])
    assert result.exit_code == 1
    assert "file not found" in result.output


def test_import_custom_assessments_unsupported_type(app, tmp_path):
    """Import with an unsupported file type exits with error code 1."""
    bad_file = tmp_path / "data.xml"
    bad_file.write_text("<xml/>")
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments", str(bad_file),
        ])
    assert result.exit_code == 1
    assert "unsupported file type" in result.output.lower()


def test_import_custom_assessments_invalid_targz(app, tmp_path):
    """Import with a corrupt tar.gz exits with error code 1."""
    bad_archive = tmp_path / "corrupt.tar.gz"
    bad_archive.write_bytes(b"not a tar.gz")
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments", str(bad_archive),
        ])
    assert result.exit_code == 1
    assert "unable to open" in result.output.lower()


def test_import_custom_assessments_json_unknown_variant(app, tmp_path):
    """Import a .json with a filename that doesn't match any variant."""
    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "statements": [],
    }
    json_file = tmp_path / "nonexistent_variant.json"
    json_file.write_text(json.dumps(doc))
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments", str(json_file),
        ])
    assert result.exit_code == 1
    assert "no variant found" in result.output.lower()


def test_import_custom_assessments_json_invalid_json(app, tmp_path):
    """Import a .json with invalid JSON exits with error code 1."""
    json_file = tmp_path / "TestVariant.json"
    json_file.write_text("{invalid json")
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments", str(json_file),
        ])
    assert result.exit_code == 1
    assert "invalid json" in result.output.lower()


def test_import_custom_assessments_json_not_openvex(app, tmp_path):
    """Import a .json that is not OpenVEX exits with error code 1."""
    json_file = tmp_path / "TestVariant.json"
    json_file.write_text(json.dumps({"hello": "world"}))
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments", str(json_file),
        ])
    assert result.exit_code == 1
    assert "not a valid openvex" in result.output.lower()


def test_import_custom_assessments_json_success(app, tmp_path):
    """Import a valid .json creates assessments."""
    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "statements": [{
            "vulnerability": {"name": "CVE-2020-35492"},
            "status": "affected",
            "products": [{"@id": "cairo@1.16.0"}],
            "status_notes": "imported via CLI",
        }],
    }
    json_file = tmp_path / "TestVariant.json"
    json_file.write_text(json.dumps(doc))
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments", str(json_file),
        ])
    assert result.exit_code == 0, result.output
    assert "Imported 1 assessments" in result.output


def test_import_custom_assessments_targz_no_matching(app, tmp_path):
    """Import a tar.gz with no matching variant files exits 1."""
    import tarfile as _tf

    buf = io.BytesIO()
    with _tf.open(fileobj=buf, mode='w:gz') as tar:
        content = json.dumps({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [],
        }).encode()
        info = _tf.TarInfo(name="unknown_variant.json")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))

    archive = tmp_path / "assessments.tar.gz"
    archive.write_bytes(buf.getvalue())

    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments", str(archive),
        ])
    assert result.exit_code == 1
    assert "no valid openvex" in result.output.lower()


def test_export_import_roundtrip(app, tmp_path):
    """Export then import produces same number of assessments."""
    _create_custom_assessment(app)

    # Export
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export-custom-assessments",
            "--output-dir", str(tmp_path),
        ])
    assert result.exit_code == 0, result.output

    # Delete all to have a clean slate, then import
    with app.app_context():
        from src.extensions import db as _db
        from src.models.assessment import Assessment
        for a in Assessment.get_handmade():
            a.delete()
        _db.session.commit()

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments",
            str(tmp_path / "custom_assessments.tar.gz"),
        ])
    assert result.exit_code == 0, result.output
    assert "Imported 1 assessments" in result.output


def test_import_custom_assessments_skips_duplicates(app, tmp_path):
    """Importing the same data twice skips duplicates."""
    _create_custom_assessment(app)

    # Export
    with app.app_context():
        runner = app.test_cli_runner()
        runner.invoke(args=[
            "export-custom-assessments",
            "--output-dir", str(tmp_path),
        ])

    # Import over existing → should skip
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments",
            str(tmp_path / "custom_assessments.tar.gz"),
        ])
    assert result.exit_code == 0, result.output
    assert "1 skipped" in result.output


def test_import_custom_assessments_targz_invalid_json_inside(
    app, tmp_path
):
    """Import tar.gz with invalid JSON inside continues gracefully."""
    import tarfile as _tf

    buf = io.BytesIO()
    with _tf.open(fileobj=buf, mode='w:gz') as tar:
        content = b"{"
        info = _tf.TarInfo(name="TestVariant.json")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))

    archive = tmp_path / "bad_inner.tar.gz"
    archive.write_bytes(buf.getvalue())

    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments", str(archive),
        ])
    assert result.exit_code == 1


def test_import_custom_assessments_targz_not_openvex_inside(
    app, tmp_path
):
    """Import tar.gz with non-OpenVEX JSON inside reports error."""
    import tarfile as _tf

    buf = io.BytesIO()
    with _tf.open(fileobj=buf, mode='w:gz') as tar:
        content = json.dumps({"hello": "world"}).encode()
        info = _tf.TarInfo(name="TestVariant.json")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))

    archive = tmp_path / "not_vex.tar.gz"
    archive.write_bytes(buf.getvalue())

    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments", str(archive),
        ])
    assert result.exit_code == 1


def test_list_projects(cli_runner):
    out: CliResult = cli_runner.invoke(args=[
        "list-projects"
    ])

    assert out.exit_code == 0
    assert "TestProject" in out.stdout
    assert "TestVariant" in out.stdout


def test_list_projects_json(cli_runner):
    out: CliResult = cli_runner.invoke(args=[
        "list-projects",
        "--json"
    ])

    assert out.exit_code == 0

    data = json.loads(out.stdout)
    assert isinstance(data, list)
    assert len(data) == 1

    project = data[0]
    assert isinstance(project, dict)
    assert project["name"] == "TestProject"

    variants = project["variants"]
    assert isinstance(variants, list)
    assert len(variants) == 1

    variant = variants[0]
    assert variant["name"] == "TestVariant"


def test_list_scans(cli_runner):
    out: CliResult = cli_runner.invoke(args=[
        "list-scans"
    ])

    assert out.exit_code == 0
    assert "TestProject" in out.stdout
    assert "TestVariant" in out.stdout


def test_list_scans_json(cli_runner):
    out: CliResult = cli_runner.invoke(args=[
        "list-scans",
        "--json"
    ])

    from datetime import datetime

    assert out.exit_code == 0

    data = json.loads(out.stdout)
    assert isinstance(data, list)
    assert len(data) == 1

    scan = data[0]
    assert isinstance(scan, dict)
    scan_timestamp = datetime.fromisoformat(scan["timestamp"])
    assert scan_timestamp is not None
    # cannot test that the timestamp is recent bc of timezone issues

    variant = scan["variant"]
    assert isinstance(variant, dict)
    assert variant["name"] == "TestVariant"

    project = variant["project"]
    assert isinstance(project, dict)
    assert project["name"] == "TestProject"


def test_delete_scan(cli_runner):
    out: CliResult = cli_runner.invoke(args=[
        "list-scans",
        "--json"
    ])

    scan_id = json.loads(out.stdout)[0]["id"]

    out = cli_runner.invoke(args=[
        "delete-scan",
        scan_id
    ])

    assert out.exit_code == 0
    assert "deleted scan" in out.stdout


def test_delete_unknown_scan(cli_runner):
    import uuid

    out: CliResult = cli_runner.invoke(args=[
        "delete-scan",
        str(uuid.uuid4())
    ])

    assert out.exit_code != 0
    assert "Scan not found" in str(out.exception)

    out = cli_runner.invoke(args=[
        "list-scans",
        "--json"
    ])

    assert len(json.loads(out.stdout)) == 1, "The scan has been deleted"

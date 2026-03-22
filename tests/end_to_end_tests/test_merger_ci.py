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
import json
import os
from src.bin.merger_ci import _run_main
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
def app(init_files):
    """Flask app with in-memory SQLite; all demo SBOM files are registered."""
    import os as _os
    _os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
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
        _os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


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


def test_invalid_openvex(app, init_files):
    init_files["LOCAL_USER_DATABASE_PATH"].write_text("invalid{ json")
    os.environ["IGNORE_PARSING_ERRORS"] = 'false'
    with pytest.raises(Exception):
        _run_main()

    os.environ["IGNORE_PARSING_ERRORS"] = 'true'
    _run_main()


def test_invalid_cdx(app, init_files):
    """Replaces test_invalid_time_estimates: error handling for a bad CDX file."""
    init_files["CDX_PATH"].write_text("invalid{ json")
    os.environ["IGNORE_PARSING_ERRORS"] = 'false'
    with pytest.raises(Exception):
        _run_main()

    os.environ["IGNORE_PARSING_ERRORS"] = 'true'
    _run_main()


def test_generate_docs(app):
    os.environ["GENERATE_DOCUMENTS"] = "summary.adoc, none.doesntexist"
    _run_main()


def test_ci_mode(app):
    os.environ["MATCH_CONDITION"] = "false == true"
    _run_main()

    os.environ["MATCH_CONDITION"] = "true == true"
    with pytest.raises(SystemExit) as e:
        _run_main()
    assert e.type == SystemExit
    assert e.value.code == 2

    os.environ["MATCH_CONDITION"] = "cvss >= 8"
    with pytest.raises(SystemExit) as e:
        _run_main()
    assert e.type == SystemExit
    assert e.value.code == 2

    os.environ["MATCH_CONDITION"] = "cvss >= 8 and epss == 1.23456%"
    _run_main()

    os.environ["MATCH_CONDITION"] = ""


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

# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import json
import os
from src.bin.merger_ci import main
from . import write_demo_files


@pytest.fixture()
def init_files(tmp_path):
    files = {
        "CDX_PATH": tmp_path / "input.cdx.json",
        "SPDX_FOLDER": tmp_path / "spdx",
        "SPDX_PATH": tmp_path / "spdx" / "input.spdx.json",
        "GRYPE_CDX_PATH": tmp_path / "cdx.grype.json",
        "GRYPE_SPDX_PATH": tmp_path / "spdx.grype.json",
        "YOCTO_FOLDER": tmp_path / "yocto_cve",
        "YOCTO_CVE_CHECKER": tmp_path / "yocto_cve" / "demo.json",
        "OPENVEX_PATH": tmp_path / "openvex.json",
        "TIME_ESTIMATES_PATH": tmp_path / "time_estimates.json",
        "OUTPUT_CDX_PATH": tmp_path / "output.cdx.json",
        "OUTPUT_SPDX_PATH": tmp_path / "output.spdx.json",
        "OUTPUT_SPDX3_PATH": tmp_path / "output.spdx3.json",
        "OUTPUT_PATH": tmp_path / "all-merged.json",
        "OUTPUT_PKG_PATH": tmp_path / "packages-merged.json",
        "OUTPUT_VULN_PATH": tmp_path / "vulnerabilities-merged.json",
        "OUTPUT_ASSESSEMENT_PATH": tmp_path / "assessments-merged.json",
    }
    files["YOCTO_FOLDER"].mkdir()
    files["SPDX_FOLDER"].mkdir()
    write_demo_files(files)
    return files


def test_running_script(init_files):
    for key, value in init_files.items():
        os.environ[key] = str(value)

    main()

    out_all = json.loads(init_files["OUTPUT_PATH"].read_text())
    out_pkg = json.loads(init_files["OUTPUT_PKG_PATH"].read_text())
    out_vuln = json.loads(init_files["OUTPUT_VULN_PATH"].read_text())
    out_assessment = json.loads(init_files["OUTPUT_ASSESSEMENT_PATH"].read_text())

    assert "cairo@1.16.0" in out_pkg
    assert "cairo@1.16.0" in out_all["packages"]
    assert "busybox@1.35.0" in out_pkg
    assert "busybox@1.35.0" in out_all["packages"]
    assert "c-ares@1.18.1" in out_pkg
    assert "c-ares@1.18.1" in out_all["packages"]
    assert "curl@7.82.0" in out_pkg
    assert "curl@7.82.0" in out_all["packages"]
    assert "xyz@rev2.3" in out_pkg
    assert "xyz@rev2.3" in out_all["packages"]
    assert "linux@6.8.0-40-generic" in out_pkg
    assert "linux@6.8.0-40-generic" in out_all["packages"]

    assert "CVE-2020-35492" in out_vuln
    assert "CVE-2020-35492" in out_all["vulnerabilities"]
    assert "CVE-2022-30065" in out_vuln
    assert "CVE-2022-30065" in out_all["vulnerabilities"]
    assert "CVE-2007-3152" in out_vuln
    assert "CVE-2007-3152" in out_all["vulnerabilities"]
    assert "CVE-2023-31124" in out_vuln
    assert "CVE-2023-31124" in out_all["vulnerabilities"]
    assert "CVE-2024-2398" in out_vuln
    assert "CVE-2024-2398" in out_all["vulnerabilities"]

    vuln2398 = out_vuln["CVE-2024-2398"]
    assert vuln2398["effort"]["optimistic"] == "P1D"
    assert vuln2398["effort"]["likely"] == "P2DT4H"
    assert vuln2398["effort"]["pessimistic"] == "P1W"

    assert len(out_assessment) == 6
    assert len(out_all["assessments"]) == len(out_assessment)


def test_invalid_openvex(init_files):
    for key, value in init_files.items():
        os.environ[key] = str(value)

    init_files["OPENVEX_PATH"].write_text("invalid{ json")
    os.environ["IGNORE_PARSING_ERRORS"] = 'false'
    with pytest.raises(Exception):
        main()

    os.environ["IGNORE_PARSING_ERRORS"] = 'true'
    main()


def test_invalid_time_estimates(init_files):
    for key, value in init_files.items():
        os.environ[key] = str(value)

    init_files["TIME_ESTIMATES_PATH"].write_text("invalid{ json")
    os.environ["IGNORE_PARSING_ERRORS"] = 'false'
    with pytest.raises(Exception):
        main()

    os.environ["IGNORE_PARSING_ERRORS"] = 'true'
    main()

    # test with deleted file
    os.remove(init_files["TIME_ESTIMATES_PATH"])
    main()


def test_generate_docs(init_files):
    for key, value in init_files.items():
        os.environ[key] = str(value)

    os.environ["GENERATE_DOCUMENTS"] = "summary.adoc, none.doesntexist"
    main()


def test_ci_mode(init_files):
    for key, value in init_files.items():
        os.environ[key] = str(value)

    os.environ["FAIL_CONDITION"] = "false == true"
    main()

    os.environ["FAIL_CONDITION"] = "true == true"
    with pytest.raises(SystemExit) as e:
        main()
    assert e.type == SystemExit
    assert e.value.code == 2

    os.environ["FAIL_CONDITION"] = "cvss >= 8"
    with pytest.raises(SystemExit) as e:
        main()
    assert e.type == SystemExit
    assert e.value.code == 2

    os.environ["FAIL_CONDITION"] = "cvss >= 8 and epss == 1.23456%"
    main()


def test_spdx_output_completeness(init_files):
    for key, value in init_files.items():
        os.environ[key] = str(value)

    main()

    out_spdx = json.loads(init_files["OUTPUT_SPDX_PATH"].read_text())
    assert "packages" in out_spdx
    assert len(out_spdx["packages"]) >= 6
    found_linux = False  # check package is still in SPDX
    found_cairo = False  # check package was added in SPDX
    for pkg in out_spdx["packages"]:
        if pkg["name"] == "linux" and pkg["versionInfo"] == "6.8.0-40-generic":
            found_linux = True
        if pkg["name"] == "cairo" and pkg["versionInfo"] == "1.16.0":
            found_cairo = True
    assert found_linux and found_cairo


def test_expiration_vulnerabilities(init_files):
    for key, value in init_files.items():
        os.environ[key] = str(value)

    init_files["OPENVEX_PATH"].write_text("""{
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
                "products": [
                    { "@id": "cairo@0.0.1" }
                ],
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
                "products": [
                    { "@id": "cairo@1.16.0" }
                ],
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
                "products": [
                    { "@id": "cairo@1.16.0" }
                ],
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

    main()

    out_assessment = json.loads(init_files["OUTPUT_ASSESSEMENT_PATH"].read_text())
    found_expiration = False

    for assess_id, assessment in out_assessment.items():
        if assessment["vuln_id"] == "CVE-2002-FAKE-EXPIRED":
            if assessment["status"] == "not_affected":
                assert assessment["justification"] == "component_not_present"
                assert assessment["impact_statement"] == "Vulnerable component removed, marking as expired"
                assert assessment["status_notes"] == "Vulnerability no longer present in analysis, marking as expired"
                found_expiration = True
    
    assert found_expiration

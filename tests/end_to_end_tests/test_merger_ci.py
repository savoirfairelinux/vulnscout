# -*- coding: utf-8 -*-
import pytest
import json
import os
from src.bin.merger_ci import main
from . import write_demo_files


@pytest.fixture()
def init_files(tmp_path):
    files = {
        "GRYPE_CDX_PATH": tmp_path / "cdx.grype.json",
        "GRYPE_SPDX_PATH": tmp_path / "spdx.grype.json",
        "YOCTO_FOLDER": tmp_path / "yocto_cve",
        "YOCTO_CVE_CHECKER": tmp_path / "yocto_cve" / "demo.json",
        "OPENVEX_PATH": tmp_path / "openvex.json",
        "OUTPUT_PATH": tmp_path / "all-merged.json",
        "OUTPUT_PKG_PATH": tmp_path / "packages-merged.json",
        "OUTPUT_VULN_PATH": tmp_path / "vulnerabilities-merged.json",
        "OUTPUT_ASSESSEMENT_PATH": tmp_path / "assessments-merged.json",
    }
    files["YOCTO_FOLDER"].mkdir()
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

    assert "CVE-2020-35492" in out_vuln
    assert "CVE-2020-35492" in out_all["vulnerabilities"]
    assert "CVE-2022-30065" in out_vuln
    assert "CVE-2022-30065" in out_all["vulnerabilities"]
    assert "CVE-2007-3152" in out_vuln
    assert "CVE-2007-3152" in out_all["vulnerabilities"]
    assert "CVE-2023-31124" in out_vuln
    assert "CVE-2023-31124" in out_all["vulnerabilities"]

    assert len(out_assessment) == 5
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

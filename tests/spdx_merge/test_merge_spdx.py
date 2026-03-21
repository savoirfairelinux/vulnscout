# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import pytest
from src.bin.spdx_merge import main, read_inputs
import os


@pytest.fixture
def setup(tmp_path):
    os.environ["INPUT_SPDX_FOLDER"] = "spdx_merge/data"
    os.environ["OUTPUT_SPDX_FILE"] = str(tmp_path / "output.spdx.json")


def test_merge_files_default(setup):
    os.environ["IGNORE_PARSING_ERRORS"] = 'false'
    with pytest.raises(Exception):
        main()


def test_merge_files_with_ignore_errors(setup):
    os.environ["IGNORE_PARSING_ERRORS"] = 'true'
    main()
    with open(os.environ["OUTPUT_SPDX_FILE"], 'r') as f:
        data = f.read()
        assert "cairo" in data
        assert "1.16.0" in data
        assert "libssh" in data
        assert "0.8.9" in data
        assert "SPDX-2.3" in data


def test_merge_spdx3_file(tmp_path):
    """read_inputs() uses FastSPDX3 when the document looks like SPDX 3.0 (line 43)."""
    spdx3_doc = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "spdxId": "https://sbom.example/doc",
        "@graph": [
            {
                "type": "CreationInfo",
                "specVersion": "3.0.1",
            },
            {
                "type": "software_Package",
                "spdxId": "https://sbom.example/pkg/testpkg",
                "name": "testpkg",
                "versionInfo": "1.0.0",
            }
        ]
    }
    spdx3_file = tmp_path / "sbom.spdx.json"
    spdx3_file.write_text(json.dumps(spdx3_doc))
    os.environ["INPUT_SPDX_FOLDER"] = str(tmp_path)
    os.environ["IGNORE_PARSING_ERRORS"] = 'false'

    from src.controllers.packages import PackagesController
    from src.controllers.vulnerabilities import VulnerabilitiesController
    from src.controllers.assessments import AssessmentsController
    pkg_ctrl = PackagesController()
    vuln_ctrl = VulnerabilitiesController(pkg_ctrl)
    controllers = {
        "packages": pkg_ctrl,
        "vulnerabilities": vuln_ctrl,
        "assessments": AssessmentsController(pkg_ctrl, vuln_ctrl),
    }
    read_inputs(controllers)
    # FastSPDX3 parsed the file — testpkg should be in the controller
    assert "testpkg@1.0.0" in controllers["packages"].to_dict()


def test_merge_fastspdx_fallback(tmp_path):
    """read_inputs() uses FastSPDX when IGNORE_PARSING_ERRORS=true and not SPDX3 (lines 47-48)."""
    # A valid SPDX 2.3 file that would work with fast parser
    spdx23_doc = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "name": "test-sbom",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
        "packages": [
            {
                "SPDXID": "SPDXRef-pkg-fastspdx",
                "name": "fastspdx-pkg",
                "versionInfo": "2.0.0",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
            }
        ]
    }
    spdx_file = tmp_path / "sbom.spdx.json"
    spdx_file.write_text(json.dumps(spdx23_doc))
    os.environ["INPUT_SPDX_FOLDER"] = str(tmp_path)
    os.environ["IGNORE_PARSING_ERRORS"] = 'true'  # triggers use_fastspdx=True

    from src.controllers.packages import PackagesController
    from src.controllers.vulnerabilities import VulnerabilitiesController
    from src.controllers.assessments import AssessmentsController
    pkg_ctrl = PackagesController()
    vuln_ctrl = VulnerabilitiesController(pkg_ctrl)
    controllers = {
        "packages": pkg_ctrl,
        "vulnerabilities": vuln_ctrl,
        "assessments": AssessmentsController(pkg_ctrl, vuln_ctrl),
    }
    read_inputs(controllers)
    # FastSPDX parsed the package
    assert "fastspdx-pkg@2.0.0" in controllers["packages"].to_dict()

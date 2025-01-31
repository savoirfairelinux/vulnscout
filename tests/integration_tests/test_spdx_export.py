# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.views.spdx import SPDX
from src.models.package import Package
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController
import json


@pytest.fixture
def spdx_parser():
    controllers = {}
    controllers["packages"] = PackagesController()
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    controllers["assessments"] = AssessmentsController(controllers["packages"], controllers["vulnerabilities"])
    return SPDX(controllers)


def test_export_empty_json(spdx_parser):
    output = json.loads(spdx_parser.output_as_json(True, "MY_AUTHOR_NAME"))
    try:
        assert {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
        }.items() <= output.items()
        assert output["documentNamespace"].startswith("https://")
        assert len(output["name"]) > 5
        assert len(output["creationInfo"]["creators"]) == 2
        assert any(map(lambda x: "MY_AUTHOR_NAME" in x, output["creationInfo"]["creators"]))
        assert "packages" not in output or len(output["packages"]) == 0
    except Exception as e:
        print(json.dumps(output, indent=2))
        raise e


def test_export_components_json(spdx_parser):
    pkg = Package("binutils", "2.38", [], [])
    pkg.add_purl("pkg:generic/gnu/binutils@2.38")
    pkg.add_cpe("cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*")
    spdx_parser.packagesCtrl.add(pkg)
    opsys = Package("linux", "6.8.0-40-generic", ["cpe:2.3:o:*:linux:6.8.0-40-generic:*:*:*:*:*:*:*"], [])
    spdx_parser.packagesCtrl.add(opsys)
    hw = Package("xyz", "rev2.3", ["cpe:2.3:h:*:xyz:rev2.3:*:*:*:*:*:*:*"], [])
    spdx_parser.packagesCtrl.add(hw)
    output = json.loads(spdx_parser.output_as_json())

    try:
        assert {
            "primaryPackagePurpose": "APPLICATION",
            "name": "binutils",
            "versionInfo": "2.38",
            "filesAnalyzed": False,
            "downloadLocation": "NOASSERTION"
        }.items() <= output["packages"][0].items()
        assert {
            "primaryPackagePurpose": "OPERATING-SYSTEM",
            "name": "linux",
            "versionInfo": "6.8.0-40-generic",
            "filesAnalyzed": False,
            "downloadLocation": "NOASSERTION"
        }.items() <= output["packages"][1].items()
        assert {
            "primaryPackagePurpose": "DEVICE",
            "name": "xyz",
            "versionInfo": "rev2.3",
            "filesAnalyzed": False,
            "downloadLocation": "NOASSERTION"
        }.items() <= output["packages"][2].items()

        assert len(output["packages"]) == 3
    except Exception as e:
        print(json.dumps(output, indent=2))
        raise e

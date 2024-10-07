# -*- coding: utf-8 -*-
import pytest
from src.views.fast_spdx import FastSPDX
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
    return FastSPDX(controllers)


def test_parse_empty_json(spdx_parser):
    spdx_parser.parse_from_dict(json.loads("""{
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "SBOM-SPDX-2d85f548-12fa-46d5-87ce-5e78e5e111f4",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": "2022-11-03T07:10:10Z",
            "creators": [
                "Tool: sigs.k8s.io/bom/pkg/spdx"
            ]
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://spdx.org/spdxdocs/k8s-releng-bom-7c6a33ab-bd76-4b06-b291-a850e0815b07"
    }"""))

    assert len(spdx_parser.packagesCtrl.packages) == 0
    assert len(spdx_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(spdx_parser.assessmentsCtrl.assessments) == 0


def test_parse_invalid_model_json(spdx_parser):
    with pytest.raises(Exception):
        spdx_parser.parse_from_dict(json.loads("""{
            "foo": [],
            "bar": "hello spdx"
        }"""))


def test_parse_components_json(spdx_parser):
    spdx_parser.parse_from_dict(json.loads("""{
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "SBOM-SPDX-2d85f548-12fa-46d5-87ce-5e78e5e111f4",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": "2022-11-03T07:10:10Z",
            "creators": [
                "Tool: sigs.k8s.io/bom/pkg/spdx"
            ]
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://spdx.org/spdxdocs/k8s-releng-bom-7c6a33ab-bd76-4b06-b291-a850e0815b07",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-binutils-2.38",
                "name": "binutils",
                "versionInfo": "2.38",
                "filesAnalyzed": false,
                "licenseDeclared": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "downloadLocation": "NOASSERTION"
            },
            {
                "SPDXID": "SPDXRef-harware-board-xyz",
                "name": "xyz",
                "versionInfo": "rev2.3",
                "filesAnalyzed": false,
                "downloadLocation": "NOASSERTION",
                "primaryPackagePurpose": "DEVICE"
            },
            {
                "SPDXID": "SPDXRef-linux-kernel",
                "name": "linux",
                "versionInfo": "6.8.0-40-generic",
                "filesAnalyzed": false,
                "downloadLocation": "NOASSERTION",
                "primaryPackagePurpose": "OPERATING-SYSTEM"
            },
            {
                "SPDXID": "SPDXRef-Package-xyz",
                "filesAnalyzed": true,
                "hasFiles": [
                    "SPDXRef-PackagedFile-busybox-1",
                    "SPDXRef-PackagedFile-busybox-2"
                ],
                "downloadLocation": "NOASSERTION"
            }
        ]
    }"""))

    assert len(spdx_parser.packagesCtrl) == 3
    assert len(spdx_parser.vulnerabilitiesCtrl) == 0
    assert len(spdx_parser.assessmentsCtrl) == 0
    assert "binutils@2.38" in spdx_parser.packagesCtrl
    assert "xyz@rev2.3" in spdx_parser.packagesCtrl
    assert "linux@6.8.0-40-generic" in spdx_parser.packagesCtrl
    binutils = spdx_parser.packagesCtrl.get("binutils@2.38")
    assert "cpe:2.3:a:*:binutils:2.38:*:*:*:*:*:*:*" in binutils
    board = spdx_parser.packagesCtrl.get("xyz@rev2.3")
    assert "cpe:2.3:h:*:xyz:rev2.3:*:*:*:*:*:*:*" in board
    linux = spdx_parser.packagesCtrl.get("linux@6.8.0-40-generic")
    assert "cpe:2.3:o:*:linux:6.8.0-40-generic:*:*:*:*:*:*:*" in linux

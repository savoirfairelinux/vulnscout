# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

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
    assert "cpe:2.3:a:*:xyz:rev2.3:*:*:*:*:*:*:*" in board
    linux = spdx_parser.packagesCtrl.get("linux@6.8.0-40-generic")
    assert "cpe:2.3:a:*:linux:6.8.0-40-generic:*:*:*:*:*:*:*" in linux


def test_parse_cpe23type_externalrefs(spdx_parser):
    """BOM cpe23Type externalRefs must be stored and appear before the generic CPE."""
    spdx_parser.parse_from_dict({
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test",
        "creationInfo": {"created": "2022-11-03T07:10:10Z", "creators": ["Tool: test"]},
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.com/test",
        "packages": [
            {
                "SPDXID": "SPDXRef-libtasn1",
                "name": "libtasn1-6",
                "versionInfo": "4.13-2",
                "filesAnalyzed": False,
                "downloadLocation": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "SECURITY",
                        "referenceType": "cpe23Type",
                        "referenceLocator": "cpe:2.3:a:libtasn1:libtasn1_6:4.13-2:*:*:*:*:*:*:*"
                    },
                    {
                        "referenceCategory": "SECURITY",
                        "referenceType": "cpe23Type",
                        "referenceLocator": "cpe:2.3:a:libtasn1-6:libtasn1-6:4.13-2:*:*:*:*:*:*:*"
                    },
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:deb/ubuntu/libtasn1-6@4.13-2?arch=arm64"
                    }
                ]
            }
        ]
    })

    pkg = spdx_parser.packagesCtrl.get("libtasn1-6@4.13-2")
    assert pkg is not None

    # BOM CPEs must be present
    assert "cpe:2.3:a:libtasn1:libtasn1_6:4.13-2:*:*:*:*:*:*:*" in pkg.cpe
    assert "cpe:2.3:a:libtasn1-6:libtasn1-6:4.13-2:*:*:*:*:*:*:*" in pkg.cpe

    # First CPE must be a BOM CPE (not the generic wildcard)
    assert pkg.cpe[0] == "cpe:2.3:a:libtasn1:libtasn1_6:4.13-2:*:*:*:*:*:*:*"

    # Generic fallback must still be present (as last entry)
    generic = "cpe:2.3:a:*:libtasn1-6:4.13-2:*:*:*:*:*:*:*"
    assert generic in pkg.cpe
    assert pkg.cpe[-1] == generic

    # PURL must also be parsed
    assert "pkg:deb/ubuntu/libtasn1-6@4.13-2?arch=arm64" in pkg.purl


def test_parse_cpe23type_uri_referenceType(spdx_parser):
    """referenceType given as full URI 'http://spdx.org/rdf/references/cpe23Type' must be accepted."""
    spdx_parser.parse_from_dict({
        "spdxVersion": "SPDX-2.2",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test",
        "creationInfo": {"created": "2026-05-10T05:32:45Z", "creators": ["Tool: OpenEmbedded"]},
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.com/test",
        "packages": [
            {
                "SPDXID": "SPDXRef-linux-kernel",
                "name": "linux-jammy-nvidia-tegra",
                "versionInfo": "5.15.148+git",
                "filesAnalyzed": False,
                "downloadLocation": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "SECURITY",
                        "referenceType": "http://spdx.org/rdf/references/cpe23Type",
                        "referenceLocator": "cpe:2.3:*:*:linux_kernel:5.15.148:*:*:*:*:*:*:*"
                    }
                ]
            }
        ]
    })

    pkg = spdx_parser.packagesCtrl.get("linux-jammy-nvidia-tegra@5.15.148")
    assert pkg is not None

    # URI-form referenceType CPE must be extracted
    assert "cpe:2.3:*:*:linux_kernel:5.15.148:*:*:*:*:*:*:*" in pkg.cpe
    # Must be first (before generic fallback)
    assert pkg.cpe[0] == "cpe:2.3:*:*:linux_kernel:5.15.148:*:*:*:*:*:*:*"


def test_parse_no_cpe23type_still_gets_generic(spdx_parser):
    """Packages without cpe23Type externalRefs must still receive the generic CPE fallback."""
    spdx_parser.parse_from_dict({
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test",
        "creationInfo": {"created": "2022-11-03T07:10:10Z", "creators": ["Tool: test"]},
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.com/test",
        "packages": [
            {
                "SPDXID": "SPDXRef-binutils",
                "name": "binutils",
                "versionInfo": "2.38",
                "filesAnalyzed": False,
                "downloadLocation": "NOASSERTION"
            }
        ]
    })

    pkg = spdx_parser.packagesCtrl.get("binutils@2.38")
    assert pkg is not None
    assert len(pkg.cpe) == 1
    assert pkg.cpe[0] == "cpe:2.3:a:*:binutils:2.38:*:*:*:*:*:*:*"


def test_device_and_os_packages_get_type_a_generic_cpe(spdx_parser):
    """DEVICE and OPERATING-SYSTEM packages without cpe23Type refs get a type-a generic CPE.

    primaryPackagePurpose is not used to generate h/o CPEs — BOM cpe23Type externalRefs
    are the authoritative source for hardware/OS CPE types. When no cpe23Type refs are
    present, the generic fallback (type a, wildcard vendor) is used for all packages.
    """
    spdx_parser.parse_from_dict({
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test",
        "creationInfo": {"created": "2022-11-03T07:10:10Z", "creators": ["Tool: test"]},
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.com/test",
        "packages": [
            {
                "SPDXID": "SPDXRef-board",
                "name": "my-board",
                "versionInfo": "rev1",
                "filesAnalyzed": False,
                "downloadLocation": "NOASSERTION",
                "primaryPackagePurpose": "DEVICE"
            },
            {
                "SPDXID": "SPDXRef-kernel",
                "name": "linux",
                "versionInfo": "6.8.0",
                "filesAnalyzed": False,
                "downloadLocation": "NOASSERTION",
                "primaryPackagePurpose": "OPERATING-SYSTEM"
            }
        ]
    })

    board = spdx_parser.packagesCtrl.get("my-board@rev1")
    assert board is not None
    assert board.cpe == ["cpe:2.3:a:*:my-board:rev1:*:*:*:*:*:*:*"]

    kernel = spdx_parser.packagesCtrl.get("linux@6.8.0")
    assert kernel is not None
    assert kernel.cpe == ["cpe:2.3:a:*:linux:6.8.0:*:*:*:*:*:*:*"]

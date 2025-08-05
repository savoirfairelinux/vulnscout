# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.views.fast_spdx3 import FastSPDX3
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController


@pytest.fixture
def spdx3_parser():
    controllers = {}
    controllers["packages"] = PackagesController()
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    controllers["assessments"] = AssessmentsController(controllers["packages"], controllers["vulnerabilities"])
    return FastSPDX3(controllers)


def test_parse_empty_json(spdx3_parser):
    spdx3_parser.parse_from_dict({
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "SBOM-SPDX3-test",
        "creationInfo": {
            "created": "2024-03-20T00:00:00Z",
            "creators": ["Tool: VulnScout"],
            "specVersion": "3.0.1"
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://spdx.org/spdxdocs/test",
        "@graph": []
    })

    assert len(spdx3_parser.packagesCtrl) == 0
    assert len(spdx3_parser.vulnerabilitiesCtrl) == 0
    assert len(spdx3_parser.assessmentsCtrl) == 0


def test_parse_packages(spdx3_parser):
    spdx3_parser.parse_from_dict({
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            {
                "type": "CreationInfo",
                "@id": "_:CreationInfo1",
                "created": "2025-04-08T13:09:06Z",
                "createdBy": [
                    "http://spdx.org/spdxdocs/bitbake-5ae3-87c2-0c3a1a5812ba/bitbake/agent/OpenEmbedded"
                ],
                "createdUsing": [
                    "http://spdx.org/spdxdocs/bitbake-5ae3-87c2-0c3a1a5812ba/bitbake/tool/oe-spdx-creator_1_0"
                ],
                "specVersion": "3.0.1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/binutils-test/package/binutils",
                "creationInfo": "_:CreationInfo1",
                "description": "GNU binutils",
                "externalIdentifier": [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cpe23Type",
                        "identifier": "cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*"
                    }
                ],
                "name": "binutils",
                "summary": "GNU binary utilities",
                "software_primaryPurpose": "application",
                "software_homePage": "https://www.gnu.org/software/binutils/",
                "software_packageVersion": "2.38"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/linux-test/package/linux",
                "creationInfo": "_:CreationInfo1",
                "description": "Linux kernel",
                "externalIdentifier": [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cpe23Type",
                        "identifier": "cpe:2.3:o:linux:linux:6.8.0:*:*:*:*:*:*:*"
                    }
                ],
                "name": "linux",
                "summary": "Linux kernel",
                "software_primaryPurpose": "operating-system",
                "software_homePage": "https://www.kernel.org/",
                "software_packageVersion": "6.8.0"
            }
        ]
    })

    assert len(spdx3_parser.packagesCtrl) == 2
    assert "binutils@2.38" in spdx3_parser.packagesCtrl
    assert "linux@6.8.0" in spdx3_parser.packagesCtrl

    binutils = spdx3_parser.packagesCtrl.get("binutils@2.38")
    assert len(binutils.cpe) > 0
    assert "binutils" in binutils.cpe[0]
    assert "2.38" in binutils.cpe[0]

    linux = spdx3_parser.packagesCtrl.get("linux@6.8.0")
    assert len(linux.cpe) > 0
    assert "linux" in linux.cpe[0]
    assert "6.8.0" in linux.cpe[0]


def test_parse_assessments(spdx3_parser):
    """Test parsing SPDX files with assessments."""
    spdx3_parser.parse_from_dict({
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            {
                "type": "CreationInfo",
                "@id": "_:CreationInfo1",
                "created": "2025-04-08T13:09:06Z",
                "createdBy": [
                    "http://spdx.org/spdxdocs/bitbake-agent/OpenEmbedded"
                ],
                "createdUsing": [
                    "http://spdx.org/spdxdocs/bitbake-tool/oe-spdx-creator_1_0"
                ],
                "specVersion": "3.0.1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/linux-yocto/package/kernel",
                "creationInfo": "_:CreationInfo1",
                "description": "Linux kernel",
                "externalIdentifier": [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cpe23Type",
                        "identifier": "cpe:2.3:o:linux:linux:6.12.22:*:*:*:*:*:*:*"
                    }
                ],
                "name": "kernel",
                "summary": "Linux kernel",
                "software_primaryPurpose": "operating-system",
                "software_homePage": "https://www.kernel.org/",
                "software_packageVersion": "6.12.22+git"
            },
            {
                "type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/linux-yocto/vex-not-affected/1",
                "from": "http://spdxdocs.org/openembedded-alias/linux-yocto/vulnerability/CVE-2023-1234",
                "to": ["http://spdx.org/spdxdocs/linux-yocto/package/kernel"],
                "relationshipType": "doesNotAffect",
                "security_vexVersion": "1.0.0",
                "security_justificationType": "vulnerableCodeNotPresent",
                "security_impactStatement": "The vulnerable code is not present in this package"
            },
            {
                "type": "security_VexAffectedVulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/linux-yocto/vex-affected/2",
                "from": "http://spdxdocs.org/openembedded-alias/linux-yocto/vulnerability/CVE-2023-5678",
                "to": ["http://spdx.org/spdxdocs/linux-yocto/package/kernel"],
                "relationshipType": "affects",
                "security_vexVersion": "1.0.0",
                "security_justificationType": "exploitabilityConfirmed",
                "security_impactStatement": "This vulnerability affects the kernel"
            },
            {
                "type": "security_VexFixedVulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/linux-yocto/vex-fixed/67890",
                "from": "http://spdxdocs.org/openembedded-alias/linux-yocto/vulnerability/CVE-2024-1234",
                "to": ["http://spdx.org/spdxdocs/linux-yocto/package/kernel"],
                "relationshipType": "fixedIn",
                "security_vexVersion": "1.0.0",
                "security_impactStatement": "This vulnerability has been fixed in this package"
            }
        ]
    })

    assert len(spdx3_parser.packagesCtrl) == 1
    assert "kernel@6.12.22" in spdx3_parser.packagesCtrl

    assert len(spdx3_parser.assessmentsCtrl) == 3

    not_affected = spdx3_parser.assessmentsCtrl.gets_by_vuln("CVE-2023-1234")[0]
    assert not_affected.status == "not_affected"
    assert len(not_affected.packages) == 1
    assert not_affected.justification == "vulnerable_code_not_present"
    assert "The vulnerable code is not present in this package" in not_affected.impact_statement

    affected = spdx3_parser.assessmentsCtrl.gets_by_vuln("CVE-2023-5678")[0]
    assert affected.status == "affected"
    assert len(affected.packages) == 1
    # exploitabilityConfirmed is not in the JUSTIFICATION_MAP, so it should not be set
    assert affected.justification == ""
    assert "This vulnerability affects the kernel" in affected.impact_statement

    fixed = spdx3_parser.assessmentsCtrl.gets_by_vuln("CVE-2024-1234")[0]
    assert fixed.status == "fixed"
    assert len(fixed.packages) == 1
    assert "This vulnerability has been fixed in this package" in fixed.impact_statement


def test_extract_vulnerabilities(spdx3_parser):
    """Test extracting vulnerabilities"""

    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            {
                "type": "CreationInfo",
                "@id": "_:CreationInfo1",
                "created": "2025-04-08T13:09:06Z",
                "createdBy": [
                    "http://spdx.org/spdxdocs/bitbake-agent/OpenEmbedded"
                ],
                "createdUsing": [
                    "http://spdx.org/spdxdocs/bitbake-tool/oe-spdx-creator_1_0"
                ],
                "specVersion": "3.0.1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/linux-yocto/package/kernel",
                "name": "kernel",
                "software_packageVersion": "6.12.22",
                "creationInfo": "_:CreationInfo1",
                "description": "Linux kernel",
                "externalIdentifier": [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cpe23Type",
                        "identifier": "cpe:2.3:o:linux:linux:6.12.22:*:*:*:*:*:*:*"
                    }
                ],
                "summary": "Linux kernel",
                "software_primaryPurpose": "operating-system",
                "software_homePage": "https://www.kernel.org/"
            },
            {
                "type": "security_Vulnerability",
                "spdxId": "http://spdx.org/spdxdocs/linux-yocto/vulnerability/CVE-2023-1234",
                "externalIdentifier": [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cve",
                        "identifier": "CVE-2023-1234",
                        "identifierLocator": [
                            "https://cveawg.mitre.org/api/cve/CVE-2023-1234",
                            "https://www.cve.org/CVERecord?id=CVE-2023-1234"
                        ]
                    }
                ]
            },
            {
                "type": "Relationship",
                "spdxId": "http://spdx.org/spdxdocs/linux-yocto/relationship/1",
                "creationInfo": "_:CreationInfo1",
                "from": "http://spdx.org/spdxdocs/linux-yocto/package/kernel",
                "relationshipType": "hasAssociatedVulnerability",
                "to": ["http://spdx.org/spdxdocs/linux-yocto/vulnerability/CVE-2023-1234"]
            },
            {
                "type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/linux-yocto/vex-not-affected/1",
                "from": "http://spdx.org/spdxdocs/linux-yocto/vulnerability/CVE-2023-1234",
                "to": ["http://spdx.org/spdxdocs/linux-yocto/package/kernel"],
                "relationshipType": "doesNotAffect"
            }
        ]
    }

    spdx3_parser.parse_from_dict(spdx_data)

    assert len(spdx3_parser.vulnerabilitiesCtrl) == 1
    assert "CVE-2023-1234" in spdx3_parser.vulnerabilitiesCtrl

    vuln = spdx3_parser.vulnerabilitiesCtrl.get("CVE-2023-1234")
    assert vuln.id == "CVE-2023-1234"
    assert "https://cveawg.mitre.org/api/cve/CVE-2023-1234" == vuln.datasource
    assert vuln.namespace == "unknown"
    assert "https://www.cve.org/CVERecord?id=CVE-2023-1234" in vuln.urls


def test_package_vulnerability_relationships(spdx3_parser):
    """Test parsing SPDX files with package-vulnerability relationships."""
    spdx3_parser.parse_from_dict({
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            {
                "type": "CreationInfo",
                "@id": "_:CreationInfo1",
                "created": "2025-04-08T13:09:06Z",
                "createdBy": ["http://spdx.org/spdxdocs/bitbake-agent/OpenEmbedded"],
                "createdUsing": ["http://spdx.org/spdxdocs/bitbake-tool/oe-spdx-creator_1_0"],
                "specVersion": "3.0.1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/glibc/package/libc6",
                "creationInfo": "_:CreationInfo1",
                "description": "GNU C Library",
                "externalIdentifier": [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cpe23Type",
                        "identifier": "cpe:2.3:a:gnu:glibc:2.38:*:*:*:*:*:*:*"
                    }
                ],
                "name": "libc6",
                "summary": "GNU C Library",
                "software_primaryPurpose": "library",
                "software_homePage": "https://www.gnu.org/software/libc/",
                "software_packageVersion": "2.38"
            },
            {
                "type": "security_Vulnerability",
                "spdxId": "http://spdx.org/spdxdocs/glibc/vulnerability/CVE-2019-1010022",
                "externalIdentifier": [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cve",
                        "identifier": "CVE-2019-1010022",
                        "identifierLocator": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1010022"]
                    }
                ]
            },
            {
                "type": "Relationship",
                "spdxId": "http://spdx.org/spdxdocs/glibc/relationship/1",
                "creationInfo": "_:CreationInfo1",
                "from": "http://spdx.org/spdxdocs/glibc/package/libc6",
                "relationshipType": "hasAssociatedVulnerability",
                "to": [
                    "http://spdx.org/spdxdocs/glibc/vulnerability/CVE-2019-1010022"
                ]
            },
            {
                "type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/linux-yocto/vex-not-affected/1",
                "from": "http://spdx.org/spdxdocs/glibc/vulnerability/CVE-2019-1010022",
                "to": ["http://spdx.org/spdxdocs/glibc/package/libc6"],
                "relationshipType": "doesNotAffect"
            }
        ]
    })

    assert len(spdx3_parser.packagesCtrl) == 1
    assert "libc6@2.38" in spdx3_parser.packagesCtrl

    assert len(spdx3_parser.vulnerabilitiesCtrl) == 1
    assert "CVE-2019-1010022" in spdx3_parser.vulnerabilitiesCtrl

    vuln = spdx3_parser.vulnerabilitiesCtrl.get("CVE-2019-1010022")
    assert vuln.id == "CVE-2019-1010022"
    assert len(vuln.packages) == 1
    assert "libc6@2.38" in vuln.packages


def test_vulnerability_without_relationship(spdx3_parser):
    """Test that vulnerabilities without hasAssociatedVulnerability relationship are not added."""
    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            {
                "type": "CreationInfo",
                "@id": "_:CreationInfo1",
                "created": "2025-04-08T13:09:06Z",
                "createdBy": [
                    "http://spdx.org/spdxdocs/bitbake-agent/OpenEmbedded"
                ],
                "createdUsing": [
                    "http://spdx.org/spdxdocs/bitbake-tool/oe-spdx-creator_1_0"
                ],
                "specVersion": "3.0.1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/linux-yocto/package/kernel",
                "name": "kernel",
                "software_packageVersion": "6.12.22",
                "creationInfo": "_:CreationInfo1",
                "description": "Linux kernel",
                "externalIdentifier": [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cpe23Type",
                        "identifier": "cpe:2.3:o:linux:linux:6.12.22:*:*:*:*:*:*:*"
                    }
                ],
                "summary": "Linux kernel",
                "software_primaryPurpose": "operating-system",
                "software_homePage": "https://www.kernel.org/"
            },
            {
                "type": "security_Vulnerability",
                "spdxId": "http://spdx.org/spdxdocs/linux-yocto/vulnerability/CVE-2023-1234",
                "externalIdentifier": [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cve",
                        "identifier": "CVE-2023-1234",
                        "identifierLocator": [
                            "https://cveawg.mitre.org/api/cve/CVE-2023-1234",
                            "https://www.cve.org/CVERecord?id=CVE-2023-1234"
                        ]
                    }
                ]
            }
        ]
    }

    spdx3_parser.parse_from_dict(spdx_data)

    # Verify that the vulnerability was not added since there's no hasAssociatedVulnerability relationship
    assert len(spdx3_parser.vulnerabilitiesCtrl) == 0
    assert "CVE-2023-1234" not in spdx3_parser.vulnerabilitiesCtrl


def test_graph_as_string_instead_of_list(spdx3_parser):
    """Test parsing when @graph is provided as a string instead of a list."""
    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": "invalid_string_instead_of_list"
    }

    spdx3_parser.parse_from_dict(spdx_data)

    assert len(spdx3_parser.packagesCtrl) == 0
    assert len(spdx3_parser.vulnerabilitiesCtrl) == 0
    assert len(spdx3_parser.assessmentsCtrl) == 0


def test_graph_as_none(spdx3_parser):
    """Test parsing when @graph is None."""
    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": None
    }

    spdx3_parser.parse_from_dict(spdx_data)

    assert len(spdx3_parser.packagesCtrl) == 0
    assert len(spdx3_parser.vulnerabilitiesCtrl) == 0
    assert len(spdx3_parser.assessmentsCtrl) == 0


def test_missing_graph_field(spdx3_parser):
    """Test parsing when @graph field is completely missing."""
    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT"
    }

    spdx3_parser.parse_from_dict(spdx_data)

    assert len(spdx3_parser.packagesCtrl) == 0
    assert len(spdx3_parser.vulnerabilitiesCtrl) == 0
    assert len(spdx3_parser.assessmentsCtrl) == 0


def test_graph_with_invalid_element_types(spdx3_parser):
    """Test parsing when @graph contains non-dictionary elements."""
    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            "invalid_string_element",
            123,
            None,
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/valid/package/test",
                "name": "test",
                "software_packageVersion": "1.0"
            }
        ]
    }

    spdx3_parser.parse_from_dict(spdx_data)

    assert len(spdx3_parser.packagesCtrl) == 1
    assert "test@1.0" in spdx3_parser.packagesCtrl


def test_package_missing_required_fields(spdx3_parser):
    """Test parsing packages with missing name or version."""
    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/test/package/no-name",
                "software_packageVersion": "1.0"
                # Missing name
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/test/package/no-version",
                "name": "test-package"
                # Missing version
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/test/package/valid",
                "name": "valid-package",
                "software_packageVersion": "2.0"
            }
        ]
    }

    spdx3_parser.parse_from_dict(spdx_data)

    # Only the valid package should be added
    assert len(spdx3_parser.packagesCtrl) == 1
    assert "valid-package@2.0" in spdx3_parser.packagesCtrl


def test_vex_relationship_invalid_structure(spdx3_parser):
    """Test parsing VEX relationships with invalid structure."""
    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/test/package/kernel",
                "name": "kernel",
                "software_packageVersion": "6.0"
            },
            {
                "type": "security_Vulnerability",
                "spdxId": "http://spdx.org/spdxdocs/test/vulnerability/CVE-2023-1234",
                "externalIdentifier": [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cve",
                        "identifier": "CVE-2023-1234"
                    }
                ]
            },
            {
                "type": "Relationship",
                "spdxId": "http://spdx.org/spdxdocs/test/relationship/1",
                "from": "http://spdx.org/spdxdocs/test/package/kernel",
                "relationshipType": "hasAssociatedVulnerability",
                "to": ["http://spdx.org/spdxdocs/test/vulnerability/CVE-2023-1234"]
            },
            {
                "type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/test/vex/missing-from",
                "to": ["http://spdx.org/spdxdocs/test/package/kernel"],
                "relationshipType": "doesNotAffect"
                # Missing 'from' field
            },
            {
                "type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/test/vex/missing-to",
                "from": "http://spdx.org/spdxdocs/test/vulnerability/CVE-2023-1234",
                "relationshipType": "doesNotAffect"
                # Missing 'to' field
            },
            {
                "type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/test/vex/invalid-to-type",
                "from": "http://spdx.org/spdxdocs/test/vulnerability/CVE-2023-1234",
                "to": "invalid_string_instead_of_list",
                "relationshipType": "doesNotAffect"
            }
        ]
    }

    spdx3_parser.parse_from_dict(spdx_data)

    assert len(spdx3_parser.packagesCtrl) == 1
    assert len(spdx3_parser.vulnerabilitiesCtrl) == 0
    assert len(spdx3_parser.assessmentsCtrl) == 0

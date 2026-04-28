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
    assert affected.status == "under_investigation"
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
                "description": "Inappropriate implementation in Intents in Google Chrome...",
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
    assert "Inappropriate implementation in Intents in Google Chrome..." in vuln.texts.values()
    # Description must be under "description" key to be persisted to the DB
    assert vuln.texts.get("description") == "Inappropriate implementation in Intents in Google Chrome..."


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


def test_package_vulnerability_cvss(spdx3_parser):
    """Test parsing SPDX files with package-vulnerability-cvss relationships."""
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
            },
            {
                "type": "security_CvssV3VulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/008360af-75f7-5c35-aac9-47e538e98f3d/cvss-V3_0/d10b1a11b649d80033c50f2a78e242d6",
                "comment": "nvd@nist.gov",
                "creationInfo": "_:CreationInfo323",
                "from": "http://spdx.org/spdxdocs/glibc/vulnerability/CVE-2019-1010022",
                "relationshipType": "hasAssessmentFor",
                "to": ["http://spdx.org/spdxdocs/glibc/package/libc6"],
                "security_score": "6.3",
                "security_severity": "medium",
                "security_vectorString": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N"
            },
            {
                "type": "security_CvssV2VulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/008360af-75f7-5c35-aac9-47e538e98f3d/cvss-V2_0/d10b1a11b649d80033c50f2a78e242d6",
                "creationInfo": "_:CreationInfo323",
                "from": "http://spdx.org/spdxdocs/glibc/vulnerability/CVE-2019-1010022",
                "relationshipType": "hasAssessmentFor",
                "to": ["http://spdx.org/spdxdocs/glibc/package/libc6"],
                "security_score": "6.2",
                "security_vectorString": "AV:L/AC:M/Au:N/C:C/I:C/A:C"
            },
        ]
    })

    assert len(spdx3_parser.packagesCtrl) == 1
    assert "libc6@2.38" in spdx3_parser.packagesCtrl

    assert len(spdx3_parser.vulnerabilitiesCtrl) == 1
    assert "CVE-2019-1010022" in spdx3_parser.vulnerabilitiesCtrl

    vuln = spdx3_parser.vulnerabilitiesCtrl.get("CVE-2019-1010022")
    assert vuln.id == "CVE-2019-1010022"
    
    assert len(vuln.severity_cvss) == 2
    cvss_nist, cvss_other = vuln.severity_cvss
    
    assert cvss_nist.base_score == 6.3
    assert cvss_nist.vector_string == "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N"
    assert cvss_nist.author == "nvd@nist.gov"

    assert cvss_other.base_score == 6.2
    assert cvss_other.vector_string == "AV:L/AC:M/Au:N/C:C/I:C/A:C"


def test_package_vulnerability_cvss_malformed(spdx3_parser):
    """Test parsing SPDX files with malformed package-vulnerability-cvss relationships."""
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
            },
            {
                "type": "security_CvssV3VulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/008360af-75f7-5c35-aac9-47e538e98f3d/cvss-V3_0/d10b1a11b649d80033c50f2a78e242d6",
                "comment": "nvd@nist.gov",
                "creationInfo": "_:CreationInfo323",
                "from": "http://spdx.org/spdxdocs/glibc/vulnerability/CVE-2019-1010022",
                "relationshipType": "hasAssessmentFor",
                "to": ["http://spdx.org/spdxdocs/glibc/package/libc6"],
                "security_score": "6.3",
                "security_severity": "medium",
                "security_vectorString": "AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N" # missing CVSS version
            },
            {
                "type": "security_CvssV3VulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/008360af-75f7-5c35-aac9-47e538e98f3d/cvss-V3_0/d10b1a11b649d80033c50f2a78e242d6",
                "comment": "nvd@nist.gov",
                "creationInfo": "_:CreationInfo323",
                "from": "http://spdx.org/spdxdocs/glibc/vulnerability/CVE-2019-1010022",
                "relationshipType": "somethingElse", # wrong relationship type
                "to": ["http://spdx.org/spdxdocs/glibc/package/libc6"],
                "security_score": "6.3",
                "security_severity": "medium",
                "security_vectorString": "AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N" # missing CVSS version
            },
            {
                "type": "security_CvssV2VulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/008360af-75f7-5c35-aac9-47e538e98f3d/cvss-V2_0/d10b1a11b649d80033c50f2a78e242d6",
                "creationInfo": "_:CreationInfo323",
                "from": "http://spdx.org/spdxdocs/glibc/vulnerability/", # missing CVE
                "relationshipType": "hasAssessmentFor",
                "to": ["http://spdx.org/spdxdocs/glibc/package/libc6"],
                "security_score": "6.2",
                "security_vectorString": "AV:L/AC:M/Au:N/C:C/I:C/A:C"
            },
            {
                "type": "security_CvssV2VulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/008360af-75f7-5c35-aac9-47e538e98f3d/cvss-V2_0/d10b1a11b649d80033c50f2a78e242d6",
                "creationInfo": "_:CreationInfo323",
                # missing from
                "relationshipType": "hasAssessmentFor",
                "to": ["http://spdx.org/spdxdocs/glibc/package/libc6"],
                "security_score": "6.2",
                "security_vectorString": "AV:L/AC:M/Au:N/C:C/I:C/A:C"
            },
        ]
    })

    assert len(spdx3_parser.packagesCtrl) == 1
    assert "libc6@2.38" in spdx3_parser.packagesCtrl

    assert len(spdx3_parser.vulnerabilitiesCtrl) == 1
    assert "CVE-2019-1010022" in spdx3_parser.vulnerabilitiesCtrl

    vuln = spdx3_parser.vulnerabilitiesCtrl.get("CVE-2019-1010022")
    assert vuln.id == "CVE-2019-1010022"
    
    assert len(vuln.severity_cvss) == 0


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


def test_could_parse_spdx(spdx3_parser):
    """Test could_parse_spdx version checking."""
    # Valid SPDX 3.x
    spdx_v3 = {
        "@graph": [
            {
                "@type": "CreationInfo",
                "specVersion": "3.0.1"
            }
        ]
    }
    assert spdx3_parser.could_parse_spdx(spdx_v3) is True
    
    # Valid SPDX 3.x with "type" instead of "@type"
    spdx_v3_alt = {
        "@graph": [
            {
                "type": "CreationInfo",
                "specVersion": "3.1.0"
            }
        ]
    }
    assert spdx3_parser.could_parse_spdx(spdx_v3_alt) is True
    
    # Invalid - SPDX 2.x
    spdx_v2 = {
        "@graph": [
            {
                "type": "CreationInfo",
                "specVersion": "2.3"
            }
        ]
    }
    assert spdx3_parser.could_parse_spdx(spdx_v2) is False
    
    # Invalid - no specVersion
    spdx_no_version = {
        "@graph": [
            {
                "type": "CreationInfo"
            }
        ]
    }
    assert spdx3_parser.could_parse_spdx(spdx_no_version) is False
    
    # Invalid - empty
    assert spdx3_parser.could_parse_spdx({}) is False


def test_extract_purl_variations(spdx3_parser):
    """Test extract_purl with different field names."""
    # Test with 'packageUrl'
    element1 = {"packageUrl": "pkg:generic/test@1.0"}
    assert spdx3_parser.extract_purl(element1) == "pkg:generic/test@1.0"
    
    # Test with 'software_packageUrl'
    element2 = {"software_packageUrl": "pkg:generic/test@2.0"}
    assert spdx3_parser.extract_purl(element2) == "pkg:generic/test@2.0"
    
    # Test with no PURL
    element3 = {"name": "test"}
    assert spdx3_parser.extract_purl(element3) is None


def test_extract_cpes_invalid_structure(spdx3_parser):
    """Test extract_cpes with invalid externalIdentifier structure."""
    # Non-list externalIdentifier
    element1 = {"externalIdentifier": "invalid_string"}
    assert spdx3_parser.extract_cpes(element1) == []
    
    # List with non-dict items
    element2 = {"externalIdentifier": ["string", 123, None]}
    assert spdx3_parser.extract_cpes(element2) == []
    
    # List with dicts but wrong type
    element3 = {
        "externalIdentifier": [
            {"externalIdentifierType": "other", "identifier": "value"}
        ]
    }
    assert spdx3_parser.extract_cpes(element3) == []
    
    # Valid CPE
    element4 = {
        "externalIdentifier": [
            {"externalIdentifierType": "cpe23", "identifier": "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*"},
            {"externalIdentifierType": "cpe22", "identifier": "cpe:/a:test:test:2.0"}
        ]
    }
    cpes = spdx3_parser.extract_cpes(element4)
    assert len(cpes) == 2
    assert "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*" in cpes
    assert "cpe:/a:test:test:2.0" in cpes


def test_package_with_skip_purposes(spdx3_parser):
    """Test that packages with certain purposes are skipped."""
    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            {
                "type": "CreationInfo",
                "@id": "_:CreationInfo1",
                "specVersion": "3.0.1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/test/package/source",
                "name": "source-package",
                "software_packageVersion": "1.0",
                "software_primaryPurpose": "source",
                "creationInfo": "_:CreationInfo1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/test/package/dev",
                "name": "dev-package",
                "software_packageVersion": "1.0",
                "software_primaryPurpose": "development",
                "creationInfo": "_:CreationInfo1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/test/package/doc",
                "name": "doc-package",
                "software_packageVersion": "1.0",
                "software_primaryPurpose": "documentation",
                "creationInfo": "_:CreationInfo1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/test/package/app",
                "name": "app-package",
                "software_packageVersion": "1.0",
                "software_primaryPurpose": "application",
                "creationInfo": "_:CreationInfo1"
            }
        ]
    }
    
    spdx3_parser.parse_from_dict(spdx_data)
    
    # Only the application package should be included
    assert len(spdx3_parser.packagesCtrl) == 1
    assert "app-package@1.0" in spdx3_parser.packagesCtrl
    assert "source-package@1.0" not in spdx3_parser.packagesCtrl
    assert "dev-package@1.0" not in spdx3_parser.packagesCtrl
    assert "doc-package@1.0" not in spdx3_parser.packagesCtrl


def test_vex_relationship_unknown_package_uri(spdx3_parser):
    """Test VEX relationship when package URI is not in mapping."""
    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            {
                "type": "CreationInfo",
                "@id": "_:CreationInfo1",
                "specVersion": "3.0.1"
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
                "type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/test/vex/1",
                "from": "http://spdx.org/spdxdocs/test/vulnerability/CVE-2023-1234",
                "to": ["http://spdx.org/spdxdocs/test/package/unknown"],
                "relationshipType": "doesNotAffect"
            }
        ]
    }
    
    spdx3_parser.parse_from_dict(spdx_data)
    
    # Assessment should not be created when package is not found
    assert len(spdx3_parser.assessmentsCtrl) == 0


def test_relationship_with_empty_to_list(spdx3_parser):
    """Test relationship with empty 'to' list."""
    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            {
                "type": "CreationInfo",
                "@id": "_:CreationInfo1",
                "specVersion": "3.0.1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/test/package/kernel",
                "name": "kernel",
                "software_packageVersion": "6.0",
                "creationInfo": "_:CreationInfo1"
            },
            {
                "type": "Relationship",
                "spdxId": "http://spdx.org/spdxdocs/test/relationship/1",
                "from": "http://spdx.org/spdxdocs/test/package/kernel",
                "relationshipType": "hasAssociatedVulnerability",
                "to": []
            }
        ]
    }
    
    spdx3_parser.parse_from_dict(spdx_data)
    
    assert len(spdx3_parser.packagesCtrl) == 1
    assert len(spdx3_parser.vulnerabilitiesCtrl) == 0


def test_vex_impact_statement(spdx3_parser):
    """Test VEX relationships with impact statements."""
    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            {
                "type": "CreationInfo",
                "@id": "_:CreationInfo1",
                "specVersion": "3.0.1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/test/package/kernel",
                "name": "kernel",
                "software_packageVersion": "6.0",
                "creationInfo": "_:CreationInfo1"
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
                "spdxId": "http://spdx.org/spdxdocs/test/vex/1",
                "from": "http://spdx.org/spdxdocs/test/vulnerability/CVE-2023-1234",
                "to": ["http://spdx.org/spdxdocs/test/package/kernel"],
                "relationshipType": "doesNotAffect",
                "security_impactStatement": "This is a detailed impact statement",
                "security_justificationType": "componentNotPresent"
            }
        ]
    }
    
    spdx3_parser.parse_from_dict(spdx_data)
    
    assessments = spdx3_parser.assessmentsCtrl.gets_by_vuln("CVE-2023-1234")
    assert len(assessments) == 1
    assert assessments[0].impact_statement == "This is a detailed impact statement"
    assert assessments[0].justification == "component_not_present"


def test_parse_controllers_from_dict(spdx3_parser):
    """Test parse_controllers_from_dict which only parses packages."""
    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            {
                "type": "CreationInfo",
                "@id": "_:CreationInfo1",
                "specVersion": "3.0.1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/test/package/test",
                "name": "test",
                "software_packageVersion": "1.0",
                "creationInfo": "_:CreationInfo1"
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
            }
        ]
    }
    
    spdx3_parser.parse_controllers_from_dict(spdx_data)
    
    # Only packages should be parsed, not vulnerabilities
    assert len(spdx3_parser.packagesCtrl) == 1
    assert len(spdx3_parser.vulnerabilitiesCtrl) == 0


def test_external_identifier_with_multiple_locators(spdx3_parser):
    """Test vulnerability with multiple identifier locators."""
    spdx_data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "specVersion": "3.0.1",
        "SPDXID": "SPDXRef-DOCUMENT",
        "@graph": [
            {
                "type": "CreationInfo",
                "@id": "_:CreationInfo1",
                "specVersion": "3.0.1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/test/package/test",
                "name": "test",
                "software_packageVersion": "1.0",
                "creationInfo": "_:CreationInfo1"
            },
            {
                "type": "security_Vulnerability",
                "spdxId": "http://spdx.org/spdxdocs/test/vulnerability/CVE-2023-5678",
                "externalIdentifier": [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cve",
                        "identifier": "CVE-2023-5678",
                        "identifierLocator": [
                            "https://primary.datasource.com/CVE-2023-5678",
                            "https://secondary.datasource.com/CVE-2023-5678",
                            "https://tertiary.datasource.com/CVE-2023-5678"
                        ]
                    }
                ]
            },
            {
                "type": "Relationship",
                "spdxId": "http://spdx.org/spdxdocs/test/relationship/1",
                "from": "http://spdx.org/spdxdocs/test/package/test",
                "relationshipType": "hasAssociatedVulnerability",
                "to": ["http://spdx.org/spdxdocs/test/vulnerability/CVE-2023-5678"]
            },
            {
                "type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/test/vex/1",
                "from": "http://spdx.org/spdxdocs/test/vulnerability/CVE-2023-5678",
                "to": ["http://spdx.org/spdxdocs/test/package/test"],
                "relationshipType": "doesNotAffect"
            }
        ]
    }
    
    spdx3_parser.parse_from_dict(spdx_data)
    
    vuln = spdx3_parser.vulnerabilitiesCtrl.get("CVE-2023-5678")
    assert vuln.datasource == "https://primary.datasource.com/CVE-2023-5678"
    # Secondary and tertiary URLs should be in the URLs list
    assert "https://secondary.datasource.com/CVE-2023-5678" in vuln.urls
    assert "https://tertiary.datasource.com/CVE-2023-5678" in vuln.urls


def test_merge_components_non_dict(spdx3_parser):
    """merge_components_into_controller with a non-dict input returns early (line 89)."""
    spdx3_parser.merge_components_into_controller("not-a-dict")
    spdx3_parser.merge_components_into_controller(42)
    spdx3_parser.merge_components_into_controller(None)
    assert len(spdx3_parser.packagesCtrl) == 0


def test_convert_to_package_with_cpe_and_purl(spdx3_parser):
    """_convert_to_package stores CPEs (line 142) and PURL (line 147) when present."""
    component = {
        "type": "software_Package",
        "spdxId": "http://example.com/pkg/libfoo",
        "name": "libfoo",
        "versionInfo": "1.2.3",
        "packageUrl": "pkg:deb/debian/libfoo@1.2.3",
        "externalIdentifier": [
            {
                "externalIdentifierType": "cpe23",
                "identifier": "cpe:2.3:a:libfoo:libfoo:1.2.3:*:*:*:*:*:*:*"
            }
        ]
    }
    pkg = spdx3_parser._convert_to_package(component)
    assert pkg is not None
    assert any("libfoo" in c for c in pkg.cpe)
    assert any("libfoo" in p for p in pkg.purl)


def test_merge_vulnerabilities_non_dict(spdx3_parser):
    """merge_vulnerabilities_into_controller with a non-dict returns early (lines 189-190)."""
    spdx3_parser.merge_vulnerabilities_into_controller("not-a-dict")
    spdx3_parser.merge_vulnerabilities_into_controller(42)
    assert len(spdx3_parser.vulnerabilitiesCtrl) == 0


def test_extract_explicit_vulns_edge_cases(spdx3_parser):
    """_extract_explicit_vulnerabilities handles various bad externalIdentifier formats (lines 247-260)."""
    graph = [
        # externalIdentifier is not a list → line 247
        {
            "type": "security_Vulnerability",
            "externalIdentifier": "not-a-list"
        },
        # ext_id is not a dict → line 250
        {
            "type": "security_Vulnerability",
            "externalIdentifier": ["just-a-string"]
        },
        # identifier type != 'cve' → line 252
        {
            "type": "security_Vulnerability",
            "externalIdentifier": [
                {"externalIdentifierType": "cwe", "identifier": "CWE-79"}
            ]
        },
        # identifier is empty → line 256
        {
            "type": "security_Vulnerability",
            "externalIdentifier": [
                {"externalIdentifierType": "cve", "identifier": ""}
            ]
        },
        # locators is not a list → line 260 (locators = [])
        {
            "type": "security_Vulnerability",
            "externalIdentifier": [
                {
                    "externalIdentifierType": "cve",
                    "identifier": "CVE-2099-EDGEX",
                    "identifierLocator": "not-a-list"
                }
            ]
        },
    ]
    spdx3_parser._extract_explicit_vulnerabilities(graph)
    # Only CVE-2099-EDGEX should have been added (locators fall back to [])
    assert spdx3_parser.vulnerabilitiesCtrl.get("CVE-2099-EDGEX") is not None


def test_extract_cvss_with_unknown_vuln(spdx3_parser):
    """_extract_vulnerabilities_cvss skips elements where vulnerability is not found (line 314)."""
    graph = [
        {
            "type": "security_CvssV3VulnAssessmentRelationship",
            "from": "http://spdx.org/spdxdocs/test/vulnerability/CVE-9999-77777",
            "relationshipType": "hasAssessmentFor",
            "to": ["http://example.com/pkg/foo"],
            "security_vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "security_score": "9.8",
        }
    ]
    # Should not raise even though CVE-9999-77777 is not registered in the controller
    spdx3_parser._extract_vulnerabilities_cvss(graph)


def test_process_pkg_vuln_relationships_edge_cases(spdx3_parser):
    """_process_package_vulnerability_relationships handles missing fields (lines 356, 360, 369-370, 375)."""
    graph = [
        # type=Relationship but wrong relationshipType → line 356
        {
            "type": "Relationship",
            "from": "http://example.com/pkg/foo",
            "relationshipType": "contains",
            "to": ["http://example.com/vuln/CVE-2099-X"]
        },
        # correct type/relationshipType but no 'from' → line 360
        {
            "type": "Relationship",
            "relationshipType": "hasAssociatedVulnerability",
            "to": ["http://example.com/vuln/CVE-2099-X"]
        },
        # 'from' not in uri_to_package map → lines 369-370
        {
            "type": "Relationship",
            "from": "http://example.com/pkg/UNKNOWN-PACKAGE",
            "relationshipType": "hasAssociatedVulnerability",
            "to": ["http://example.com/vuln/CVE-2099-X"]
        },
        # vuln_uri has no CVE pattern → line 375
        {
            "type": "Relationship",
            "from": "http://example.com/pkg/foo",
            "relationshipType": "hasAssociatedVulnerability",
            "to": ["http://example.com/some-non-cve-path"]
        },
    ]
    # Register "foo" package so the 'from' lookup works for the last element
    spdx3_parser.uri_to_package["http://example.com/pkg/foo"] = "libfoo@1.0"
    # Should not raise regardless
    spdx3_parser._process_package_vulnerability_relationships(graph)


def test_extract_cve_id_empty_text(spdx3_parser):
    """_extract_cve_id returns None when text is empty/None (line 386)."""
    assert spdx3_parser._extract_cve_id("") is None
    assert spdx3_parser._extract_cve_id(None) is None


def test_process_vex_non_dict(spdx3_parser):
    """process_vex_relationships with non-dict input returns early (lines 406-407)."""
    spdx3_parser.process_vex_relationships("not-a-dict")
    spdx3_parser.process_vex_relationships(42)
    assert len(spdx3_parser.assessmentsCtrl.assessments) == 0


def test_parse_vex_relationship_no_cve_in_from(spdx3_parser):
    """_parse_vex_relationship returns None when 'from' has no CVE ID (line 442)."""
    element = {
        "type": "security_VexNotAffectedVulnAssessmentRelationship",
        "from": "http://example.com/advisory/GHSA-1234",  # no CVE pattern
        "to": ["http://example.com/pkg/libbar"],
        "relationshipType": "doesNotAffect"
    }
    result = spdx3_parser._parse_vex_relationship(element)
    assert result is None


def test_spdx3_cvss_persisted_to_db(spdx3_parser):
    """CVSS scores from security_CvssV*VulnAssessmentRelationship elements
    must be persisted as Metrics rows in the DB, not just kept in-memory."""
    from src.models.metrics import Metrics
    from src.extensions import db

    spdx3_parser.parse_from_dict({
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {
                "type": "CreationInfo",
                "@id": "_:CreationInfo1",
                "created": "2025-04-08T13:09:06Z",
                "createdBy": ["http://spdx.org/agents/test"],
                "specVersion": "3.0.1"
            },
            {
                "type": "software_Package",
                "spdxId": "http://spdx.org/spdxdocs/test/package/foo",
                "creationInfo": "_:CreationInfo1",
                "name": "foo",
                "software_packageVersion": "1.0",
                "externalIdentifier": [{
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "cpe23Type",
                    "identifier": "cpe:2.3:a:foo:foo:1.0:*:*:*:*:*:*:*"
                }]
            },
            {
                "type": "security_Vulnerability",
                "spdxId": "http://spdx.org/spdxdocs/test/vulnerability/CVE-2025-90001",
                "creationInfo": "_:CreationInfo1",
                "externalIdentifier": [{
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "cve",
                    "identifier": "CVE-2025-90001",
                    "identifierLocator": ["https://www.cve.org/CVERecord?id=CVE-2025-90001"]
                }]
            },
            {
                "type": "Relationship",
                "spdxId": "http://spdx.org/spdxdocs/test/relationship/1",
                "creationInfo": "_:CreationInfo1",
                "from": "http://spdx.org/spdxdocs/test/package/foo",
                "relationshipType": "hasAssociatedVulnerability",
                "to": ["http://spdx.org/spdxdocs/test/vulnerability/CVE-2025-90001"]
            },
            {
                "type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/test/vex/1",
                "creationInfo": "_:CreationInfo1",
                "from": "http://spdx.org/spdxdocs/test/vulnerability/CVE-2025-90001",
                "to": ["http://spdx.org/spdxdocs/test/package/foo"],
                "relationshipType": "doesNotAffect"
            },
            {
                "type": "security_CvssV3VulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/test/cvss-v3/1",
                "comment": "nvd@nist.gov",
                "creationInfo": "_:CreationInfo1",
                "from": "http://spdx.org/spdxdocs/test/vulnerability/CVE-2025-90001",
                "relationshipType": "hasAssessmentFor",
                "to": ["http://spdx.org/spdxdocs/test/package/foo"],
                "security_score": "9.8",
                "security_severity": "critical",
                "security_vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            },
            {
                "type": "security_CvssV2VulnAssessmentRelationship",
                "spdxId": "http://spdx.org/spdxdocs/test/cvss-v2/1",
                "creationInfo": "_:CreationInfo1",
                "from": "http://spdx.org/spdxdocs/test/vulnerability/CVE-2025-90001",
                "relationshipType": "hasAssessmentFor",
                "to": ["http://spdx.org/spdxdocs/test/package/foo"],
                "security_score": "7.5",
                "security_vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"
            }
        ]
    })
    db.session.commit()

    # In-memory: severity_cvss should have both entries
    vuln = spdx3_parser.vulnerabilitiesCtrl.get("CVE-2025-90001")
    assert vuln is not None
    assert len(vuln.severity_cvss) == 2

    # DB: Metrics rows must exist
    db.session.expire_all()
    metrics = db.session.execute(
        db.select(Metrics).where(Metrics.vulnerability_id == "CVE-2025-90001")
    ).scalars().all()
    assert len(metrics) == 2

    versions = {m.version: m for m in metrics}
    assert "3.1" in versions
    assert float(versions["3.1"].score) == 9.8
    assert versions["3.1"].vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    assert "2.0" in versions
    assert float(versions["2.0"].score) == 7.5
    assert versions["2.0"].vector == "AV:N/AC:L/Au:N/C:P/I:P/A:P"


def test_spdx3_description_persisted_to_db(spdx3_parser):
    """SPDX3 vulnerability description must be stored under the 'description' key
    and persisted to the DB description column."""
    from src.models.vulnerability import Vulnerability as VulnModel
    from src.extensions import db

    spdx3_parser.parse_from_dict({
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {
                "type": "CreationInfo",
                "@id": "_:CreationInfo1",
                "created": "2025-04-08T13:09:06Z",
                "createdBy": ["http://spdx.org/agents/test"],
                "specVersion": "3.0.1"
            },
            {
                "type": "security_Vulnerability",
                "spdxId": "http://spdx.org/spdxdocs/test/vulnerability/CVE-2025-SPDX3DESC",
                "creationInfo": "_:CreationInfo1",
                "description": "Test description from SPDX3 vulnerability element.",
                "externalIdentifier": [{
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "cve",
                    "identifier": "CVE-2025-SPDX3DESC",
                    "identifierLocator": ["https://www.cve.org/CVERecord?id=CVE-2025-SPDX3DESC"]
                }]
            }
        ]
    })
    db.session.commit()

    # Verify description is under the 'description' key in the in-memory DTO
    vuln = spdx3_parser.vulnerabilitiesCtrl.get("CVE-2025-SPDX3DESC")
    assert vuln is not None
    assert vuln.texts.get("description") == "Test description from SPDX3 vulnerability element."

    # Verify it persists to the DB
    db.session.expire_all()
    record = VulnModel.get_by_id("CVE-2025-SPDX3DESC")
    assert record is not None
    assert record.description == "Test description from SPDX3 vulnerability element."
    # Verify to_dict returns it under "texts" → "description"
    assert record.to_dict()["texts"]["description"] == "Test description from SPDX3 vulnerability element."

# -*- coding: utf-8 -*-
import pytest
from src.views.grype_vulns import GrypeVulns
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController
import json


@pytest.fixture
def grype_parser():
    controllers = {}
    controllers["packages"] = PackagesController()
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    controllers["assessments"] = AssessmentsController(controllers["packages"], controllers["vulnerabilities"])
    return GrypeVulns(controllers)


def test_parse_empty_json(grype_parser):
    grype_parser.load_from_dict(json.loads("""{
        "matches": [
            {
                "vulnerability": { },
                "relatedVulnerabilities": [],
                "matchDetails": [],
                "artifact": { }
            }
        ]
    }"""))
    assert len(grype_parser.packagesCtrl.packages) == 0
    assert len(grype_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(grype_parser.assessmentsCtrl.assessments) == 0


def test_parse_invalid_model_json(grype_parser):
    grype_parser.load_from_dict(json.loads("""{
        "matches": [
            {
                "foo": [],
                "bar": { }
            }
        ]
    }"""))
    assert len(grype_parser.packagesCtrl.packages) == 0
    assert len(grype_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(grype_parser.assessmentsCtrl.assessments) == 0


def test_parse_artifact_json(grype_parser):
    grype_parser.load_from_dict(json.loads("""{
        "matches": [
            {
                "vulnerability": { },
                "relatedVulnerabilities": [],
                "matchDetails": [],
                "artifact": {
                    "id": "00a810ca5fed6ade",
                    "name": "binutils",
                    "version": "2.38",
                    "type": "UnknownPackage",
                    "locations": [],
                    "language": "",
                    "licenses": [],
                    "cpes": [
                        "cpe:2.3:a:*:binutils:2.38:*:*:*:*:*:*:*"
                    ],
                    "purl": "pkg:generic/binutils@2.38",
                    "upstreams": []
                }
            },
            {
                "vulnerability": { },
                "relatedVulnerabilities": [],
                "matchDetails": [],
                "artifact": {
                    "id": "0be740738cf18168",
                    "name": "cairo",
                    "version": "1.16.0",
                    "type": "UnknownPackage",
                    "locations": [],
                    "language": "",
                    "licenses": [],
                    "cpes": [
                        "cpe:2.3:a:*:cairo:1.16.0:*:*:*:*:*:*:*"
                    ],
                    "purl": "pkg:generic/cairo@1.16.0",
                    "upstreams": []
                }
            }
        ]
    }"""))
    assert len(grype_parser.packagesCtrl.packages) == 2
    assert len(grype_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(grype_parser.assessmentsCtrl.assessments) == 0
    assert "binutils@2.38" in grype_parser.packagesCtrl.packages
    assert "cairo@1.16.0" in grype_parser.packagesCtrl.packages


def test_parse_match_details_json(grype_parser):
    grype_parser.load_from_dict(json.loads("""{
        "matches": [
            {
                "vulnerability": { },
                "relatedVulnerabilities": [],
                "matchDetails": [
                    {
                        "type": "cpe-match",
                        "matcher": "stock-matcher",
                        "searchedBy": {
                            "namespace": "nvd:cpe",
                            "cpes": [
                                "cpe:2.3:a:*:cairo:1.16.0:*:*:*:*:*:*:*"
                            ],
                            "Package": {
                                "name": "cairo",
                                "version": "1.16.0"
                            }
                        },
                        "found": {
                            "vulnerabilityID": "CVE-2020-35492",
                            "versionConstraint": "< 1.17.4 (unknown)",
                            "cpes": [
                                "cpe:2.3:a:cairographics:cairo:*:*:*:*:*:*:*:*"
                            ]
                        }
                    }
                ],
                "artifact": { }
            },
            {
                "vulnerability": { },
                "relatedVulnerabilities": [],
                "matchDetails": [
                    {
                        "type": "purl-match",
                        "matcher": "stock-matcher",
                        "searchedBy": {
                            "namespace": "unknown",
                            "purl": "pkg:generic/MarkupSafe@2.1.1",
                            "Package": {
                                "name": "MarkupSafe",
                                "version": "2.1.1"
                            }
                        },
                        "found": {
                            "vulnerabilityID": "CVE-2020-99999",
                            "versionConstraint": "< 2.2.0 (unknown)",
                            "purl": "pkg:python/MarkupSafe@2.1.1"
                        }
                    }
                ],
                "artifact": { }
            }
        ]
    }"""))
    assert len(grype_parser.packagesCtrl.packages) == 2
    assert len(grype_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(grype_parser.assessmentsCtrl.assessments) == 0
    assert "cairo@1.16.0" in grype_parser.packagesCtrl.packages
    cairo = grype_parser.packagesCtrl.packages.get("cairo@1.16.0")
    assert "cpe:2.3:a:cairographics:cairo:*:*:*:*:*:*:*:*" in cairo


def test_parse_vulnerability_json(grype_parser):
    grype_parser.load_from_dict(json.loads("""{
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2020-35492",
                    "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2020-35492",
                    "namespace": "nvd:cpe",
                    "severity": "High",
                    "urls": [
                        "https://bugzilla.redhat.com/show_bug.cgi?id=1898396",
                        "https://security.gentoo.org/glsa/202305-21"
                    ],
                    "description": "A flaw was found in cairo's image-compositor.c \
in all versions prior to 1.17.4. This flaw allows an attacker who can provide a crafted \
input file to cairo's image-compositor (for example, by convincing a user to open a file \
in an application using cairo, or if an application uses cairo on untrusted input) to \
cause a stack buffer overflow -> out-of-bounds WRITE. The highest impact from this vulnerability \
is to confidentiality, integrity, as well as system availability.",
                    "cvss": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "version": "2.0",
                            "vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                            "metrics": {
                                "baseScore": 6.8,
                                "exploitabilityScore": 8.6,
                                "impactScore": 6.4
                            },
                            "vendorMetadata": {}
                        },
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "version": "3.1",
                            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                            "metrics": {
                                "baseScore": 7.8,
                                "exploitabilityScore": 1.8,
                                "impactScore": 5.9
                            },
                            "vendorMetadata": {}
                        }
                    ],
                    "fix": {
                    "versions": [],
                    "state": "unknown"
                    },
                    "advisories": []
                },
                "relatedVulnerabilities": [],
                "matchDetails": [],
                "artifact": {
                    "id": "0be740738cf18168",
                    "name": "cairo",
                    "version": "1.16.0",
                    "type": "UnknownPackage",
                    "locations": [],
                    "language": "",
                    "licenses": [],
                    "cpes": [
                        "cpe:2.3:a:*:cairo:1.16.0:*:*:*:*:*:*:*"
                    ],
                    "purl": "pkg:generic/cairo@1.16.0",
                    "upstreams": []
                }
            }
        ]
    }"""))
    assert len(grype_parser.packagesCtrl.packages) == 1
    assert len(grype_parser.vulnerabilitiesCtrl.vulnerabilities) == 1
    assert len(grype_parser.assessmentsCtrl.assessments) == 1
    assert "cairo@1.16.0" in grype_parser.packagesCtrl.packages
    assert "CVE-2020-35492" in grype_parser.vulnerabilitiesCtrl.vulnerabilities
    cve = grype_parser.vulnerabilitiesCtrl.get("CVE-2020-35492")
    assert cve.severity_label == "high"
    assert len(cve.urls) == 2
    assert len(cve.severity_cvss) == 2
    assessment = grype_parser.assessmentsCtrl.gets_by_vuln("CVE-2020-35492")[0]
    assert assessment.is_compatible_status("under_investigation")

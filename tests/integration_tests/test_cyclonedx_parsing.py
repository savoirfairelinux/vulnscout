# -*- coding: utf-8 -*-
import pytest
from src.views.cyclonedx import CycloneDx
from src.models.assessment import VulnAssessment
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController
import json


@pytest.fixture
def cdx_parser():
    controllers = {}
    controllers["packages"] = PackagesController()
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    controllers["assessments"] = AssessmentsController(controllers["packages"], controllers["vulnerabilities"])
    return CycloneDx(controllers)


def test_parse_empty_json(cdx_parser):
    cdx_parser.load_from_dict(json.loads("""{
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:88fabcfa-7529-4ba2-8256-29bec0c03900",
        "version": 1,
        "components": [],
        "dependencies": []
    }"""))
    cdx_parser.parse_and_merge()

    assert len(cdx_parser.packagesCtrl.packages) == 0
    assert len(cdx_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(cdx_parser.assessmentsCtrl.assessments) == 0


def test_parse_invalid_model_json(cdx_parser):
    cdx_parser.load_from_dict(json.loads("""{
        "foo": [],
        "bar": "hello world"
    }"""))
    cdx_parser.parse_and_merge()
    assert len(cdx_parser.packagesCtrl.packages) == 0
    assert len(cdx_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(cdx_parser.assessmentsCtrl.assessments) == 0


def test_parse_components_json(cdx_parser):
    cdx_parser.load_from_dict(json.loads("""{
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:88fabcfa-7529-4ba2-8256-29bec0c03900",
        "version": 1,
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:generic/gnu/binutils@2.38",
                "group": "gnu",
                "name": "binutils",
                "version": "2.38",
                "cpe": "cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*",
                "purl": "pkg:generic/gnu/binutils@2.38"
            },
            {
                "type": "library",
                "group": "cairographics",
                "name": "cairo",
                "version": "1.16.0",
                "description": "Cairo is a 2D graphics library with support for multiple output devices.",
                "cpe": "cpe:2.3:a:cairographics:cairo:1.16.0:*:*:*:*:*:*:*",
                "purl": "pkg:generic/cairographics/cairo@1.16.0"
            }
        ]
    }"""))
    cdx_parser.parse_and_merge()
    assert len(cdx_parser.packagesCtrl) == 2
    assert len(cdx_parser.vulnerabilitiesCtrl) == 0
    assert len(cdx_parser.assessmentsCtrl) == 0
    assert "binutils@2.38" in cdx_parser.packagesCtrl
    assert "cairo@1.16.0" in cdx_parser.packagesCtrl
    binutils = cdx_parser.packagesCtrl.get("binutils@2.38")
    assert "cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*" in binutils
    print(binutils.purl)
    assert "pkg:generic/gnu/binutils@2.38" in binutils


def test_parse_vulnerabilities_json(cdx_parser):
    cdx_parser.load_from_dict(json.loads("""{
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:88fabcfa-7529-4ba2-8256-29bec0c03900",
        "version": 1,
        "components": [
            {
                "type": "library",
                "group": "cairographics",
                "name": "cairo",
                "version": "1.16.0",
                "description": "Cairo is a 2D graphics library with support for multiple output devices.",
                "cpe": "cpe:2.3:a:cairographics:cairo:1.16.0:*:*:*:*:*:*:*",
                "purl": "pkg:generic/cairographics/cairo@1.16.0",
                "bom-ref": "pkg:generic/cairographics/cairo@1.16.0"
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2020-35492",
                "bom-ref": "CVE-2020-35492",
                "source": {
                    "name": "NVD",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-35492"
                },
                "references": [
                    {
                        "id": "CVE-2018-99999",
                        "source": {
                            "name": "NVD",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-99999"
                        }
                    }
                ],
                "advisories": [
                    {
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1898396"
                    }
                ],
                "ratings": [
                    {
                        "method": "CVSSv31",
                        "source": {
                            "name": "NVD",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-35492"
                        },
                        "score": 7.8,
                        "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                        "severity": "high"
                    },
                    {
                        "method": "other",
                        "score": 9.5,
                        "severity": "critical"
                    }
                ],
                "cwes": [ 787, 121 ],
                "description": "A flaw was found in cairo's image-compositor.c",
                "detail": "Function image_compositor_create make buffer overflow",
                "recommendation": "Update to version >= 1.17.4",
                "workaround": "Disable red color in images",
                "created": "2020-12-17T00:00:00Z",
                "published": "2021-03-18T18:59:41Z",
                "updated": "2021-03-18T18:59:41Z",
                "analysis": {
                    "state": "exploitable",
                    "justification": "protected_by_mitigating_control",
                    "response": [ "update" ]
                },
                "affects": [
                    {
                        "ref": "pkg:generic/cairographics/cairo@1.16.0",
                        "versions": [
                            {
                                "range": "vers:generic/>=0.0.0|<1.17.4"
                            },
                            {
                                "range": "vers:generic/>=1.17.4",
                                "status": "unaffected"
                            }
                        ]
                    }
                ]
            }
        ]
    }"""))
    # + analysis: "lastUpdated": "2021-03-18T18:59:41Z"
    cdx_parser.parse_and_merge()
    assert len(cdx_parser.packagesCtrl) == 1
    assert len(cdx_parser.vulnerabilitiesCtrl) == 1
    assert len(cdx_parser.assessmentsCtrl) == 1
    assert "cairo@1.16.0" in cdx_parser.packagesCtrl

    cve = cdx_parser.vulnerabilitiesCtrl.get("CVE-2020-35492")
    assert cve.datasource == "https://nvd.nist.gov/vuln/detail/CVE-2020-35492"
    assert cve.texts["description"] == "A flaw was found in cairo's image-compositor.c"
    assert cve.texts["detail"] == "Function image_compositor_create make buffer overflow"
    assert "https://bugzilla.redhat.com/show_bug.cgi?id=1898396" in cve.urls
    assert len(cve.severity["cvss"]) == 1
    assert cve.severity["cvss"][0].base_score == 7.8
    assert cve.severity["cvss"][0].vector_string == "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
    assert cve.severity["severity"] == "critical"
    assert cve.severity["max_score"] == 9.5

    assess = cdx_parser.assessmentsCtrl.gets_by_vuln("CVE-2020-35492")[0]
    assert assess.is_compatible_status("exploitable")
    assert assess.is_compatible_justification("inline_mitigations_already_exist")
    assert assess.workaround == "Disable red color in images"
    assert "workaround_available" in assess.responses
    assert "update" in assess.responses

    assert "cairo@1.16.0" in cve


def test_parsing_assessment_already_present(cdx_parser):
    assess = VulnAssessment("CVE-2020-35492", ["cairo@1.16.0"])
    assess.set_status("affected")
    assess.set_status_notes("1st status notes")
    assess.set_status_notes("2nd status notes", True)
    assess.set_not_affected_reason("Some impact stmt")
    cdx_parser.assessmentsCtrl.add(assess)

    cdx_parser.load_from_dict(json.loads("""{
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:88fabcfa-7529-4ba2-8256-29bec0c03900",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "cairo",
                "version": "1.16.0",
                "bom-ref": "pkg:generic/cairo@1.16.0"
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2020-35492",
                "bom-ref": "CVE-2020-35492",
                "detail": "Function image_compositor_create make buffer overflow",
                "workaround": "Disable red color in images",
                "updated": "2021-03-18T18:59:41Z",
                "analysis": {
                    "state": "exploitable",
                    "detail": "1st status notes\\nSome impact stmt\\n2nd status notes\\nAdded status notes",
                    "response": [ "update" ]
                },
                "affects": [
                    { "ref": "pkg:generic/cairo@1.16.0" }
                ]
            }
        ]
    }"""))
    cdx_parser.parse_and_merge()
    assert len(cdx_parser.packagesCtrl) == 1
    assert len(cdx_parser.vulnerabilitiesCtrl) == 1
    assert len(cdx_parser.assessmentsCtrl) == 1
    assert "cairo@1.16.0" in cdx_parser.packagesCtrl
    assert "CVE-2020-35492" in cdx_parser.vulnerabilitiesCtrl

    assess_final = cdx_parser.assessmentsCtrl.gets_by_vuln("CVE-2020-35492")[0]
    assert assess_final.is_compatible_status("exploitable")
    assert assess_final.status_notes == "1st status notes\n2nd status notes\nAdded status notes"
    assert assess_final.impact_statement == "Some impact stmt"
    assert assess_final.workaround == "Disable red color in images"
    assert "workaround_available" in assess_final.responses
    assert "update" in assess_final.responses

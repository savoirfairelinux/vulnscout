# -*- coding: utf-8 -*-
import pytest
from src.views.openvex import OpenVex
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from src.models.assessment import VulnAssessment
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController
import json


@pytest.fixture
def openvex_parser():
    controllers = {}
    controllers["packages"] = PackagesController()
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    controllers["assessments"] = AssessmentsController(controllers["packages"], controllers["vulnerabilities"])
    return OpenVex(controllers)


@pytest.fixture
def pkg_ABC():
    return Package("abc", "1.2.3", ["cpe:2.3:a:abc:abc:1.2.3:*:*:*:*:*:*:*"], ["pkg:generic/abc@1.2.3"])


@pytest.fixture
def vuln_123():
    vuln = Vulnerability("CVE-1234-000", ["scanner"], "https://nvd.nist.gov/vuln/detail/CVE-1234-000", "unknown")
    vuln.add_package("abc@1.2.3")
    vuln.add_text("A flaw was found in abc's image-compositor.c (...)", "description")
    vuln.add_alias("CVE-1234-999")
    return vuln


@pytest.fixture
def assesment_123(pkg_ABC, vuln_123):
    assess = VulnAssessment(vuln_123.id, [pkg_ABC])
    assess.set_status("in_triage")
    return assess


def test_parse_empty_json(openvex_parser):
    openvex_parser.load_from_dict(json.loads("""{
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
        "author": "Savoir-Faire Linux",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": 1,
        "statements": []
    }"""))
    assert len(openvex_parser.packagesCtrl.packages) == 0
    assert len(openvex_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(openvex_parser.assessmentsCtrl.assessments) == 0


def test_parse_invalid_model_json(openvex_parser):
    openvex_parser.load_from_dict(json.loads("""{
        "foo": [],
        "bar": { },
        "statements": [{}]
    }"""))
    assert len(openvex_parser.packagesCtrl.packages) == 0
    assert len(openvex_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(openvex_parser.assessmentsCtrl.assessments) == 0


def test_parse_statements(openvex_parser):
    openvex_parser.load_from_dict(json.loads("""{
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
        "author": "Savoir-Faire Linux",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": 1,
        "statements": [
            {
                "vulnerability": {
                    "name": "CVE-2020-35492"
                },
                "products": [
                    {
                        "@id": "pkg:generic/cairo@1.16.0",
                        "identifiers": {
                            "cpe23": "cpe:2.3:a:cairographics:cairo:1.16.0:*:*:*:*:*:*:*",
                            "purl": "pkg:generic/cairo@1.16.0"
                        }
                    }
                ],
                "status": "affected"
            },
            {
                "vulnerability": {
                    "@id": "https://nvd.nist.gov/vuln/detail/CVE-2020-35492",
                    "name": "CVE-2020-35492",
                    "description": "A flaw was found in cairo's image-compositor.c (...)",
                    "aliases": ["CVE-1234-00000"]
                },
                "products": [
                    {
                        "@id": "pkg:generic/binutils@2.38",
                        "identifiers": {
                            "purl": "pkg:generic/binutils@2.38"
                        }
                    }
                ],
                "status": "affected"
            },
            {
                "vulnerability": {
                    "name": "CVE-2020-35492"
                },
                "products": [
                    {
                        "@id": "abc@1.2.3"
                    }
                ],
                "status": "affected"
            }
        ]
    }"""))
    assert len(openvex_parser.packagesCtrl.packages) == 3
    assert "cairo@1.16.0" in openvex_parser.packagesCtrl
    assert "binutils@2.38" in openvex_parser.packagesCtrl
    assert "abc@1.2.3" in openvex_parser.packagesCtrl

    assert len(openvex_parser.vulnerabilitiesCtrl.vulnerabilities) == 1
    vuln = openvex_parser.vulnerabilitiesCtrl.get("CVE-2020-35492")
    assert vuln is not None
    assert vuln.texts["description"] == "A flaw was found in cairo's image-compositor.c (...)"
    assert len(vuln.aliases) == 1

    assert len(openvex_parser.assessmentsCtrl.assessments) == 3


def test_parse_statement_details(openvex_parser):
    openvex_parser.load_from_dict(json.loads("""{
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
        "author": "Savoir-Faire Linux",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": 1,
        "statements": [
            {
                "vulnerability": {
                    "@id": "https://nvd.nist.gov/vuln/detail/CVE-2020-35492",
                    "name": "CVE-2020-35492",
                    "description": "A flaw was found in cairo's image-compositor.c (...)",
                    "aliases": ["CVE-1234-00000"]
                },
                "products": [
                    { "@id": "binutils@2.38" }
                ],
                "status": "not_affected",
                "justification": "inline_mitigations_already_exist",
                "impact_statement": "Color red was removed from image before being sent to cairo",
                "action_statement": "Use product version 7.10+",
                "action_statement_timestamp": "2023-01-08T18:02:03.647787998-06:00",
                "status_notes": "This vulnerability was mitigated by the use of a color filter in image-pipeline.c",
                "timestamp": "2023-01-06T15:05:42.647787998Z",
                "last_updated": "2023-01-08T18:02:03.647787998Z",

                "scanners": ["some_scanner"]
            }
        ]
    }"""))
    assert len(openvex_parser.packagesCtrl.packages) == 1
    assert len(openvex_parser.vulnerabilitiesCtrl.vulnerabilities) == 1
    vuln = openvex_parser.vulnerabilitiesCtrl.get("CVE-2020-35492")
    assert vuln.found_by == ["openvex", "some_scanner"]

    assert len(openvex_parser.assessmentsCtrl.assessments) == 1
    assess = openvex_parser.assessmentsCtrl.gets_by_vuln("CVE-2020-35492")[0]
    assert assess.status == "not_affected"
    assert assess.justification == "inline_mitigations_already_exist"
    assert assess.impact_statement == "Color red was removed from image before being sent to cairo"
    assert assess.workaround == "Use product version 7.10+"
    assert assess.workaround_timestamp == "2023-01-08T18:02:03.647787998-06:00"
    assert assess.status_notes == "This vulnerability was mitigated by the use of a color filter in image-pipeline.c"
    assert assess.timestamp == "2023-01-06T15:05:42.647787998Z"
    assert assess.last_update == "2023-01-08T18:02:03.647787998Z"


def test_encode_empty(openvex_parser):
    output = openvex_parser.to_dict()
    assert {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "author": "Savoir-Faire Linux",
        "version": 1,
        "statements": []
    }.items() <= output.items()
    assert len(output["@id"]) >= 5
    assert len(output["timestamp"]) >= 5
    assert len(output["statements"]) == 0


def test_encode_with_data(openvex_parser, pkg_ABC, vuln_123, assesment_123):
    openvex_parser.packagesCtrl.add(pkg_ABC)
    openvex_parser.vulnerabilitiesCtrl.add(vuln_123)
    openvex_parser.assessmentsCtrl.add(assesment_123)
    output = openvex_parser.to_dict()
    assert len(output["statements"]) == 1
    statement = output["statements"][0]
    assert {
        "name": "CVE-1234-000",
        "description": "A flaw was found in abc's image-compositor.c (...)",
        "aliases": ["CVE-1234-999"],
        "@id": "https://nvd.nist.gov/vuln/detail/CVE-1234-000"
    }.items() <= statement["vulnerability"].items()
    assert len(statement["products"]) == 1
    assert {
        "@id": "abc@1.2.3",
        "identifiers": {
            "cpe23": "cpe:2.3:a:abc:abc:1.2.3:*:*:*:*:*:*:*",
            "purl": "pkg:generic/abc@1.2.3"
        }
    }.items() <= statement["products"][0].items()
    assert statement["status"] == "under_investigation"


def test_encode_detailled_assessment(openvex_parser, assesment_123):
    assesment_123.set_status("not_affected")
    assesment_123.set_status_notes("This vulnerability is mitigated by the use of a color filter in image-pipeline.c")
    assesment_123.set_justification("protected_at_runtime")
    assesment_123.set_not_affected_reason("Color red was removed from image before being sent to cairo")
    assesment_123.set_workaround("Use product version 7.10+", "2023-01-08T18:02:03.647787998-06:00")
    openvex_parser.assessmentsCtrl.add(assesment_123)
    output = openvex_parser.to_dict()
    assert len(output["statements"]) == 1
    statement = output["statements"][0]
    assert {
        "status": "not_affected",
        "status_notes": "This vulnerability is mitigated by the use of a color filter in image-pipeline.c",
        "justification": "inline_mitigations_already_exist",
        "impact_statement": "Color red was removed from image before being sent to cairo",
        "action_statement": "Use product version 7.10+",
        "action_statement_timestamp": "2023-01-08T18:02:03.647787998-06:00"
    }.items() <= statement.items()

# -*- coding: utf-8 -*-
import pytest
from src.views.time_estimates import TimeEstimates
from src.models.vulnerability import Vulnerability
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController
import json


@pytest.fixture
def time_estimates_parser():
    controllers = {}
    controllers["packages"] = PackagesController()
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    controllers["assessments"] = AssessmentsController(controllers["packages"], controllers["vulnerabilities"])
    return TimeEstimates(controllers)


@pytest.fixture
def vuln_123():
    vuln = Vulnerability("CVE-1234-000", ["scanner"], "https://nvd.nist.gov/vuln/detail/CVE-1234-000", "unknown")
    vuln.add_package("abc@1.2.3")
    vuln.add_text("A flaw was found in abc's image-compositor.c (...)", "description")
    vuln.add_alias("CVE-1234-999")
    vuln.set_effort('PT4H', 'P1DT2H', 'P2.5D')
    return vuln


def test_parse_empty_json(time_estimates_parser):
    time_estimates_parser.load_from_dict(json.loads("""{
        "author": "Savoir-faire Linux",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": 1,
        "tasks": { }
    }"""))
    assert len(time_estimates_parser.packagesCtrl.packages) == 0
    assert len(time_estimates_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(time_estimates_parser.assessmentsCtrl.assessments) == 0


def test_parse_invalid_model_json(time_estimates_parser):
    time_estimates_parser.load_from_dict(json.loads("""{
        "foo": [],
        "bar": { },
        "tasks": { }
    }"""))
    assert len(time_estimates_parser.packagesCtrl.packages) == 0
    assert len(time_estimates_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(time_estimates_parser.assessmentsCtrl.assessments) == 0


def test_parse_tasks_not_existing(time_estimates_parser):
    time_estimates_parser.load_from_dict(json.loads("""{
        "author": "Savoir-faire Linux",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": 1,
        "tasks": {
            "CVE-2020-35492": {
                "optimistic": "PT2H",
                "likely": "P1D",
                "pessimistic": "P2.5D"
            }
        }
    }"""))
    assert len(time_estimates_parser.packagesCtrl.packages) == 0
    assert len(time_estimates_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(time_estimates_parser.assessmentsCtrl.assessments) == 0


def test_parse_tasks(time_estimates_parser, vuln_123):
    time_estimates_parser.vulnerabilitiesCtrl.add(vuln_123)
    time_estimates_parser.load_from_dict(json.loads("""{
        "author": "Savoir-faire Linux",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": 1,
        "tasks": {
            "CVE-1234-000": {
                "optimistic": "P3D",
                "likely": "P5D",
                "pessimistic": "P1W3DT18H"
            }
        }
    }"""))
    assert len(time_estimates_parser.packagesCtrl.packages) == 0
    assert len(time_estimates_parser.assessmentsCtrl.assessments) == 0

    assert len(time_estimates_parser.vulnerabilitiesCtrl.vulnerabilities) == 1
    vuln = time_estimates_parser.vulnerabilitiesCtrl.get("CVE-1234-000")
    assert vuln.effort["optimistic"] == "P3D"
    assert vuln.effort["likely"] == "P1W"
    assert vuln.effort["pessimistic"] == "P2WT2H"


def test_encode_empty(time_estimates_parser):
    output = time_estimates_parser.to_dict()
    assert {
        "author": "Savoir-faire Linux",
        "version": 1,
        "tasks": {}
    }.items() <= output.items()
    assert len(output["timestamp"]) >= 5
    assert len(output["tasks"].items()) == 0


def test_encode_with_data(time_estimates_parser, vuln_123):
    time_estimates_parser.vulnerabilitiesCtrl.add(vuln_123)
    output = time_estimates_parser.to_dict()

    assert len(output["tasks"].items()) == 1
    assert "CVE-1234-000" in output["tasks"]
    task = output["tasks"]["CVE-1234-000"]

    assert {
        "optimistic": "PT4H",
        "likely": "P1DT2H",
        "pessimistic": "P2DT4H"
    }.items() <= task.items()

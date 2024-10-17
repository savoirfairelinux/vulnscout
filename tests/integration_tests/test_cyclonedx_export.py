# -*- coding: utf-8 -*-
import pytest
from src.views.cyclonedx import CycloneDx
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from src.models.cvss import CVSS
from src.models.assessment import VulnAssessment, VALID_STATUS_CDX_VEX, VALID_JUSTIFICATION_CDX_VEX
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController
from datetime import datetime
import json


@pytest.fixture
def cdx_exporter():
    controllers = {}
    controllers["packages"] = PackagesController()
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    controllers["assessments"] = AssessmentsController(controllers["packages"], controllers["vulnerabilities"])
    return CycloneDx(controllers)


def test_export_empty_json(cdx_exporter):
    output = json.loads(cdx_exporter.output_as_json(6, "MY_AUTHOR_NAME"))
    try:
        assert {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1
        }.items() <= output.items()
        assert output["serialNumber"].startswith("urn:uuid:")
        assert len(output["serialNumber"]) > 36
        assert output["metadata"]["manufacturer"]["name"] == "MY_AUTHOR_NAME"
        assert "components" not in output or len(output["components"]) == 0
        assert "vulnerabilities" not in output or len(output["vulnerabilities"]) == 0
    except Exception as e:
        print(json.dumps(output, indent=2))
        raise e


def test_cdx_export_severity():
    assert CycloneDx.str_to_severity("INFO") == "info"
    assert CycloneDx.str_to_severity("low") == "low"
    assert CycloneDx.str_to_severity("Medium") == "medium"
    assert CycloneDx.str_to_severity("HiGh") == "high"
    assert CycloneDx.str_to_severity("CritICAL") == "critical"
    assert CycloneDx.str_to_severity("84348") == "unknown"


def test_cdx_cvss_methods():
    assert CycloneDx.cvss_to_rating_method(CVSS("4", "", "", 0, 0, 0)) == "CVSSv4"
    assert CycloneDx.cvss_to_rating_method(CVSS("3.1", "", "", 0, 0, 0)) == "CVSSv31"
    assert CycloneDx.cvss_to_rating_method(CVSS("3", "", "", 0, 0, 0)) == "CVSSv3"
    assert CycloneDx.cvss_to_rating_method(CVSS("2", "", "", 0, 0, 0)) == "CVSSv2"
    assert CycloneDx.cvss_to_rating_method(CVSS("1", "", "", 0, 0, 0)) == "other"
    assert CycloneDx.cvss_to_rating_method(CVSS("dfgvb", "", "", 0, 0, 0)) == "other"


def test_cdx_export_vex_state():
    for state in VALID_STATUS_CDX_VEX:
        assert CycloneDx.str_to_vex_status(state).lower() == state
    assert CycloneDx.str_to_vex_status("897797") == "in_triage"


def test_cdx_export_vex_justification():
    for justification in VALID_JUSTIFICATION_CDX_VEX:
        assert CycloneDx.str_to_vex_justification(justification).lower() == justification
    assert CycloneDx.str_to_vex_justification("897797") is None


def test_export_components_json(cdx_exporter):
    pkg_1 = Package("binutils", "2.38", [], [])
    pkg_1.add_purl("pkg:generic/gnu/binutils@2.38")
    pkg_1.add_cpe("cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*")
    cdx_exporter.packagesCtrl.add(pkg_1)
    pkg_2 = Package("cairo", "1.16.0", [], [])
    cdx_exporter.packagesCtrl.add(pkg_2)
    output = json.loads(cdx_exporter.output_as_json())

    try:
        assert {
            "type": "library",
            "bom-ref": "pkg:generic/gnu/binutils@2.38",
            "group": "gnu",
            "name": "binutils",
            "version": "2.38",
            "cpe": "cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*",
            "purl": "pkg:generic/gnu/binutils@2.38"
        }.items() <= output["components"][0].items()
        assert {
            "type": "library",
            "bom-ref": "pkg:generic/cairo@1.16.0",
            "name": "cairo",
            "version": "1.16.0",
            "cpe": "cpe:2.3:*:*:cairo:1.16.0:*:*:*:*:*:*:*",
            "purl": "pkg:generic/cairo@1.16.0"
        }.items() <= output["components"][1].items()

        assert len(output["components"]) == 2
        assert "vulnerabilities" not in output or len(output["vulnerabilities"]) == 0
    except Exception as e:
        print(json.dumps(output, indent=2))
        raise e


def test_export_vulnerabilities_json(cdx_exporter):
    pkg_1 = Package("cairo", "1.16.0", [], [])
    cdx_exporter.packagesCtrl.add(pkg_1)

    vuln_1 = Vulnerability("CVE-2020-35492", ["grype"], "https://nvd.nist.gov/vuln/detail/CVE-2020-35492", "NVD")
    vuln_1.add_package(pkg_1)
    vuln_1.add_alias("CVE-2018-99999")
    vuln_1.add_text("A flaw was found in cairo's image-compositor.c", "description")
    vuln_1.add_text("Function image_compositor_create make buffer overflow", "detail")
    vuln_1.add_url("https://bugzilla.redhat.com/show_bug.cgi?id=1898396")

    cvss_1 = CVSS("2.0", "AV:L/AC:L/Au:N/C:C/I:C/A:C", "redhat", 5.0, 0.0, 0.0)
    vuln_1.register_cvss(cvss_1)
    cvss_2 = CVSS("3.1", "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "NVD", 7.8, 0.0, 0.0)
    vuln_1.register_cvss(cvss_2)

    vuln_2 = Vulnerability("CVE-9999-1234", ["grype"], "https://nvd.nist.gov/vuln/detail/CVE-9999-1234", "NVD")
    cvss_3 = CVSS("3.0", "AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "fake", 2.0, 0.0, 0.0)
    vuln_2.register_cvss(cvss_3)
    vuln_2.severity_without_cvss("Critical", 9.7)

    cdx_exporter.vulnerabilitiesCtrl.add(vuln_1)
    cdx_exporter.vulnerabilitiesCtrl.add(vuln_2)
    output = json.loads(cdx_exporter.output_as_json())

    try:
        assert {
            "id": "CVE-2020-35492",
            "bom-ref": "CVE-2020-35492",
            "source": {
                "name": "NVD",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-35492"
            },
            "references": [
                {
                    "id": "CVE-2018-99999",
                    # "source": {
                    #     "name": "NVD",
                    #     "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-99999"
                    # }
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
                        # "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-35492"
                    },
                    "score": "7.8",
                    "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                    "severity": "high"
                },
                {
                    "method": "CVSSv2",
                    "source": {
                        "name": "redhat"
                    },
                    "score": "5.0",
                    "vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
                    "severity": "medium"
                }
            ],
            "description": "A flaw was found in cairo's image-compositor.c",
            "detail": "Function image_compositor_create make buffer overflow",
            "affects": [
                {
                    "ref": "pkg:generic/cairo@1.16.0"
                }
            ]
            # + analysis: "lastUpdated": "2021-03-18T18:59:41Z"
        }.items() <= output["vulnerabilities"][0].items()

        assert {
            "id": "CVE-9999-1234",
            "ratings": [
                {
                    "method": "other",
                    "score": "9.7",
                    "severity": "critical"
                },
                {
                    "method": "CVSSv3",
                    "source": {
                        "name": "fake",
                    },
                    "score": "2.0",
                    "vector": "AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                    "severity": "low"
                }
            ]
        }.items() <= output["vulnerabilities"][1].items()

        assert len(output["components"]) == 1
        assert len(output["vulnerabilities"]) == 2
    except Exception as e:
        print(json.dumps(output, indent=2))
        raise e


def test_export_assessments_json(cdx_exporter):
    pkg_1 = Package("cairo", "1.16.0", [], [])
    cdx_exporter.packagesCtrl.add(pkg_1)

    vuln_1 = Vulnerability("CVE-2020-35492", ["grype"], "https://nvd.nist.gov/vuln/detail/CVE-2020-35492", "NVD")
    vuln_1.add_package(pkg_1)
    cdx_exporter.vulnerabilitiesCtrl.add(vuln_1)

    assess_1 = VulnAssessment("CVE-2020-35492", ["cairo@1.16.0"])
    assess_1.set_status("under_investigation")
    assess_1.set_status_notes("Our team is analysing source code.")
    assess_1.set_not_affected_reason("Some impact stmt")
    assess_1.timestamp = datetime(2020, 1, 1, 0, 0, 0)

    assess_2 = VulnAssessment("CVE-2020-35492", ["cairo@1.16.0"])
    assess_2.set_status("not_affected")
    assess_2.set_justification("vulnerable_code_not_present")
    assess_2.add_response("update")
    assess_2.set_workaround("Disable X in config or upgrade to version Y")
    assess_2.timestamp = datetime(2022, 1, 1, 0, 0, 0)

    cdx_exporter.assessmentsCtrl.add(assess_1)
    output = json.loads(cdx_exporter.output_as_json())

    try:
        assert {
            "id": "CVE-2020-35492",
            "bom-ref": "CVE-2020-35492",
            "analysis": {
                "state": "in_triage",
                "detail": "Our team is analysing source code.\nSome impact stmt"
            }
        }.items() <= output["vulnerabilities"][0].items()

        cdx_exporter.assessmentsCtrl.add(assess_2)
        output = json.loads(cdx_exporter.output_as_json())

        assert {
            "id": "CVE-2020-35492",
            "bom-ref": "CVE-2020-35492",
            "analysis": {
                "detail": "",
                "state": "not_affected",
                "justification": "code_not_present",
                "response": ["update"],
            },
            "workaround": "Disable X in config or upgrade to version Y"
        }.items() <= output["vulnerabilities"][0].items()

        assert len(output["components"]) == 1
        assert len(output["vulnerabilities"]) == 1
    except Exception as e:
        print(json.dumps(output, indent=2))
        raise e

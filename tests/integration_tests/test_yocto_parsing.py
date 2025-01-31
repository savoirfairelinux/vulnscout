# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.views.yocto_vulns import YoctoVulns
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController
import json


@pytest.fixture
def yocto_parser():
    controllers = {}
    controllers["packages"] = PackagesController()
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    controllers["assessments"] = AssessmentsController(controllers["packages"], controllers["vulnerabilities"])
    return YoctoVulns(controllers)


def test_parse_empty_json(yocto_parser):
    yocto_parser.load_from_dict(json.loads("""{
        "version": "1",
        "package": []
    }"""))
    assert len(yocto_parser.packagesCtrl) == 0
    assert len(yocto_parser.vulnerabilitiesCtrl) == 0
    assert len(yocto_parser.assessmentsCtrl) == 0


def test_parse_invalid_model_json(yocto_parser):
    yocto_parser.load_from_dict(json.loads("""{
        "foo": [],
        "bar": { }
    }"""))
    assert len(yocto_parser.packagesCtrl) == 0
    assert len(yocto_parser.vulnerabilitiesCtrl) == 0
    assert len(yocto_parser.assessmentsCtrl) == 0


def test_parse_package_empty_json(yocto_parser):
    yocto_parser.load_from_dict(json.loads("""{
        "version": "1",
        "package": [
            {
                "name": "c-ares",
                "layer": "meta-oe",
                "version": "1.18.1",
                "products": [
                    {
                        "product": "c-ares",
                        "cvesInRecord": "No"
                    }
                ],
                "issue": []
            },
            {
                "foo": "bar"
            }
        ]
    }"""))
    assert len(yocto_parser.packagesCtrl) == 1
    assert len(yocto_parser.vulnerabilitiesCtrl) == 0
    assert len(yocto_parser.assessmentsCtrl) == 0
    assert "c-ares@1.18.1" in yocto_parser.packagesCtrl


def test_parse_package_vulnerabilities_json(yocto_parser):
    # Include two times the same package and include 3 vulnerabilities with one repeated two times
    # This is for testing deduplication work well
    yocto_parser.load_from_dict(json.loads("""{
        "version": "1",
        "package": [
            {
                "name": "c-ares",
                "layer": "meta-oe",
                "version": "1.18.1",
                "products": [
                    {
                        "product": "c-ares",
                        "cvesInRecord": "Yes"
                    }
                ],
                "issue": [
                    {
                        "id": "CVE-2007-3152",
                        "summary": "c-ares before 1.4.0 uses a predictable seed for the \
random number generator for the DNS Transaction ID field, which might allow remote attackers \
to spoof DNS responses by guessing the field value.",
                        "scorev2": "7.5",
                        "scorev3": "0.0",
                        "vector": "NETWORK",
                        "status": "Patched",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2007-3152"
                    },
                    {
                        "id": "CVE-2016-5180",
                        "summary": "Heap-based buffer overflow in the ares_create_query function \
in c-ares 1.x before 1.12.0 allows remote attackers to cause a denial of service \
(out-of-bounds write) or possibly execute arbitrary code via a hostname with an escaped trailing dot.",
                        "scorev2": "7.5",
                        "scorev3": "9.8",
                        "vector": "NETWORK",
                        "status": "Unpatched",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2016-5180"
                    }
                ]
            },
            {
                "name": "c-ares",
                "layer": "meta-oe",
                "version": "1.18.1",
                "products": [
                    {
                        "product": "c-ares",
                        "cvesInRecord": "Yes"
                    }
                ],
                "issue": [
                    {
                        "id": "CVE-2023-31124",
                        "summary": "c-ares is an asynchronous resolver library. When cross-compiling c-ares \
and using the autotools build system, CARES_RANDOM_FILE will not be set, as seen when cross compiling \
aarch64 android. This will downgrade to using rand() as a fallback which could allow an attacker to take \
advantage of the lack of entropy by not using a CSPRNG. This issue was patched in version 1.19.1.",
                        "scorev2": "0.0",
                        "scorev3": "3.7",
                        "vector": "LOCAL",
                        "status": "Ignored",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-31124"
                    },
                    {
                        "id": "CVE-2016-5180",
                        "summary": "Heap-based buffer overflow in the ares_create_query function \
in c-ares 1.x before 1.12.0 allows remote attackers to cause a denial of service \
(out-of-bounds write) or possibly execute arbitrary code via a hostname with an escaped trailing dot.",
                        "scorev2": "7.5",
                        "scorev3": "9.8",
                        "vector": "NETWORK",
                        "status": "Unpatched",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2016-5180"
                    }
                ]
            }
        ]
    }"""))
    assert len(yocto_parser.packagesCtrl) == 1
    assert len(yocto_parser.vulnerabilitiesCtrl) == 3
    assert len(yocto_parser.assessmentsCtrl) == 3
    assert "CVE-2007-3152" in yocto_parser.vulnerabilitiesCtrl
    assert "CVE-2016-5180" in yocto_parser.vulnerabilitiesCtrl
    assert "CVE-2023-31124" in yocto_parser.vulnerabilitiesCtrl

    cve_2007 = yocto_parser.vulnerabilitiesCtrl.get("CVE-2007-3152")
    cve_2016 = yocto_parser.vulnerabilitiesCtrl.get("CVE-2016-5180")
    cve_2023 = yocto_parser.vulnerabilitiesCtrl.get("CVE-2023-31124")
    assert len(cve_2007.severity_cvss) == 1
    assert cve_2007.severity_label == "high"
    assert len(cve_2016.severity_cvss) == 2
    assert cve_2016.severity_label == "critical"
    assert len(cve_2023.severity_cvss) == 1
    assert cve_2023.severity_label == "low"

    assessment_1 = yocto_parser.assessmentsCtrl.gets_by_vuln("CVE-2007-3152")[0]
    assessment_2 = yocto_parser.assessmentsCtrl.gets_by_vuln("CVE-2016-5180")[0]
    assessment_3 = yocto_parser.assessmentsCtrl.gets_by_vuln("CVE-2023-31124")[0]
    assert assessment_1.is_compatible_status("fixed")
    assert assessment_2.is_compatible_status("under_investigation")
    assert assessment_3.is_compatible_status("not_affected")

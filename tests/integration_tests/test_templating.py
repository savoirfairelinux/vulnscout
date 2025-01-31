# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.views.templates import Templates
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from src.models.assessment import VulnAssessment
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController
import os


@pytest.fixture
def templates_parser():
    controllers = {}
    controllers["packages"] = PackagesController()
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    controllers["assessments"] = AssessmentsController(controllers["packages"], controllers["vulnerabilities"])
    return Templates(controllers)


@pytest.fixture
def pkg_ABC():
    return Package("abc", "1.2.3", ["cpe:2.3:a:abc:abc:1.2.3:*:*:*:*:*:*:*"], ["pkg:generic/abc@1.2.3"])


@pytest.fixture
def vuln_123():
    vuln = Vulnerability("CVE-1234-000", ["scanner"], "https://nvd.nist.gov/vuln/detail/CVE-1234-000", "unknown")
    vuln.add_package("abc@1.2.3")
    vuln.add_text("A flaw was found in abc's image-compositor.c (...)", "description")
    vuln.add_alias("CVE-1234-999")
    vuln.set_epss(0.5, 0.97)
    vuln.severity_without_cvss("medium", 5.4, True)
    return vuln


@pytest.fixture
def assesment_123(pkg_ABC, vuln_123):
    assess = VulnAssessment(vuln_123.id, [pkg_ABC])
    assess.set_status("in_triage")
    return assess


def init_template():
    os.makedirs("templates", exist_ok=True)
    with open("templates/test_templates.pytest", "w+") as f:
        f.write("{{ (vulnerabilities | as_list | status_active | sort_by_epss | severity(\"medium\") | first).id }}")


def clean_template():
    try:
        os.remove("templates/test_templates.pytest")
        os.rmdir("templates")
    except:
        pass


def test_template_render(templates_parser, pkg_ABC, vuln_123, assesment_123):
    try:
        init_template()
        templates_parser.packagesCtrl.add(pkg_ABC)
        templates_parser.vulnerabilitiesCtrl.add(vuln_123)
        templates_parser.assessmentsCtrl.add(assesment_123)

        assert templates_parser.render("test_templates.pytest") == vuln_123.id
    except Exception as e:
        clean_template()
        raise e
    finally:
        clean_template()

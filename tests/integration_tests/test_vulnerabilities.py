# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.models.package import Package
from src.models.vulnerability import Vulnerability


@pytest.fixture
def pkg_ABC():
    pkg = Package("abc", "1.0.0")
    pkg.generate_generic_cpe()
    pkg.generate_generic_purl()
    return pkg


@pytest.fixture
def pkg_XYZ():
    pkg = Package("xyz", "2.3.4")
    pkg.generate_generic_cpe()
    pkg.generate_generic_purl()
    return pkg


@pytest.fixture
def pkg_controller(pkg_ABC, pkg_XYZ):
    controller = PackagesController()
    controller.add(pkg_ABC)
    controller.add(pkg_XYZ)
    return controller


@pytest.fixture
def vuln_123():
    vuln = Vulnerability("CVE-2022-1230", ["test"], "test", "test")
    vuln.add_url("https://cve.com/1230")
    vuln.add_text("CVE-123", "text1")
    vuln.add_package("test@1.0.0")
    vuln.add_advisory("advisory 1")
    return vuln


@pytest.fixture
def vuln_456(vuln_123, pkg_ABC):
    vuln = Vulnerability("CVE-2022-4560", ["test"], "test", "test")
    vuln.add_alias(vuln_123.id)
    vuln.add_related_vulnerability("CVE-000")
    vuln.add_url("https://cve.com/4560")
    vuln.add_text("CVE-456", "text2")
    vuln.add_package(pkg_ABC)
    vuln.add_advisory("advisory 2")
    return vuln


@pytest.fixture
def vuln_789(vuln_456, pkg_XYZ):
    vuln = Vulnerability("CVE-2022-1789", ["test"], "test", "test")
    vuln.add_alias(vuln_456.id)
    vuln.add_url("https://cve.com/1789")
    vuln.add_package(pkg_XYZ)
    return vuln


@pytest.fixture
def vuln_controller(pkg_controller, vuln_123):
    controller = VulnerabilitiesController(pkg_controller)
    controller.add(vuln_123)
    return controller


def test_vulnerability_not_present(vuln_controller, vuln_456):
    """
    GIVEN a VulnerabilitiesController instance
    WHEN no parameters are passed
    THEN check that the instance is created with empty attributes
    """
    assert vuln_controller.get(vuln_456.id) is None
    assert vuln_456.id not in vuln_controller
    assert vuln_456 not in vuln_controller
    assert vuln_controller.resolve_id(vuln_456.id)["is_alias"] is False
    assert vuln_controller.resolve_id(vuln_456.id)["id"] is None


def test_add_vulnerability(vuln_controller, vuln_123):
    """
    GIVEN a VulnerabilitiesController instance
    WHEN a vulnerability is added
    THEN check that the vulnerability is added correctly to the controller
    """
    assert len(vuln_controller) == 1
    assert vuln_controller.get(vuln_123.id) == vuln_123
    assert vuln_123.id in vuln_controller
    assert vuln_123 in vuln_controller
    found_vuln = 0
    for v in vuln_controller:
        if v == vuln_123:
            found_vuln = 1
    assert found_vuln == 1


def test_add_vulnerability_with_alias(vuln_controller, vuln_123, vuln_456):
    """
    GIVEN a VulnerabilitiesController instance
    WHEN a vulnerability is added with an alias
    THEN check that the vulnerability is added correctly to the controller
    """
    vuln_controller.add(vuln_456)
    assert len(vuln_controller) == 1
    assert vuln_controller.get(vuln_456.id) == vuln_123
    assert vuln_456.id in vuln_controller
    assert vuln_456 in vuln_controller
    assert vuln_controller.resolve_id(vuln_123.id)["is_alias"] is False
    assert vuln_controller.resolve_id(vuln_123.id)["id"] == vuln_123.id
    assert vuln_controller.resolve_id(vuln_456.id)["is_alias"] is True
    assert vuln_controller.resolve_id(vuln_456.id)["id"] == vuln_123.id


def test_removing_vulnerability(vuln_controller, vuln_123, vuln_456):
    """
    GIVEN a VulnerabilitiesController instance
    WHEN a vulnerability is added and removed
    THEN check that the vulnerability and their alias are removed correctly from the controller
    """
    vuln_controller.add(vuln_456)
    assert vuln_controller.remove(vuln_123.id) is True
    assert len(vuln_controller) == 0
    assert vuln_123.id not in vuln_controller
    assert vuln_456.id not in vuln_controller
    assert vuln_controller.remove(vuln_123.id) is False


def test_export_import_vulnerabilities(vuln_controller, pkg_controller, vuln_123):
    """
    GIVEN a VulnerabilitiesController instance with vulnerabilities
    WHEN the controller is exported and imported
    THEN check that the controller is correctly exported and imported
    """
    new_vulnCtrl = VulnerabilitiesController.from_dict(pkg_controller, vuln_controller.to_dict())
    assert len(new_vulnCtrl) == len(vuln_controller)
    assert vuln_123 in new_vulnCtrl


def test_add_vulnerability_already_present(vuln_controller, vuln_123, vuln_456, vuln_789):
    """
    GIVEN a VulnerabilitiesController instance with a vulnerability
    WHEN the vulnerability is added again
    THEN check that the vulnerability is merged with the existing one
    """
    vuln_controller.add(None)
    assert len(vuln_controller) == 1
    assert len(vuln_controller.alias_registered) == 0

    vuln_controller.add(vuln_123)
    assert len(vuln_controller) == 1
    assert len(vuln_controller.alias_registered) == 0

    vuln_controller.add(vuln_456)
    assert len(vuln_controller) == 1
    assert len(vuln_controller.alias_registered) == 1

    vuln_controller.add(vuln_789)
    assert len(vuln_controller) == 1
    assert len(vuln_controller.alias_registered) == 2

    vuln_controller.add(vuln_789)
    assert len(vuln_controller) == 1
    assert len(vuln_controller.alias_registered) == 2


def test_fetch_epss_scores(vuln_controller):
    for i in range(1000, 1085):
        # missing CVE in NVD and EPSS score
        if i == 1017 or i == 1060:
            continue
        vuln = Vulnerability(f"CVE-2022-{i}", ["test"], "test", "test")
        vuln_controller.add(vuln)

    assert len(vuln_controller) >= 80
    vuln_controller.fetch_epss_scores()
    for v in vuln_controller.vulnerabilities.values():
        if v.epss["score"] is None:
            print(v.id, "is missing EPSS score")
    have_scores = [v.epss["score"] is not None for v in vuln_controller.vulnerabilities.values()]
    assert len(have_scores) >= 80
    assert all(have_scores) is True

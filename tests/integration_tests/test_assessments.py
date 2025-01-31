# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from src.models.assessment import VulnAssessment
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController


@pytest.fixture
def pkg_ABC():
    return Package("abc", "1.0.0")


@pytest.fixture
def pkg_XYZ():
    return Package("xyz", "2.3.4")


@pytest.fixture
def pkg_controller(pkg_ABC, pkg_XYZ):
    controller = PackagesController()
    controller.add(pkg_ABC)
    controller.add(pkg_XYZ)
    return controller


@pytest.fixture
def vuln_123():
    return Vulnerability("CVE-123", ["test"], "test", "test")


@pytest.fixture
def vuln_456(vuln_123, pkg_ABC):
    vuln = Vulnerability("CVE-456", ["test"], "test", "test")
    vuln.add_alias(vuln_123.id)
    vuln.add_package(pkg_ABC)
    return vuln


@pytest.fixture
def vuln_controller(pkg_controller, vuln_123, vuln_456):
    controller = VulnerabilitiesController(pkg_controller)
    controller.add(vuln_123)
    controller.add(vuln_456)
    return controller


@pytest.fixture
def assessment_1(vuln_123, pkg_ABC):
    return VulnAssessment(vuln_123, [pkg_ABC])


@pytest.fixture
def assessment_2(vuln_123, pkg_XYZ):
    return VulnAssessment(vuln_123, [pkg_XYZ])


@pytest.fixture
def assessment_3(vuln_456, pkg_ABC):
    return VulnAssessment(vuln_456, [pkg_ABC])


@pytest.fixture
def assessment_controller(pkg_controller, vuln_controller, assessment_1, assessment_3):
    ctrl = AssessmentsController(pkg_controller, vuln_controller)
    ctrl.add(assessment_1)
    ctrl.add(assessment_3)
    return ctrl


def test_get_by_id(assessment_controller, assessment_1, assessment_2):
    assert assessment_controller.get_by_id(assessment_1.id) == assessment_1
    assert assessment_controller.get_by_id(assessment_2.id) is None
    assert assessment_1 in assessment_controller
    assert assessment_2.id not in assessment_controller
    assert None not in assessment_controller


def test_add_assessment(assessment_controller, assessment_2):
    assessment_controller.add(assessment_2)
    assert assessment_2 in assessment_controller
    assert len(assessment_controller) == 3
    assessment_controller.add(None)
    assert len(assessment_controller) == 3
    assessment_controller.add(assessment_2)
    assert len(assessment_controller) == 3


def test_remove_assessment(assessment_controller, assessment_1):
    assert assessment_1 in assessment_controller
    assert assessment_controller.remove(assessment_1.id) is True
    assert assessment_1 not in assessment_controller
    assert len(assessment_controller) == 1
    assert assessment_controller.remove(assessment_1.id) is False
    assert len(assessment_controller) == 1


def test_get_by_vuln(assessment_controller, vuln_123, vuln_456, assessment_2):
    assessment_controller.add(assessment_2)
    ssmt_123 = assessment_controller.gets_by_vuln(vuln_123)
    ssmt_456 = assessment_controller.gets_by_vuln(vuln_456.id)
    ssmt_none = assessment_controller.gets_by_vuln(None)
    assert len(ssmt_123) == 2
    assert len(ssmt_456) == 1
    assert len(ssmt_none) == 0
    assert assessment_2 in ssmt_123
    assert assessment_2 not in ssmt_456


def test_get_by_pkg(assessment_controller, pkg_ABC, pkg_XYZ, assessment_2):
    assessment_controller.add(assessment_2)
    ssmt_ABC = assessment_controller.gets_by_pkg(pkg_ABC)
    ssmt_XYZ = assessment_controller.gets_by_pkg(pkg_XYZ.id)
    ssmt_none = assessment_controller.gets_by_pkg(None)
    assert len(ssmt_ABC) == 2
    assert len(ssmt_XYZ) == 1
    assert len(ssmt_none) == 0
    assert assessment_2 not in ssmt_ABC
    assert assessment_2 in ssmt_XYZ


def test_get_by_vuln_pkg(assessment_controller, vuln_123, vuln_456, pkg_ABC, pkg_XYZ, assessment_2):
    assessment_controller.add(assessment_2)
    ssmt_123_ABC = assessment_controller.gets_by_vuln_pkg(vuln_123, pkg_ABC)
    ssmt_123_XYZ = assessment_controller.gets_by_vuln_pkg(vuln_123.id, pkg_XYZ)
    ssmt_456_XYZ = assessment_controller.gets_by_vuln_pkg(vuln_456.id, pkg_XYZ.id)
    assert len(ssmt_123_ABC) == 1
    assert len(ssmt_123_XYZ) == 1
    assert len(ssmt_456_XYZ) == 0
    assert assessment_2 not in ssmt_123_ABC
    assert assessment_2 in ssmt_123_XYZ
    assert assessment_2 not in ssmt_456_XYZ


def test_export_import_assessments(assessment_controller, pkg_controller, vuln_controller, assessment_1):
    data = assessment_controller.to_dict()
    new_controller = AssessmentsController.from_dict(pkg_controller, vuln_controller, data)
    assert len(new_controller) == len(assessment_controller)
    assert assessment_1 in assessment_controller
    assert assessment_1 in new_controller
    for assess in assessment_controller:
        assert assess in new_controller

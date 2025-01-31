# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.models.package import Package
from src.controllers.packages import PackagesController


@pytest.fixture
def empty_controller():
    return PackagesController()


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
def pkg_not_included():
    pkg = Package("not_included", "0.5.41")
    return pkg


@pytest.fixture
def controller_with_packages(pkg_ABC, pkg_XYZ):
    controller = PackagesController()
    controller.add(pkg_ABC)
    controller.add(pkg_XYZ)
    return controller


def test_adding_packages(controller_with_packages, pkg_ABC, pkg_not_included):
    """
    GIVEN a PackagesController
    WHEN adding packages
    THEN check the Packages are added without duplicate
    """
    controller_with_packages.add(pkg_ABC)
    assert len(controller_with_packages) == 2
    assert controller_with_packages.get(pkg_ABC.id) == pkg_ABC

    controller_with_packages.add(pkg_not_included)
    assert len(controller_with_packages) == 3
    assert pkg_not_included in controller_with_packages

    controller_with_packages.add(None)
    assert len(controller_with_packages) == 3


def test_removing_packages(controller_with_packages, pkg_XYZ, pkg_ABC):
    """
    GIVEN a PackagesController with two Packages
    WHEN removing one Package
    THEN check the Package is removed
    """
    assert len(controller_with_packages) == 2
    assert controller_with_packages.remove(pkg_XYZ.id) is True

    assert len(controller_with_packages) == 1
    assert pkg_XYZ not in controller_with_packages
    assert pkg_ABC.id in controller_with_packages

    assert controller_with_packages.remove(pkg_XYZ.id) is False


def test_export_import_package(controller_with_packages):
    """
    GIVEN a PackageController
    WHEN exporting to dict and importing back from this dict
    THEN check the Packages is the same
    """
    ctrl_bis = PackagesController.from_dict(controller_with_packages.to_dict())

    assert len(ctrl_bis) == len(controller_with_packages)
    for pkg_id in controller_with_packages:
        assert pkg_id in ctrl_bis


def test_invalid_inputs(empty_controller):
    """
    GIVEN a PackagesController
    WHEN calling function with invalid package or input doesn't throw an error
    THEN check the inputs are handled correctly
    """
    assert len(empty_controller) == 0
    assert empty_controller.get("abc@1.0.0") is None
    assert 42 not in empty_controller
    assert None not in empty_controller
    assert empty_controller.get(None) is None
    assert empty_controller.remove(None) is False
    assert empty_controller.remove("not_included@0.5.41") is False

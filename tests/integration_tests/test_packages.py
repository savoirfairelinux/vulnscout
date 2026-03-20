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
    assert controller_with_packages.get(pkg_ABC.string_id) == pkg_ABC

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
    assert controller_with_packages.remove(pkg_XYZ.string_id) is True

    assert len(controller_with_packages) == 1
    assert pkg_XYZ not in controller_with_packages
    assert pkg_ABC.string_id in controller_with_packages

    assert controller_with_packages.remove(pkg_XYZ.string_id) is False


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


# ---------------------------------------------------------------------------
# Tests for DB-fallback paths and extra methods
# ---------------------------------------------------------------------------

def test_get_db_id_and_resolve():
    """
    GIVEN a PackagesController with a persisted package
    WHEN get_db_id and get_or_resolve_db_id are called
    THEN they return the correct DB UUID
    """
    ctrl = PackagesController()
    pkg = Package("resolver-pkg", "0.1")
    ctrl.add(pkg)
    sid = "resolver-pkg@0.1"

    # get_db_id from cache
    db_id = ctrl.get_db_id(sid)
    assert db_id is not None

    # get_or_resolve_db_id from cache
    assert ctrl.get_or_resolve_db_id(sid) == db_id

    # get_or_resolve_db_id from DB (clear cache)
    ctrl._db_id_cache.clear()
    resolved = ctrl.get_or_resolve_db_id(sid)
    assert resolved == db_id

    # Unknown string_id returns None
    assert ctrl.get_or_resolve_db_id("nonexistent@0.0") is None


def test_controller_db_fallback_paths():
    """
    GIVEN a PackagesController with packages in DB but empty in-memory cache
    WHEN to_dict, __len__, __iter__, __contains__ are called
    THEN they fall back to the DB
    """
    # Populate DB via a separate controller
    c1 = PackagesController()
    c1.add(Package("dbfallback-pkg", "3.0"))

    # Create a fresh controller with empty caches
    c2 = PackagesController()
    c2._cache.clear()
    c2._db_id_cache.clear()

    # __len__ DB fallback
    assert len(c2) >= 1

    # __contains__ DB fallback (str not in cache)
    assert "dbfallback-pkg@3.0" in c2

    # __iter__ DB fallback
    pkg_ids = [p.string_id for p in c2]
    assert "dbfallback-pkg@3.0" in pkg_ids

    # to_dict DB fallback
    d = c2.to_dict()
    assert "dbfallback-pkg@3.0" in d


def test_from_dict_with_data():
    """
    GIVEN a data dict with package entries
    WHEN PackagesController.from_dict is called
    THEN all packages are created and accessible
    """
    data = {
        "alpha@1.0": {"name": "alpha", "version": "1.0", "cpe": [], "purl": [], "licences": ""},
        "beta@2.0": {"name": "beta", "version": "2.0", "cpe": ["cpe:x"], "purl": ["pkg:y"], "licences": "MIT"},
    }
    ctrl = PackagesController.from_dict(data)
    assert "alpha@1.0" in ctrl
    assert "beta@2.0" in ctrl


def test_package_exists():
    """
    GIVEN a package persisted to DB
    WHEN Package.exists is called
    THEN it returns True/False correctly
    """
    from src.models.package import Package as Pkg

    assert Pkg.exists("nonexistent-pkg", "0.0") is False

    ctrl = PackagesController()
    ctrl.add(Package("exists-check-pkg", "1.2.3"))
    assert Pkg.exists("exists-check-pkg", "1.2.3") is True


def test_package_get_by_string_id_no_at():
    """
    GIVEN a string_id without '@'
    WHEN Package.get_by_string_id is called
    THEN it returns None immediately
    """
    from src.models.package import Package as Pkg

    assert Pkg.get_by_string_id("invalidstringid") is None
    assert Pkg.get_by_string_id("noslash") is None


def test_package_bulk_find_or_create():
    """
    GIVEN a list of package dicts
    WHEN Package.bulk_find_or_create is called
    THEN packages are created/merged in bulk
    """
    from src.models.package import Package as Pkg

    # Empty list returns empty dict
    assert Pkg.bulk_find_or_create([]) == {}

    # Create two packages
    items = [
        {"name": "bulk-a", "version": "1.0"},
        {"name": "bulk-b", "version": "2.0", "cpe": ["cpe:x"], "purl": ["pkg:y"]},
    ]
    result = Pkg.bulk_find_or_create(items)
    assert "bulk-a@1.0" in result
    assert "bulk-b@2.0" in result

    # Second call merges CPE/PURL into existing records
    items2 = [{"name": "bulk-a", "version": "1.0", "cpe": ["cpe:extra"]}]
    result2 = Pkg.bulk_find_or_create(items2)
    assert "cpe:extra" in (result2["bulk-a@1.0"].cpe or [])


def test_preload_cache_with_finding():
    """
    GIVEN a PackagesController with a persisted package and a Finding in DB
    WHEN _preload_cache is called on a fresh controller
    THEN the finding cache is populated
    """
    from src.models.finding import Finding
    from src.models.vulnerability import Vulnerability as VulnModel

    # Persist package + vulnerability + finding
    c1 = PackagesController()
    pkg = Package("preload-pkg", "1.0")
    c1.add(pkg)
    vuln = VulnModel.create_record("CVE-PRELOAD-1")
    pkg_db_id = c1.get_db_id("preload-pkg@1.0")
    Finding.get_or_create(pkg_db_id, "CVE-PRELOAD-1")

    # Fresh controller with _preload_cache
    c2 = PackagesController()
    c2._preload_cache()
    assert "preload-pkg@1.0" in c2._cache
    assert len(c2._finding_cache) >= 1

# -*- coding: utf-8 -*-
import pytest
from src.models.package import Package


@pytest.fixture
def pkg_v1():
    return Package("test", "1.0.0")


@pytest.fixture
def pkg_v2():
    return Package("test", "2.0.0")


@pytest.fixture
def generic_pkg():
    pkg = Package("mypackage", "1.0.0")
    pkg.generate_generic_cpe()
    pkg.generate_generic_purl()
    return pkg


@pytest.fixture
def invalid_pkg():
    return Package("test", "v1.0.0-rc.5b+build.beta-4")


@pytest.fixture
def cairo_pkg():
    pkg = Package("cairo", "1.16.0")
    pkg.add_cpe("cpe:2.3:a:cairographics:cairo:1.16.0:*:*:*:*:*:*:*")
    pkg.add_purl("pkg:deb/debian/cairo@1.16.0")
    return pkg


def test_create_package(generic_pkg):
    """
    GIVEN a Package name and version
    WHEN the Package is created
    THEN check the Package id, cpe and purl is correct
    """
    assert generic_pkg.id == "mypackage@1.0.0"
    assert generic_pkg.cpe[0] == "cpe:2.3:*:*:mypackage:1.0.0:*:*:*:*:*:*:*"
    assert generic_pkg.purl[0] == "pkg:generic/mypackage@1.0.0"


def test_compare_same_package(pkg_v1):
    """
    GIVEN two Packages with the same name and version
    WHEN comparing the two Packages
    THEN check the comparison is correct
    """
    pkg_v1_bis = Package("test", "1.0.0")
    assert pkg_v1 == pkg_v1_bis
    assert pkg_v1 <= pkg_v1_bis
    assert pkg_v1 >= pkg_v1_bis
    assert not pkg_v1 < pkg_v1_bis
    assert not pkg_v1 > pkg_v1_bis
    assert not pkg_v1 != pkg_v1_bis
    assert str(pkg_v1) == str(pkg_v1_bis)
    assert hash(pkg_v1) == hash(pkg_v1_bis)


def test_compare_different_version(pkg_v1, pkg_v2):
    """
    GIVEN two Packages with the same name but different version
    WHEN comparing the two Packages
    THEN check the sort is made using the version of the package
    """
    assert pkg_v1 < pkg_v2
    assert pkg_v1 <= pkg_v2
    assert pkg_v1 != pkg_v2
    assert not pkg_v1 > pkg_v2
    assert not pkg_v1 >= pkg_v2
    assert not pkg_v1 == pkg_v2
    assert str(pkg_v1) != str(pkg_v2)
    assert hash(pkg_v1) != hash(pkg_v2)


def test_compare_different_package(pkg_v1, generic_pkg):
    """
    GIVEN two Packages with different names
    WHEN comparing the two Packages
    THEN check the sort is using the name of the package
    """
    assert pkg_v1 > generic_pkg
    assert pkg_v1 >= generic_pkg
    assert pkg_v1 != generic_pkg
    assert not pkg_v1 < generic_pkg
    assert not pkg_v1 <= generic_pkg
    assert not pkg_v1 == generic_pkg
    assert str(pkg_v1) != str(generic_pkg)
    assert hash(pkg_v1) != hash(generic_pkg)


def test_export_import_package(cairo_pkg):
    """
    GIVEN a Package
    WHEN exporting to dict and importing back from this dict
    THEN check the Package is the same
    """
    cairo_bis = Package.from_dict(cairo_pkg.to_dict())
    assert cairo_pkg == cairo_bis
    assert cairo_pkg.id == cairo_bis.id
    assert cairo_pkg.name == cairo_bis.name
    assert cairo_pkg.version == cairo_bis.version
    assert len(cairo_pkg.cpe) == len(cairo_bis.cpe)
    assert len(cairo_pkg.purl) == len(cairo_bis.purl)


def test_merge_different_packages(pkg_v1, pkg_v2, generic_pkg):
    """
    GIVEN two different Packages
    WHEN trying to merging the two Packages
    THEN check the merge is not possible
    """
    assert not pkg_v1.merge(pkg_v2)
    assert not pkg_v1.merge(generic_pkg)


def test_merge_same_package():
    """
    GIVEN two same Packages
    WHEN trying to merging the two Packages
    THEN check the merge is possible
    """
    pkg1 = Package("demo", "1.0.0", ["cpe:2.3:*:A-corp:demo:1.0.0:*:*:*:*:*:*:*"], ["pkg:A-corp/demo@1.0.0"])
    pkg2 = Package("demo", "1.0.0", ["cpe:2.3:*:B-corp:demo:1.0.0:*:*:*:*:*:*:*"], ["pkg:B-corp/demo@1.0.0"])
    assert pkg1.merge(pkg2)
    assert pkg1 == pkg2
    assert pkg1.id == pkg2.id
    assert len(pkg1.cpe) == 2
    assert len(pkg1.purl) == 2


def test_version_not_semver(invalid_pkg, pkg_v1):
    """
    GIVEN a Package with a version not following the semver format
    WHEN comparing with other package
    THEN check the version is correctly working even without semver
    """
    assert invalid_pkg > pkg_v1
    assert invalid_pkg >= pkg_v1
    assert invalid_pkg != pkg_v1
    assert not invalid_pkg < pkg_v1
    assert not invalid_pkg <= pkg_v1
    assert not invalid_pkg == pkg_v1
    assert str(invalid_pkg) != str(pkg_v1)
    assert hash(invalid_pkg) != hash(pkg_v1)


def test_contains(cairo_pkg, generic_pkg):
    """
    GIVEN a Package
    WHEN using __contains__ with another package, id, cpe or purl
    THEN check the function is working correctly
    """
    assert "cairo@1.16.0" in cairo_pkg
    assert Package("cairo", "1.16.0") in cairo_pkg
    assert "cpe:2.3:a:cairographics:cairo:1.16.0:*:*:*:*:*:*:*" in cairo_pkg
    assert "pkg:deb/debian/cairo@1.16.0" in cairo_pkg

    assert generic_pkg.id not in cairo_pkg
    assert generic_pkg not in cairo_pkg
    assert generic_pkg.cpe[0] not in cairo_pkg
    assert generic_pkg.purl[0] not in cairo_pkg
    assert 5 not in cairo_pkg
    assert {"foo": "bar"} not in cairo_pkg


def test_package_with_vendor():
    """
    GIVEN a Package with a vendor:name format
    WHEN creating the Package
    THEN check the vendor is correctly added to the CPE and PURL
    """
    pkg = Package("vendor:name", "1.0.0")
    assert len(pkg.cpe) == 1
    assert pkg.cpe[0] == "cpe:2.3:a:vendor:name:1.0.0:*:*:*:*:*:*:*"
    assert len(pkg.purl) == 1
    assert pkg.purl[0] == "pkg:generic/vendor/name@1.0.0"

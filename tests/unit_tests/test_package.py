# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from packageurl import PackageURL
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
    assert generic_pkg.string_id == "mypackage@1.0.0"
    assert generic_pkg.cpe[0] == "cpe:2.3:a:*:mypackage:1.0.0:*:*:*:*:*:*:*"
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
    assert cairo_pkg.string_id == cairo_bis.string_id
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
    assert pkg1.string_id == pkg2.string_id
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

    assert generic_pkg.string_id not in cairo_pkg
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


def test_add_empty_cpe_and_purl():
    """
    GIVEN a Package
    WHEN calling add_cpe('') and add_purl('') with empty strings
    THEN check the operations are no-ops (empty-string early return)
    """
    pkg = Package("foo", "1.0.0")
    initial_cpe = list(pkg.cpe or [])
    initial_purl = list(pkg.purl or [])
    pkg.add_cpe("")
    pkg.add_purl("")
    assert list(pkg.cpe or []) == initial_cpe
    assert list(pkg.purl or []) == initial_purl


def test_lt_fallback_same_name_invalid_versions():
    """
    GIVEN two Packages with the same name but non-semver versions
    WHEN comparing them with __lt__ (and __gt__)
    THEN check the fallback string comparison is used
    """
    a = Package("same-name", "invalid_version_a")
    b = Package("same-name", "invalid_version_b")
    # string comparison: "invalid_version_a" < "invalid_version_b"
    assert a < b
    assert not b < a
    assert b > a
    assert not a > b


# --- Supplier tests ---

def test_supplier_in_string_id():
    pkg = Package("foo", "1.0", supplier="Organization: Acme Corp (x@a.com)")
    assert pkg.string_id == "foo@1.0::Organization: Acme Corp (x@a.com)"


def test_no_supplier_string_id():
    pkg = Package("foo", "1.0")
    assert pkg.string_id == "foo@1.0"


def test_packages_same_name_version_different_supplier_not_equal():
    pkg_a = Package("foo", "1.0", supplier="Organization: Acme Corp")
    pkg_b = Package("foo", "1.0", supplier="Organization: Bar Inc")
    assert pkg_a != pkg_b
    assert hash(pkg_a) != hash(pkg_b)


def test_packages_same_name_version_same_supplier_equal():
    pkg_a = Package("foo", "1.0", supplier="Organization: Acme Corp")
    pkg_b = Package("foo", "1.0", supplier="Organization: Acme Corp")
    assert pkg_a == pkg_b
    assert hash(pkg_a) == hash(pkg_b)


def test_supplier_in_to_dict_from_dict():
    pkg = Package("foo", "1.0", supplier="Organization: Acme Corp")
    data = pkg.to_dict()
    assert data["supplier"] == "Organization: Acme Corp"
    restored = Package.from_dict(data)
    assert restored.supplier == "Organization: Acme Corp"
    assert restored.string_id == "foo@1.0::Organization: Acme Corp"


def test_to_dict_exposes_id_and_package_id():
    """
    GIVEN a Package with an explicit database UUID
    WHEN serialising with to_dict
    THEN check it exposes both the human-readable id (string_id) and the
         database UUID as package_id
    """
    import uuid
    pkg_uuid = uuid.UUID("12345678-1234-5678-1234-567812345678")
    pkg = Package("foo", "1.0", supplier="Organization: Acme Corp")
    pkg.id = pkg_uuid
    data = pkg.to_dict()
    assert data["id"] == pkg.string_id
    assert data["id"] == "foo@1.0::Organization: Acme Corp"
    assert data["package_id"] == str(pkg_uuid)


def test_to_dict_package_id_distinguishes_same_string_id():
    """
    GIVEN two packages sharing the same name@version but with different UUIDs
    WHEN serialising with to_dict
    THEN check package_id differs so enrichment cannot conflate them
    """
    import uuid
    pkg_a = Package("foo", "1.0")
    pkg_a.id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    pkg_b = Package("foo", "1.0")
    pkg_b.id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    data_a = pkg_a.to_dict()
    data_b = pkg_b.to_dict()
    assert data_a["id"] == data_b["id"]
    assert data_a["package_id"] != data_b["package_id"]


def test_to_dict_package_id_is_none_when_unpersisted():
    """
    GIVEN a Package that has not been persisted (no database id yet)
    WHEN serialising with to_dict
    THEN check package_id is None rather than the literal string "None"
    """
    pkg = Package("foo", "1.0")
    assert pkg.id is None
    data = pkg.to_dict()
    assert data["package_id"] is None


def test_sort_packages_mixed_suppliers():
    pkg_acme = Package("foo", "1.0", supplier="Organization: Acme Corp")
    pkg_bar  = Package("foo", "1.0", supplier="Organization: Bar Inc")
    pkg_none = Package("foo", "1.0")
    result = sorted([pkg_bar, pkg_none, pkg_acme])
    # No-supplier (empty string) sorts before any named supplier
    assert result[0].supplier == ""
    # Remaining two are deterministic (alphabetical)
    assert result[1].supplier < result[2].supplier


def test_purl_epoch_qualifier_normalized_to_version_prefix():
    pkg = Package("procps", "2:3.3.12-3ubuntu1.2")
    pkg.add_purl("pkg:deb/ubuntu/procps@3.3.12-3ubuntu1.2?arch=arm64&distro=ubuntu-18.04&epoch=2")
    assert "pkg:deb/ubuntu/procps@2:3.3.12-3ubuntu1.2?arch=arm64&distro=ubuntu-18.04" in pkg.purl


def test_purl_url_encoded_epoch_normalized():
    pkg = Package("procps", "2:3.3.12-3ubuntu1.2")
    pkg.add_purl("pkg:deb/ubuntu/procps@2%3A3.3.12-3ubuntu1.2?arch=arm64&distro=ubuntu-18.04")
    assert "pkg:deb/ubuntu/procps@2:3.3.12-3ubuntu1.2?arch=arm64&distro=ubuntu-18.04" in pkg.purl


def test_purl_epoch_forms_deduplicate():
    pkg = Package("procps", "2:3.3.12-3ubuntu1.2")
    pkg.add_purl("pkg:deb/ubuntu/procps@2%3A3.3.12-3ubuntu1.2?arch=arm64&distro=ubuntu-18.04")
    pkg.add_purl("pkg:deb/ubuntu/procps@3.3.12-3ubuntu1.2?arch=arm64&distro=ubuntu-18.04&epoch=2")
    # Both normalize to the same canonical form — no duplicate
    assert len([p for p in pkg.purl if "procps" in p and "deb" in p]) == 1


def test_rpm_purl_epoch_qualifier_normalized_to_version_prefix():
    pkg = Package("bash", "1:5.1.8-6.el9")
    pkg.add_purl("pkg:rpm/fedora/bash@5.1.8-6.el9?arch=x86_64&epoch=1")
    assert "pkg:rpm/fedora/bash@1:5.1.8-6.el9?arch=x86_64" in pkg.purl


def test_rpm_purl_epoch_forms_deduplicate():
    pkg = Package("bash", "1:5.1.8-6.el9")
    pkg.add_purl("pkg:rpm/fedora/bash@5.1.8-6.el9?arch=x86_64&epoch=1")
    pkg.add_purl("pkg:rpm/fedora/bash@1:5.1.8-6.el9?arch=x86_64")
    # Both normalize to the same canonical form — no duplicate
    assert len([p for p in pkg.purl if "bash" in p and "rpm" in p]) == 1


def test_purl_normalization_non_deb_unchanged():
    pkg = Package("mypackage", "1.0.0")
    generic_purl = "pkg:generic/mypackage@1.0.0"
    pkg.add_purl(generic_purl)
    assert generic_purl in pkg.purl


def test_purl_malformed_stored_as_is():
    pkg = Package("mypackage", "1.0.0")
    malformed = "not-a-valid-purl-at-all"
    pkg.add_purl(malformed)
    assert malformed in pkg.purl


def test_purl_epoch_qualifier_without_version_not_corrupted():
    pkg = Package("procps", "")
    no_version_purl = "pkg:deb/ubuntu/procps?epoch=2"
    pkg.add_purl(no_version_purl)
    assert "None" not in pkg.purl[0]


def test_generic_purl_keeps_slash_inside_name():
    pkg = Package("Prosys OPC UA SDK Client/Server", "5.4.0-201")
    stored = pkg.generate_generic_purl()
    assert pkg.purl == [stored]
    assert stored == "pkg:generic/Prosys%20OPC%20UA%20SDK%20Client%2FServer@5.4.0-201"
    assert PackageURL.from_string(stored).name == "Prosys OPC UA SDK Client/Server"


def test_generic_purl_with_supplier_namespace():
    pkg = Package("foo", "1.0", supplier="Organization: Acme Corp (x@a.com)")
    assert pkg.generate_generic_purl() == "pkg:generic/acme-corp/foo@1.0"


def test_generic_purl_without_name_keeps_raw_format():
    pkg = Package("", "1.0")
    assert pkg.generate_generic_purl() == "pkg:generic/@1.0"
    assert pkg.purl == ["pkg:generic/@1.0"]


def test_declared_purl_with_encoded_slash_round_trips():
    pkg = Package("foo", "1.0")
    pkg.add_purl("pkg:generic/acme/foo%2Fbar@1.0?arch=x86_64#sub/dir")
    assert pkg.purl == ["pkg:generic/acme/foo%2Fbar@1.0?arch=x86_64#sub/dir"]


def test_fallback_identifiers_added_without_declared_identifiers():
    pkg = Package("mypackage", "1.0.0")
    pkg.add_fallback_identifiers()
    assert pkg.cpe == ["cpe:2.3:a:*:mypackage:1.0.0:*:*:*:*:*:*:*"]
    assert pkg.purl == ["pkg:generic/mypackage@1.0.0"]


@pytest.mark.parametrize(("cpe", "purl"), [
    ([], ["pkg:maven/com.prosysopc.ua/prosys-opc-ua-sdk-client-server@5.4.0-201"]),
    (["cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*"], []),
])
def test_fallback_identifiers_skipped_with_declared_identifier(cpe, purl):
    pkg = Package("name", "1.0", cpe, purl)
    pkg.add_fallback_identifiers()
    assert pkg.cpe == cpe
    assert pkg.purl == purl


@pytest.mark.parametrize("supplier", [
    "OpenEmbedded ()",
    "openembedded",
    "OPENEMBEDDED",
    "Organization: OpenEmbedded (info@openembedded.org)",
    "OpenEmnedded ()",
    "openemnedded",
])
def test_constructor_strips_openembedded_supplier(supplier):
    """The OpenEmbedded supplier (and its OpenEmnedded typo) is dropped."""
    pkg = Package("busybox", "1.36.1", supplier=supplier)
    assert pkg.supplier == ""
    assert pkg.string_id == "busybox@1.36.1"


@pytest.mark.parametrize("supplier,expected", [
    ("Organization: Acme Corp", "Organization: Acme Corp"),
    ("  Acme Corp  ", "Acme Corp"),
    ("", ""),
    (None, ""),
])
def test_constructor_preserves_and_trims_other_suppliers(supplier, expected):
    """Non-OpenEmbedded suppliers are kept (trimmed of surrounding whitespace)."""
    pkg = Package("busybox", "1.36.1", supplier=supplier)
    assert pkg.supplier == expected


def test_normalize_supplier_helper_directly():
    from src.models.package import _normalize_supplier
    assert _normalize_supplier("OpenEmbedded ()") == ""
    assert _normalize_supplier("prefix OpenEmbedded suffix") == ""
    assert _normalize_supplier("OpenEmnedded ()") == ""
    assert _normalize_supplier(None) == ""
    assert _normalize_supplier("  Acme  ") == "Acme"

# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""DB-backed tests for Package supplier identity."""

import pytest
from src.bin.webapp import create_app
from src.extensions import db as _db
from src.models.package import Package
from src.models.project import Project
from src.models.variant import Variant
from src.models.scan import Scan


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("SCAN_FILE", "/dev/null")
    application = create_app()
    application.config.update({"TESTING": True})
    with application.app_context():
        _db.create_all()
        yield application
        _db.drop_all()


def test_find_or_create_different_supplier_creates_new_row(app):
    pkg_a = Package.find_or_create("foo", "1.0", supplier="Organization: Acme Corp")
    pkg_b = Package.find_or_create("foo", "1.0", supplier="Organization: Bar Inc")
    pkg_none = Package.find_or_create("foo", "1.0")
    _db.session.flush()
    assert pkg_a.id != pkg_b.id
    assert pkg_a.id != pkg_none.id
    assert pkg_b.id != pkg_none.id


def test_find_or_create_same_supplier_returns_same_row(app):
    pkg_a = Package.find_or_create("foo", "1.0", supplier="Organization: Acme Corp")
    _db.session.flush()
    pkg_b = Package.find_or_create("foo", "1.0", supplier="Organization: Acme Corp")
    assert pkg_a.id == pkg_b.id


def test_get_by_string_id_with_supplier(app):
    Package.find_or_create("foo", "1.0", supplier="Organization: Acme Corp (x@a.com)")
    _db.session.flush()
    found = Package.get_by_string_id("foo@1.0::Organization: Acme Corp (x@a.com)")
    assert found is not None
    assert found.supplier == "Organization: Acme Corp (x@a.com)"


def test_get_by_string_id_email_at_sign_doesnt_corrupt(app):
    """@ in supplier email must not corrupt name/version split."""
    Package.find_or_create("foo", "1.0", supplier="Organization: Acme Corp (contact@acme.com)")
    _db.session.flush()
    found = Package.get_by_string_id("foo@1.0::Organization: Acme Corp (contact@acme.com)")
    assert found is not None
    assert found.name == "foo"
    assert found.version == "1.0"


def test_get_by_string_id_backward_compat(app):
    """Old name@version string_ids (no ::) still resolve correctly."""
    Package.find_or_create("foo", "1.0")
    _db.session.flush()
    found = Package.get_by_string_id("foo@1.0")
    assert found is not None
    assert found.name == "foo"
    assert found.supplier == ""


def test_bulk_find_or_create_with_suppliers(app):
    items = [
        {"name": "foo", "version": "1.0", "supplier": "Organization: Acme Corp"},
        {"name": "foo", "version": "1.0", "supplier": "Organization: Bar Inc"},
        {"name": "bar", "version": "2.0"},
    ]
    result = Package.bulk_find_or_create(items)
    assert len(result) == 3
    acme_key = "foo@1.0::Organization: Acme Corp"
    bar_key = "foo@1.0::Organization: Bar Inc"
    plain_key = "bar@2.0"
    assert acme_key in result
    assert bar_key in result
    assert plain_key in result
    assert result[acme_key].id != result[bar_key].id


def test_controller_from_dict_roundtrip_preserves_supplier(app):
    from src.controllers.packages import PackagesController
    ctrl = PackagesController()
    ctrl.add(Package("foo", "1.0", supplier="Organization: Acme Corp"))
    serialised = ctrl.to_dict()
    ctrl2 = PackagesController.from_dict(serialised)
    key = "foo@1.0::Organization: Acme Corp"
    assert key in ctrl2.packages
    assert ctrl2.packages[key].supplier == "Organization: Acme Corp"


def test_controller_current_sbom_document_defaults_to_none(app):
    from src.controllers.packages import PackagesController
    ctrl = PackagesController()
    assert ctrl.current_sbom_document is None


def test_active_package_ids_for_scans_returns_empty_for_non_sbom_scan(app):
    from src.helpers.active_scans import active_package_ids_for_scans

    project = Project.create("active-scan-proj")
    variant = Variant.create("active-scan-variant", project.id)
    tool_scan = Scan.create("tool-only", variant.id, scan_type="tool", scan_source="osv")

    assert active_package_ids_for_scans([tool_scan.id]) == set()


def test_active_package_ids_for_scans_returns_empty_for_empty_input(app):
    from src.helpers.active_scans import active_package_ids_for_scans
    assert active_package_ids_for_scans([]) == set()


def test_active_package_ids_for_scans_restrict_filters_to_requested(app):
    """restrict_to_package_ids narrows the result to the requested package ids."""
    from src.helpers.active_scans import active_package_ids_for_scans
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("restrict-proj")
    variant = Variant.create("restrict-variant", project.id)
    sbom_scan = Scan.create("sbom", variant.id, scan_type="sbom")
    document = SBOMDocument.create("sbom.json", "test", sbom_scan.id)
    pkg_a = Package.create("pkg-a", "1.0.0")
    pkg_b = Package.create("pkg-b", "2.0.0")
    SBOMPackage.create(document.id, pkg_a.id)
    SBOMPackage.create(document.id, pkg_b.id)
    _db.session.flush()

    # Without restriction: both packages are active.
    assert active_package_ids_for_scans([sbom_scan.id]) == {pkg_a.id, pkg_b.id}

    # With restriction: only the requested (present) package is returned.
    assert active_package_ids_for_scans(
        [sbom_scan.id], restrict_to_package_ids={pkg_a.id}
    ) == {pkg_a.id}

    # A restriction listing a package absent from the SBOM yields an empty set.
    absent = Package.create("pkg-c", "3.0.0")
    assert active_package_ids_for_scans(
        [sbom_scan.id], restrict_to_package_ids={absent.id}
    ) == set()


def test_active_package_ids_for_scans_restrict_empty_returns_empty(app):
    """An empty restriction set short-circuits to an empty result."""
    from src.helpers.active_scans import active_package_ids_for_scans
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("restrict-empty-proj")
    variant = Variant.create("restrict-empty-variant", project.id)
    sbom_scan = Scan.create("sbom", variant.id, scan_type="sbom")
    document = SBOMDocument.create("sbom.json", "test", sbom_scan.id)
    pkg = Package.create("pkg-x", "1.0.0")
    SBOMPackage.create(document.id, pkg.id)
    _db.session.flush()

    assert active_package_ids_for_scans(
        [sbom_scan.id], restrict_to_package_ids=set()
    ) == set()



def test_find_or_create_openembedded_collapses_into_blank_supplier(app):
    """An OpenEmbedded supplier resolves to the same row as the blank one."""
    pkg_oe = Package.find_or_create("busybox", "1.36.1", supplier="OpenEmbedded ()")
    _db.session.flush()
    pkg_blank = Package.find_or_create("busybox", "1.36.1")
    assert pkg_oe.supplier == ""
    assert pkg_oe.id == pkg_blank.id


def test_exists_normalizes_openembedded_supplier(app):
    """exists() must match the cleaned (blank) row for an OpenEmbedded query."""
    Package.find_or_create("busybox", "1.36.1")
    _db.session.flush()
    assert Package.exists("busybox", "1.36.1", supplier="OpenEmbedded ()") is True


def test_get_by_string_id_normalizes_openembedded_supplier(app):
    """A string_id carrying an OpenEmbedded supplier resolves to the blank row."""
    Package.find_or_create("busybox", "1.36.1")
    _db.session.flush()
    found = Package.get_by_string_id("busybox@1.36.1::OpenEmbedded ()")
    assert found is not None
    assert found.supplier == ""


def test_bulk_find_or_create_collapses_openembedded_supplier(app):
    """bulk_find_or_create() deduplicates OpenEmbedded with the blank supplier."""
    result = Package.bulk_find_or_create([
        {"name": "busybox", "version": "1.36.1", "supplier": "OpenEmbedded ()"},
        {"name": "busybox", "version": "1.36.1", "supplier": ""},
    ])
    _db.session.flush()
    ids = {pkg.id for pkg in result.values()}
    assert len(ids) == 1
    assert "busybox@1.36.1" in result
    assert result["busybox@1.36.1"].supplier == ""

# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Unit tests for src/models/sbom_package.py (SBOMPackage junction model)."""

import os
import uuid
import pytest


@pytest.fixture(scope="module")
def app():
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        from src.bin.webapp import create_app
        from src.extensions import db as _db
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture(scope="module")
def sbom_doc(app):
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.sbom_document import SBOMDocument
    proj = Project.create("sbom-pkg-test-proj")
    variant = Variant.create("main", proj.id)
    scan = Scan.create("test scan", variant.id)
    return SBOMDocument.create("/sbom/test.spdx", "test-source", scan.id)


@pytest.fixture(scope="module")
def pkg(app):
    from src.models.package import Package
    return Package.create("testlib", "3.1.4")


class TestSBOMPackageRepr:
    def test_repr(self, app, sbom_doc, pkg):
        from src.models.sbom_package import SBOMPackage
        assoc = SBOMPackage(sbom_document_id=sbom_doc.id, package_id=pkg.id)
        r = repr(assoc)
        assert "SBOMPackage" in r
        assert "sbom_document_id" in r
        assert "package_id" in r


class TestSBOMPackageCreate:
    def test_create_with_uuid_objects(self, app, sbom_doc, pkg):
        from src.models.sbom_package import SBOMPackage
        assoc = SBOMPackage.create(sbom_doc.id, pkg.id)
        assert assoc.sbom_document_id == sbom_doc.id
        assert assoc.package_id == pkg.id

    def test_create_with_uuid_strings(self, app, sbom_doc, pkg):
        from src.models.sbom_package import SBOMPackage
        from src.extensions import db
        # Use fresh UUIDs via different package/doc to avoid PK conflict
        from src.models.package import Package
        pkg2 = Package.create("testlib-str", "3.1.5")
        assoc = SBOMPackage.create(str(sbom_doc.id), str(pkg2.id))
        assert assoc.sbom_document_id == sbom_doc.id
        assert assoc.package_id == pkg2.id
        assoc.delete()


class TestSBOMPackageGet:
    def test_get_returns_association(self, app, sbom_doc, pkg):
        from src.models.sbom_package import SBOMPackage
        # Ensure it exists first
        SBOMPackage.get_or_create(sbom_doc.id, pkg.id)
        found = SBOMPackage.get(sbom_doc.id, pkg.id)
        assert found is not None
        assert found.sbom_document_id == sbom_doc.id

    def test_get_with_strings(self, app, sbom_doc, pkg):
        from src.models.sbom_package import SBOMPackage
        found = SBOMPackage.get(str(sbom_doc.id), str(pkg.id))
        assert found is not None

    def test_get_returns_none_when_missing(self, app, sbom_doc):
        from src.models.sbom_package import SBOMPackage
        result = SBOMPackage.get(sbom_doc.id, uuid.uuid4())
        assert result is None


class TestSBOMPackageGetByDocument:
    def test_get_by_document(self, app, sbom_doc, pkg):
        from src.models.sbom_package import SBOMPackage
        SBOMPackage.get_or_create(sbom_doc.id, pkg.id)
        results = SBOMPackage.get_by_document(sbom_doc.id)
        assert any(a.package_id == pkg.id for a in results)

    def test_get_by_document_string(self, app, sbom_doc, pkg):
        from src.models.sbom_package import SBOMPackage
        results = SBOMPackage.get_by_document(str(sbom_doc.id))
        assert isinstance(results, list)


class TestSBOMPackageGetByPackage:
    def test_get_by_package(self, app, sbom_doc, pkg):
        from src.models.sbom_package import SBOMPackage
        SBOMPackage.get_or_create(sbom_doc.id, pkg.id)
        results = SBOMPackage.get_by_package(pkg.id)
        assert any(a.sbom_document_id == sbom_doc.id for a in results)

    def test_get_by_package_string(self, app, sbom_doc, pkg):
        from src.models.sbom_package import SBOMPackage
        results = SBOMPackage.get_by_package(str(pkg.id))
        assert isinstance(results, list)


class TestSBOMPackageGetOrCreate:
    def test_get_or_create_creates_new(self, app, sbom_doc):
        from src.models.sbom_package import SBOMPackage
        from src.models.package import Package
        pkg_new = Package.create("new-lib", "0.0.1")
        assoc = SBOMPackage.get_or_create(sbom_doc.id, pkg_new.id)
        assert assoc is not None
        assert assoc.package_id == pkg_new.id
        assoc.delete()

    def test_get_or_create_returns_existing(self, app, sbom_doc, pkg):
        from src.models.sbom_package import SBOMPackage
        SBOMPackage.get_or_create(sbom_doc.id, pkg.id)
        assoc1 = SBOMPackage.get_or_create(sbom_doc.id, pkg.id)
        assoc2 = SBOMPackage.get_or_create(sbom_doc.id, pkg.id)
        assert assoc1.sbom_document_id == assoc2.sbom_document_id
        assert assoc1.package_id == assoc2.package_id


class TestSBOMPackageDelete:
    def test_delete_removes_association(self, app, sbom_doc):
        from src.models.sbom_package import SBOMPackage
        from src.models.package import Package
        pkg_del = Package.create("del-lib", "1.2.3")
        assoc = SBOMPackage.create(sbom_doc.id, pkg_del.id)
        assoc.delete()
        assert SBOMPackage.get(sbom_doc.id, pkg_del.id) is None

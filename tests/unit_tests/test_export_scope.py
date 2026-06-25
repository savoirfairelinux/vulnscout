# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for src/helpers/export_scope.py."""

import os
import uuid
import pytest

from src.bin.webapp import create_app
from src.extensions import db as _db
from src.models.project import Project
from src.models.variant import Variant
from src.models.scan import Scan
from src.models.sbom_document import SBOMDocument
from src.models.sbom_package import SBOMPackage
from src.models.package import Package
from src.helpers.export_scope import ExportScope, _as_uuid, compute_export_scope


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def project(app):
    return Project.create("ScopeProject")


@pytest.fixture()
def variant(app, project):
    return Variant.create("ScopeVariant", project.id)


@pytest.fixture()
def scan(app, variant):
    return Scan.create("sbom-scan", variant.id)


@pytest.fixture()
def package(app):
    return Package.create("test-pkg", "1.0")


@pytest.fixture()
def sbom_doc_with_package(app, scan, package):
    doc = SBOMDocument.create("/path/to/sbom.spdx", "spdx", scan.id)
    SBOMPackage.create(doc.id, package.id)
    return doc


# ---------------------------------------------------------------------------
# _as_uuid
# ---------------------------------------------------------------------------

class TestAsUuid:
    def test_returns_uuid_unchanged(self):
        uid = uuid.uuid4()
        assert _as_uuid(uid) is uid

    def test_converts_string_to_uuid(self):
        uid = uuid.uuid4()
        result = _as_uuid(str(uid))
        assert result == uid
        assert isinstance(result, uuid.UUID)


# ---------------------------------------------------------------------------
# compute_export_scope — no arguments
# ---------------------------------------------------------------------------

class TestComputeExportScopeNone:
    def test_returns_none_when_no_args(self, app):
        result = compute_export_scope()
        assert result is None


# ---------------------------------------------------------------------------
# compute_export_scope — variant_id
# ---------------------------------------------------------------------------

class TestComputeExportScopeVariant:
    def test_variant_scope_with_packages(self, app, variant, sbom_doc_with_package, package):
        scope = compute_export_scope(variant_id=variant.id)
        assert isinstance(scope, ExportScope)
        assert variant.id in scope.variant_ids
        assert package.id in scope.package_ids

    def test_variant_scope_accepts_string_id(self, app, variant, sbom_doc_with_package, package):
        scope = compute_export_scope(variant_id=str(variant.id))
        assert isinstance(scope, ExportScope)
        assert variant.id in scope.variant_ids

    def test_variant_scope_empty_when_no_scan(self, app, variant):
        scope = compute_export_scope(variant_id=variant.id)
        assert isinstance(scope, ExportScope)
        assert variant.id in scope.variant_ids
        assert len(scope.package_ids) == 0

    def test_variant_id_takes_precedence_over_project_id(self, app, variant, project, sbom_doc_with_package, package):
        scope = compute_export_scope(variant_id=variant.id, project_id=project.id)
        assert isinstance(scope, ExportScope)
        # Only the single variant is in scope, not all project variants
        assert scope.variant_ids == {variant.id}


# ---------------------------------------------------------------------------
# compute_export_scope — project_id
# ---------------------------------------------------------------------------

class TestComputeExportScopeProject:
    def test_project_scope_includes_all_variants(self, app, project, variant, sbom_doc_with_package, package):
        v2 = Variant.create("ScopeVariant2", project.id)
        scope = compute_export_scope(project_id=project.id)
        assert isinstance(scope, ExportScope)
        assert variant.id in scope.variant_ids
        assert v2.id in scope.variant_ids

    def test_project_scope_includes_packages(self, app, project, variant, sbom_doc_with_package, package):
        scope = compute_export_scope(project_id=project.id)
        assert package.id in scope.package_ids

    def test_project_scope_accepts_string_id(self, app, project, variant, sbom_doc_with_package):
        scope = compute_export_scope(project_id=str(project.id))
        assert isinstance(scope, ExportScope)
        assert variant.id in scope.variant_ids

    def test_project_scope_empty_project(self, app):
        empty_project = Project.create("EmptyProject")
        scope = compute_export_scope(project_id=empty_project.id)
        assert isinstance(scope, ExportScope)
        assert len(scope.variant_ids) == 0
        assert len(scope.package_ids) == 0

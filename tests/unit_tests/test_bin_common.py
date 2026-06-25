# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for src/bin/_common.py — covers the error-exit branches."""

import os
import pytest

from src.bin.webapp import create_app
from src.extensions import db as _db
from src.models.project import Project
from src.models.variant import Variant
from src.bin._common import (
    get_default_author,
    resolve_project,
    resolve_project_variant,
    DEFAULT_VARIANT_NAME,
)


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
    return Project.create("CommonTestProject")


@pytest.fixture()
def variant(app, project):
    return Variant.create("CommonTestVariant", project.id)


# ---------------------------------------------------------------------------
# get_default_author
# ---------------------------------------------------------------------------

class TestGetDefaultAuthor:
    def test_returns_env_var_when_set(self, monkeypatch):
        monkeypatch.setenv("AUTHOR_NAME", "Test Author")
        assert get_default_author() == "Test Author"

    def test_returns_default_when_not_set(self, monkeypatch):
        monkeypatch.delenv("AUTHOR_NAME", raising=False)
        assert get_default_author() == "Savoir-faire Linux"


# ---------------------------------------------------------------------------
# resolve_project
# ---------------------------------------------------------------------------

class TestResolveProject:
    def test_returns_project_when_found(self, app, project):
        result = resolve_project("CommonTestProject")
        assert result.id == project.id

    def test_exits_when_project_not_found(self, app):
        # Lines 33-34: the error branch
        with pytest.raises(SystemExit) as exc_info:
            resolve_project("NonExistentProject")
        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# resolve_project_variant — create=False (error paths)
# ---------------------------------------------------------------------------

class TestResolveProjectVariantNoCreate:
    def test_returns_project_and_variant_when_both_found(self, app, project, variant):
        p, v = resolve_project_variant("CommonTestProject", "CommonTestVariant")
        assert p.id == project.id
        assert v.id == variant.id

    def test_uses_default_variant_name_when_variant_is_none(self, app, project):
        Variant.create(DEFAULT_VARIANT_NAME, project.id)
        p, v = resolve_project_variant("CommonTestProject", None)
        assert v.name == DEFAULT_VARIANT_NAME

    def test_exits_when_project_not_found(self, app):
        # Lines 68-69: project not found branch
        with pytest.raises(SystemExit) as exc_info:
            resolve_project_variant("GhostProject", "SomeVariant")
        assert exc_info.value.code == 1

    def test_exits_when_variant_not_found(self, app, project):
        # Lines 73-74: variant not found branch
        with pytest.raises(SystemExit) as exc_info:
            resolve_project_variant("CommonTestProject", "GhostVariant")
        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# resolve_project_variant — create=True (happy path)
# ---------------------------------------------------------------------------

class TestResolveProjectVariantCreate:
    def test_creates_project_and_variant_when_missing(self, app):
        p, v = resolve_project_variant("BrandNewProject", "BrandNewVariant", create=True)
        assert p.name == "BrandNewProject"
        assert v.name == "BrandNewVariant"

    def test_returns_existing_when_already_present(self, app, project, variant):
        p, v = resolve_project_variant(
            "CommonTestProject", "CommonTestVariant", create=True
        )
        assert p.id == project.id
        assert v.id == variant.id

# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""DB-backed tests for src/models/assessment.py — property fallbacks and
add_package edge cases that require a real ORM session (lines 163-165,
178-179, 229, 240-241)."""

import pytest


# ---------------------------------------------------------------------------
# DB app fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    import os
    from src.bin.webapp import create_app
    from src.extensions import db as _db

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
def db_package(app):
    from src.models.package import Package
    return Package.create("assesspkg", "1.0.0")


@pytest.fixture()
def db_vuln(app):
    from src.models.vulnerability import Vulnerability
    return Vulnerability.create_record("CVE-2099-ASSESS")


@pytest.fixture()
def db_finding(app, db_package, db_vuln):
    from src.models.finding import Finding
    return Finding.create(db_package.id, db_vuln.id)


@pytest.fixture()
def db_assessment(app, db_finding):
    """Persisted Assessment created via the ORM constructor (not new_dto)."""
    from src.models.assessment import Assessment
    from src.extensions import db
    a = Assessment(
        status="affected",
        status_notes="",
        justification="",
        impact_statement="",
        responses=[],
        workaround="",
        finding_id=db_finding.id,
    )
    db.session.add(a)
    db.session.commit()
    return a


# ---------------------------------------------------------------------------
# vuln_id / packages — property fallback via finding (lines 163-165, 178-179)
# ---------------------------------------------------------------------------

class TestAssessmentPropertyFallbacks:
    def test_vuln_id_from_finding(self, app, db_assessment, db_vuln):
        """Assessment.vuln_id falls back to finding.vulnerability_id when _vuln_id
        is empty (lines 163-165)."""
        from src.extensions import db as _db

        # Refresh to ensure orm.reconstructor has run, then force the fallback
        _db.session.expire(db_assessment)
        _db.session.refresh(db_assessment)
        db_assessment._vuln_id = ""

        assert db_assessment.vuln_id == db_vuln.id

    def test_packages_from_finding(self, app, db_assessment, db_package):
        """Assessment.packages falls back to finding.package.string_id when
        _packages is empty (lines 178-179)."""
        from src.extensions import db as _db

        _db.session.expire(db_assessment)
        _db.session.refresh(db_assessment)
        db_assessment._packages = []

        pkgs = db_assessment.packages
        assert isinstance(pkgs, list)
        assert any(db_package.name in p for p in pkgs)


# ---------------------------------------------------------------------------
# add_package — Package instance path and AttributeError fallback
# (lines 229, 240-241)
# ---------------------------------------------------------------------------

class TestAssessmentAddPackage:
    def test_add_package_instance(self):
        """add_package accepts a Package instance and uses its string_id (line 229)."""
        from src.models.assessment import Assessment
        from src.models.package import Package

        assess = Assessment.new_dto("CVE-2099-PKG")
        pkg = Package("testpkg", "9.9.9")
        result = assess.add_package(pkg)
        assert result is True
        assert "testpkg@9.9.9" in assess.packages

    def test_add_package_non_package_object_returns_false(self):
        """add_package with an object that lacks string_id returns False (lines 240-241)."""
        from src.models.assessment import Assessment

        assess = Assessment.new_dto("CVE-2099-PKG")

        class WeirdObj:
            pass  # no string_id attribute

        result = assess.add_package(WeirdObj())
        assert result is False

    def test_add_package_string_deduplication(self):
        """Calling add_package with the same string twice only stores it once."""
        from src.models.assessment import Assessment

        assess = Assessment.new_dto("CVE-2099-PKG")
        assess.add_package("pkg@1.0")
        assess.add_package("pkg@1.0")
        assert assess.packages.count("pkg@1.0") == 1

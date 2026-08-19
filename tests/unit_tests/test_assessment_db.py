# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""DB-backed tests for src/models/assessment.py — property fallbacks and
add_package edge cases that require a real ORM session (lines 163-165,
178-179, 229, 240-241)."""

import pytest


def _make_two_assessments():
    """Create two persisted assessments on one finding, for grouping tests."""
    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability

    Vulnerability.create_record(id="CVE-2026-0001")
    pkg = Package.create(name="grouped-pkg", version="1.0.0")
    finding = Finding.create(package_id=pkg.id, vulnerability_id="CVE-2026-0001")
    first = Assessment.create(status="not_affected", finding_id=finding.id)
    second = Assessment.create(status="not_affected", finding_id=finding.id)
    return first, second


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


# ---------------------------------------------------------------------------
# Lines 162-164: vuln_id property exception path
# ---------------------------------------------------------------------------

class TestAssessmentPropertyExceptions:
    def test_vuln_id_exception_returns_empty(self):
        """Lines 162-164: when finding.vulnerability_id raises, vuln_id returns ''."""
        from src.models.assessment import Assessment
        from unittest.mock import PropertyMock, patch

        assess = Assessment.new_dto("CVE-2099-EXC")
        assess._vuln_id = ""

        # Patch the 'finding' property at the class level for this test only
        with patch.object(type(assess), "finding",
                          new_callable=PropertyMock,
                          side_effect=RuntimeError("DB gone")):
            result = assess.vuln_id
        assert result == ""

    def test_packages_exception_returns_empty_list(self):
        """Lines 177-178: when finding.package access raises, packages returns []."""
        from src.models.assessment import Assessment
        from unittest.mock import PropertyMock, patch

        assess = Assessment.new_dto("CVE-2099-EXC2")
        assess._packages = []

        with patch.object(type(assess), "finding",
                          new_callable=PropertyMock,
                          side_effect=RuntimeError("lazy load failed")):
            result = assess.packages
        assert result == []

    def test_add_package_initializes_list_on_bare_object(self):
        """Line 228: add_package creates _packages list when attribute is absent."""
        from src.models.assessment import Assessment

        assess = object.__new__(Assessment)  # bypass __init__, no _packages set
        result = assess.add_package("bare@1.0")
        assert result is True
        assert "bare@1.0" in assess._packages

    def test_add_package_package_subclass_with_broken_string_id(self):
        """Lines 239-240: AttributeError when string_id raises on a Package subclass."""
        from src.models.assessment import Assessment
        from src.models.package import Package

        class _BrokenPkg(Package):
            @property
            def string_id(self):
                raise AttributeError("no string_id")

        assess = Assessment.new_dto("CVE-2099-EXC3")
        broken = object.__new__(_BrokenPkg)
        result = assess.add_package(broken)
        assert result is False


def test_create_group_links_every_assessment(app):
    with app.app_context():
        from src.models.assessment_group_member import AssessmentGroupMember
        first, second = _make_two_assessments()

        group_id = AssessmentGroupMember.create_group([first.id, second.id])

        assert set(AssessmentGroupMember.get_assessment_ids(group_id)) == {first.id, second.id}
        assert AssessmentGroupMember.get_group_id(first.id) == group_id


def test_assessment_belongs_to_at_most_one_group(app):
    with app.app_context():
        from sqlalchemy.exc import IntegrityError
        from src.extensions import db
        from src.models.assessment_group_member import AssessmentGroupMember
        first, second = _make_two_assessments()
        AssessmentGroupMember.create_group([first.id, second.id])

        with pytest.raises(IntegrityError):
            AssessmentGroupMember.create_group([first.id])
        db.session.rollback()


def test_get_group_id_is_none_for_ungrouped_assessment(app):
    with app.app_context():
        from src.models.assessment_group_member import AssessmentGroupMember
        first, _ = _make_two_assessments()

        assert AssessmentGroupMember.get_group_id(first.id) is None


def test_to_dict_exposes_group_id_when_grouped(app):
    with app.app_context():
        from src.models.assessment_group_member import AssessmentGroupMember
        first, second = _make_two_assessments()
        group_id = AssessmentGroupMember.create_group([first.id, second.id])

        assert first.to_dict()["group_id"] == str(group_id)


def test_to_dict_group_id_is_none_when_ungrouped(app):
    with app.app_context():
        first, _ = _make_two_assessments()

        assert first.to_dict()["group_id"] is None


def test_build_groups_collapses_members_into_one_entry(app):
    with app.app_context():
        from src.controllers.assessment_groups import build_groups
        from src.models.assessment_group_member import AssessmentGroupMember
        first, second = _make_two_assessments()
        group_id = AssessmentGroupMember.create_group([first.id, second.id])

        groups = build_groups([first, second])

        assert len(groups) == 1
        assert groups[0]["group_id"] == str(group_id)
        assert set(groups[0]["assessment_ids"]) == {str(first.id), str(second.id)}
        assert len(groups[0]["targets"]) == 2


def test_build_groups_keeps_ungrouped_assessments_as_single_entries(app):
    with app.app_context():
        from src.controllers.assessment_groups import build_groups
        first, second = _make_two_assessments()

        groups = build_groups([first, second])

        assert len(groups) == 2
        assert all(g["group_id"] is None for g in groups)
        assert all(len(g["targets"]) == 1 for g in groups)


def test_load_group_returns_every_member(app):
    with app.app_context():
        from src.controllers.assessment_groups import load_group
        from src.models.assessment_group_member import AssessmentGroupMember
        first, second = _make_two_assessments()
        group_id = AssessmentGroupMember.create_group([first.id, second.id])

        assert {a.id for a in load_group(group_id)} == {first.id, second.id}


def test_load_group_is_empty_for_unknown_id(app):
    with app.app_context():
        import uuid
        from src.controllers.assessment_groups import load_group

        assert load_group(uuid.uuid4()) == []

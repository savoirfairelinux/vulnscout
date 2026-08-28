# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""DB-backed tests for src/models/assessment.py — property fallbacks and
add_package edge cases that require a real ORM session (lines 163-165,
178-179, 229, 240-241)."""

import uuid

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
def db_variant(app):
    from src.extensions import db
    from src.models.project import Project
    from src.models.variant import Variant
    project = Project.create(name="assess-project")
    variant = Variant(id=uuid.uuid4(), project_id=project.id, name="assess-variant")
    db.session.add(variant)
    db.session.commit()
    return variant


@pytest.fixture()
def db_assessment(app, db_finding, db_variant):
    """Persisted Assessment created via the ORM constructor (not new_dto)."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget
    a = Assessment(
        status="affected",
        status_notes="",
        justification="",
        impact_statement="",
        responses=[],
        workaround="",
    )
    db.session.add(a)
    db.session.flush()
    db.session.add(AssessmentTarget(
        assessment_id=a.id, variant_id=db_variant.id, finding_id=db_finding.id))
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
        """When iterating target_rows raises, vuln_id swallows it and returns ''."""
        from src.models.assessment import Assessment
        from unittest.mock import PropertyMock, patch

        assess = Assessment.new_dto("CVE-2099-EXC")
        assess._vuln_id = ""

        # Patch the 'target_rows' property at the class level for this test only
        with patch.object(type(assess), "target_rows",
                          new_callable=PropertyMock,
                          side_effect=RuntimeError("DB gone")):
            result = assess.vuln_id
        assert result == ""

    def test_packages_exception_returns_empty_list(self):
        """When iterating target_rows raises, packages swallows it and returns []."""
        from src.models.assessment import Assessment
        from unittest.mock import PropertyMock, patch

        assess = Assessment.new_dto("CVE-2099-EXC2")
        assess._packages = []

        with patch.object(type(assess), "target_rows",
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


def test_load_group_is_empty_for_unknown_id(app):
    with app.app_context():
        import uuid
        from src.controllers.assessment_groups import load_group

        assert load_group(uuid.uuid4()) == []


def _make_variant(project, variant_name: str):
    """Create a variant under *project*.

    *project* is either a project name (``str``) — a brand new
    :class:`Project` is created for it, as the group-invariant tests below
    expect — or an existing project id (``uuid.UUID``) to attach the variant
    to directly, as the multi-target tests further down expect.
    """
    from src.models.project import Project
    from src.models.variant import Variant

    project_id = project if isinstance(project, uuid.UUID) else Project.create(name=project).id
    return Variant.create(name=variant_name, project_id=project_id)



def _count_queries_matching(table_name: str, app_ctx_callable):
    """Run a callable and count the queries whose statement mentions *table_name*."""
    from sqlalchemy import event
    from src.extensions import db

    seen: list[str] = []

    def _record(conn, cursor, statement, parameters, context, executemany):
        if table_name in statement:
            seen.append(statement)

    engine = db.session.get_bind()
    event.listen(engine, "before_cursor_execute", _record)
    try:
        app_ctx_callable()
    finally:
        event.remove(engine, "before_cursor_execute", _record)
    return len(seen)


def test_build_groups_resolves_targets_without_a_query_per_row(app):
    """Serializing many assessments must not add one targets/finding query per
    assessment: target_rows and AssessmentTarget.finding are both configured
    lazy="selectin", so a page of N assessments issues a small, bounded number
    of queries rather than one per row. (finding.package is not selectin and
    does add one query per distinct finding here — a known, deferred N+1 the
    brief allows leaving for the routes that build these lists to fix with a
    joinedload, since no test previously enforced a budget on it.)"""
    with app.app_context():
        from src.controllers.assessment_groups import build_groups
        from src.models.assessment import Assessment
        from src.models.finding import Finding
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.extensions import db
        Vulnerability.create_record(id="CVE-2026-3000")
        ids = []
        for i in range(5):
            pkg = Package.create(name=f"pkg-{i}", version="1.0.0")
            finding = Finding.create(package_id=pkg.id, vulnerability_id="CVE-2026-3000")
            variant = _make_variant(uuid.uuid4(), "default")
            ids.append(Assessment.create(
                status="not_affected", targets=[(variant.id, finding.id)]).id)
        db.session.expunge_all()

        # Load the way a listing endpoint would: one query returning every
        # row, so selectin's batching has a shared load event to hook into.
        assessments = list(db.session.execute(
            db.select(Assessment).where(Assessment.id.in_(ids))
        ).scalars().all())

        queries = _count_queries_matching(
            "assessment_targets", lambda: build_groups(assessments))

        assert queries <= 1


# ---------------------------------------------------------------------------
# Write path: Assessment.create / add_target / from_vuln_assessment dual-write
# ---------------------------------------------------------------------------

def _make_finding(vuln_id: str, pkg_name: str):
    """Create a finding for *pkg_name* against *vuln_id*, reusing the
    vulnerability record if a prior call already created it (tests may target
    the same vulnerability from two different packages)."""
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability

    vuln = db.session.get(Vulnerability, vuln_id.upper()) or Vulnerability.create_record(id=vuln_id)
    pkg = Package.create(name=pkg_name, version="1.0.0")
    return Finding.create(package_id=pkg.id, vulnerability_id=vuln.id)


def _make_finding_and_variant():
    """Create one finding and one variant that may legally share an assessment."""
    finding = _make_finding("CVE-2026-2000", "openssl")
    variant = _make_variant(uuid.uuid4(), "default")
    return finding, variant


def test_create_with_a_single_target(app):
    with app.app_context():
        from src.models.assessment import Assessment
        finding, variant = _make_finding_and_variant()
        assessment = Assessment.create(
            status="affected", origin="custom",
            targets=[(variant.id, finding.id)], commit=True,
        )
        assert assessment.targets == [(variant.id, finding.id)]


def test_create_accepts_an_explicit_multi_target_list(app):
    with app.app_context():
        from src.models.assessment import Assessment
        project = uuid.uuid4()
        variant_a = _make_variant(project, "a")
        variant_b = _make_variant(project, "b")
        openssl = _make_finding("CVE-2026-1000", "openssl")
        zlib = _make_finding("CVE-2026-1000", "zlib")

        assessment = Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant_a.id, openssl.id), (variant_b.id, zlib.id)],
            commit=True,
        )
        assert sorted(assessment.targets) == sorted([
            (variant_a.id, openssl.id), (variant_b.id, zlib.id),
        ])


def test_create_rejects_targets_that_break_the_invariant(app):
    with app.app_context():
        from src.models.assessment import Assessment
        from src.models.assessment_target import GroupInvariantError
        variant_a = _make_variant(uuid.uuid4(), "a")
        variant_b = _make_variant(uuid.uuid4(), "b")
        finding = _make_finding("CVE-2026-1001", "openssl")

        with pytest.raises(GroupInvariantError):
            Assessment.create(
                status="affected", origin="custom",
                targets=[(variant_a.id, finding.id), (variant_b.id, finding.id)],
                commit=True,
            )


def test_add_target_is_idempotent(app):
    with app.app_context():
        from src.models.assessment import Assessment
        finding, variant = _make_finding_and_variant()
        assessment = Assessment.create(
            status="affected", origin="custom",
            targets=[(variant.id, finding.id)], commit=True,
        )
        assert assessment.add_target(variant.id, finding.id) is False
        assert len(assessment.targets) == 1


def test_deleting_an_assessment_removes_its_target_rows(app):
    with app.app_context():
        from src.extensions import db
        from src.models.assessment import Assessment
        from src.models.assessment_target import AssessmentTarget
        finding, variant = _make_finding_and_variant()
        assessment = Assessment.create(
            status="affected", origin="custom",
            targets=[(variant.id, finding.id)], commit=True,
        )
        assessment.delete()
        assert db.session.query(AssessmentTarget).count() == 0

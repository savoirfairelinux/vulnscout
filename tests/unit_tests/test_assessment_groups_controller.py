# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the read path in src/controllers/assessment_groups.py.

A group is now an assessment: ``group_id`` is the assessment's own id and its
targets come from ``target_rows`` instead of bucketed sibling rows.
"""

import uuid

import pytest


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


def _make_variant(project, variant_name: str):
    """Create a variant under *project* (a project name or an existing project id)."""
    from src.models.project import Project
    from src.models.variant import Variant

    project_id = project if isinstance(project, uuid.UUID) else Project.create(name=project).id
    return Variant.create(name=variant_name, project_id=project_id)


def _make_finding(vuln_id: str, pkg_name: str):
    """Create a finding for *pkg_name* against *vuln_id*, reusing the
    vulnerability record if a prior call already created it."""
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


@pytest.mark.skip(
    reason="Assessment.create raises GroupInvariantError for more than one target"
    " pair (the ORM guard in Assessment.create fires before the DB is ever"
    " reached, so assessment_targets' uq_assessment_targets_assessment_id"
    " constraint is never the thing that stops this -- PR-A's expand-phase"
    " invariant, lifted only in Task 14). Enable once Task 14 drops the guard.")
def test_a_multi_target_assessment_is_one_group_with_two_targets(app):
    with app.app_context():
        from src.controllers.assessment_groups import build_groups
        from src.models.assessment import Assessment

        project = uuid.uuid4()
        variant_a = _make_variant(project, "a")
        variant_b = _make_variant(project, "b")
        openssl = _make_finding("CVE-2026-2000", "openssl")
        zlib = _make_finding("CVE-2026-2000", "zlib")
        assessment = Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant_a.id, openssl.id), (variant_b.id, zlib.id)],
            commit=True,
        )

        groups = build_groups([assessment])

        assert len(groups) == 1
        assert groups[0]["group_id"] == str(assessment.id)
        assert groups[0]["assessment_ids"] == [str(assessment.id)]
        # ``package`` is the finding's package string_id ("name@version"), and
        # targets sort by (variant_id, package) — variant ids are random, so
        # compare as a set rather than assuming creation order survives.
        assert {t["package"] for t in groups[0]["targets"]} == {
            openssl.package.string_id, zlib.package.string_id}


def test_two_content_identical_assessments_stay_two_groups(app):
    """Grouping is now storage, not inference: rows that merely look alike are
    no longer fused at read time."""
    with app.app_context():
        from src.controllers.assessment_groups import build_groups
        from src.models.assessment import Assessment

        finding, variant = _make_finding_and_variant()
        one = Assessment.create(status="affected", origin="custom",
                                targets=[(variant.id, finding.id)],
                                commit=True)
        two = Assessment.create(status="affected", origin="custom",
                                targets=[(variant.id, finding.id)],
                                commit=True)

        groups = build_groups([one, two])

        assert len(groups) == 2


@pytest.mark.skip(
    reason="load_group still resolves groups through AssessmentGroupMember"
    " (the write path Task 15 fuses); an assessment written on its own has no"
    " membership row, so 'a group is now an assessment' only holds once"
    " Task 15/14 land. Enable then.")
def test_load_group_returns_the_assessment_itself(app):
    with app.app_context():
        from src.controllers.assessment_groups import load_group
        from src.models.assessment import Assessment

        finding, variant = _make_finding_and_variant()
        assessment = Assessment.create(status="affected", origin="custom",
                                       targets=[(variant.id, finding.id)],
                                       commit=True)

        assert [a.id for a in load_group(assessment.id)] == [assessment.id]


def test_load_group_of_an_unknown_id_is_empty(app):
    with app.app_context():
        from src.controllers.assessment_groups import load_group

        assert load_group(uuid.uuid4()) == []


@pytest.mark.skip(
    reason="Assessment.create raises GroupInvariantError for more than one target"
    " pair (the ORM guard in Assessment.create fires before the DB is ever"
    " reached, so assessment_targets' uq_assessment_targets_assessment_id"
    " constraint is never the thing that stops this -- PR-A's expand-phase"
    " invariant, lifted only in Task 14). Enable once Task 14 drops the guard.")
def test_to_dict_exposes_every_touched_variant(app):
    with app.app_context():
        from src.models.assessment import Assessment

        project = uuid.uuid4()
        variant_a = _make_variant(project, "a")
        variant_b = _make_variant(project, "b")
        openssl = _make_finding("CVE-2026-2001", "openssl")
        zlib = _make_finding("CVE-2026-2001", "zlib")
        assessment = Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant_a.id, openssl.id), (variant_b.id, zlib.id)],
            commit=True,
        )

        data = assessment.to_dict()

        assert sorted(data["variant_ids"]) == sorted([str(variant_a.id), str(variant_b.id)])
        # The legacy singular field still collapses to None for a genuine
        # cross-variant assessment — unchanged behavior.
        assert data["variant_id"] is None


@pytest.mark.skip(
    reason="Assessment.create raises GroupInvariantError for more than one target"
    " pair (the ORM guard in Assessment.create fires before the DB is ever"
    " reached, so assessment_targets' uq_assessment_targets_assessment_id"
    " constraint is never the thing that stops this -- PR-A's expand-phase"
    " invariant, lifted only in Task 14). Enable once Task 14 drops the guard.")
def test_outdated_is_scoped_to_the_variant_the_package_is_stale_in(app, monkeypatch):
    """A package stale in one variant must not flag the same package elsewhere.

    ``stale_packages`` accumulates across every variant an assessment targets,
    so it cannot answer a per-variant question; ``stale_targets`` keeps the
    variant dimension and is what the flag has to key on.  The annotation is
    injected here so the assertion is about the controller's keying rather
    than about SBOM scan setup.
    """
    with app.app_context():
        from src.controllers import assessment_groups
        from src.models.assessment import Assessment

        project = uuid.uuid4()
        variant_a = _make_variant(project, "a")
        variant_b = _make_variant(project, "b")
        openssl_a = _make_finding("CVE-2026-2100", "openssl")
        openssl_b = _make_finding("CVE-2026-2100", "openssl")
        assessment = Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant_a.id, openssl_a.id), (variant_b.id, openssl_b.id)],
            commit=True,
        )

        def _fake_annotate(dicts):
            for d in dicts:
                d["outdated"] = True
                d["stale_packages"] = [openssl_a.package.string_id]
                d["stale_targets"] = [
                    {"variant_id": str(variant_a.id), "package_name": "openssl"},
                ]

        monkeypatch.setattr(
            assessment_groups, "annotate_assessments_outdated", _fake_annotate)

        groups = assessment_groups.build_groups([assessment])

        outdated_by_variant = {
            t["variant_id"]: t["outdated"] for t in groups[0]["targets"]}
        assert outdated_by_variant[str(variant_a.id)] is True
        assert outdated_by_variant[str(variant_b.id)] is False

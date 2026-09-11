# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the additive ``assessment_targets`` table and its invariants."""

import os
import uuid
import pytest


@pytest.fixture()
def app():
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


def _finding(vuln_id: str, pkg_name: str):
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability

    vuln = db.session.get(Vulnerability, vuln_id.upper()) or Vulnerability(id=vuln_id)
    pkg = Package(id=uuid.uuid4(), name=pkg_name, version="1.0")
    db.session.add_all([vuln, pkg])
    db.session.flush()
    finding = Finding(id=uuid.uuid4(), vulnerability_id=vuln_id, package_id=pkg.id)
    db.session.add(finding)
    db.session.flush()
    return finding


def _variant(project_id: uuid.UUID, name: str):
    from src.extensions import db
    from src.models.variant import Variant

    variant = Variant(id=uuid.uuid4(), project_id=project_id, name=name)
    db.session.add(variant)
    db.session.flush()
    return variant


def test_assessment_exposes_its_targets_as_pairs(app):
    """PR-A's ``uq_assessment_targets_assessment_id`` allows one row per
    assessment, so ``targets`` reports exactly the pair that was stored.
    PR-D drops the constraint and this becomes a list of several pairs."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget

    project = uuid.uuid4()
    variant_a = _variant(project, "a")
    openssl = _finding("CVE-2026-0001", "openssl")

    assessment = Assessment(id=uuid.uuid4(), status="not_affected", origin="custom")
    db.session.add(assessment)
    db.session.flush()
    db.session.add(
        AssessmentTarget(assessment_id=assessment.id,
                         variant_id=variant_a.id, finding_id=openssl.id))
    db.session.commit()

    assert assessment.targets == [(variant_a.id, openssl.id)]


def test_a_second_target_row_for_one_assessment_is_refused(app):
    """The invariant that lets the scalar mirror stay unambiguous, asserted
    against the real schema rather than assumed.  PR-D removes this test with
    the constraint."""
    from sqlalchemy.exc import IntegrityError

    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget

    project = uuid.uuid4()
    variant_a = _variant(project, "a")
    variant_b = _variant(project, "b")
    finding = _finding("CVE-2026-0018", "openssl")

    assessment = Assessment(id=uuid.uuid4(), status="not_affected", origin="custom")
    db.session.add(assessment)
    db.session.flush()
    db.session.add(AssessmentTarget(assessment_id=assessment.id,
                                    variant_id=variant_a.id, finding_id=finding.id))
    db.session.commit()

    db.session.add(AssessmentTarget(assessment_id=assessment.id,
                                    variant_id=variant_b.id, finding_id=finding.id))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_add_target_replaces_the_single_target_it_may_hold(app):
    """``add_target`` overwrites instead of appending while the constraint
    stands -- ``staging``'s last-write-wins on the scalar columns.  PR-D
    restores appending."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget
    from src.models.project import Project

    project = Project.create("replace-proj")
    variant_a = _variant(project.id, "a")
    variant_b = _variant(project.id, "b")
    finding = _finding("CVE-2026-0019", "openssl")
    assessment = Assessment.create(
        status="affected", origin="custom",
        targets=[(variant_a.id, finding.id)], commit=True,
    )

    assert assessment.add_target(variant_b.id, finding.id) is True
    db.session.commit()

    assert assessment.targets == [(variant_b.id, finding.id)]
    assert (assessment.variant_id, assessment.finding_id) == (variant_b.id, finding.id)
    assert db.session.query(AssessmentTarget).count() == 1


def test_create_refuses_more_than_one_target(app):
    """PR-A cannot store a second target, so it must not pretend to: mirroring
    only the first pair would leave the columns disagreeing with the request.
    PR-D removes this restriction."""
    from src.models.assessment import Assessment
    from src.models.assessment_target import GroupInvariantError
    from src.models.project import Project

    project = Project.create("refuse-multi-proj")
    variant_a = _variant(project.id, "a")
    variant_b = _variant(project.id, "b")
    finding = _finding("CVE-2026-0020", "openssl")

    with pytest.raises(GroupInvariantError, match="only one target"):
        Assessment.create(
            status="affected", origin="custom",
            targets=[(variant_a.id, finding.id), (variant_b.id, finding.id)],
            commit=True,
        )


def test_deleting_an_assessment_deletes_its_targets(app):
    """The DB-level cascade never fires because PRAGMA foreign_keys is OFF,
    so this proves the ORM-level cascade does the work."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget

    project = uuid.uuid4()
    variant = _variant(project, "a")
    finding = _finding("CVE-2026-0002", "openssl")
    assessment = Assessment(id=uuid.uuid4(), status="affected", origin="custom")
    db.session.add(assessment)
    db.session.flush()
    db.session.add(AssessmentTarget(assessment_id=assessment.id,
                                    variant_id=variant.id, finding_id=finding.id))
    db.session.commit()

    db.session.delete(assessment)
    db.session.commit()

    assert db.session.query(AssessmentTarget).count() == 0


def test_finding_is_reachable_from_its_targets(app):
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget

    project = uuid.uuid4()
    variant = _variant(project, "a")
    finding = _finding("CVE-2026-0003", "openssl")
    assessment = Assessment(id=uuid.uuid4(), status="affected", origin="custom")
    db.session.add(assessment)
    db.session.flush()
    db.session.add(AssessmentTarget(assessment_id=assessment.id,
                                    variant_id=variant.id, finding_id=finding.id))
    db.session.commit()

    assert len(finding.assessment_targets) == 1


def test_targets_spanning_two_vulnerabilities_are_rejected(app):
    from src.extensions import db
    from src.models.assessment_target import GroupInvariantError, validate_targets

    project = uuid.uuid4()
    variant = _variant(project, "a")
    one = _finding("CVE-2026-0004", "openssl")
    two = _finding("CVE-2026-0005", "zlib")
    db.session.commit()

    with pytest.raises(GroupInvariantError, match="different vulnerabilities"):
        validate_targets([(variant.id, one.id), (variant.id, two.id)])


def test_targets_spanning_two_projects_are_rejected(app):
    from src.extensions import db
    from src.models.assessment_target import GroupInvariantError, validate_targets

    variant_a = _variant(uuid.uuid4(), "a")
    variant_b = _variant(uuid.uuid4(), "b")
    finding = _finding("CVE-2026-0006", "openssl")
    db.session.commit()

    with pytest.raises(GroupInvariantError, match="different projects"):
        validate_targets([(variant_a.id, finding.id), (variant_b.id, finding.id)])


def test_targets_in_one_project_and_one_vulnerability_are_accepted(app):
    from src.extensions import db
    from src.models.assessment_target import validate_targets

    project = uuid.uuid4()
    variant_a = _variant(project, "a")
    variant_b = _variant(project, "b")
    openssl = _finding("CVE-2026-0007", "openssl")
    zlib = _finding("CVE-2026-0007", "zlib")
    db.session.commit()

    validate_targets([(variant_a.id, openssl.id), (variant_b.id, zlib.id)])


def test_an_unknown_target_is_rejected(app):
    from src.extensions import db
    from src.models.assessment_target import GroupInvariantError, validate_targets

    variant = _variant(uuid.uuid4(), "a")
    db.session.commit()

    with pytest.raises(GroupInvariantError, match="Unknown target"):
        validate_targets([(variant.id, uuid.uuid4())])


def test_an_empty_target_set_is_accepted(app):
    from src.models.assessment_target import validate_targets

    validate_targets([])


def test_deleting_a_variant_reaps_its_targets_and_orphaned_assessments(app):
    """Nothing else clears these rows: the FK has no ondelete and sqlite's
    foreign_keys pragma stays off, so orphans would keep surfacing in
    unfiltered reads while pointing at a variant that no longer exists."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget
    from src.models.project import Project

    project = Project.create("reap-proj")
    variant = _variant(project.id, "a")
    finding = _finding("CVE-2026-0010", "openssl")
    assessment = Assessment.create(
        status="affected", origin="custom",
        targets=[(variant.id, finding.id)], commit=True,
    )
    assessment_id = assessment.id

    variant.delete()

    assert db.session.query(AssessmentTarget).count() == 0
    assert db.session.get(Assessment, assessment_id) is None


def test_deleting_a_variant_spares_assessments_targeting_another(app):
    """The reaper is criterion-scoped: only the targets naming the deleted
    variant go, and only the assessments those targets were the last reach to.

    PR-A holds one target per assessment, so "still reachable" can only be
    expressed across two assessments here; PR-D restores the single-assessment,
    two-target version of this scenario when it drops the constraint.
    """
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget
    from src.models.project import Project

    project = Project.create("reap-keep-proj")
    variant_a = _variant(project.id, "a")
    variant_b = _variant(project.id, "b")
    finding = _finding("CVE-2026-0011", "openssl")
    doomed = Assessment.create(
        status="affected", origin="custom",
        targets=[(variant_a.id, finding.id)], commit=True,
    )
    survivor = Assessment.create(
        status="affected", origin="custom",
        targets=[(variant_b.id, finding.id)], commit=True,
    )
    doomed_id, survivor_id = doomed.id, survivor.id

    variant_a.delete()

    assert db.session.get(Assessment, doomed_id) is None
    kept = db.session.get(Assessment, survivor_id)
    assert kept is not None
    assert kept.targets == [(variant_b.id, finding.id)]
    assert db.session.query(AssessmentTarget).count() == 1


def test_deleting_a_project_reaps_its_variants_assessments(app):
    """The reaper is a mapper event, so the project's ORM cascade triggers it."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget
    from src.models.project import Project

    project = Project.create("reap-cascade-proj")
    variant = _variant(project.id, "a")
    finding = _finding("CVE-2026-0012", "openssl")
    assessment = Assessment.create(
        status="affected", origin="custom",
        targets=[(variant.id, finding.id)], commit=True,
    )
    assessment_id = assessment.id

    project.delete()

    assert db.session.query(AssessmentTarget).count() == 0
    assert db.session.get(Assessment, assessment_id) is None


def test_deleting_a_finding_reaps_its_targets_and_orphaned_assessments(app):
    """Mirrors the variant reaper: ``assessment_targets.finding_id`` is part of
    the primary key, so the ORM's default null-out would raise on flush."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget
    from src.models.project import Project

    project = Project.create("reap-finding-proj")
    variant = _variant(project.id, "a")
    finding = _finding("CVE-2026-0013", "openssl")
    assessment = Assessment.create(
        status="affected", origin="custom",
        targets=[(variant.id, finding.id)], commit=True,
    )
    assessment_id = assessment.id

    finding.delete()

    assert db.session.query(AssessmentTarget).count() == 0
    assert db.session.get(Assessment, assessment_id) is None


def test_deleting_a_finding_spares_assessments_targeting_another(app):
    """Mirrors the variant case: only the targets naming the deleted finding
    go.  See that test for why the still-reachable assessment is a second row
    in PR-A rather than a second target on the same one."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget
    from src.models.project import Project

    project = Project.create("reap-finding-keep-proj")
    variant = _variant(project.id, "a")
    openssl = _finding("CVE-2026-0014", "openssl")
    zlib = _finding("CVE-2026-0014", "zlib")
    doomed = Assessment.create(
        status="affected", origin="custom",
        targets=[(variant.id, openssl.id)], commit=True,
    )
    survivor = Assessment.create(
        status="affected", origin="custom",
        targets=[(variant.id, zlib.id)], commit=True,
    )
    doomed_id, survivor_id = doomed.id, survivor.id

    openssl.delete()

    assert db.session.get(Assessment, doomed_id) is None
    kept = db.session.get(Assessment, survivor_id)
    assert kept is not None
    assert kept.targets == [(variant.id, zlib.id)]
    assert db.session.query(AssessmentTarget).count() == 1


def test_deleting_a_package_reaps_its_findings_assessments(app):
    """The reaper is a mapper event, so the package's ORM cascade triggers it."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget
    from src.models.package import Package
    from src.models.project import Project

    project = Project.create("reap-package-proj")
    variant = _variant(project.id, "a")
    finding = _finding("CVE-2026-0015", "openssl")
    assessment = Assessment.create(
        status="affected", origin="custom",
        targets=[(variant.id, finding.id)], commit=True,
    )
    assessment_id = assessment.id
    package = db.session.get(Package, finding.package_id)
    assert package is not None

    package.delete()

    assert db.session.query(AssessmentTarget).count() == 0
    assert db.session.get(Assessment, assessment_id) is None


def test_deleting_a_variant_reaps_an_assessment_with_no_targets(app):
    """PR-A still accepts one target-less shape -- the custom-data import of
    an item naming no variant, which ``staging`` stored the same way.  Such a
    row is reachable only through the scalar mirror, so the parent's deletion
    must take it along, exactly as the ORM cascade used to.  (The bulk scan
    ingestion is no longer such a path: it writes its own target rows.)"""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.project import Project

    project = Project.create("reap-scalar-proj")
    variant = _variant(project.id, "a")
    finding = _finding("CVE-2026-0016", "openssl")
    assessment = Assessment(
        id=uuid.uuid4(), status="affected", origin="scc",
        variant_id=variant.id, finding_id=finding.id,
    )
    db.session.add(assessment)
    db.session.commit()
    assessment_id = assessment.id

    variant.delete()

    assert db.session.get(Assessment, assessment_id) is None


def test_deleting_a_finding_reaps_an_assessment_with_no_targets(app):
    """Mirrors the variant case for the other scalar mirror column."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.project import Project

    project = Project.create("reap-scalar-finding-proj")
    variant = _variant(project.id, "a")
    finding = _finding("CVE-2026-0017", "openssl")
    assessment = Assessment(
        id=uuid.uuid4(), status="affected", origin="scc",
        variant_id=variant.id, finding_id=finding.id,
    )
    db.session.add(assessment)
    db.session.commit()
    assessment_id = assessment.id

    finding.delete()

    assert db.session.get(Assessment, assessment_id) is None

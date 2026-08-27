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
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget

    project = uuid.uuid4()
    variant_a = _variant(project, "a")
    variant_b = _variant(project, "b")
    openssl = _finding("CVE-2026-0001", "openssl")
    zlib = _finding("CVE-2026-0001", "zlib")

    assessment = Assessment(id=uuid.uuid4(), status="not_affected", origin="custom")
    db.session.add(assessment)
    db.session.flush()
    db.session.add_all([
        AssessmentTarget(assessment_id=assessment.id,
                         variant_id=variant_a.id, finding_id=openssl.id),
        AssessmentTarget(assessment_id=assessment.id,
                         variant_id=variant_b.id, finding_id=zlib.id),
    ])
    db.session.commit()

    assert sorted(assessment.targets) == sorted([
        (variant_a.id, openssl.id),
        (variant_b.id, zlib.id),
    ])


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

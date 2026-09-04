# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for src/helpers/outdated_cleanup.py's multi-target reachability.

Assessments are reachable only through their assessment_targets rows now, not
the scalar Assessment.finding_id/variant_id columns.  A reachability query
that still consults the scalar column can silently delete a finding (or leave
an assessment behind, or leave its target rows behind) that is actually still
in use — these tests guard the two silent-failure sites identified for this
task: _delete_orphaned_findings and the target-reaping helper.
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


def test_a_finding_held_only_by_a_multi_target_assessment_survives(app):
    """_delete_orphaned_findings must see reachability through targets."""
    with app.app_context():
        from src.extensions import db
        from src.helpers.outdated_cleanup import _delete_orphaned_findings
        from src.models.assessment import Assessment
        from src.models.finding import Finding

        project = uuid.uuid4()
        variant = _make_variant(project, "a")
        openssl = _make_finding("CVE-2026-4000", "openssl")
        zlib = _make_finding("CVE-2026-4000", "zlib")
        Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant.id, openssl.id), (variant.id, zlib.id)],
            commit=True,
        )

        _delete_orphaned_findings({zlib.id})

        assert db.session.get(Finding, zlib.id) is not None


def test_a_finding_with_no_remaining_reference_is_still_reaped(app):
    """The reachability fix doesn't turn _delete_orphaned_findings into a no-op."""
    with app.app_context():
        from src.extensions import db
        from src.helpers.outdated_cleanup import _delete_orphaned_findings
        from src.models.finding import Finding

        project = uuid.uuid4()
        _make_variant(project, "a")
        orphan = _make_finding("CVE-2026-4002", "curl")

        deleted_count, vulnerability_ids = _delete_orphaned_findings({orphan.id})

        assert deleted_count == 1
        assert vulnerability_ids == {"CVE-2026-4002"}
        assert db.session.get(Finding, orphan.id) is None


def test_reaping_one_target_leaves_the_assessment_and_its_siblings(app):
    """remove_target deletes only the reaped target, not the whole assessment."""
    with app.app_context():
        from src.extensions import db
        from src.helpers.outdated_cleanup import remove_target
        from src.models.assessment import Assessment

        project = uuid.uuid4()
        variant = _make_variant(project, "a")
        openssl = _make_finding("CVE-2026-4001", "openssl")
        zlib = _make_finding("CVE-2026-4001", "zlib")
        assessment = Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant.id, openssl.id), (variant.id, zlib.id)],
            commit=True,
        )

        removed = remove_target(assessment.id, variant.id, zlib.id)

        assert removed is True
        assert db.session.get(Assessment, assessment.id) is not None
        assert assessment.targets == [(variant.id, openssl.id)]


def test_reaping_the_last_target_deletes_the_assessment(app):
    """remove_target deletes the assessment once it has no targets left."""
    with app.app_context():
        from src.extensions import db
        from src.helpers.outdated_cleanup import remove_target
        from src.models.assessment import Assessment

        project = uuid.uuid4()
        variant = _make_variant(project, "a")
        openssl = _make_finding("CVE-2026-4003", "openssl")
        assessment = Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant.id, openssl.id)],
            commit=True,
        )
        assessment_id = assessment.id

        removed = remove_target(assessment_id, variant.id, openssl.id)

        assert removed is True
        assert db.session.get(Assessment, assessment_id) is None


def test_remove_target_is_false_for_an_unknown_target(app):
    """remove_target reports False instead of raising for a target that isn't there."""
    with app.app_context():
        from src.helpers.outdated_cleanup import remove_target
        from src.models.assessment import Assessment

        project = uuid.uuid4()
        variant = _make_variant(project, "a")
        openssl = _make_finding("CVE-2026-4004", "openssl")
        zlib = _make_finding("CVE-2026-4004", "zlib")
        assessment = Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant.id, openssl.id)],
            commit=True,
        )

        assert remove_target(assessment.id, variant.id, zlib.id) is False
        assert remove_target(uuid.uuid4(), variant.id, openssl.id) is False


def test_split_outdated_keeps_an_assessment_whose_other_targets_are_current(app):
    """A partly-superseded assessment is stripped, not deleted.

    ``annotate_assessments_outdated`` flags the whole assessment as soon as one
    package name goes stale, but the record now covers several targets: the
    ones that are still current must keep the analyst's verdict.
    """
    with app.app_context():
        from src.helpers.outdated_cleanup import _split_outdated_by_target
        from src.models.assessment import Assessment

        project = uuid.uuid4()
        variant_a = _make_variant(project, "a")
        variant_b = _make_variant(project, "b")
        openssl = _make_finding("CVE-2026-4005", "openssl")
        assessment = Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant_a.id, openssl.id), (variant_b.id, openssl.id)],
            commit=True,
        )

        # Only variant A's copy of openssl was superseded.
        fully_stale, partial = _split_outdated_by_target([{
            "uuid": assessment.id,
            "stale_targets": [{"variant_id": str(variant_a.id), "package_name": "openssl"}],
        }])

        assert fully_stale == []
        assert partial == [(assessment.id, variant_a.id, openssl.id)]


def test_split_outdated_deletes_an_assessment_whose_targets_are_all_stale(app):
    """Every target superseded → whole-record delete, as before multi-target."""
    with app.app_context():
        from src.helpers.outdated_cleanup import _split_outdated_by_target
        from src.models.assessment import Assessment

        project = uuid.uuid4()
        variant_a = _make_variant(project, "a")
        variant_b = _make_variant(project, "b")
        openssl = _make_finding("CVE-2026-4006", "openssl")
        assessment = Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant_a.id, openssl.id), (variant_b.id, openssl.id)],
            commit=True,
        )

        fully_stale, partial = _split_outdated_by_target([{
            "uuid": assessment.id,
            "stale_targets": [
                {"variant_id": str(variant_a.id), "package_name": "openssl"},
                {"variant_id": str(variant_b.id), "package_name": "openssl"},
            ],
        }])

        assert fully_stale == [assessment.id]
        assert partial == []


def test_split_outdated_falls_back_to_whole_delete_without_target_detail(app):
    """No per-target detail → pre-multi-target behaviour (delete the record)."""
    with app.app_context():
        from src.helpers.outdated_cleanup import _split_outdated_by_target
        from src.models.assessment import Assessment

        project = uuid.uuid4()
        variant = _make_variant(project, "a")
        openssl = _make_finding("CVE-2026-4007", "openssl")
        assessment = Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant.id, openssl.id)],
            commit=True,
        )

        fully_stale, partial = _split_outdated_by_target([
            {"uuid": assessment.id, "stale_targets": []},
        ])

        assert fully_stale == [assessment.id]
        assert partial == []


def test_delete_outdated_data_strips_stale_targets_without_losing_the_verdict(app):
    """The public entry point keeps a partly-stale assessment alive."""
    with app.app_context():
        from unittest.mock import patch

        from src.extensions import db
        from src.helpers import outdated_cleanup
        from src.models.assessment import Assessment

        project = uuid.uuid4()
        variant_a = _make_variant(project, "a")
        variant_b = _make_variant(project, "b")
        openssl = _make_finding("CVE-2026-4008", "openssl")
        assessment = Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant_a.id, openssl.id), (variant_b.id, openssl.id)],
            commit=True,
        )
        assessment_id = assessment.id

        outdated = [{
            "id": str(assessment_id),
            "uuid": assessment_id,
            "finding_ids": [],
            "stale_targets": [{"variant_id": str(variant_a.id), "package_name": "openssl"}],
        }]
        with patch.object(outdated_cleanup, "_outdated_assessments", return_value=outdated):
            result = outdated_cleanup.delete_outdated_data()

        assert result["assessments_deleted"] == 0
        assert result["assessment_targets_removed"] == 1
        survivor = db.session.get(Assessment, assessment_id)
        assert survivor is not None
        assert survivor.targets == [(variant_b.id, openssl.id)]

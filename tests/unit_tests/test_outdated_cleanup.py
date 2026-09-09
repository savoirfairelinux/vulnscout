# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for PR-B's target-join conversion of ``src/helpers/outdated_cleanup.py``.

The cleanup module reaches an assessment's variant and finding through its
``assessment_targets`` rows instead of the scalar ``Assessment.variant_id`` /
``Assessment.finding_id`` columns.  These are *delete* paths, so three
properties have to hold at once:

1. **Equivalence** — on data written through the ordinary write paths, the
   target-joined queries return exactly what the scalar ones at ``ba8c3978``
   returned.  The oracles below are line-for-line restatements of that code.
2. **Reach** — an assessment held only by its target row (the PR-D shape,
   simulated here by stripping the mirrored scalars from a committed row,
   since ``uq_assessment_targets_assessment_id`` forbids a second target) is
   still found by every migrated site.
3. **No leak, no over-delete** — the one shape PR-A still writes without a
   target row (the variant-less custom-data import: NULL ``variant_id``,
   non-NULL ``finding_id``) must keep being collected by the delete paths and
   must keep protecting its finding from the orphan reaper.  Nothing may be
   left dangling either: bulk DELETE bypasses the mapper events that reap
   target rows.
"""

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


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------

def _variant(project_id: uuid.UUID, name: str):
    from src.models.variant import Variant

    return Variant.create(name=name, project_id=project_id)


def _finding(vuln_id: str, pkg_name: str, version: str = "1.0.0"):
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability

    vuln = db.session.get(Vulnerability, vuln_id.upper()) or Vulnerability.create_record(id=vuln_id)
    pkg = Package.find_or_create(pkg_name, version)
    db.session.commit()
    return Finding.get_or_create(pkg.id, vuln.id)


def _sbom_scan(variant_id: uuid.UUID, packages, name: str = "sbom"):
    """Create an SBOM scan for *variant_id* listing *packages*."""
    from src.extensions import db
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.scan import Scan

    scan = Scan.create(name, variant_id, scan_type="sbom")
    document = SBOMDocument.create(f"/{name}.json", "spdx", scan.id)
    for package in packages:
        SBOMPackage.create(document.id, package.id)
    db.session.commit()
    return scan


def _custom_assessment(variant_id: uuid.UUID, finding_id: uuid.UUID):
    from src.extensions import db
    from src.models.assessment import Assessment

    assessment = Assessment.create(
        status="not_affected", origin="custom",
        targets=[(variant_id, finding_id)],
    )
    db.session.commit()
    return assessment


def _strip_scalar_mirror(assessment_id: uuid.UUID) -> None:
    """Clear the mirrored scalar columns, leaving only the target row.

    This is the PR-D row shape.  Reached through Core SQL rather than the ORM
    so the model's mirroring logic cannot put the columns back.
    """
    from src.extensions import db
    from src.models.assessment import Assessment

    db.session.execute(
        db.update(Assessment)
        .where(Assessment.id == assessment_id)
        .values(variant_id=None, finding_id=None)
    )
    db.session.commit()
    db.session.expire_all()


def _drop_target_rows(assessment_id: uuid.UUID) -> None:
    """Leave the scalar mirror alone and remove the target rows.

    This is the legacy target-less shape PR-A still accepts: the variant-less
    custom-data import writes ``finding_id`` with a NULL ``variant_id``, and a
    target row cannot exist for it because ``variant_id`` is part of the
    target's primary key.  Written here through Core SQL because
    ``Assessment.create`` refuses to produce it directly.
    """
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget

    db.session.execute(
        db.delete(AssessmentTarget).where(AssessmentTarget.assessment_id == assessment_id)
    )
    db.session.execute(
        db.update(Assessment).where(Assessment.id == assessment_id).values(variant_id=None)
    )
    db.session.commit()
    db.session.expire_all()


def _dangle_target(assessment_id: uuid.UUID) -> None:
    """Delete the assessment row only, leaving its target row behind.

    This is the residue a PR-A deployment produces: ``delete_outdated_data``
    and ``delete_orphaned_vulnerabilities`` bulk-DELETE assessments, and Core
    DML fires none of the mapper events that reap target rows, so every run
    before PR-B left one dangling ``assessment_targets`` row per deleted
    assessment.  Such a row names an assessment that no longer exists.
    """
    from src.extensions import db
    from src.models.assessment import Assessment

    db.session.execute(db.delete(Assessment).where(Assessment.id == assessment_id))
    db.session.commit()
    db.session.expire_all()


def _fetch(model, primary_key):
    """Re-read a row after a bulk DELETE.

    ``db.session.get`` would otherwise try to refresh the stale instance the
    identity map still holds and raise ``ObjectDeletedError``; expunging first
    forces a fresh SELECT, which is what these assertions are about.
    """
    from src.extensions import db

    db.session.expunge_all()
    return db.session.get(model, primary_key)


def _target_rows():
    from src.extensions import db
    from src.models.assessment_target import AssessmentTarget

    return sorted(
        db.session.execute(
            db.select(
                AssessmentTarget.assessment_id,
                AssessmentTarget.variant_id,
                AssessmentTarget.finding_id,
            )
        ).all()
    )


# ---------------------------------------------------------------------------
# Oracles: the queries exactly as they stood at ba8c3978, before this task.
# ---------------------------------------------------------------------------

def _scalar_outdated_assessments():
    """Pre-PR-B :func:`_outdated_assessments`, kept as the equivalence oracle."""
    from src.extensions import db
    from src.helpers.assessment_staleness import annotate_assessments_outdated
    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.package import Package

    rows = db.session.execute(
        db.select(
            Assessment.id,
            Assessment.origin,
            Assessment.variant_id,
            Assessment.finding_id,
            Finding.vulnerability_id,
            Package.name,
            Package.version,
            Package.supplier,
        )
        .outerjoin(Finding, Finding.id == Assessment.finding_id)
        .outerjoin(Package, Package.id == Finding.package_id)
        .where(Assessment.origin == "custom", Assessment.variant_id.is_not(None))
    )
    assessments: list[dict] = []
    ids_by_string: dict[str, uuid.UUID] = {}
    for assessment_id, origin, variant_id, finding_id, vulnerability_id, name, version, supplier in rows:
        package_id = f"{name}@{version}" if name is not None else ""
        if package_id and supplier:
            package_id += f"::{supplier}"
        assessments.append({
            "id": str(assessment_id),
            "origin": origin,
            "variant_id": str(variant_id),
            "finding_id": finding_id,
            "vuln_id": vulnerability_id or "",
            "packages": [package_id] if package_id else [],
        })
        ids_by_string[str(assessment_id)] = assessment_id
    annotate_assessments_outdated(assessments)
    return [
        {**assessment, "uuid": ids_by_string[assessment["id"]]}
        for assessment in assessments
        if assessment["outdated"]
    ]


def _scalar_orphan_finding_ids(finding_ids):
    """Pre-PR-B :func:`_delete_orphaned_findings` selection, without the delete."""
    from src.extensions import db
    from src.models.finding import Finding

    return sorted(db.session.execute(
        db.select(Finding.id)
        .where(Finding.id.in_(finding_ids))
        .where(~Finding.observations.any())
        .where(~Finding.assessments.any())
        .where(~Finding.time_estimates.any())
    ).scalars(), key=str)


def _scalar_assessment_counts(vulnerability_ids):
    """Pre-PR-B assessment count of :func:`orphaned_vulnerabilities_preview`."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.finding import Finding

    return {
        vulnerability_id: count
        for vulnerability_id, count in db.session.execute(
            db.select(Finding.vulnerability_id, db.func.count(Assessment.id))
            .join(Assessment, Assessment.finding_id == Finding.id)
            .where(Finding.vulnerability_id.in_(vulnerability_ids))
            .group_by(Finding.vulnerability_id)
        ).all()
    }


def _scalar_assessment_ids_for_findings(finding_ids):
    """Pre-PR-B assessment selection of :func:`delete_orphaned_vulnerabilities`."""
    from src.extensions import db
    from src.models.assessment import Assessment

    return set(db.session.execute(
        db.select(Assessment.id).where(Assessment.finding_id.in_(finding_ids))
    ).scalars())


# ---------------------------------------------------------------------------
# Scenario: one variant whose openssl went stale, one whose openssl is current.
# ---------------------------------------------------------------------------

def _staleness_scenario():
    """Seed two variants of one project, only the first of which went stale.

    ``stale`` runs openssl 2.0.0 — and is still affected by the same CVE
    there, which is what makes 2.0.0 supersede the analyst's verdict on
    1.0.0 — so its assessment is outdated.  ``current`` still runs openssl
    1.0.0, so its assessment, on the very same finding, is not.  Dropping the
    variant half of any join therefore changes the answer.
    """
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.project import Project

    project = Project.create(name="cleanup")
    stale_variant = _variant(project.id, "stale")
    current_variant = _variant(project.id, "current")

    old_finding = _finding("CVE-2026-8000", "openssl", "1.0.0")
    new_package = Package.find_or_create("openssl", "2.0.0")
    db.session.commit()
    new_finding = Finding.get_or_create(new_package.id, "CVE-2026-8000")
    db.session.commit()

    stale_scan = _sbom_scan(stale_variant.id, [new_package], name="stale-sbom")
    Observation.create(finding_id=new_finding.id, scan_id=stale_scan.id)
    db.session.commit()
    _sbom_scan(current_variant.id, [db.session.get(Package, old_finding.package_id)],
               name="current-sbom")

    stale_assessment = _custom_assessment(stale_variant.id, old_finding.id)
    current_assessment = _custom_assessment(current_variant.id, old_finding.id)
    return {
        "stale_variant": stale_variant.id,
        "current_variant": current_variant.id,
        "finding": old_finding.id,
        "new_finding": new_finding.id,
        "stale_assessment": stale_assessment.id,
        "current_assessment": current_assessment.id,
    }


class TestOutdatedAssessments:
    """``_outdated_assessments`` reads variant and finding from the target row."""

    def test_matches_the_scalar_query_on_mirrored_data(self, app):
        with app.app_context():
            from src.helpers.outdated_cleanup import _outdated_assessments

            ids = _staleness_scenario()

            oracle = _scalar_outdated_assessments()
            migrated = _outdated_assessments()

            assert [a["uuid"] for a in oracle] == [ids["stale_assessment"]]
            assert [a["uuid"] for a in migrated] == [ids["stale_assessment"]]
            assert [a["variant_id"] for a in migrated] == [str(ids["stale_variant"])]
            assert [a["finding_id"] for a in migrated] == [ids["finding"]]
            assert [a["packages"] for a in migrated] == [["openssl@1.0.0"]]

    def test_reaches_an_assessment_held_only_by_its_target_row(self, app):
        with app.app_context():
            from src.helpers.outdated_cleanup import _outdated_assessments

            ids = _staleness_scenario()
            _strip_scalar_mirror(ids["stale_assessment"])

            assert [a["uuid"] for a in _scalar_outdated_assessments()] == []
            assert [a["uuid"] for a in _outdated_assessments()] == [ids["stale_assessment"]]

    def test_skips_the_target_less_legacy_assessment(self, app):
        """A variant-less custom-data import has no variant to be stale in."""
        with app.app_context():
            from src.helpers.outdated_cleanup import _outdated_assessments

            ids = _staleness_scenario()
            _drop_target_rows(ids["stale_assessment"])

            assert [a["uuid"] for a in _scalar_outdated_assessments()] == []
            assert [a["uuid"] for a in _outdated_assessments()] == []


class TestDeleteOrphanedFindings:
    """Reachability of a finding runs through targets *and* the scalar mirror."""

    def test_reaps_a_finding_nothing_references(self, app):
        with app.app_context():
            from src.extensions import db
            from src.helpers.outdated_cleanup import _delete_orphaned_findings
            from src.models.finding import Finding
            from src.models.project import Project

            _variant(Project.create(name="orphans").id, "a")
            orphan = _finding("CVE-2026-8010", "curl")

            assert _scalar_orphan_finding_ids({orphan.id}) == [orphan.id]
            assert _delete_orphaned_findings({orphan.id}) == (1, {"CVE-2026-8010"})
            assert _fetch(Finding, orphan.id) is None

    def test_keeps_a_finding_reached_only_by_a_target_row(self, app):
        with app.app_context():
            from src.extensions import db
            from src.helpers.outdated_cleanup import _delete_orphaned_findings
            from src.models.finding import Finding
            from src.models.project import Project

            variant = _variant(Project.create(name="orphans").id, "a")
            held = _finding("CVE-2026-8011", "openssl")
            assessment = _custom_assessment(variant.id, held.id)
            _strip_scalar_mirror(assessment.id)

            # The pre-PR-B query saw nothing holding it and would have deleted it.
            assert _scalar_orphan_finding_ids({held.id}) == [held.id]
            assert _delete_orphaned_findings({held.id}) == (0, set())
            assert _fetch(Finding, held.id) is not None

    def test_keeps_a_finding_reached_only_by_the_scalar_mirror(self, app):
        """The target-less legacy shape still protects its finding."""
        with app.app_context():
            from src.extensions import db
            from src.helpers.outdated_cleanup import _delete_orphaned_findings
            from src.models.finding import Finding
            from src.models.project import Project

            variant = _variant(Project.create(name="orphans").id, "a")
            held = _finding("CVE-2026-8012", "zlib")
            assessment = _custom_assessment(variant.id, held.id)
            _drop_target_rows(assessment.id)

            assert _scalar_orphan_finding_ids({held.id}) == []
            assert _delete_orphaned_findings({held.id}) == (0, set())
            assert _fetch(Finding, held.id) is not None

    def test_reaps_a_finding_held_only_by_a_dangling_target_row(self, app):
        """A target row whose assessment is gone must not hold a finding alive.

        This is the shape an upgraded database carries: PR-A ran its bulk
        assessment DELETE without reaping targets.  ``ba8c3978`` reaped such a
        finding, so PR-B must too.
        """
        with app.app_context():
            from src.helpers.outdated_cleanup import _delete_orphaned_findings
            from src.models.finding import Finding
            from src.models.project import Project

            variant = _variant(Project.create(name="orphans").id, "a")
            orphan = _finding("CVE-2026-8013", "busybox")
            assessment = _custom_assessment(variant.id, orphan.id)
            _dangle_target(assessment.id)

            assert _target_rows() == [(assessment.id, variant.id, orphan.id)]
            assert _scalar_orphan_finding_ids({orphan.id}) == [orphan.id]
            assert _delete_orphaned_findings({orphan.id}) == (1, {"CVE-2026-8013"})
            assert _fetch(Finding, orphan.id) is None
            # The residue itself survives, exactly as it did at ba8c3978.
            # Purging pre-existing dangling rows is a data repair, deferred to
            # PR-D with the mirror columns.
            assert _target_rows() == [(assessment.id, variant.id, orphan.id)]


class TestDeleteOutdatedData:
    """The bulk assessment delete takes the target rows with it."""

    def test_deletes_the_outdated_assessment_and_its_target_row(self, app):
        with app.app_context():
            from src.extensions import db
            from src.helpers.outdated_cleanup import delete_outdated_data
            from src.models.assessment import Assessment

            ids = _staleness_scenario()

            result = delete_outdated_data()

            assert result["assessments_deleted"] == 1
            assert _fetch(Assessment, ids["stale_assessment"]) is None
            assert _fetch(Assessment, ids["current_assessment"]) is not None
            # No target row may survive its assessment: a dangling one would
            # keep the deleted assessment's finding looking referenced.
            assert _target_rows() == [
                (ids["current_assessment"], ids["current_variant"], ids["finding"]),
            ]

    def test_reaps_the_finding_the_deleted_assessment_held(self, app):
        with app.app_context():
            from src.extensions import db
            from src.helpers.outdated_cleanup import delete_outdated_data
            from src.models.finding import Finding
            from src.models.observation import Observation
            from src.models.package import Package
            from src.models.project import Project

            project = Project.create(name="cleanup-solo")
            variant = _variant(project.id, "stale")
            old_finding_id = _finding("CVE-2026-8020", "openssl", "1.0.0").id
            new_package = Package.find_or_create("openssl", "2.0.0")
            db.session.commit()
            new_finding = Finding.get_or_create(new_package.id, "CVE-2026-8020")
            db.session.commit()
            scan = _sbom_scan(variant.id, [new_package], name="stale-sbom")
            Observation.create(finding_id=new_finding.id, scan_id=scan.id)
            db.session.commit()
            _custom_assessment(variant.id, old_finding_id)

            result = delete_outdated_data()

            assert result["assessments_deleted"] == 1
            assert result["findings_deleted"] == 1
            assert _fetch(Finding, old_finding_id) is None
            assert _target_rows() == []


class TestOrphanedVulnerabilitiesPreview:
    """Assessment counts are aggregated through the target rows."""

    def test_matches_the_scalar_count_on_mirrored_data(self, app):
        with app.app_context():
            from src.helpers.outdated_cleanup import orphaned_vulnerabilities_preview
            from src.models.project import Project

            project = Project.create(name="preview")
            variant_a = _variant(project.id, "a")
            variant_b = _variant(project.id, "b")
            finding = _finding("CVE-2026-8030", "openssl")
            other = _finding("CVE-2026-8031", "zlib")
            _custom_assessment(variant_a.id, finding.id)
            _custom_assessment(variant_b.id, finding.id)
            _custom_assessment(variant_a.id, other.id)

            assert _scalar_assessment_counts(["CVE-2026-8030", "CVE-2026-8031"]) == {
                "CVE-2026-8030": 2, "CVE-2026-8031": 1,
            }
            assert orphaned_vulnerabilities_preview() == [
                {"id": "CVE-2026-8030", "assessments": 2},
                {"id": "CVE-2026-8031", "assessments": 1},
            ]

    def test_counts_an_assessment_held_only_by_its_target_row(self, app):
        with app.app_context():
            from src.helpers.outdated_cleanup import orphaned_vulnerabilities_preview
            from src.models.project import Project

            variant = _variant(Project.create(name="preview").id, "a")
            finding = _finding("CVE-2026-8032", "openssl")
            assessment = _custom_assessment(variant.id, finding.id)
            _strip_scalar_mirror(assessment.id)

            assert _scalar_assessment_counts(["CVE-2026-8032"]) == {}
            assert orphaned_vulnerabilities_preview() == [
                {"id": "CVE-2026-8032", "assessments": 1},
            ]

    def test_counts_the_target_less_legacy_assessment(self, app):
        with app.app_context():
            from src.helpers.outdated_cleanup import orphaned_vulnerabilities_preview
            from src.models.project import Project

            variant = _variant(Project.create(name="preview").id, "a")
            finding = _finding("CVE-2026-8033", "openssl")
            assessment = _custom_assessment(variant.id, finding.id)
            _drop_target_rows(assessment.id)

            assert _scalar_assessment_counts(["CVE-2026-8033"]) == {"CVE-2026-8033": 1}
            assert orphaned_vulnerabilities_preview() == [
                {"id": "CVE-2026-8033", "assessments": 1},
            ]


class TestDeleteOrphanedVulnerabilities:
    """The assessments to delete are collected through the target rows."""

    def test_matches_the_scalar_selection_on_mirrored_data(self, app):
        with app.app_context():
            from src.extensions import db
            from src.helpers.outdated_cleanup import delete_orphaned_vulnerabilities
            from src.models.assessment import Assessment
            from src.models.finding import Finding
            from src.models.project import Project

            project = Project.create(name="orphan-vulns")
            variant = _variant(project.id, "a")
            finding_id = _finding("CVE-2026-8040", "openssl").id
            assessment_id = _custom_assessment(variant.id, finding_id).id

            assert _scalar_assessment_ids_for_findings([finding_id]) == {assessment_id}

            result = delete_orphaned_vulnerabilities()

            assert result == {
                "vulnerabilities_deleted": 1, "assessments_deleted": 1, "findings_deleted": 1,
            }
            assert _fetch(Assessment, assessment_id) is None
            assert _fetch(Finding, finding_id) is None
            assert _target_rows() == []

    def test_deletes_an_assessment_held_only_by_its_target_row(self, app):
        with app.app_context():
            from src.extensions import db
            from src.helpers.outdated_cleanup import delete_orphaned_vulnerabilities
            from src.models.assessment import Assessment
            from src.models.project import Project

            variant = _variant(Project.create(name="orphan-vulns").id, "a")
            finding_id = _finding("CVE-2026-8041", "openssl").id
            assessment_id = _custom_assessment(variant.id, finding_id).id
            _strip_scalar_mirror(assessment_id)

            # The pre-PR-B selection could not see it, and left it behind
            # pointing at a deleted finding.
            assert _scalar_assessment_ids_for_findings([finding_id]) == set()

            result = delete_orphaned_vulnerabilities()

            assert result == {
                "vulnerabilities_deleted": 1, "assessments_deleted": 1, "findings_deleted": 1,
            }
            assert _fetch(Assessment, assessment_id) is None
            assert _target_rows() == []

    def test_deletes_the_target_less_legacy_assessment(self, app):
        """The variant-less custom-data import shape is still collected."""
        with app.app_context():
            from src.extensions import db
            from src.helpers.outdated_cleanup import delete_orphaned_vulnerabilities
            from src.models.assessment import Assessment
            from src.models.project import Project

            variant = _variant(Project.create(name="orphan-vulns").id, "a")
            finding_id = _finding("CVE-2026-8042", "openssl").id
            assessment_id = _custom_assessment(variant.id, finding_id).id
            _drop_target_rows(assessment_id)

            assert _scalar_assessment_ids_for_findings([finding_id]) == {assessment_id}

            result = delete_orphaned_vulnerabilities()

            assert result == {
                "vulnerabilities_deleted": 1, "assessments_deleted": 1, "findings_deleted": 1,
            }
            assert _fetch(Assessment, assessment_id) is None

    def test_does_not_count_a_dangling_target_row_as_an_assessment(self, app):
        """A target row whose assessment is gone must not inflate the count."""
        with app.app_context():
            from src.helpers.outdated_cleanup import delete_orphaned_vulnerabilities
            from src.models.assessment import Assessment
            from src.models.finding import Finding
            from src.models.project import Project

            variant = _variant(Project.create(name="orphan-vulns").id, "a")
            finding_id = _finding("CVE-2026-8045", "openssl").id
            live_id = _custom_assessment(variant.id, finding_id).id
            dead_id = _custom_assessment(variant.id, finding_id).id
            _dangle_target(dead_id)

            # ba8c3978 collected assessments by the scalar mirror, so the
            # deleted assessment's residue contributed nothing.
            assert _scalar_assessment_ids_for_findings([finding_id]) == {live_id}
            assert _target_rows() == sorted([
                (live_id, variant.id, finding_id),
                (dead_id, variant.id, finding_id),
            ])

            result = delete_orphaned_vulnerabilities()

            assert result == {
                "vulnerabilities_deleted": 1, "assessments_deleted": 1, "findings_deleted": 1,
            }
            assert _fetch(Assessment, live_id) is None
            assert _fetch(Finding, finding_id) is None
            assert _target_rows() == []

    def test_leaves_an_assessment_of_a_different_finding_alone(self, app):
            from src.extensions import db
            from src.helpers.outdated_cleanup import delete_orphaned_vulnerabilities
            from src.models.assessment import Assessment
            from src.models.observation import Observation
            from src.models.project import Project
            from src.models.scan import Scan

            project = Project.create(name="orphan-vulns")
            variant_id = _variant(project.id, "a").id
            doomed_id = _finding("CVE-2026-8043", "openssl").id
            kept_id = _finding("CVE-2026-8044", "zlib").id
            doomed_assessment_id = _custom_assessment(variant_id, doomed_id).id
            kept_assessment_id = _custom_assessment(variant_id, kept_id).id
            scan = Scan.create("tool", variant_id, scan_type="tool")
            Observation.create(finding_id=kept_id, scan_id=scan.id)
            db.session.commit()

            result = delete_orphaned_vulnerabilities()

            assert result == {
                "vulnerabilities_deleted": 1, "assessments_deleted": 1, "findings_deleted": 1,
            }
            assert _fetch(Assessment, doomed_assessment_id) is None
            assert _fetch(Assessment, kept_assessment_id) is not None
            assert _target_rows() == [(kept_assessment_id, variant_id, kept_id)]

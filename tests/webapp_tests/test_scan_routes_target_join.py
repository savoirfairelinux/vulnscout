# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for PR-B's target-join conversion of ``src/routes/scans.py``.

Two sites there stopped reading the scalar ``Assessment.variant_id`` /
``Assessment.finding_id`` columns and join ``assessment_targets`` instead: the
import de-duplication (``_existing_assessment_identities``) and the
newly-detected assessment list of a tool scan's diff.

``uq_assessment_targets_assessment_id`` holds every assessment to exactly one
target row mirroring those scalars, so the conversion has to be
behaviour-neutral; stripping the mirror from a committed row is how a
single-target world exhibits the PR-D shape the join must still reach.
"""

import os
import uuid

import pytest


@pytest.fixture()
def app(tmp_path):
    from src.bin.webapp import create_app
    from src.extensions import db as _db

    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


def _finding(vuln_id: str, pkg_name: str, version: str = "1.0.0"):
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability

    vuln = db.session.get(Vulnerability, vuln_id.upper()) or Vulnerability.create_record(id=vuln_id)
    package = Package.find_or_create(pkg_name, version)
    db.session.commit()
    return Finding.get_or_create(package.id, vuln.id)


def _strip_scalar_mirror(assessment_id: uuid.UUID) -> None:
    """Clear the mirrored scalar columns, leaving only the target row."""
    from src.extensions import db
    from src.models.assessment import Assessment

    db.session.execute(
        db.update(Assessment)
        .where(Assessment.id == assessment_id)
        .values(variant_id=None, finding_id=None)
    )
    db.session.commit()
    db.session.expire_all()


def _scalar_existing_assessment_identities(variant_id, finding_ids):
    """Pre-PR-B ``_existing_assessment_identities``, kept as the oracle."""
    from src.extensions import db
    from src.models.assessment import Assessment

    identities: set[tuple] = set()
    for assessment in db.session.execute(
        db.select(Assessment).where(
            Assessment.variant_id == variant_id,
            Assessment.finding_id.in_(finding_ids),
        )
    ).scalars().all():
        identities.add((
            assessment.finding_id,
            assessment.status or "",
            assessment.simplified_status or "",
            assessment.status_notes or "",
            assessment.justification or "",
            assessment.impact_statement or "",
        ))
    return identities


class TestExistingAssessmentIdentities:
    """The import de-duplication reads its (variant, finding) pair from targets."""

    def _seed(self):
        from src.extensions import db
        from src.models.assessment import Assessment
        from src.models.project import Project
        from src.models.variant import Variant

        project = Project.create(name="import")
        mine = Variant.create(name="mine", project_id=project.id)
        other = Variant.create(name="other", project_id=project.id)
        openssl = _finding("CVE-2026-9000", "openssl")
        zlib = _finding("CVE-2026-9001", "zlib")

        wanted = Assessment.create(
            status="not_affected", origin="custom", status_notes="mine",
            targets=[(mine.id, openssl.id)],
        )
        # Same finding, a different variant: a dropped variant predicate
        # would widen the identity set with this one.
        Assessment.create(
            status="affected", origin="custom", status_notes="theirs",
            targets=[(other.id, openssl.id)],
        )
        # Same variant, a different finding: excluded by the finding filter.
        Assessment.create(
            status="affected", origin="custom", status_notes="elsewhere",
            targets=[(mine.id, zlib.id)],
        )
        db.session.commit()
        return {
            "variant": mine.id, "other_variant": other.id,
            "openssl": openssl.id, "zlib": zlib.id, "assessment": wanted.id,
            "identity": (
                openssl.id, "not_affected", wanted.simplified_status or "", "mine", "", "",
            ),
        }

    def test_matches_the_scalar_query_on_mirrored_data(self, app):
        with app.app_context():
            from src.routes.scans import _existing_assessment_identities

            ids = self._seed()

            oracle = _scalar_existing_assessment_identities(ids["variant"], [ids["openssl"]])
            migrated = _existing_assessment_identities(ids["variant"], [ids["openssl"]])

            assert oracle == {ids["identity"]}
            assert migrated == {ids["identity"]}

    def test_reaches_an_assessment_held_only_by_its_target_row(self, app):
        with app.app_context():
            from src.routes.scans import _existing_assessment_identities

            ids = self._seed()
            _strip_scalar_mirror(ids["assessment"])

            assert _scalar_existing_assessment_identities(
                ids["variant"], [ids["openssl"]]) == set()
            assert _existing_assessment_identities(
                ids["variant"], [ids["openssl"]]) == {ids["identity"]}


class TestNewlyDetectedAssessments:
    """A tool scan's diff lists its new assessments through their target rows."""

    def _seed(self, app):
        import time
        from src.extensions import db
        from src.models.assessment import Assessment
        from src.models.observation import Observation
        from src.models.package import Package
        from src.models.project import Project
        from src.models.sbom_document import SBOMDocument
        from src.models.sbom_package import SBOMPackage
        from src.models.scan import Scan
        from src.models.variant import Variant

        project = Project.create(name="diff")
        variant = Variant.create(name="v", project_id=project.id)

        sbom_scan = Scan.create("sbom", variant.id, scan_type="sbom")
        package = Package.find_or_create("openssl", "1.0.0")
        db.session.commit()
        document = SBOMDocument.create("/sbom.json", "spdx", sbom_scan.id)
        SBOMPackage.create(document.id, package.id)
        db.session.commit()

        time.sleep(0.05)
        # A pre-existing assessment from an earlier tool scan of the same
        # variant.  It belongs to the "before" set, so a join that widened the
        # result set would surface it beside the new one.
        old_scan = Scan.create("nvd", variant.id, scan_type="tool")
        old_scan.scan_source = "nvd"
        old_finding = _finding("CVE-2026-9011", "openssl")
        Observation.create(finding_id=old_finding.id, scan_id=old_scan.id)
        db.session.commit()
        old_assessment = Assessment.create(
            status="affected", origin="nvd", status_notes="old",
            targets=[(variant.id, old_finding.id)],
        )
        old_assessment.timestamp = old_scan.timestamp
        db.session.commit()

        time.sleep(0.05)
        tool_scan = Scan.create("nvd", variant.id, scan_type="tool")
        tool_scan.scan_source = "nvd"
        finding = _finding("CVE-2026-9010", "openssl")
        Observation.create(finding_id=finding.id, scan_id=tool_scan.id)
        db.session.commit()

        assessment = Assessment.create(
            status="not_affected", origin="nvd", status_notes="note",
            targets=[(variant.id, finding.id)],
        )
        assessment.timestamp = tool_scan.timestamp
        db.session.commit()
        return {"tool_scan": str(tool_scan.id), "assessment": assessment.id}

    def test_lists_the_new_assessment(self, app):
        with app.app_context():
            ids = self._seed(app)

        response = app.test_client().get(f"/api/scans/{ids['tool_scan']}/export-diff")

        assert response.status_code == 200
        assert response.get_json()["newly_detected_assessments"] == [{
            "vulnerability_id": "CVE-2026-9010", "status": "not_affected",
            "simplified_status": "Pending Assessment", "justification": "",
            "impact_statement": "", "status_notes": "note",
        }]

    def test_lists_an_assessment_held_only_by_its_target_row(self, app):
        with app.app_context():
            ids = self._seed(app)
            _strip_scalar_mirror(ids["assessment"])

        response = app.test_client().get(f"/api/scans/{ids['tool_scan']}/export-diff")

        assert response.status_code == 200
        assert response.get_json()["newly_detected_assessments"] == [{
            "vulnerability_id": "CVE-2026-9010", "status": "not_affected",
            "simplified_status": "Pending Assessment", "justification": "",
            "impact_statement": "", "status_notes": "note",
        }]

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for Task 7's target-join conversion of the scan queries, diff and
scan command modules.

Assessments are reachable only through their assessment_targets rows now, not
the scalar Assessment.finding_id/variant_id columns.  A genuine multi-target
assessment (created with ``targets=[...]`` and no scalar columns) exercises
every silent-failure site this task converted: the "does this already have a
pending assessment" existence checks in ``_scan_helpers.py`` and
``cmd_vuln_scan.py``, the import-dedup identity lookup in ``scans.py``, and
the global-result assessment query in ``_scan_diff.py``.
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
    from src.models.project import Project
    from src.models.variant import Variant

    project_id = project if isinstance(project, uuid.UUID) else Project.create(name=project).id
    return Variant.create(name=variant_name, project_id=project_id)


def _make_finding(vuln_id: str, pkg_name: str):
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability

    vuln = db.session.get(Vulnerability, vuln_id.upper()) or Vulnerability.create_record(id=vuln_id)
    pkg = Package.create(name=pkg_name, version="1.0.0")
    return Finding.create(package_id=pkg.id, vulnerability_id=vuln.id)


def test_scan_helpers_existence_check_finds_a_multi_target_assessment(app):
    """create_observation_and_assessment must not duplicate a pending
    assessment when the (variant, finding) pair is already covered only by a
    multi-target assessment's target row (no scalar finding_id/variant_id)."""
    with app.app_context():
        from src.extensions import db
        from src.models.assessment import Assessment
        from src.models.scan import Scan
        from src.routes._scan_helpers import create_observation_and_assessment

        project = uuid.uuid4()
        variant = _make_variant(project, "a")
        openssl = _make_finding("CVE-2026-4001", "openssl")
        zlib = _make_finding("CVE-2026-4001", "zlib")
        Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant.id, openssl.id), (variant.id, zlib.id)],
            commit=True,
        )
        scan = Scan.create("s", variant.id, scan_type="tool")

        create_observation_and_assessment(
            openssl, scan, variant.id, "grype", set(), set(),
        )
        db.session.commit()

        assert db.session.query(Assessment).count() == 1


def test_cmd_vuln_scan_existence_check_finds_a_multi_target_assessment(app):
    """_persist_finding (the CLI-command twin of the helper above) must reach
    the same conclusion through assessment_targets."""
    with app.app_context():
        from src.bin.cmd_vuln_scan import _persist_finding
        from src.extensions import db
        from src.models.assessment import Assessment
        from src.models.scan import Scan

        project = uuid.uuid4()
        variant = _make_variant(project, "a")
        openssl = _make_finding("CVE-2026-4002", "openssl")
        zlib = _make_finding("CVE-2026-4002", "zlib")
        Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant.id, openssl.id), (variant.id, zlib.id)],
            commit=True,
        )
        scan = Scan.create("s", variant.id, scan_type="tool")

        _persist_finding(
            openssl.package_id, openssl.vulnerability_id, scan.id, variant.id,
            "nvd", set(), set(),
        )
        db.session.commit()

        assert db.session.query(Assessment).count() == 1


def test_existing_assessment_identities_keys_by_target_finding_id(app):
    """A multi-target assessment has no single finding_id of its own; the
    identity lookup must key off each target's own finding_id instead, or
    every multi-target assessment collapses onto the same identity."""
    with app.app_context():
        from src.models.assessment import Assessment
        from src.routes.scans import _existing_assessment_identities

        project = uuid.uuid4()
        variant = _make_variant(project, "a")
        openssl = _make_finding("CVE-2026-4003", "openssl")
        zlib = _make_finding("CVE-2026-4003", "zlib")
        assessment = Assessment.create(
            status="not_affected", justification="j", impact_statement="i",
            status_notes="n", origin="custom",
            targets=[(variant.id, openssl.id), (variant.id, zlib.id)],
            commit=True,
        )
        # Confirms this assessment exercises the multi-target gap being tested.
        assert len(assessment.target_rows) == 2

        identities = _existing_assessment_identities(
            variant.id, [openssl.id, zlib.id],
        )

        assert (openssl.id, "not_affected", "", "n", "j", "i") in identities
        assert (zlib.id, "not_affected", "", "n", "j", "i") in identities
        assert len(identities) == 2


def test_global_assessment_rows_by_scan_surfaces_a_multi_target_assessment(app):
    """A multi-target assessment (no scalar finding_id/variant_id) must still
    surface in the scan-diff global-result query, not just single-target
    assessments created through the scalar Assessment.create() shortcut."""
    with app.app_context():
        from src.extensions import db
        from src.models.assessment import Assessment
        from src.models.observation import Observation
        from src.models.scan import Scan
        from src.routes._scan_diff import _global_assessment_rows_by_scan

        project = uuid.uuid4()
        variant = _make_variant(project, "a")
        openssl = _make_finding("CVE-2026-4004", "openssl")
        zlib = _make_finding("CVE-2026-4004", "zlib")
        scan = Scan.create("s", variant.id, scan_type="sbom")
        Observation.create(finding_id=openssl.id, scan_id=scan.id)
        db.session.commit()
        Assessment.create(
            status="not_affected", origin="sbom",
            targets=[(variant.id, openssl.id), (variant.id, zlib.id)],
            commit=True,
        )

        rows = _global_assessment_rows_by_scan([scan.id])
        pkg_ids = {pkg for (_aid, pkg) in rows.get(scan.id, [])}

        assert openssl.package_id in pkg_ids

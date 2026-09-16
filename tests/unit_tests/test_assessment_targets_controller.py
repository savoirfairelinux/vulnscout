# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the read path in src/controllers/assessment_targets.py."""

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


def test_a_multi_target_assessment_has_both_targets(app):
    with app.app_context():
        from src.controllers.assessment_targets import annotate_targets
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

        results = annotate_targets([assessment])

        assert len(results) == 1
        assert results[0]["id"] == str(assessment.id)
        # ``package`` is the finding's package string_id ("name@version"), and
        # targets sort by (variant_id, package) — variant ids are random, so
        # compare as a set rather than assuming creation order survives.
        assert {t["package"] for t in results[0]["targets"]} == {
            openssl.package.string_id, zlib.package.string_id}


def test_two_content_identical_assessments_stay_two_entries(app):
    with app.app_context():
        from src.controllers.assessment_targets import annotate_targets
        from src.models.assessment import Assessment

        finding, variant = _make_finding_and_variant()
        one = Assessment.create(status="affected", origin="custom",
                                targets=[(variant.id, finding.id)],
                                commit=True)
        two = Assessment.create(status="affected", origin="custom",
                                targets=[(variant.id, finding.id)],
                                commit=True)

        results = annotate_targets([one, two])

        assert len(results) == 2


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


def test_outdated_is_scoped_to_the_variant_the_package_is_stale_in(app, monkeypatch):
    """A package stale in one variant must not flag the same package elsewhere.

    ``stale_packages`` accumulates across every variant an assessment targets,
    so it cannot answer a per-variant question; ``stale_targets`` keeps the
    variant dimension and is what the flag has to key on.  The annotation is
    injected here so the assertion is about the controller's keying rather
    than about SBOM scan setup.
    """
    with app.app_context():
        from src.controllers import assessment_targets
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
            assessment_targets, "annotate_assessments_outdated", _fake_annotate)

        results = assessment_targets.annotate_targets([assessment])

        outdated_by_variant = {
            t["variant_id"]: t["outdated"] for t in results[0]["targets"]}
        assert outdated_by_variant[str(variant_a.id)] is True
        assert outdated_by_variant[str(variant_b.id)] is False

# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Regression tests for the multi-target assessment refactor.

Each test here pins behaviour that existed before assessments gained
``assessment_targets`` and that the refactor changed by accident:

- a variant-scoped export must not disclose another variant's targets;
- a version-2 export must stay re-importable even when it spans variants;
- ``GET /api/assessments`` must not hide a multi-target assessment's coverage;
- the pending-AI duplicate guard must fire for every covered variant.
"""

import json
import os
import uuid
from datetime import datetime, timezone

import pytest

from src.bin.webapp import create_app
from src.extensions import db
from . import write_demo_files, setup_demo_db

PROJECT_UUID = uuid.UUID("11111111-1111-1111-1111-111111111111")
VARIANT_A = uuid.UUID("22222222-2222-2222-2222-222222222222")
SCAN_A = uuid.UUID("33333333-3333-3333-3333-333333333333")
VARIANT_B = uuid.UUID("55555555-5555-5555-5555-555555555555")
SCAN_B = uuid.UUID("66666666-6666-6666-6666-666666666666")

VULN_ID = "CVE-2020-35492"
PKG_A = "cairo@1.16.0"
PKG_B = "abc@1.2.3"


@pytest.fixture()
def init_files(tmp_path):
    files = {
        "status": tmp_path / "status.txt",
        "packages": tmp_path / "packages-merged.json",
        "vulnerabilities": tmp_path / "vulnerabilities-merged.json",
        "assessments": tmp_path / "assessments-merged.json",
        "openvex": tmp_path / "openvex.json",
        "time_estimates": tmp_path / "time_estimates.json",
    }
    write_demo_files(files)
    return files


@pytest.fixture()
def app(init_files):
    """App with two variants of one project, each observing its own package.

    Variant A observes ``cairo``, variant B observes ``abc``; both for the same
    CVE, which is what lets one assessment legitimately target both.
    """
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": init_files["status"],
            "OPENVEX_FILE": str(init_files["openvex"]),
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        setup_demo_db(application, extra_packages=[PKG_B])
        with application.app_context():
            from src.models.finding import Finding
            from src.models.observation import Observation
            from src.models.package import Package
            from src.models.scan import Scan
            from src.models.variant import Variant

            db.session.add(Variant(id=VARIANT_B, name="second", project_id=PROJECT_UUID))
            db.session.add(Scan(id=SCAN_B, variant_id=VARIANT_B))
            db.session.commit()

            package_b = Package.get_by_string_id(PKG_B)
            assert package_b is not None
            finding_b = Finding.get_or_create(package_b.id, VULN_ID)
            Observation.create(finding_b.id, SCAN_B, commit=False)
            db.session.commit()
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


def _finding_id(package_string_id):
    from src.models.finding import Finding
    from src.models.package import Package

    package = Package.get_by_string_id(package_string_id)
    assert package is not None
    finding = Finding.get_by_package_and_vulnerability(package_string_id, VULN_ID)
    if finding is None:
        finding = Finding.get_or_create(package.id, VULN_ID)
    return finding.id


def _make_cross_variant_assessment(origin="custom", status="fixed"):
    """One assessment covering (variant A, cairo) and (variant B, abc)."""
    from src.models.assessment import Assessment as DBAssessment

    return DBAssessment.create(
        status=status,
        origin=origin,
        simplified_status="Fixed",
        timestamp=datetime(2024, 6, 8, 12, 0, 0, tzinfo=timezone.utc),
        targets=[
            (VARIANT_A, _finding_id(PKG_A)),
            (VARIANT_B, _finding_id(PKG_B)),
        ],
    )


# ── R3: a variant-scoped export must not leak other variants ──────────────

def test_scoped_export_excludes_out_of_scope_targets(app):
    from src.helpers.assessment_io import build_custom_data_export

    with app.app_context():
        _make_cross_variant_assessment()
        exported = build_custom_data_export([VARIANT_A])

    assert len(exported["assessments"]) == 1
    record = exported["assessments"][0]
    assert [t["variant_id"] for t in record["targets"]] == [str(VARIANT_A)]
    assert [t["package"] for t in record["targets"]] == [PKG_A]
    # packages and the scalar variant_id describe the same subset as targets.
    assert record["packages"] == [PKG_A]
    assert record["variant_id"] == str(VARIANT_A)


def test_scoped_export_of_the_other_variant_is_symmetric(app):
    from src.helpers.assessment_io import build_custom_data_export

    with app.app_context():
        _make_cross_variant_assessment()
        exported = build_custom_data_export([VARIANT_B])

    record = exported["assessments"][0]
    assert [t["variant_id"] for t in record["targets"]] == [str(VARIANT_B)]
    assert record["packages"] == [PKG_B]
    assert record["variant_id"] == str(VARIANT_B)


def test_unscoped_export_keeps_every_target(app):
    """A full backup stays lossless: only the *scoped* export is truncated."""
    from src.helpers.assessment_io import build_custom_data_export

    with app.app_context():
        _make_cross_variant_assessment()
        exported = build_custom_data_export(None)

    record = exported["assessments"][0]
    assert {t["variant_id"] for t in record["targets"]} == {str(VARIANT_A), str(VARIANT_B)}
    assert sorted(record["packages"]) == sorted([PKG_A, PKG_B])
    # No single variant covers it, so the legacy scalar field is null.
    assert record["variant_id"] is None


# ── R4: VulnScout must accept its own version-2 export ────────────────────

def test_detect_format_accepts_v2_export_spanning_variants(app):
    from src.helpers.assessment_io import (
        build_custom_data_export,
        detect_review_export_format,
    )

    with app.app_context():
        _make_cross_variant_assessment()
        exported = build_custom_data_export(None)

    assert exported["assessments"][0]["variant_id"] is None
    # Round-trip through JSON: this is what export-update/import receive.
    assert detect_review_export_format(json.loads(json.dumps(exported))) == "custom"


def test_detect_format_still_rejects_v1_record_without_variant(app):
    from src.helpers.assessment_io import detect_review_export_format

    doc = {
        "version": 1,
        "assessments": [{"variant_id": None, "vuln_id": VULN_ID, "packages": []}],
        "ai_assessments": [], "cvss": [], "time_estimates": [],
    }
    with pytest.raises(ValueError):
        detect_review_export_format(doc)


def test_detect_format_rejects_v2_record_with_unusable_targets(app):
    from src.helpers.assessment_io import detect_review_export_format

    doc = {
        "version": 2,
        # A target that names no variant at all cannot be resolved on import.
        "assessments": [{
            "variant_id": None, "vuln_id": VULN_ID, "packages": [],
            "targets": [{"package": PKG_A}],
        }],
        "ai_assessments": [], "cvss": [], "time_estimates": [],
    }
    with pytest.raises(ValueError):
        detect_review_export_format(doc)


def test_scoped_export_round_trips_through_import(app):
    """The scoped export must remain importable, restoring only its targets."""
    from src.helpers.assessment_io import (
        build_custom_data_export,
        build_variant_by_name_map,
        detect_review_export_format,
        import_custom_data,
    )
    from src.models.assessment import Assessment as DBAssessment

    with app.app_context():
        _make_cross_variant_assessment()
        exported = json.loads(json.dumps(build_custom_data_export([VARIANT_A])))
        assert detect_review_export_format(exported) == "custom"

        for assessment in DBAssessment.get_by_vulnerability(VULN_ID):
            if assessment.origin == "custom":
                assessment.delete()

        result = import_custom_data(
            exported,
            build_variant_by_name_map(PROJECT_UUID),
            use_original_timestamps=True,
        )
        assert not result["errors"], result["errors"]

        restored = [
            a for a in DBAssessment.get_by_vulnerability(VULN_ID)
            if a.origin == "custom"
        ]
        assert len(restored) == 1
        assert {t.variant_id for t in restored[0].target_rows} == {VARIANT_A}


# ── R5: the list endpoint must report the whole target set ────────────────

def test_list_endpoint_reports_every_target(client, app):
    with app.app_context():
        assessment_id = str(_make_cross_variant_assessment().id)

    listed = json.loads(client.get("/api/assessments?format=list").data)
    record = next(a for a in listed if a["id"] == assessment_id)

    assert sorted(record["packages"]) == sorted([PKG_A, PKG_B])
    assert record["variant_ids"] == sorted([str(VARIANT_A), str(VARIANT_B)])
    # No single variant covers it, matching Assessment.to_dict's semantics.
    assert record["variant_id"] is None


def test_list_endpoint_scoped_to_variant_reports_only_that_variant(client, app):
    with app.app_context():
        assessment_id = str(_make_cross_variant_assessment().id)

    listed = json.loads(client.get(f"/api/assessments?format=list&variant_id={VARIANT_A}").data)
    record = next(a for a in listed if a["id"] == assessment_id)

    assert record["packages"] == [PKG_A]
    assert record["variant_ids"] == [str(VARIANT_A)]
    assert record["variant_id"] == str(VARIANT_A)


def test_list_endpoint_emits_one_record_per_assessment(client, app):
    """Folding targets back together must not duplicate the assessment."""
    with app.app_context():
        assessment_id = str(_make_cross_variant_assessment().id)

    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert [a["id"] for a in listed].count(assessment_id) == 1

    keyed = json.loads(client.get("/api/assessments?format=dict").data)
    assert sorted(keyed[assessment_id]["packages"]) == sorted([PKG_A, PKG_B])


# ── R2: the pending-AI guard must cover every targeted variant ────────────

def test_covers_variant_matches_each_target(app):
    with app.app_context():
        assessment = _make_cross_variant_assessment()
        assert assessment.covers_variant(VARIANT_A)
        assert assessment.covers_variant(VARIANT_B)
        assert not assessment.covers_variant(uuid.uuid4())
        assert not assessment.covers_variant(None)
        # single_variant_id collapses to None here -- the bug this replaces.
        assert assessment.single_variant_id is None


def test_covers_variant_treats_empty_target_set_as_unscoped(app):
    """The legacy record seeded with no targets keeps its old NULL semantics."""
    from src.models.assessment import Assessment as DBAssessment

    with app.app_context():
        legacy = DBAssessment.get_by_id("da4d18f0-d89e-4d54-819d-86fc884cc737")
        assert legacy is not None
        assert legacy.target_rows == []
        assert legacy.covers_variant(None)
        assert not legacy.covers_variant(VARIANT_A)


def test_pending_ai_guard_blocks_a_variant_already_covered(client, app):
    with app.app_context():
        _make_cross_variant_assessment(origin="ai", status="under_investigation")

    # Variant A is one of the two targets, so a second AI suggestion for it
    # must be refused exactly as it was when rows were per-variant.
    response = client.post(
        f"/api/vulnerabilities/{VULN_ID}/assessments",
        json={
            "packages": [PKG_A],
            "status": "affected",
            "variant_id": str(VARIANT_A),
            "ai_generated": True,
        },
    )
    assert response.status_code == 409

    response_b = client.post(
        f"/api/vulnerabilities/{VULN_ID}/assessments",
        json={
            "packages": [PKG_B],
            "status": "affected",
            "variant_id": str(VARIANT_B),
            "ai_generated": True,
        },
    )
    assert response_b.status_code == 409

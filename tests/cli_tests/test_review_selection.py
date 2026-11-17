# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Tests for ``src.helpers.review_selection``."""

import uuid

import pytest

from src.extensions import db as _db

from .test_cmd_ai_assess import app, ids  # noqa: F401

CVE = "CVE-2024-0001"
DEMO_ALL = "project demo (all variants)"
DEMO_X86 = "project demo (variants: x86)"


def _variant_ids(seed, *names):
    return {uuid.UUID(seed[name]) for name in names}


def _custom(seed, *variants, cve_package="openssl", origin="custom"):
    from src.models.assessment import Assessment

    finding = uuid.UUID(seed["findings"][cve_package])
    assessment = Assessment.create(
        status="affected", origin=origin,
        targets=[(uuid.UUID(seed[v]), finding) for v in variants])
    return assessment


def test_select_by_ids_groups_all_targets_with_missing_state(app, ids):  # noqa: F811
    from src.helpers.review_selection import select_by_ids
    from src.models.assessment_review import fingerprint_assessment

    with app.app_context():
        assessment = _custom(ids, "x86", "arm")
        selections, errors = select_by_ids([assessment.id], _variant_ids(ids, "x86", "arm"), DEMO_ALL)
        assert errors == []
        [selection] = selections
        assert selection.assessment_id == assessment.id
        assert selection.vuln_id == CVE
        assert selection.fingerprint == fingerprint_assessment(assessment)
        assert selection.excluded_targets == 0
        assert [(t.variant, t.package, t.review_state) for t in selection.targets] == [
            ("arm", "openssl@3.0", "missing"), ("x86", "openssl@3.0", "missing")]
        assert {t.project_id for t in selection.targets} == {uuid.UUID(ids["demo"])}


def test_select_by_ids_reports_unknown_and_non_custom_together(app, ids):  # noqa: F811
    from src.helpers.review_selection import select_by_ids

    with app.app_context():
        sbom = _custom(ids, "x86", origin="sbom")
        unknown = uuid.uuid4()
        selections, errors = select_by_ids([unknown, sbom.id], _variant_ids(ids, "x86"), DEMO_ALL)
        assert selections == []
        assert errors == [
            f"Assessment {unknown} not found.",
            f"Assessment {sbom.id} has origin 'sbom'; only custom assessments can be reviewed.",
        ]


def test_select_by_ids_scopes_targets_to_project(app, ids):  # noqa: F811
    from src.helpers.review_selection import select_by_ids
    from src.models.assessment_target import AssessmentTarget

    with app.app_context():
        elsewhere = _custom(ids, "default", cve_package="openssl")
        mixed = _custom(ids, "x86")
        # Cross-project targets are rejected by Assessment.create, so attach one directly.
        mixed.target_rows.append(AssessmentTarget(
            variant_id=uuid.UUID(ids["default"]), finding_id=uuid.UUID(ids["findings"]["openssl"])))
        _db.session.commit()

        selections, errors = select_by_ids(
            [elsewhere.id, mixed.id], _variant_ids(ids, "x86", "arm"), DEMO_ALL)
        assert errors == [f"Assessment {elsewhere.id} has no target in {DEMO_ALL}."]
        [selection] = selections
        assert [t.variant for t in selection.targets] == ["x86"]
        assert selection.excluded_targets == 1


def test_select_by_cve_restricts_to_variants(app, ids):  # noqa: F811
    from src.helpers.review_selection import select_by_cve

    with app.app_context():
        assessment = _custom(ids, "x86", "arm")
        selections, ignored, errors = select_by_cve([CVE], _variant_ids(ids, "x86"), DEMO_X86)
        assert (ignored, errors) == (0, [])
        [selection] = selections
        assert selection.assessment_id == assessment.id
        assert [t.variant for t in selection.targets] == ["x86"]
        assert selection.excluded_targets == 1


def test_select_by_cve_counts_non_custom_as_ignored(app, ids):  # noqa: F811
    from src.helpers.review_selection import select_by_cve

    with app.app_context():
        custom = _custom(ids, "x86")
        _custom(ids, "x86", origin="sbom")
        selections, ignored, errors = select_by_cve([CVE], _variant_ids(ids, "x86"), DEMO_X86)
        assert errors == []
        assert ignored == 1
        assert [s.assessment_id for s in selections] == [custom.id]


def test_ignored_counts_only_non_custom_assessments_with_a_target_in_scope(app, ids):  # noqa: F811
    from src.helpers.review_selection import select_by_cve
    with app.app_context():
        custom = _custom(ids, "x86")
        _custom(ids, "x86", origin="sbom")
        _custom(ids, "default", origin="sbom")
        selections, ignored, errors = select_by_cve([CVE], _variant_ids(ids, "x86"), DEMO_X86)
        assert (ignored, errors) == (1, [])
        assert [s.assessment_id for s in selections] == [custom.id]


def test_select_by_cve_errors_explain_why_nothing_is_reviewable(app, ids):  # noqa: F811
    from src.helpers.review_selection import select_by_cve

    with app.app_context():
        _custom(ids, "x86", origin="sbom")
        selections, ignored, errors = select_by_cve(
            ["cve-2024-0001", "CVE-2024-0004"], _variant_ids(ids, "x86"), DEMO_X86)
        assert selections == []
        assert ignored == 1
        assert len(errors) == 2
        assert errors[0].startswith(f"{CVE}: no custom assessment to review in {DEMO_X86}. ")
        assert "Its 1 assessment(s) there come from SBOM scans or pending AI suggestions" in errors[0]
        assert errors[1].startswith(
            f"CVE-2024-0004: no custom assessment to review in {DEMO_X86}. "
            "This CVE has no assessment there")


def test_select_by_cve_does_not_paginate(app, ids):  # noqa: F811
    from src.helpers.review_selection import select_by_cve

    with app.app_context():
        for _ in range(60):
            _custom(ids, "x86")
        selections, ignored, errors = select_by_cve([CVE], _variant_ids(ids, "x86"), DEMO_X86)
        assert (ignored, errors) == (0, [])
        assert len(selections) == 60


def test_duplicates_are_removed_preserving_order(app, ids):  # noqa: F811
    from src.helpers.review_selection import select_by_cve, select_by_ids

    with app.app_context():
        first = _custom(ids, "x86", cve_package="openssl")
        second = _custom(ids, "x86", cve_package="libxml2")
        scope = _variant_ids(ids, "x86")
        selections, errors = select_by_ids([second.id, first.id, second.id], scope, DEMO_X86)
        assert [s.assessment_id for s in selections] == [second.id, first.id]
        assert errors == []

        selections, _, errors = select_by_cve(["CVE-2024-0004", CVE, "CVE-2024-0004", CVE.lower()], scope, DEMO_X86)
        assert [s.vuln_id for s in selections] == ["CVE-2024-0004", CVE]
        assert errors == []


def test_review_state_is_reported_per_target(app, ids):  # noqa: F811
    from src.helpers.review_selection import select_by_ids
    from src.models.assessment_review import AssessmentReview, fingerprint_assessment

    with app.app_context():
        assessment = _custom(ids, "x86", "arm")
        AssessmentReview.upsert(
            assessment.id, uuid.UUID(ids["x86"]), uuid.UUID(ids["findings"]["openssl"]),
            fingerprint_assessment(assessment) or "", "affected", "agrees")
        [selection], _ = select_by_ids([assessment.id], _variant_ids(ids, "x86", "arm"), DEMO_ALL)
        assert {t.variant: t.review_state for t in selection.targets} == {"x86": "fresh", "arm": "missing"}

        assessment.status_notes = "edited"
        _db.session.commit()
        [selection], _ = select_by_ids([assessment.id], _variant_ids(ids, "x86", "arm"), DEMO_ALL)
        assert {t.variant: t.review_state for t in selection.targets} == {"x86": "stale", "arm": "missing"}


@pytest.mark.parametrize("scope", [set()])
def test_empty_scope_selects_nothing(app, ids, scope):  # noqa: F811
    from src.helpers.review_selection import select_by_cve

    with app.app_context():
        _custom(ids, "x86")
        selections, ignored, errors = select_by_cve([CVE], scope, "project demo (variants: none)")
        assert selections == [] and ignored == 0
        assert len(errors) == 1

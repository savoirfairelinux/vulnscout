# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
import pytest
from datetime import datetime, timedelta, timezone

from src.extensions import db
from src.models.assessment import Assessment
from src.models.assessment_review import AssessmentReview
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from src.models.finding import Finding
from src.models.project import Project
from src.models.variant import Variant


@pytest.fixture
def variant():
    project = Project.get_or_create("proj-1")
    return Variant.get_or_create("default", project.id)


@pytest.fixture
def finding(variant):
    pkg = Package.find_or_create("openssl", "3.0.8")
    vuln = Vulnerability.get_or_create("CVE-2024-0001")
    return Finding.get_or_create(package_id=pkg.id, vulnerability_id=vuln.id)


def make_assessment(finding, variant, origin="custom", **kwargs):
    fields = {
        "status": "not_affected",
        "justification": "component_not_present",
        "status_notes": "not in image",
        "impact_statement": "",
        "workaround": "",
    }
    fields.update(kwargs)
    row = Assessment(
        id=uuid.uuid4(),
        origin=origin,
        finding_id=finding.id,
        variant_id=variant.id,
        timestamp=datetime.now(timezone.utc),
        **fields,
    )
    db.session.add(row)
    db.session.commit()
    return row


def test_upsert_creates_then_overwrites_single_review(finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)

    # Act
    first = AssessmentReview.upsert(
        assessment_id=assessment.id, status="affected", rationale="openssl is in the rootfs"
    )
    second = AssessmentReview.upsert(
        assessment_id=assessment.id, status="fixed", rationale="patched in 3.0.8"
    )

    # Assert
    assert first.id == second.id
    assert second.status == "fixed"
    assert second.rationale == "patched in 3.0.8"
    assert len(AssessmentReview.get_for_variants([variant.id])) == 1


def test_verdict_agrees_when_all_vex_fields_match(finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)

    # Act
    review = AssessmentReview.upsert(
        assessment_id=assessment.id,
        status="not_affected",
        justification="component_not_present",
        impact_statement="",
        workaround="",
        responses=[],
        rationale="verified: openssl absent from the manifest",
    )

    # Assert
    assert review.to_dict()["verdict"] == "agrees"


def test_verdict_differs_when_status_differs(finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)

    # Act
    review = AssessmentReview.upsert(
        assessment_id=assessment.id, status="affected", rationale="openssl 3.0.8 is in the rootfs"
    )

    # Assert
    assert review.to_dict()["verdict"] == "differs"


def test_is_stale_when_assessment_edited_after_review(finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    review = AssessmentReview.upsert(
        assessment_id=assessment.id, status="affected", rationale="r"
    )
    assert review.to_dict()["is_stale"] is False

    # Act
    assessment.timestamp = review.timestamp + timedelta(minutes=1)
    db.session.commit()

    # Assert
    assert review.to_dict()["is_stale"] is True


def test_deleting_assessment_cascades_to_review(finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    AssessmentReview.upsert(assessment_id=assessment.id, status="affected", rationale="r")
    assessment_id = assessment.id

    # Act
    db.session.delete(assessment)
    db.session.commit()

    # Assert
    assert AssessmentReview.get_by_assessment(assessment_id) is None


@pytest.fixture
def client():
    # Reuse the app already created (and bound to the in-memory db with
    # tables) by the autouse ``flask_app_ctx`` fixture in conftest.py,
    # rather than creating a second Flask app: a second app would get its
    # own separate ``sqlite:///:memory:`` database with no tables, and
    # wouldn't see the assessments created via the ``finding``/``variant``
    # fixtures above. Bypass the "scan not finished" 503 guard since no
    # real scan status file is involved here.
    from flask import current_app
    app = current_app._get_current_object()
    app._INT_SCAN_FINISHED = True
    return app.test_client()


def test_put_review_creates_and_returns_it(client, finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)

    # Act
    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json={"status": "affected", "rationale": "openssl 3.0.8 is in the rootfs"},
    )

    # Assert
    assert resp.status_code == 200
    body = resp.get_json()["review"]
    assert body["status"] == "affected"
    assert body["verdict"] == "differs"
    assert body["assessment_id"] == str(assessment.id)


def test_put_review_rejects_non_custom_origin(client, finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant, origin="sbom")

    # Act
    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json={"status": "affected", "rationale": "r"},
    )

    # Assert
    assert resp.status_code == 409
    assert "custom" in resp.get_json()["error"]


def test_put_review_rejects_invalid_status(client, finding, variant):
    assessment = make_assessment(finding, variant)

    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json={"status": "banana", "rationale": "r"},
    )

    assert resp.status_code == 400


def test_put_review_rejects_invalid_justification(client, finding, variant):
    assessment = make_assessment(finding, variant)

    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json={"status": "not_affected", "justification": "banana", "rationale": "r"},
    )

    assert resp.status_code == 400


def test_put_review_requires_rationale(client, finding, variant):
    assessment = make_assessment(finding, variant)

    resp = client.put(f"/api/assessments/{assessment.id}/review", json={"status": "affected"})

    assert resp.status_code == 400


def test_put_review_overwrites_existing(client, finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json={"status": "affected", "rationale": "first"},
    )

    # Act
    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json={"status": "fixed", "rationale": "second"},
    )

    # Assert
    assert resp.status_code == 200
    assert resp.get_json()["review"]["rationale"] == "second"
    assert len(AssessmentReview.get_for_variants([variant.id])) == 1


def test_get_review_404_when_absent(client, finding, variant):
    assessment = make_assessment(finding, variant)

    assert client.get(f"/api/assessments/{assessment.id}/review").status_code == 404


def test_delete_review_404_when_absent(client, finding, variant):
    assessment = make_assessment(finding, variant)

    assert client.delete(f"/api/assessments/{assessment.id}/review").status_code == 404


def test_delete_review_removes_it(client, finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json={"status": "affected", "rationale": "r"},
    )

    # Act
    resp = client.delete(f"/api/assessments/{assessment.id}/review")

    # Assert
    assert resp.status_code == 200
    assert AssessmentReview.get_by_assessment(assessment.id) is None


def test_list_custom_assessments_excludes_other_origins(client, finding, variant):
    # Arrange
    make_assessment(finding, variant, origin="custom")
    make_assessment(finding, variant, origin="sbom")

    # Act
    resp = client.get(f"/api/custom-assessments?variant_id={variant.id}")

    # Assert
    assert resp.status_code == 200
    rows = resp.get_json()
    assert len(rows) == 1
    assert rows[0]["origin"] == "custom"
    assert rows[0]["has_review"] is False


def test_list_custom_assessments_has_review_filter(client, finding, variant):
    # Arrange
    reviewed = make_assessment(finding, variant)
    make_assessment(finding, variant, status_notes="second")
    client.put(
        f"/api/assessments/{reviewed.id}/review",
        json={"status": "affected", "rationale": "r"},
    )

    # Act
    with_review = client.get(
        f"/api/custom-assessments?variant_id={variant.id}&has_review=true"
    ).get_json()
    without_review = client.get(
        f"/api/custom-assessments?variant_id={variant.id}&has_review=false"
    ).get_json()

    # Assert
    assert [r["id"] for r in with_review] == [str(reviewed.id)]
    assert str(reviewed.id) not in [r["id"] for r in without_review]


def test_list_custom_assessments_limit_and_order(client, finding, variant):
    # Arrange
    older = make_assessment(finding, variant, status_notes="older")
    newer = make_assessment(finding, variant, status_notes="newer")
    older.timestamp = newer.timestamp - timedelta(hours=1)
    db.session.commit()

    # Act
    rows = client.get(
        f"/api/custom-assessments?variant_id={variant.id}&order=timestamp_desc&limit=1"
    ).get_json()

    # Assert
    assert len(rows) == 1
    assert rows[0]["id"] == str(newer.id)


def test_list_custom_assessments_rejects_bad_limit(client, variant):
    resp = client.get(f"/api/custom-assessments?variant_id={variant.id}&limit=0")

    assert resp.status_code == 400


def test_bulk_reviews_keyed_by_assessment_id(client, finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json={"status": "affected", "rationale": "r"},
    )

    # Act
    body = client.get(f"/api/assessment-reviews?variant_id={variant.id}").get_json()

    # Assert
    assert str(assessment.id) in body
    assert body[str(assessment.id)]["status"] == "affected"


def test_single_assessment_embeds_its_review(client, finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json={"status": "affected", "rationale": "r"},
    )

    # Act
    body = client.get(f"/api/assessments/{assessment.id}").get_json()

    # Assert
    assert body["review"]["status"] == "affected"


def test_single_assessment_review_is_none_when_absent(client, finding, variant):
    assessment = make_assessment(finding, variant)

    assert client.get(f"/api/assessments/{assessment.id}").get_json()["review"] is None

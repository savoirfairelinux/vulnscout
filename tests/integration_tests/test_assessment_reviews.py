# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
import pytest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from sqlalchemy import event

from src.extensions import db
from src.models.assessment import Assessment
from src.models.assessment_target import AssessmentTarget
from src.models.assessment_review import AssessmentReview, fingerprint_assessment
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


@pytest.fixture
def other_finding(variant):
    """A second finding on the same vulnerability, for multi-target assessments."""
    pkg = Package.find_or_create("zlib", "1.2.13")
    vuln = Vulnerability.get_or_create("CVE-2024-0001")
    return Finding.get_or_create(package_id=pkg.id, vulnerability_id=vuln.id)


def make_assessment(finding, variant, origin="custom", targets=None, **kwargs):
    """Create an assessment. ``targets`` overrides the default single ``(variant, finding)``."""
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
        timestamp=datetime.now(timezone.utc),
        **fields,
    )
    db.session.add(row)
    db.session.flush()
    for target_variant, target_finding in (targets or [(variant, finding)]):
        db.session.add(AssessmentTarget(
            assessment_id=row.id, variant_id=target_variant.id, finding_id=target_finding.id))
    db.session.commit()
    return row


def upsert_for(assessment, finding, variant, **kwargs):
    """``AssessmentReview.upsert`` for the ``(variant, finding)`` target, with test defaults."""
    kwargs.setdefault("status", "affected")
    kwargs.setdefault("rationale", "r")
    return AssessmentReview.upsert(
        assessment_id=assessment.id, variant_id=variant.id, finding_id=finding.id, **kwargs
    )


def target_json(finding, variant, **kwargs):
    payload = {"variant_id": str(variant.id), "finding_id": str(finding.id)}
    payload.update(kwargs)
    return payload


def target_query(finding, variant):
    return f"variant_id={variant.id}&finding_id={finding.id}"


def test_upsert_creates_then_overwrites_single_review(finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)

    # Act
    first = upsert_for(assessment, finding, variant, status="affected", rationale="openssl is in the rootfs")
    second = upsert_for(assessment, finding, variant, status="fixed", rationale="patched in 3.0.8")

    # Assert
    assert first.id == second.id
    assert second.status == "fixed"
    assert second.rationale == "patched in 3.0.8"
    assert len(AssessmentReview.get_for_variants([variant.id])) == 1


def test_verdict_agrees_when_all_vex_fields_match(finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)

    # Act
    review = upsert_for(
        assessment, finding, variant,
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
    review = upsert_for(assessment, finding, variant, status="affected", rationale="openssl 3.0.8 is in the rootfs")

    # Assert
    assert review.to_dict()["verdict"] == "differs"


def test_is_stale_when_assessment_edited_after_review(finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    review = upsert_for(assessment, finding, variant)
    assert review.to_dict()["is_stale"] is False

    # Act
    assessment.update(
        status_notes="reassessed: openssl is linked in",
        timestamp=review.timestamp + timedelta(minutes=1),
    )
    db.session.commit()

    # Assert
    assert assessment.timestamp > review.timestamp
    assert review.to_dict()["is_stale"] is True


def test_is_stale_when_assessment_edited_keeping_its_timestamp(finding, variant):
    """The edit form's "keep current timestamp" toggle must not hide staleness.

    Editing an assessment with ``update_timestamp=False`` preserves the VEX
    statement date, so a timestamp comparison alone reports the review as
    fresh even though the analyst rewrote the assessment underneath it.
    """
    # Arrange
    assessment = make_assessment(finding, variant, workaround="upgrade to 3.0.9")
    review = upsert_for(assessment, finding, variant)
    assert review.to_dict()["is_stale"] is False
    original_timestamp = assessment.timestamp

    # Act — edit the content while explicitly keeping the old timestamp.
    assessment.update(workaround="Intentionally make the review stale", update_timestamp=False)

    # Assert
    assert assessment.timestamp == original_timestamp
    assert review.to_dict()["is_stale"] is True


def test_is_not_stale_when_assessment_saved_without_content_change(finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    review = upsert_for(assessment, finding, variant)

    # Act — a re-save that bumps the timestamp but changes no reviewed field.
    assessment.update(status=assessment.status)

    # Assert
    assert assessment.timestamp > review.timestamp
    assert review.to_dict()["is_stale"] is False


def test_legacy_review_without_fingerprint_falls_back_to_timestamp(finding, variant):
    # Arrange — simulate a review written before fingerprints existed.
    assessment = make_assessment(finding, variant)
    review = upsert_for(assessment, finding, variant)
    review.reviewed_fingerprint = None
    db.session.commit()
    assert review.to_dict()["is_stale"] is False

    # Act
    assessment.timestamp = review.timestamp + timedelta(minutes=1)
    db.session.commit()

    # Assert
    assert review.to_dict()["is_stale"] is True


def test_re_reviewing_a_stale_review_clears_staleness(finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    review = upsert_for(assessment, finding, variant)
    assessment.update(status_notes="rewritten", update_timestamp=False)
    assert review.to_dict()["is_stale"] is True

    # Act
    review = upsert_for(assessment, finding, variant, rationale="re-derived")

    # Assert
    assert review.to_dict()["is_stale"] is False


def test_deleting_assessment_cascades_to_review(finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    upsert_for(assessment, finding, variant)
    assessment_id = assessment.id

    # Act
    db.session.delete(assessment)
    db.session.commit()

    # Assert
    assert AssessmentReview.get_for_target(assessment_id, variant.id, finding.id) is None


def test_two_targets_on_one_assessment_hold_independent_reviews(finding, other_finding, variant):
    # Arrange: one assessment covering two findings in the same variant.
    assessment = make_assessment(
        finding, variant, targets=[(variant, finding), (variant, other_finding)]
    )

    # Act
    review_a = upsert_for(assessment, finding, variant, status="affected", rationale="a")
    review_b = upsert_for(assessment, other_finding, variant, status="fixed", rationale="b")

    # Assert
    assert review_a.id != review_b.id
    assert review_a.status == "affected"
    assert review_b.status == "fixed"
    all_reviews = AssessmentReview.get_all_for_assessment(assessment.id)
    assert {r.id for r in all_reviews} == {review_a.id, review_b.id}


def test_upsert_only_touches_the_matching_targets_row(finding, other_finding, variant):
    # Arrange
    assessment = make_assessment(
        finding, variant, targets=[(variant, finding), (variant, other_finding)]
    )
    upsert_for(assessment, finding, variant, status="affected", rationale="a")
    upsert_for(assessment, other_finding, variant, status="fixed", rationale="b")

    # Act: re-review just one target.
    upsert_for(assessment, finding, variant, status="not_affected", rationale="a2")

    # Assert
    updated = AssessmentReview.get_for_target(assessment.id, variant.id, finding.id)
    untouched = AssessmentReview.get_for_target(assessment.id, variant.id, other_finding.id)
    assert updated.status == "not_affected"
    assert untouched.status == "fixed"
    assert untouched.rationale == "b"


def test_deleting_one_targets_review_leaves_others_intact(finding, other_finding, variant):
    # Arrange
    assessment = make_assessment(
        finding, variant, targets=[(variant, finding), (variant, other_finding)]
    )
    upsert_for(assessment, finding, variant)
    upsert_for(assessment, other_finding, variant)

    # Act
    review_a = AssessmentReview.get_for_target(assessment.id, variant.id, finding.id)
    review_a.delete()

    # Assert
    assert AssessmentReview.get_for_target(assessment.id, variant.id, finding.id) is None
    assert AssessmentReview.get_for_target(assessment.id, variant.id, other_finding.id) is not None


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
        json=target_json(finding, variant, status="affected", rationale="openssl 3.0.8 is in the rootfs"),
    )

    # Assert
    assert resp.status_code == 200
    body = resp.get_json()["review"]
    assert body["status"] == "affected"
    assert body["verdict"] == "differs"
    assert body["assessment_id"] == str(assessment.id)
    assert body["variant_id"] == str(variant.id)
    assert body["package"] == "openssl@3.0.8"


def test_put_review_rejects_non_custom_origin(client, finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant, origin="sbom")

    # Act
    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="affected", rationale="r"),
    )

    # Assert
    assert resp.status_code == 409
    assert "custom" in resp.get_json()["error"]


def test_put_review_rejects_invalid_status(client, finding, variant):
    assessment = make_assessment(finding, variant)

    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="banana", rationale="r"),
    )

    assert resp.status_code == 400


def test_put_review_rejects_invalid_justification(client, finding, variant):
    assessment = make_assessment(finding, variant)

    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="not_affected", justification="banana", rationale="r"),
    )

    assert resp.status_code == 400


def test_put_review_requires_rationale(client, finding, variant):
    assessment = make_assessment(finding, variant)

    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="affected"),
    )

    assert resp.status_code == 400


def test_put_review_requires_a_target(client, finding, variant):
    assessment = make_assessment(finding, variant)

    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json={"status": "affected", "rationale": "r"},
    )

    assert resp.status_code == 400


def test_put_review_rejects_a_target_not_on_the_assessment(client, finding, other_finding, variant):
    assessment = make_assessment(finding, variant)

    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(other_finding, variant, status="affected", rationale="r"),
    )

    assert resp.status_code == 400
    assert "target" in resp.get_json()["error"].lower()


def test_put_review_accepts_package_string_in_place_of_finding_id(client, finding, variant):
    assessment = make_assessment(finding, variant)

    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json={
            "variant_id": str(variant.id),
            "package": "openssl@3.0.8",
            "status": "affected",
            "rationale": "r",
        },
    )

    assert resp.status_code == 200
    assert resp.get_json()["review"]["package"] == "openssl@3.0.8"


def test_put_review_overwrites_existing(client, finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="affected", rationale="first"),
    )

    # Act
    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="fixed", rationale="second"),
    )

    # Assert
    assert resp.status_code == 200
    assert resp.get_json()["review"]["rationale"] == "second"
    assert len(AssessmentReview.get_for_variants([variant.id])) == 1


def test_editing_assessment_marks_review_stale_over_http(client, finding, variant):
    """The UI flow: review an assessment, then edit it keeping its timestamp.

    ``PUT /api/assessments/<id>`` sends ``update_timestamp: false`` whenever
    the edit form's "keep current timestamp" toggle is left on (its default),
    so the review must go stale on content alone. The update is applied
    through the same model call the route makes; this test covers the review
    endpoints reporting it.
    """
    # Arrange
    assessment = make_assessment(finding, variant, status="affected", justification="")
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="affected", rationale="openssl is linked in"),
    )
    fresh = client.get(
        f"/api/assessments/{assessment.id}/review?{target_query(finding, variant)}"
    ).get_json()["review"]
    assert fresh["is_stale"] is False

    # Act — exactly what update_assessment() does for a keep-timestamp edit.
    assessment.update(
        status="affected",
        status_notes="Intentionally make the review stale",
        update_timestamp=False,
    )

    # Assert
    review = client.get(
        f"/api/assessments/{assessment.id}/review?{target_query(finding, variant)}"
    ).get_json()["review"]
    assert review["is_stale"] is True
    listed = client.get(f"/api/assessment-reviews?variant_id={variant.id}").get_json()
    assert listed[str(assessment.id)][0]["is_stale"] is True


def test_get_review_404_when_absent(client, finding, variant):
    assessment = make_assessment(finding, variant)

    resp = client.get(f"/api/assessments/{assessment.id}/review?{target_query(finding, variant)}")
    assert resp.status_code == 404


def test_get_review_requires_a_target(client, finding, variant):
    assessment = make_assessment(finding, variant)

    assert client.get(f"/api/assessments/{assessment.id}/review").status_code == 400


def test_delete_review_404_when_absent(client, finding, variant):
    assessment = make_assessment(finding, variant)

    resp = client.delete(f"/api/assessments/{assessment.id}/review?{target_query(finding, variant)}")
    assert resp.status_code == 404


def test_delete_review_removes_it(client, finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="affected", rationale="r"),
    )

    # Act
    resp = client.delete(f"/api/assessments/{assessment.id}/review?{target_query(finding, variant)}")

    # Assert
    assert resp.status_code == 200
    assert AssessmentReview.get_for_target(assessment.id, variant.id, finding.id) is None


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
    assert rows[0]["target_reviews"] == [
        {"variant_id": str(variant.id), "package": "openssl@3.0.8", "has_review": False, "is_stale": False}
    ]


def test_list_custom_assessments_has_review_filter(client, finding, variant):
    # Arrange
    reviewed = make_assessment(finding, variant)
    make_assessment(finding, variant, status_notes="second")
    client.put(
        f"/api/assessments/{reviewed.id}/review",
        json=target_json(finding, variant, status="affected", rationale="r"),
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


def test_list_custom_assessments_partial_target_review(client, finding, other_finding, variant):
    # Arrange: one assessment, two targets, only one reviewed.
    assessment = make_assessment(
        finding, variant, targets=[(variant, finding), (variant, other_finding)]
    )
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="affected", rationale="r"),
    )

    # Act
    row = client.get(f"/api/custom-assessments?variant_id={variant.id}").get_json()[0]

    # Assert: assessment-level flag is true if any target is reviewed, but the
    # per-target breakdown shows which target still needs one.
    assert row["has_review"] is True
    by_package = {t["package"]: t for t in row["target_reviews"]}
    assert by_package["openssl@3.0.8"]["has_review"] is True
    assert by_package["zlib@1.2.13"]["has_review"] is False


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
        json=target_json(finding, variant, status="affected", rationale="r"),
    )

    # Act
    body = client.get(f"/api/assessment-reviews?variant_id={variant.id}").get_json()

    # Assert
    assert str(assessment.id) in body
    assert [r["status"] for r in body[str(assessment.id)]] == ["affected"]


def test_bulk_reviews_group_multiple_targets_under_one_assessment(client, finding, other_finding, variant):
    # Arrange
    assessment = make_assessment(
        finding, variant, targets=[(variant, finding), (variant, other_finding)]
    )
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="affected", rationale="a"),
    )
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(other_finding, variant, status="fixed", rationale="b"),
    )

    # Act
    body = client.get(f"/api/assessment-reviews?variant_id={variant.id}").get_json()

    # Assert
    statuses = {r["package"]: r["status"] for r in body[str(assessment.id)]}
    assert statuses == {"openssl@3.0.8": "affected", "zlib@1.2.13": "fixed"}


def test_single_assessment_embeds_its_reviews(client, finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="affected", rationale="r"),
    )

    # Act
    body = client.get(f"/api/assessments/{assessment.id}").get_json()

    # Assert
    assert [r["status"] for r in body["reviews"]] == ["affected"]


def test_single_assessment_reviews_is_empty_when_absent(client, finding, variant):
    assessment = make_assessment(finding, variant)

    assert client.get(f"/api/assessments/{assessment.id}").get_json()["reviews"] == []


def test_list_assessment_target_reviews_returns_every_target(client, finding, other_finding, variant):
    # Arrange
    assessment = make_assessment(
        finding, variant, targets=[(variant, finding), (variant, other_finding)]
    )
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="affected", rationale="a"),
    )
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(other_finding, variant, status="fixed", rationale="b"),
    )

    # Act
    body = client.get(f"/api/assessments/{assessment.id}/reviews").get_json()

    # Assert
    statuses = {r["package"]: r["status"] for r in body["reviews"]}
    assert statuses == {"openssl@3.0.8": "affected", "zlib@1.2.13": "fixed"}


@contextmanager
def count_queries():
    """Count SELECT statements issued against ``db.engine`` in the block."""
    counter = {"n": 0}

    def _on_execute(*_args, **_kwargs):
        counter["n"] += 1

    event.listen(db.engine, "before_cursor_execute", _on_execute)
    try:
        yield counter
    finally:
        event.remove(db.engine, "before_cursor_execute", _on_execute)


def test_get_for_variants_query_count_does_not_scale_with_n(finding, variant):
    # Arrange: several reviews so an N+1 on ``.assessment`` would show up as
    # extra queries proportional to the number of reviews.
    variant_id = variant.id
    for i in range(5):
        assessment = make_assessment(finding, variant, status_notes=f"row-{i}")
        upsert_for(assessment, finding, variant)

    # Act: warm the identity map first (and grab the id above, before
    # expiring) so only the queries triggered by get_for_variants +
    # to_dict() itself are counted, not an unrelated refresh of the
    # ``variant`` fixture object.
    db.session.expire_all()
    with count_queries() as counter:
        reviews = AssessmentReview.get_for_variants([variant_id])
        [r.to_dict() for r in reviews]

    # Assert: the reviews join plus one selectin batch each for
    # target_rows and their findings — three queries total, independent of
    # how many rows come back.
    assert len(reviews) == 5
    assert counter["n"] == 3


# ----------------------------------------------------------------------
# Error handling and scoping on the HTTP surface
# ----------------------------------------------------------------------


@pytest.mark.parametrize("method", ["get", "put", "delete"])
def test_review_routes_reject_malformed_assessment_id(client, method):
    # Act
    resp = getattr(client, method)("/api/assessments/not-a-uuid/review", json={})

    # Assert
    assert resp.status_code == 400


@pytest.mark.parametrize("method", ["get", "put", "delete"])
def test_review_routes_404_on_unknown_assessment(client, method):
    # Act
    resp = getattr(client, method)(f"/api/assessments/{uuid.uuid4()}/review", json={})

    # Assert
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "Assessment not found"


def test_put_review_rejects_non_list_responses(client, finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)

    # Act
    resp = client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="affected", rationale="r", responses="will_not_fix"),
    )

    # Assert
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "responses must be a list"


def test_list_custom_assessments_rejects_non_integer_limit(client, variant):
    # Act
    resp = client.get(f"/api/custom-assessments?variant_id={variant.id}&limit=abc")

    # Assert
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "limit and offset must be integers"


def test_list_custom_assessments_orders_ascending(client, finding, variant):
    # Arrange: two assessments, the second one newer.
    now = datetime.now(timezone.utc)
    older = make_assessment(finding, variant, status_notes="older")
    older.timestamp = now - timedelta(days=1)
    newer = make_assessment(finding, variant, status_notes="newer")
    newer.timestamp = now
    db.session.commit()

    # Act
    body = client.get(
        f"/api/custom-assessments?variant_id={variant.id}&order=timestamp_asc"
    ).get_json()

    # Assert
    notes = [row["status_notes"] for row in body]
    assert notes.index("older") < notes.index("newer")


@pytest.mark.parametrize(
    "url",
    ["/api/custom-assessments?variant_id=nope", "/api/assessment-reviews?variant_id=nope"],
)
def test_scoped_routes_reject_malformed_variant_id(client, url):
    # Act / Assert
    assert client.get(url).status_code == 400


@pytest.mark.parametrize(
    "url",
    ["/api/custom-assessments?project_id=nope", "/api/assessment-reviews?project_id=nope"],
)
def test_scoped_routes_reject_malformed_project_id(client, url):
    # Act / Assert
    assert client.get(url).status_code == 400


def test_scoped_routes_accept_a_project_id(client, finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="affected", rationale="r"),
    )
    project_id = variant.project_id

    # Act
    listed = client.get(f"/api/custom-assessments?project_id={project_id}").get_json()
    reviews = client.get(f"/api/assessment-reviews?project_id={project_id}").get_json()

    # Assert: the project scope resolves to its variants, so both endpoints
    # see the assessment created under ``variant``.
    assert [row["id"] for row in listed] == [str(assessment.id)]
    assert str(assessment.id) in reviews


def test_scoped_routes_without_scope_return_everything(client, finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    client.put(
        f"/api/assessments/{assessment.id}/review",
        json=target_json(finding, variant, status="affected", rationale="r"),
    )

    # Act: no variant_id / project_id at all.
    listed = client.get("/api/custom-assessments").get_json()
    reviews = client.get("/api/assessment-reviews").get_json()

    # Assert
    assert [row["id"] for row in listed] == [str(assessment.id)]
    assert str(assessment.id) in reviews


# ----------------------------------------------------------------------
# Model-level derived values
# ----------------------------------------------------------------------


def test_fingerprint_of_missing_assessment_is_none():
    # Act / Assert
    assert fingerprint_assessment(None) is None


def test_repr_mentions_status_and_assessment(finding, variant):
    # Arrange
    assessment = make_assessment(finding, variant)
    review = upsert_for(assessment, finding, variant)

    # Act
    text = repr(review)

    # Assert
    assert "affected" in text
    assert str(assessment.id) in text


def test_verdict_differs_when_responses_differ(finding, variant):
    # Arrange: identical VEX fields, different response lists.
    assessment = make_assessment(
        finding, variant, status="affected", justification=None, responses=["will_not_fix"]
    )
    review = upsert_for(
        assessment, finding, variant,
        status="affected",
        rationale="r",
        status_notes="not in image",
        impact_statement="",
        workaround="",
        responses=["workaround_available"],
    )

    # Act / Assert
    assert review.verdict() == "differs"


def test_orphan_review_differs_and_is_not_stale(finding, variant):
    # Arrange: a review whose parent assessment isn't loaded (never persisted).
    orphan = AssessmentReview(
        assessment_id=uuid.uuid4(), variant_id=variant.id, finding_id=finding.id,
        status="affected", rationale="r",
    )

    # Act / Assert
    assert orphan.verdict() == "differs"
    assert orphan.is_stale() is False


def test_legacy_review_without_timestamps_is_not_stale(finding, variant):
    # Arrange: a pre-fingerprint review whose timestamps are both missing.
    assessment = make_assessment(finding, variant)
    review = upsert_for(assessment, finding, variant)
    assert review.assessment is not None  # load the relationship first

    # Act / Assert: kept in-session only, since both columns are NOT NULL in
    # the schema and only legacy in-memory rows can reach this branch.
    with db.session.no_autoflush:
        review.reviewed_fingerprint = None
        review.timestamp = None
        assert review.is_stale() is False
    db.session.rollback()

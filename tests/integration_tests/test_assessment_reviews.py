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

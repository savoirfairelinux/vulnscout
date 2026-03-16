# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional

from ..models.assessment import Assessment


class AssessmentDBController:
    """
    Service layer for :class:`Assessment` CRUD operations.

    Delegates persistence to the model and provides dictionary serialisation
    for API responses.
    """

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def serialize(assessment: Assessment) -> dict:
        """Return a JSON-serialisable dict representation of *assessment*."""
        return {
            "id": str(assessment.id),
            "source": assessment.source,
            "status": assessment.status,
            "simplified_status": assessment.simplified_status,
            "status_notes": assessment.status_notes,
            "justification": assessment.justification,
            "impact_statement": assessment.impact_statement,
            "workaround": assessment.workaround,
            "timestamp": assessment.timestamp.isoformat() if assessment.timestamp else None,
            "responses": assessment.responses or [],
            "finding_id": str(assessment.finding_id) if assessment.finding_id else None,
            "variant_id": str(assessment.variant_id) if assessment.variant_id else None,
        }

    @staticmethod
    def serialize_list(assessments: list[Assessment]) -> list[dict]:
        """Return a list of serialised assessment dicts."""
        return [AssessmentDBController.serialize(a) for a in assessments]

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @staticmethod
    def get(assessment_id: uuid.UUID | str) -> Optional[Assessment]:
        """Return the assessment matching *assessment_id*, or ``None`` if not found."""
        if isinstance(assessment_id, str):
            assessment_id = uuid.UUID(assessment_id)
        return Assessment.get_by_id(assessment_id)

    @staticmethod
    def get_by_finding(finding_id: uuid.UUID | str) -> list[Assessment]:
        """Return all assessments for the given finding."""
        return Assessment.get_by_finding(finding_id)

    @staticmethod
    def get_by_variant(variant_id: uuid.UUID | str) -> list[Assessment]:
        """Return all assessments for the given variant."""
        return Assessment.get_by_variant(variant_id)

    @staticmethod
    def get_by_finding_and_variant(
        finding_id: uuid.UUID | str,
        variant_id: uuid.UUID | str,
    ) -> list[Assessment]:
        """Return assessments matching both *finding_id* and *variant_id*."""
        return Assessment.get_by_finding_and_variant(finding_id, variant_id)

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    @staticmethod
    def create(
        status: str,
        finding_id: Optional[uuid.UUID | str] = None,
        variant_id: Optional[uuid.UUID | str] = None,
        **kwargs,
    ) -> Assessment:
        """Validate inputs and create a new :class:`Assessment`.

        :raises ValueError: if *status* is empty or blank.
        """
        status = status.strip()
        if not status:
            raise ValueError("Assessment status must not be empty.")
        return Assessment.create(status=status, finding_id=finding_id, variant_id=variant_id, **kwargs)

    @staticmethod
    def update(
        assessment: Assessment | uuid.UUID | str,
        **kwargs,
    ) -> Assessment:
        """Update *assessment* fields.

        :raises ValueError: if the assessment is not found.
        """
        if isinstance(assessment, Assessment):
            resolved = assessment
        else:
            found = AssessmentDBController.get(assessment)
            if found is None:
                raise ValueError("Assessment not found.")
            resolved = found
        return resolved.update(**kwargs)

    @staticmethod
    def delete(assessment: Assessment | uuid.UUID | str) -> None:
        """Delete *assessment*.

        :raises ValueError: if the assessment is not found.
        """
        if isinstance(assessment, Assessment):
            resolved = assessment
        else:
            found = AssessmentDBController.get(assessment)
            if found is None:
                raise ValueError("Assessment not found.")
            resolved = found
        resolved.delete()

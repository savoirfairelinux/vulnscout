# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import request
from flask.typing import ResponseReturnValue

from ..models.assessment import (
    Assessment,
    VALID_STATUS_OPENVEX,
    VALID_JUSTIFICATION_OPENVEX,
)
from ..models.assessment_review import AssessmentReview
from ._scan_helpers import parse_uuid_or_400


def _load_assessment(assessment_id: str):
    """Resolve an assessment by ID string. Returns ``(assessment, error_response)``."""
    assessment_uuid, err = parse_uuid_or_400(assessment_id, "assessment_id")
    if err:
        return None, err
    assessment = Assessment.get_by_id(assessment_uuid)
    if assessment is None:
        return None, ({"error": "Assessment not found"}, 404)
    return assessment, None


def init_app(app) -> None:

    @app.route('/api/assessments/<assessment_id>/review', methods=['GET'])
    def get_assessment_review(assessment_id: str) -> ResponseReturnValue:
        """Return the AI review attached to an assessment.

        OpenAPI:
        response 200 JsonObject Review payload.
        response 404 Error Assessment or review not found.
        """
        assessment, err = _load_assessment(assessment_id)
        if err:
            return err
        review = AssessmentReview.get_by_assessment(assessment.id)
        if review is None:
            return {"error": "Review not found"}, 404
        return {"review": review.to_dict()}, 200

    @app.route('/api/assessments/<assessment_id>/review', methods=['PUT'])
    def put_assessment_review(assessment_id: str) -> ResponseReturnValue:
        """Create or overwrite the AI review attached to a custom assessment.

        OpenAPI:
        response 200 JsonObject Review payload.
        response 400 Error Invalid payload.
        response 404 Error Assessment not found.
        response 409 Error Assessment origin is not 'custom'.
        """
        assessment, err = _load_assessment(assessment_id)
        if err:
            return err

        if assessment.origin != "custom":
            return {
                "error": (
                    f"Assessment origin is '{assessment.origin or 'sbom'}'; "
                    "only custom assessments can be reviewed"
                )
            }, 409

        data = request.get_json(silent=True) or {}
        status = data.get("status")
        rationale = data.get("rationale")

        if status not in VALID_STATUS_OPENVEX:
            return {"error": f"status must be one of {', '.join(VALID_STATUS_OPENVEX)}"}, 400
        if not rationale or not str(rationale).strip():
            return {"error": "rationale is required"}, 400

        justification = data.get("justification") or None
        if justification is not None and justification not in VALID_JUSTIFICATION_OPENVEX:
            return {
                "error": f"justification must be one of {', '.join(VALID_JUSTIFICATION_OPENVEX)}"
            }, 400

        responses = data.get("responses")
        if responses is not None and not isinstance(responses, list):
            return {"error": "responses must be a list"}, 400

        review = AssessmentReview.upsert(
            assessment_id=assessment.id,
            status=status,
            rationale=str(rationale).strip(),
            status_notes=data.get("status_notes") or None,
            justification=justification,
            impact_statement=data.get("impact_statement") or None,
            workaround=data.get("workaround") or None,
            responses=responses,
        )
        return {"status": "success", "review": review.to_dict()}, 200

    @app.route('/api/assessments/<assessment_id>/review', methods=['DELETE'])
    def delete_assessment_review(assessment_id: str) -> ResponseReturnValue:
        """Discard the AI review attached to an assessment.

        OpenAPI:
        response 200 JsonObject Deletion confirmation.
        response 404 Error Assessment or review not found.
        """
        assessment, err = _load_assessment(assessment_id)
        if err:
            return err
        review = AssessmentReview.get_by_assessment(assessment.id)
        if review is None:
            return {"error": "Review not found"}, 404
        review.delete()
        return {"status": "success", "deleted": assessment_id}, 200

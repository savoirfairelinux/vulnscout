# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from uuid import UUID

from flask import request
from flask.typing import ResponseReturnValue

from ..models.assessment import (
    Assessment,
    VALID_STATUS_OPENVEX,
    VALID_JUSTIFICATION_OPENVEX,
)
from ..models.assessment_review import AssessmentReview
from ..models.variant import Variant
from ._scan_helpers import parse_uuid_or_400


def _load_assessment(assessment_id: str):
    """Resolve an assessment by ID string. Returns ``(assessment, error_response)``."""
    assessment_uuid, err = parse_uuid_or_400(assessment_id, "assessment_id")
    if err:
        return None, err
    if assessment_uuid is None:
        return None, ({"error": "Internal error"}, 500)
    assessment = Assessment.get_by_id(assessment_uuid)
    if assessment is None:
        return None, ({"error": "Assessment not found"}, 404)
    return assessment, None


def _scoped_variant_ids() -> "tuple[list[UUID] | None, ResponseReturnValue | None]":
    """Resolve variant_id / project_id query args into a variant ID list."""
    variant_id = request.args.get('variant_id')
    project_id = request.args.get('project_id')
    if variant_id:
        variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
        if err:
            return None, err
        if variant_uuid is None:
            return None, ({"error": "Internal error"}, 500)
        return [variant_uuid], None
    if project_id:
        project_uuid, err = parse_uuid_or_400(project_id, "project_id")
        if err:
            return None, err
        if project_uuid is None:
            return None, ({"error": "Internal error"}, 500)
        return [v.id for v in Variant.get_by_project(project_uuid)], None
    return None, None


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

    @app.route('/api/custom-assessments', methods=['GET'])
    def list_custom_assessments() -> ResponseReturnValue:
        """List assessments with origin 'custom', annotated with review presence.

        OpenAPI:
        query variant_id uuid optional Filter by a single variant ID.
        query project_id uuid optional Filter by a single project ID.
        query has_review string optional 'true' or 'false' to filter on review presence.
        query order string optional 'timestamp_desc' (default) or 'timestamp_asc'.
        query limit integer optional Maximum rows to return, default 50.
        query offset integer optional Rows to skip, default 0.
        response 200 JsonObject Custom assessment collection.
        response 400 Error Invalid identifiers or pagination values.
        """
        variant_ids, err = _scoped_variant_ids()
        if err:
            return err

        try:
            limit = int(request.args.get('limit', 50))
            offset = int(request.args.get('offset', 0))
        except ValueError:
            return {"error": "limit and offset must be integers"}, 400
        if limit < 1 or offset < 0:
            return {"error": "limit must be >= 1 and offset >= 0"}, 400

        # get_by_origin already orders by timestamp descending.
        assessments = Assessment.get_by_origin(variant_ids, origin="custom")
        if request.args.get('order') == 'timestamp_asc':
            assessments = list(reversed(assessments))

        reviewed_ids = {r.assessment_id for r in AssessmentReview.get_for_variants(variant_ids)}

        has_review = request.args.get('has_review')
        if has_review == 'true':
            assessments = [a for a in assessments if a.id in reviewed_ids]
        elif has_review == 'false':
            assessments = [a for a in assessments if a.id not in reviewed_ids]

        rows = []
        for a in assessments[offset:offset + limit]:
            row = a.to_dict()
            row["has_review"] = a.id in reviewed_ids
            rows.append(row)
        return rows, 200

    @app.route('/api/assessment-reviews', methods=['GET'])
    def list_assessment_reviews() -> ResponseReturnValue:
        """Return reviews keyed by assessment ID for a variant or project scope.

        OpenAPI:
        query variant_id uuid optional Filter by a single variant ID.
        query project_id uuid optional Filter by a single project ID.
        response 200 JsonObject Reviews keyed by assessment ID.
        response 400 Error Invalid identifiers.
        """
        variant_ids, err = _scoped_variant_ids()
        if err:
            return err
        reviews = AssessmentReview.get_for_variants(variant_ids)
        return {str(r.assessment_id): r.to_dict() for r in reviews}, 200

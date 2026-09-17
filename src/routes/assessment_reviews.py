# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from uuid import UUID

from flask import request
from flask.typing import ResponseReturnValue

from ..extensions import db
from ..models.assessment import (
    Assessment,
    VALID_STATUS_OPENVEX,
    VALID_JUSTIFICATION_OPENVEX,
)
from ..models.assessment_review import AssessmentReview
from ..models.finding import Finding
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


def _resolve_target(
    assessment: Assessment, source: dict
) -> "tuple[UUID, UUID, None] | tuple[None, None, ResponseReturnValue]":
    """Resolve which of *assessment*'s targets a review request refers to.

    *source* is either ``request.args`` or the parsed JSON body; both carry
    ``variant_id`` plus either ``finding_id`` or ``package`` (as returned by
    ``Assessment.target_pairs``). The resolved pair must be one of the
    assessment's own targets — a review can't be written against a target the
    assessment doesn't have.
    """
    variant_id = source.get("variant_id")
    if not variant_id:
        return None, None, ({"error": "variant_id is required"}, 400)
    variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
    if err:
        return None, None, err
    if variant_uuid is None:
        return None, None, ({"error": "Internal error"}, 500)

    finding_id = source.get("finding_id")
    if finding_id:
        finding_uuid, err = parse_uuid_or_400(finding_id, "finding_id")
        if err:
            return None, None, err
        if finding_uuid is None:
            return None, None, ({"error": "Internal error"}, 500)
    else:
        package = source.get("package")
        if not package:
            return None, None, ({"error": "finding_id or package is required"}, 400)
        finding = Finding.get_by_package_and_vulnerability(package, assessment.vuln_id)
        if finding is None:
            return None, None, ({"error": f"No finding for package {package!r}"}, 400)
        finding_uuid = finding.id

    if (variant_uuid, finding_uuid) not in set(assessment.targets):
        return None, None, ({"error": "Not a target of this assessment"}, 400)
    return variant_uuid, finding_uuid, None


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
        """Return the AI review attached to one target of an assessment.

        OpenAPI:
        query variant_id uuid required The target's variant.
        query finding_id uuid optional The target's finding (or pass ``package``).
        query package string optional The target's package string-id.
        response 200 JsonObject Review payload.
        response 400 Error Invalid or missing target.
        response 404 Error Assessment or review not found.
        """
        assessment, err = _load_assessment(assessment_id)
        if err:
            return err
        variant_uuid, finding_uuid, err = _resolve_target(assessment, request.args)
        if err:
            return err
        assert variant_uuid is not None and finding_uuid is not None
        review = AssessmentReview.get_for_target(assessment.id, variant_uuid, finding_uuid)
        if review is None:
            return {"error": "Review not found"}, 404
        return {"review": review.to_dict()}, 200

    @app.route('/api/assessments/<assessment_id>/reviews', methods=['GET'])
    def list_assessment_target_reviews(assessment_id: str) -> ResponseReturnValue:
        """Return every review attached to an assessment, across all its targets.

        OpenAPI:
        response 200 JsonObject List of review payloads.
        response 404 Error Assessment not found.
        """
        assessment, err = _load_assessment(assessment_id)
        if err:
            return err
        reviews = AssessmentReview.get_all_for_assessment(assessment.id)
        return {"reviews": [r.to_dict() for r in reviews]}, 200

    @app.route('/api/assessments/<assessment_id>/review', methods=['PUT'])
    def put_assessment_review(assessment_id: str) -> ResponseReturnValue:
        """Create or overwrite the AI review attached to one target of a custom assessment.

        OpenAPI:
        body variant_id uuid required The target's variant.
        body finding_id uuid optional The target's finding (or pass ``package``).
        body package string optional The target's package string-id.
        response 200 JsonObject Review payload.
        response 400 Error Invalid payload or target.
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
        variant_uuid, finding_uuid, err = _resolve_target(assessment, data)
        if err:
            return err
        assert variant_uuid is not None and finding_uuid is not None

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
            variant_id=variant_uuid,
            finding_id=finding_uuid,
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
        """Discard the AI review attached to one target of an assessment.

        OpenAPI:
        query variant_id uuid required The target's variant.
        query finding_id uuid optional The target's finding (or pass ``package``).
        query package string optional The target's package string-id.
        response 200 JsonObject Deletion confirmation.
        response 400 Error Invalid or missing target.
        response 404 Error Assessment or review not found.
        """
        assessment, err = _load_assessment(assessment_id)
        if err:
            return err
        variant_uuid, finding_uuid, err = _resolve_target(assessment, request.args)
        if err:
            return err
        assert variant_uuid is not None and finding_uuid is not None
        review = AssessmentReview.get_for_target(assessment.id, variant_uuid, finding_uuid)
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
        query has_review string optional 'true' for any reviewed target or 'false' for any unreviewed target.
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

        reviews_by_target: dict[tuple, "AssessmentReview"] = {
            (r.assessment_id, r.variant_id, r.finding_id): r
            for r in AssessmentReview.get_for_variants(variant_ids)
        }
        reviewed_ids = {key[0] for key in reviews_by_target}
        variant_project_ids = {
            variant_id: project_id
            for variant_id, project_id in db.session.execute(
                db.select(Variant.id, Variant.project_id).where(
                    Variant.id.in_({
                        target.variant_id
                        for assessment in assessments
                        for target in assessment.target_rows
                    })
                )
            )
        }

        def scoped_target_keys(assessment: Assessment) -> list[tuple]:
            return [
                (assessment.id, target.variant_id, target.finding_id)
                for target in assessment.target_rows
                if variant_ids is None or target.variant_id in variant_ids
            ]

        has_review = request.args.get('has_review')
        if has_review == 'true':
            assessments = [a for a in assessments if a.id in reviewed_ids]
        elif has_review == 'false':
            assessments = [
                assessment for assessment in assessments
                if any(
                    key not in reviews_by_target
                    or reviews_by_target[key].is_stale()
                    for key in scoped_target_keys(assessment)
                )
            ]

        rows = []
        for a in assessments[offset:offset + limit]:
            scoped_targets = [
                target for target in a.target_rows
                if variant_ids is None or target.variant_id in variant_ids
            ]
            target_keys = [
                (a.id, target.variant_id, target.finding_id)
                for target in scoped_targets
            ]
            row = a.to_dict()
            scoped_packages = list(dict.fromkeys(
                target.finding.package.string_id
                for target in scoped_targets
                if target.finding and target.finding.package
            ))
            scoped_variant_ids = sorted({
                str(target.variant_id) for target in scoped_targets
            })
            row["packages"] = scoped_packages
            row["variant_ids"] = scoped_variant_ids
            row["variant_id"] = (
                scoped_variant_ids[0] if len(scoped_variant_ids) == 1 else None
            )
            row["targets"] = [
                {
                    "variant_id": str(target.variant_id),
                    "project_id": str(variant_project_ids[target.variant_id]),
                    "package": target.finding.package.string_id,
                }
                for target in scoped_targets
                if target.finding and target.finding.package
            ]
            project_ids = {
                variant_project_ids[target.variant_id]
                for target in scoped_targets
            }
            row["project_id"] = (
                str(next(iter(project_ids))) if len(project_ids) == 1 else None
            )
            row["has_review"] = any(key in reviews_by_target for key in target_keys)
            row["target_reviews"] = [
                {
                    "variant_id": str(t.variant_id),
                    "package": t.finding.package.string_id if t.finding and t.finding.package else "",
                    "has_review": (a.id, t.variant_id, t.finding_id) in reviews_by_target,
                    "is_stale": reviews_by_target[(a.id, t.variant_id, t.finding_id)].is_stale()
                    if (a.id, t.variant_id, t.finding_id) in reviews_by_target else False,
                }
                for t in scoped_targets
            ]
            rows.append(row)
        return rows, 200

    @app.route('/api/assessment-reviews', methods=['GET'])
    def list_assessment_reviews() -> ResponseReturnValue:
        """Return reviews grouped by assessment ID for a variant or project scope.

        Each assessment ID may map to several reviews, one per target.

        OpenAPI:
        query variant_id uuid optional Filter by a single variant ID.
        query project_id uuid optional Filter by a single project ID.
        response 200 JsonObject Reviews grouped by assessment ID.
        response 400 Error Invalid identifiers.
        """
        variant_ids, err = _scoped_variant_ids()
        if err:
            return err
        reviews = AssessmentReview.get_for_variants(variant_ids)
        grouped: dict[str, list[dict]] = {}
        for r in reviews:
            grouped.setdefault(str(r.assessment_id), []).append(r.to_dict())
        return grouped, 200

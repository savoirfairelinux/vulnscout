# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import gzip
import json
import re
from datetime import datetime
from typing import Any, Literal, overload
from uuid import UUID

from ..models import Assessment as DBAssessment, Package, Finding, SBOMDocument, SBOMPackage
from ..models.assessment_target import AssessmentTarget, GroupInvariantError
from ..extensions import db, batch_session
from ..models.variant import Variant as DBVariant
from ._scan_helpers import parse_uuid_or_400
from ._scan_queries import VulnerabilityText, fetch_vulnerabilities_texts
from ._scan_diff import invalidate_scan_list_cache
from ..helpers.datetime_utils import ensure_utc_iso
from ..helpers.assessment_io import (
    build_openvex_doc,
    is_openvex_doc,
    import_statements as _import_openvex_statements,
    build_variant_by_name_map,
    build_custom_data_export,
    detect_review_export_format,
    import_custom_data,
    reconcile_review_export,
)
from ..helpers.assessment_staleness import annotate_assessments_outdated
from ..controllers.assessment_groups import build_groups, load_group
from ._assessment_group import (
    apply_reconcile,
    create_assessment_record,
    find_valid_finding,
    index_group_rows,
    parse_reconcile_payload,
    resolve_package,
    resolve_targets,
    validate_assessment_findings,
    validate_deletions,
)

from flask import request, Flask
from flask.typing import ResponseReturnValue
from sqlalchemy import func, select

_SCANNER_AUTHORS = {
    "nvd",
    "unknown",
    "nvd@nist.gov",
    "security-advisories@github.com",
    "cve@mitre.org",
    "secalert@redhat.com",
    "cna@cloudflare.com",
}
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

AssessmentDict = dict[str, Any]
CompactAssessment = list[str | None]


def _is_scanner_author(author: str | None) -> bool:
    if not author:
        return True
    a = author.strip().lower()
    if a in _SCANNER_AUTHORS:
        return True
    if _UUID_RE.match(a):
        return True
    return False


def _has_pending_ai(vuln_id: str, variant_id: UUID | None) -> bool:
    """True if a pending AI assessment already exists for this (vuln, variant)."""
    for a in DBAssessment.get_by_vulnerability(vuln_id):
        if a.origin == "ai" and a.single_variant_id == variant_id:
            return True
    return False


def _resolve_pending_ai_rows(
    assessment_id: str,
) -> "tuple[list[DBAssessment], ResponseReturnValue | None]":
    """Resolve the rows a legacy approve/reject request applies to.

    The addressed assessment must be a pending AI row. A group is an
    assessment, so the group this row belongs to is just the row itself.
    """
    existing = DBAssessment.get_by_id(assessment_id)
    if existing is None:
        return [], ({"error": "Assessment not found"}, 404)
    if existing.origin != "ai":
        return [], ({"error": "Not a pending AI assessment"}, 400)
    return [existing], None


def _approve_rows(rows: "list[DBAssessment]") -> ResponseReturnValue:
    """Turn every pending AI row into a custom assessment."""
    approved = []
    with batch_session():
        for row in rows:
            row.update(origin="custom")
            approved.append(row.to_dict())
    return {"status": "success", "assessments": approved}, 200


def _reject_rows(rows: "list[DBAssessment]") -> ResponseReturnValue:
    """Delete every pending AI row of the rejected group."""
    deleted_ids = [str(row.id) for row in rows]
    with batch_session():
        for row in rows:
            row.delete()
    return {"status": "success", "deleted": deleted_ids}, 200


def _parse_batch_record_ids() -> tuple[list[UUID] | None, str | None]:
    """Return unique UUIDs from a batch-delete request, or an error message."""
    payload = request.get_json(silent=True) or {}
    raw_ids = payload.get("ids")
    if not isinstance(raw_ids, list) or not raw_ids or not all(isinstance(item, str) for item in raw_ids):
        return None, "'ids' must be a non-empty list of record id strings"
    try:
        return list(dict.fromkeys(UUID(item) for item in raw_ids)), None
    except ValueError:
        return None, "'ids' must contain valid record ids"


def init_app(app: Flask) -> None:

    @overload
    def _get_db_assessment_dicts(
        variant_ids: list[UUID] | None = None,
        compact: Literal[False] = False,
    ) -> list[AssessmentDict]:
        ...

    @overload
    def _get_db_assessment_dicts(
        variant_ids: list[UUID] | None,
        compact: Literal[True],
    ) -> list[CompactAssessment]:
        ...

    def _get_db_assessment_dicts(
        variant_ids: list[UUID] | None = None,
        compact: bool = False,
    ) -> list[AssessmentDict] | list[CompactAssessment]:
        """Serialize assessments with one lightweight joined query.

        The Explorer endpoint previously materialized tens of thousands of
        Assessment, Finding, and Package ORM objects only to immediately turn
        them into dictionaries.  Selecting the response columns directly
        avoids that object-graph cost and also lets project scope use one query
        instead of one query per variant.
        """
        if compact:
            ranked = (
                db.select(
                    DBAssessment.id.label("id"),
                    AssessmentTarget.variant_id.label("variant_id"),
                    DBAssessment.timestamp.label("timestamp"),
                    DBAssessment.status.label("status"),
                    Finding.vulnerability_id.label("vulnerability_id"),
                    Package.name.label("name"),
                    Package.version.label("version"),
                    Package.supplier.label("supplier"),
                    func.row_number().over(
                        partition_by=(
                            Finding.vulnerability_id,
                            AssessmentTarget.variant_id,
                            Finding.package_id,
                        ),
                        order_by=(DBAssessment.timestamp.desc(), DBAssessment.id.desc()),
                    ).label("assessment_rank"),
                )
                .join(AssessmentTarget, AssessmentTarget.assessment_id == DBAssessment.id)
                .join(Finding, AssessmentTarget.finding_id == Finding.id)
                .outerjoin(Package, Finding.package_id == Package.id)
                .where(db.or_(DBAssessment.origin.is_(None), DBAssessment.origin != "ai"))
            )
            if variant_ids is not None:
                if not variant_ids:
                    return []
                ranked = ranked.where(AssessmentTarget.variant_id.in_(variant_ids))
            ranked = ranked.subquery()
            query = (
                db.select(
                    ranked.c.id,
                    ranked.c.variant_id,
                    ranked.c.timestamp,
                    ranked.c.status,
                    ranked.c.vulnerability_id,
                    ranked.c.name,
                    ranked.c.version,
                    ranked.c.supplier,
                )
                .where(ranked.c.assessment_rank == 1)
                .order_by(ranked.c.timestamp)
            )
        else:
            ranked = (
                db.select(
                    DBAssessment.id.label("id"),
                    DBAssessment.source.label("source"),
                    DBAssessment.origin.label("origin"),
                    AssessmentTarget.variant_id.label("variant_id"),
                    DBAssessment.timestamp.label("timestamp"),
                    DBAssessment.status.label("status"),
                    DBAssessment.status_notes.label("status_notes"),
                    DBAssessment.justification.label("justification"),
                    DBAssessment.impact_statement.label("impact_statement"),
                    DBAssessment.responses.label("responses"),
                    DBAssessment.workaround.label("workaround"),
                    Finding.vulnerability_id.label("vulnerability_id"),
                    Package.name.label("name"),
                    Package.version.label("version"),
                    Package.supplier.label("supplier"),
                    # A multi-target assessment fans out to one row per target
                    # here; unlike compact (one entry per target by design),
                    # this branch's consumers key by assessment id and expect
                    # exactly one row per assessment, so rank the joined
                    # targets and keep only one representative per assessment.
                    func.row_number().over(
                        partition_by=DBAssessment.id,
                        order_by=(AssessmentTarget.variant_id, AssessmentTarget.finding_id),
                    ).label("target_rank"),
                )
                .join(AssessmentTarget, AssessmentTarget.assessment_id == DBAssessment.id)
                .join(Finding, AssessmentTarget.finding_id == Finding.id)
                .outerjoin(Package, Finding.package_id == Package.id)
                .where(db.or_(DBAssessment.origin.is_(None), DBAssessment.origin != "ai"))
            )
            if variant_ids is not None:
                if not variant_ids:
                    return []
                ranked = ranked.where(AssessmentTarget.variant_id.in_(variant_ids))
            ranked = ranked.subquery()
            query = (
                db.select(
                    ranked.c.id,
                    ranked.c.source,
                    ranked.c.origin,
                    ranked.c.variant_id,
                    ranked.c.timestamp,
                    ranked.c.status,
                    ranked.c.status_notes,
                    ranked.c.justification,
                    ranked.c.impact_statement,
                    ranked.c.responses,
                    ranked.c.workaround,
                    ranked.c.vulnerability_id,
                    ranked.c.name,
                    ranked.c.version,
                    ranked.c.supplier,
                )
                .where(ranked.c.target_rank == 1)
                .order_by(ranked.c.timestamp)
            )

        full_result: list[AssessmentDict] = []
        compact_result: list[CompactAssessment] = []
        for row in db.session.execute(query):
            package_id = ""
            if row.name is not None:
                package_id = f"{row.name}@{row.version}"
                if row.supplier:
                    package_id += f"::{row.supplier}"
            timestamp = ensure_utc_iso(row.timestamp)
            if compact:
                # Positional encoding avoids repeating six field names for
                # every row in this high-volume Explorer-only response:
                # [id, vulnerability, package, variant, timestamp, status].
                compact_result.append([
                    str(row.id),
                    row.vulnerability_id or "",
                    package_id or None,
                    str(row.variant_id) if row.variant_id else None,
                    timestamp,
                    row.status or "",
                ])
                continue
            full_result.append({
                "id": str(row.id),
                "source": row.source or "",
                "origin": row.origin or "sbom",
                "vuln_id": row.vulnerability_id or "",
                "packages": [package_id] if package_id else [],
                "variant_id": str(row.variant_id) if row.variant_id else None,
                "timestamp": timestamp,
                "last_update": timestamp or "",
                "status": row.status or "",
                "status_notes": row.status_notes or "",
                "justification": row.justification or "",
                "impact_statement": row.impact_statement or "",
                "responses": list(row.responses or []),
                "workaround": row.workaround or "",
            })
        return compact_result if compact else full_result

    @app.route('/api/assessments')
    def index_assess() -> ResponseReturnValue:
        """List assessments with optional variant or project filtering.

        By default returns every assessment; with ``format=dict`` the response
        is keyed by assessment ID.

        OpenAPI:
        query variant_id uuid optional Filter by a single variant ID.
        query project_id uuid optional Filter by a single project ID.
        query format string optional Response format such as list or dict.
        response 200 JsonObject Assessment collection.
        """
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')
        compact = request.args.get('format') == 'compact'
        scoped_variant_ids: list[UUID] | None
        if variant_id:
            variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if variant_uuid is None:
                return {"error": "Internal error"}, 500
            scoped_variant_ids = [variant_uuid]
        elif project_id:
            from ..models.variant import Variant as DBVariant
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if project_uuid is None:
                return {"error": "Internal error"}, 500
            variants = DBVariant.get_by_project(project_uuid)
            scoped_variant_ids = [v.id for v in variants]
        else:
            scoped_variant_ids = None

        if compact:
            compact_assessments = _get_db_assessment_dicts(scoped_variant_ids, compact=True)
            payload = json.dumps(compact_assessments, separators=(",", ":")).encode()
            response = app.response_class(payload, mimetype="application/json")
            if "gzip" in request.headers.get("Accept-Encoding", "") and len(payload) > 1024:
                response.set_data(gzip.compress(payload, compresslevel=1))
                response.headers["Content-Encoding"] = "gzip"
                response.headers["Vary"] = "Accept-Encoding"
            return response

        assessments = _get_db_assessment_dicts(scoped_variant_ids, compact=False)
        annotate_assessments_outdated(assessments)
        if request.args.get('format', 'list') == "dict":
            return {a["id"]: a for a in assessments}
        return assessments

    def _review_assessments_by_origin(origin: str) -> ResponseReturnValue:
        """Return assessments matching ``origin``, enriched with a ``vuln_texts``
        key mapping to the vulnerability's ``texts`` dict so the front-end can
        display tooltips without extra requests.
        """
        from ..models.variant import Variant as DBVariant
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')
        variant_ids: list[UUID] | None
        if variant_id:
            vid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if vid is None:
                return {"error": "Internal error"}, 500
            variant_ids = [vid]
            assessments = DBAssessment.get_by_origin([vid], origin=origin)
        elif project_id:
            pid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if pid is None:
                return {"error": "Internal error"}, 500
            variant_ids = [variant.id for variant in DBVariant.get_by_project(pid)]
            assessments = DBAssessment.get_by_origin(variant_ids, origin=origin)
        else:
            variant_ids = None
            assessments = DBAssessment.get_by_origin(origin=origin)

        # Enrich with vulnerability texts for front-end tooltips (single DB pass)
        vuln_ids = {a.vuln_id for a in assessments if a.vuln_id}
        vuln_texts = fetch_vulnerabilities_texts(vuln_ids, variant_ids=variant_ids)

        assessments_serialized = []
        for a in assessments:
            a_ser = a.to_dict()
            a_ser["vuln_texts"] = list(map(VulnerabilityText.to_dict, vuln_texts[a.vuln_id]))
            assessments_serialized.append(a_ser)

        annotate_assessments_outdated(assessments_serialized)
        return assessments_serialized

    @app.route('/api/assessments/review')
    def review_assessments() -> ResponseReturnValue:
        """Return custom assessments awaiting review.

        OpenAPI:
        query variant_id uuid optional Restrict to a single variant.
        query project_id uuid optional Restrict to every variant of a project.
        response 200 JsonObject Custom assessment collection.
        """
        return _review_assessments_by_origin("custom")

    @app.route('/api/assessments/review/ai')
    def review_ai_assessments() -> ResponseReturnValue:
        """Return pending AI-generated assessments.

        OpenAPI:
        query variant_id uuid optional Restrict to a single variant.
        query project_id uuid optional Restrict to every variant of a project.
        response 200 JsonObject AI assessment collection.
        """
        return _review_assessments_by_origin("ai")

    @app.route('/api/assessments/review/export')
    def export_review_openvex() -> ResponseReturnValue:
        """Export custom assessments for one variant as an OpenVEX JSON document.

        OpenAPI:
        query variant_id uuid required Variant to export.
        query author string optional Author name embedded in exported OpenVEX documents.
        response 200 binary OpenVEX JSON download.
        response 400 Error Exactly one variant was not supplied.
        response 404 Error No review assessments available.
        """
        from ..models.variant import Variant as DBVariant

        raw_variant_ids = request.args.getlist('variant_id')
        if len(raw_variant_ids) != 1:
            return {"error": "Exactly one variant_id is required for OpenVEX export"}, 400
        variant_uuid, err = parse_uuid_or_400(raw_variant_ids[0], "variant_id")
        if err:
            return err
        if variant_uuid is None:
            return {"error": "Internal error"}, 500
        variant = DBVariant.get_by_id(variant_uuid)
        if variant is None:
            return {"error": "Variant not found"}, 404

        handmade = DBAssessment.get_by_origin([variant_uuid], origin="custom")
        if not handmade:
            return {"error": "No review assessments to export"}, 404

        author = request.args.get('author', 'Savoir-faire Linux')
        import json
        json_data = json.dumps(build_openvex_doc(handmade, author), indent=2)
        filename = re.sub(r"[^\w\-.]", "_", variant.name)
        return json_data, 200, {
            "Content-Type": "application/json",
            "Content-Disposition": f'attachment; filename="review_openvex_{filename}.json"',
        }

    @app.route('/api/assessments/review/import', methods=['POST'])
    def import_review_openvex() -> ResponseReturnValue:
        """Import an uploaded JSON OpenVEX document into one selected variant.

        OpenAPI:
        body multipart required Multipart request containing the JSON file and variant_id.
        response 200 JsonObject Import summary.
        response 400 Error Invalid uploaded OpenVEX payload.
        response 404 Error Variant not found.
        """
        if not (request.content_type and 'multipart/form-data' in request.content_type):
            return {"error": "Expected multipart/form-data with a file upload"}, 400
        uploaded = request.files.get('file')
        if not uploaded or not uploaded.filename:
            return {"error": "No file uploaded"}, 400
        if not uploaded.filename.endswith(".json"):
            return {"error": "Unsupported file type. Please upload a .json file."}, 400

        raw_variant_id = request.form.get('variant_id')
        if not raw_variant_id:
            return {"error": "variant_id is required for OpenVEX import"}, 400
        target_variant_id, err = parse_uuid_or_400(raw_variant_id, "variant_id")
        if err:
            return err
        if target_variant_id is None:
            return {"error": "Internal error"}, 500
        if DBVariant.get_by_id(target_variant_id) is None:
            return {"error": "Variant not found"}, 404

        timestamp_policy = request.form.get('timestamp_policy', 'original')
        if timestamp_policy not in {'original', 'current'}:
            return {"error": "timestamp_policy must be 'original' or 'current'"}, 400

        import json
        try:
            data = json.load(uploaded.stream)
        except Exception:
            return {"error": "Invalid JSON file"}, 400

        if not is_openvex_doc(data):
            return {
                "error": "Not a valid OpenVEX document "
                         "(missing @context with 'openvex' "
                         "or 'statements' array)"
            }, 400

        created, errors, skipped = _import_openvex_statements(
            data["statements"],
            target_variant_id,
            use_original_timestamps=timestamp_policy == 'original',
        )
        return {"status": "success", "imported": len(created), "skipped": skipped, "errors": errors}, 200

    @app.route('/api/assessments/review/time-estimates')
    def review_time_estimates() -> ResponseReturnValue:
        """Return vulnerabilities that have non-zero time estimates.

        Each entry contains the vulnerability ID and its three-point estimate
        (optimistic / likely / pessimistic) as ISO 8601 durations plus the
        raw hour values.

        OpenAPI:
        query variant_id uuid optional Restrict to a single variant.
        query project_id uuid optional Restrict to every variant of a project.
        response 200 JsonObject Vulnerabilities with time estimates.
        """
        from ..models.time_estimate import TimeEstimate
        from ..models.iso8601_duration import Iso8601Duration
        from ..models.variant import Variant as DBVariant
        from sqlalchemy.orm import joinedload

        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')

        query = (
            db.select(TimeEstimate)
            .join(Finding, TimeEstimate.finding_id == Finding.id)
            .options(joinedload(TimeEstimate.finding))
            .where(
                db.or_(
                    TimeEstimate.optimistic > 0,
                    TimeEstimate.likely > 0,
                    TimeEstimate.pessimistic > 0,
                )
            )
        )

        variant_ids_filter: list[UUID] | None = None
        if variant_id:
            variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if variant_uuid is None:
                return {"error": "Internal error"}, 500
            variant_ids_filter = [variant_uuid]
        elif project_id:
            pid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if pid is None:
                return {"error": "Internal error"}, 500
            variant_ids_filter = [v.id for v in DBVariant.get_by_project(pid)]

        if variant_ids_filter is not None:
            query = query.where(
                db.or_(
                    TimeEstimate.variant_id.in_(variant_ids_filter),
                    TimeEstimate.variant_id.is_(None),
                )
            )

        all_te = list(db.session.execute(query).scalars().all())

        def _hours_to_iso(h: int) -> str:
            try:
                return str(Iso8601Duration(f"PT{h}H"))
            except (ValueError, TypeError):
                return f"PT{h}H"

        # Bulk-load vulnerability texts to avoid N+1 queries
        vuln_ids_for_te = {te.finding.vulnerability_id for te in all_te}
        vuln_texts: dict[str, list[VulnerabilityText]]
        if vuln_ids_for_te:
            vuln_texts = fetch_vulnerabilities_texts(vuln_ids_for_te, variant_ids=variant_ids_filter)
        else:
            vuln_texts = {}

        # Key by (vuln_id, variant_id) so each variant keeps its own estimate
        # instead of variants overwriting each other for the same vulnerability.
        vuln_map: dict[tuple[str, str | None], dict] = {}
        for te in all_te:
            vid = te.finding.vulnerability_id
            scoped_variant = str(te.variant_id) if te.variant_id else None
            opt = te.optimistic or 0
            lik = te.likely or 0
            pes = te.pessimistic or 0
            vuln_map[(vid, scoped_variant)] = {
                "id": str(te.id),
                "vuln_id": vid,
                "variant_id": scoped_variant,
                "optimistic": opt,
                "likely": lik,
                "pessimistic": pes,
                "optimistic_iso": _hours_to_iso(opt),
                "likely_iso": _hours_to_iso(lik),
                "pessimistic_iso": _hours_to_iso(pes),
                "vuln_texts": list(map(VulnerabilityText.to_dict, vuln_texts.get(vid, []))),
            }

        # Prefer variant-scoped entries: when a vuln has at least one
        # variant-scoped estimate, drop its unscoped (variant-less) entry.
        vulns_with_scoped = {vid for (vid, variant) in vuln_map if variant is not None}
        result = [
            entry for (vid, variant), entry in vuln_map.items()
            if variant is not None or vid not in vulns_with_scoped
        ]

        return sorted(result, key=lambda x: (x["vuln_id"], x["variant_id"] or ""))

    @app.route('/api/assessments/review/custom-cvss')
    def review_custom_cvss() -> ResponseReturnValue:
        """Return vulnerabilities that have custom CVSS scores.

        A custom CVSS score is identified by ``origin == 'custom'``.

        OpenAPI:
        query variant_id uuid optional Restrict to a single variant.
        query project_id uuid optional Restrict to every variant of a project.
        response 200 JsonObject Vulnerabilities with custom CVSS scores.
        """
        from ..models.metrics import Metrics

        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')

        variant_ids: list[UUID] | None = None
        query = select(Metrics).where(Metrics.origin == "custom")
        if variant_id:
            vid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if vid is None:
                return {"error": "Internal error"}, 500
            variant_ids = [vid]
            query = query.where(db.or_(Metrics.variant_id == vid, Metrics.variant_id.is_(None)))
        elif project_id:
            pid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if pid is None:
                return {"error": "Internal error"}, 500
            variant_ids = [v.id for v in DBVariant.get_by_project(pid)]
            if variant_ids:
                query = query.where(db.or_(Metrics.variant_id.in_(variant_ids), Metrics.variant_id.is_(None)))
            else:
                query = query.where(db.false())
        query = query.order_by(Metrics.vulnerability_id)

        all_metrics = list(db.session.execute(query).scalars().all())

        vuln_ids = map(lambda m: m.vulnerability_id, all_metrics)
        vuln_texts = fetch_vulnerabilities_texts(vuln_ids, variant_ids=variant_ids)

        result: list[dict] = []
        for m in all_metrics:
            if _is_scanner_author(m.author):
                continue
            result.append({
                "id": str(m.id),
                "vuln_id": m.vulnerability_id,
                "variant_id": str(m.variant_id) if m.variant_id else None,
                "version": m.version or "",
                "vector_string": m.vector or "",
                "base_score": float(m.score) if m.score is not None else 0.0,
                "author": m.author,
                "origin": m.origin or "scanner",
                "vuln_texts": list(map(VulnerabilityText.to_dict, vuln_texts.get(m.vulnerability_id, []))),
            })

        return result

    @app.route('/api/assessments/review/time-estimates', methods=['DELETE'])
    def delete_review_time_estimates() -> ResponseReturnValue:
        """Delete the explicitly selected time estimates as one operation."""
        from ..models.time_estimate import TimeEstimate

        ids, error = _parse_batch_record_ids()
        if error or ids is None:
            return {"error": error or "Invalid record ids"}, 400
        records = [db.session.get(TimeEstimate, estimate_id) for estimate_id in ids]
        if any(record is None for record in records):
            return {"error": "Time estimate not found"}, 404
        for record in records:
            db.session.delete(record)
        db.session.commit()
        return {"status": "success", "deleted": [str(estimate_id) for estimate_id in ids]}, 200

    @app.route('/api/assessments/review/custom-cvss', methods=['DELETE'])
    def delete_review_custom_cvss() -> ResponseReturnValue:
        """Delete selected custom CVSS records without affecting scanner data."""
        from ..models.metrics import Metrics

        ids, error = _parse_batch_record_ids()
        if error or ids is None:
            return {"error": error or "Invalid record ids"}, 400
        records = [db.session.get(Metrics, metric_id) for metric_id in ids]
        if any(record is None or record.origin != "custom" for record in records):
            return {"error": "Custom CVSS score not found"}, 404
        for record in records:
            db.session.delete(record)
        db.session.commit()
        return {"status": "success", "deleted": [str(metric_id) for metric_id in ids]}, 200

    @app.route('/api/assessments/review/export-custom-data')
    def export_review_custom_data() -> ResponseReturnValue:
        """Export handmade and pending AI assessments, custom CVSS scores and
        time estimates as a single JSON file.

        Query parameters:

        * ``variant_id`` - restrict to selected variants; may be repeated.
        * ``project_id`` - restrict to all variants in a project.

        OpenAPI:
        query variant_id uuid optional Restrict export to selected variants; may be repeated.
        query project_id uuid optional Restrict export to a single project.
        response 200 binary Custom review data download.
        response 404 Error No custom data available.
        """
        raw_variant_ids = request.args.getlist('variant_id')
        project_id = request.args.get('project_id')

        from ..models.project import Project as DBProject

        variant_ids: list[UUID] | None = None
        project_name = None
        if raw_variant_ids:
            variant_ids = []
            for raw_variant_id in raw_variant_ids:
                variant_id, err = parse_uuid_or_400(raw_variant_id, "variant_id")
                if err:
                    return err
                if variant_id is None:
                    return {"error": "Internal error"}, 500
                variant_ids.append(variant_id)
            variant = DBVariant.get_by_id(variant_ids[0])
            if variant and variant.project:
                project_name = variant.project.name
        elif project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if project_uuid is None:
                return {"error": "Internal error"}, 500
            project = DBProject.get_by_id(project_uuid)
            if project:
                project_name = project.name
            variant_ids = [variant.id for variant in DBVariant.get_by_project(project_uuid)]

        data = build_custom_data_export(variant_ids)

        if (
            not data["assessments"]
            and not data["ai_assessments"]
            and not data["cvss"]
            and not data["time_estimates"]
        ):
            return {"error": "No custom data to export"}, 404

        import json as _json
        json_bytes = _json.dumps(data, indent=2)
        safe_name = re.sub(r'[^\w\-.]', '_', project_name) if project_name else None
        filename = f"custom_data_{safe_name}.json" if safe_name else "custom_data.json"
        return json_bytes, 200, {
            "Content-Type": "application/json",
            "Content-Disposition": f'attachment; filename="{filename}"',
        }

    @app.route('/api/assessments/review/export-update', methods=['POST'])
    def update_review_export() -> ResponseReturnValue:
        """Update an uploaded Review export using the currently selected variants.

        The uploaded document determines whether VulnScout JSON or OpenVEX is
        generated. Matching records retain their existing order, records for
        variants outside the current selection are removed, and new records
        are appended.

        OpenAPI:
        body multipart required Existing JSON export, project_id and repeated variant_id fields.
        response 200 binary Updated JSON download.
        response 400 Error Unsupported input or invalid variant selection.
        response 404 Error No review data available.
        """
        if not (request.content_type and 'multipart/form-data' in request.content_type):
            return {"error": "Expected multipart/form-data with a file upload"}, 400
        uploaded = request.files.get('file')
        if not uploaded or not uploaded.filename:
            return {"error": "No file uploaded"}, 400
        if not uploaded.filename.lower().endswith('.json'):
            return {"error": "Unsupported file type. Please upload a .json file."}, 400

        try:
            existing = json.load(uploaded.stream)
        except (TypeError, ValueError):
            return {"error": "Invalid JSON file"}, 400
        try:
            export_format = detect_review_export_format(existing)
        except ValueError as error:
            return {"error": str(error)}, 400

        raw_variant_ids = request.form.getlist('variant_id')
        if not raw_variant_ids:
            return {"error": "At least one variant_id is required"}, 400
        raw_project_id = request.form.get('project_id')
        if not raw_project_id:
            return {"error": "project_id is required"}, 400
        project_id, err = parse_uuid_or_400(raw_project_id, "project_id")
        if err:
            return err
        if project_id is None:
            return {"error": "Internal error"}, 500
        variant_ids: list[UUID] = []
        for raw_variant_id in raw_variant_ids:
            variant_id, err = parse_uuid_or_400(raw_variant_id, "variant_id")
            if err:
                return err
            if variant_id is None:
                return {"error": "Internal error"}, 500
            variant = DBVariant.get_by_id(variant_id)
            if variant is None:
                return {"error": f"Variant not found: {raw_variant_id}"}, 404
            if variant.project_id != project_id:
                return {"error": f"Variant does not belong to project: {raw_variant_id}"}, 400
            variant_ids.append(variant_id)

        if export_format == 'openvex':
            if len(variant_ids) != 1:
                return {"error": "Exactly one variant_id is required for OpenVEX export"}, 400
            handmade = DBAssessment.get_by_origin(variant_ids, origin="custom")
            current = build_openvex_doc(
                handmade,
                request.form.get('author', existing.get('author', 'Savoir-faire Linux')),
            )
        else:
            current = build_custom_data_export(variant_ids)

        try:
            updated = reconcile_review_export(existing, current)
        except ValueError as error:
            return {"error": str(error)}, 400

        filename = re.sub(r'[^\w\-.]', '_', uploaded.filename) or 'review_export.json'
        return json.dumps(updated, indent=2), 200, {
            "Content-Type": "application/json",
            "Content-Disposition": f'attachment; filename="{filename}"',
        }

    @app.route('/api/assessments/review/import-custom-data', methods=['POST'])
    def import_review_custom_data() -> ResponseReturnValue:
        """Import handmade and pending AI assessments, CVSS scores and time
        estimates from a custom-data JSON file.

        Accepts either:

        * ``multipart/form-data`` with a ``file`` field containing a ``.json``
                    file and a destination ``project_id`` field.
        * ``application/json`` body with the custom-data payload directly.

        OpenAPI:
        body JsonObject optional JSON payload or uploaded custom-data file.
        response 200 JsonObject Import summary.
        response 400 Error Invalid import payload.
        """
        import json as _json
        if request.args.getlist('variant_id'):
            return {"error": "VulnScout JSON import uses the variants in the file"}, 400

        # Parse the incoming data
        data = None
        project_id = None
        if request.content_type and 'multipart/form-data' in request.content_type:
            uploaded = request.files.get('file')
            if not uploaded or not uploaded.filename:
                return {"error": "No file uploaded"}, 400
            try:
                data = _json.load(uploaded.stream)
            except Exception:
                return {"error": "Invalid JSON file"}, 400
            project_id = request.form.get('project_id')
        elif request.content_type and 'application/json' in request.content_type:
            data = request.get_json(silent=True)
            if data is None:
                return {"error": "Invalid JSON body"}, 400
            project_id = data.get('project_id')
        else:
            return {"error": "Expected multipart/form-data or application/json"}, 400

        if not isinstance(data, dict) or "version" not in data:
            return {"error": "Invalid custom-data format. Expected {version, assessments, ...}"}, 400

        if not isinstance(project_id, str) or not project_id:
            return {"error": "project_id is required"}, 400
        project_uuid, err = parse_uuid_or_400(project_id, "project_id")
        if err:
            return err
        if project_uuid is None:
            return {"error": "Internal error"}, 500

        from ..models.project import Project as DBProject
        if DBProject.get_by_id(project_uuid) is None:
            return {"error": "Project not found"}, 404

        timestamp_policy = data.get('timestamp_policy', 'current')
        if timestamp_policy not in {'original', 'current'}:
            return {"error": "timestamp_policy must be 'original' or 'current'"}, 400

        variant_by_name = build_variant_by_name_map(project_uuid)
        result = import_custom_data(
            data,
            variant_by_name,
            use_original_timestamps=timestamp_policy == 'original',
        )

        status_code = 200 if result["status"] == "success" else 400
        return result, status_code

    @app.route('/api/assessments/<assessment_id>')
    def assess_by_id(assessment_id: str) -> ResponseReturnValue:
        """Return a single assessment by identifier.

        OpenAPI:
        response 200 JsonObject Assessment payload.
        response 404 Error Assessment not found.
        """
        item = DBAssessment.get_by_id(assessment_id)
        if item is None:
            return {"error": "Not found"}, 404
        return item.to_dict(), 200

    @app.route('/api/vulnerabilities/<vuln_id>/assessments')
    def list_assess_by_vuln(vuln_id: str) -> ResponseReturnValue:
        """List assessments linked to a vulnerability.

        OpenAPI:
        query format string optional Response format such as list or dict.
        query project_id uuid optional Restrict results to one project.
        response 200 JsonObject Assessment collection for the vulnerability.
        """
        project_uuid: UUID | None = None
        project_id = request.args.get('project_id')
        if project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err

        project_variant_ids: set[UUID] | None = None
        if project_uuid is not None:
            project_variant_ids = set(db.session.execute(
                select(DBVariant.id).where(DBVariant.project_id == project_uuid)
            ).scalars())

        # Get findings for this vulnerability then load their assessments
        findings = Finding.get_by_vulnerability(vuln_id)
        rows = []
        for f in findings:
            for a in DBAssessment.get_by_finding(f.id):
                if project_variant_ids is not None and not any(
                    t.variant_id in project_variant_ids for t in a.target_rows
                ):
                    continue
                rows.append(a)
        assessments = [a.to_dict() for a in rows]
        annotate_assessments_outdated(assessments)
        if request.args.get('format', 'list') == "dict":
            return {a["id"]: a for a in assessments}
        return assessments, 200

    @app.route('/api/vulnerabilities/<vuln_id>/assessment-groups', methods=['GET'])
    def list_assessment_groups(vuln_id: str) -> ResponseReturnValue:
        """List assessment groups for a vulnerability.

        OpenAPI:
        query project_id uuid optional Restrict results to one project.
        response 200 JsonArray Assessment groups for the vulnerability.
        """
        project_uuid: UUID | None = None
        project_id = request.args.get('project_id')
        if project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err

        project_variant_ids: set[UUID] | None = None
        if project_uuid is not None:
            project_variant_ids = set(db.session.execute(
                select(DBVariant.id).where(DBVariant.project_id == project_uuid)
            ).scalars())

        rows = []
        for finding in Finding.get_by_vulnerability(vuln_id):
            for a in DBAssessment.get_by_finding(finding.id):
                if project_variant_ids is not None and not any(
                    t.variant_id in project_variant_ids for t in a.target_rows
                ):
                    continue
                rows.append(a)
        return build_groups(rows), 200

    @app.route('/api/assessment-groups/<group_id>', methods=['GET'])
    def get_assessment_group(group_id: str) -> ResponseReturnValue:
        """Return one assessment group by its id.

        OpenAPI:
        response 200 JsonObject The assessment group.
        response 404 Error No such group.
        """
        group_uuid, err = parse_uuid_or_400(group_id, "group_id")
        if err:
            return err
        if group_uuid is None:
            return {"error": "Internal error"}, 500
        rows = load_group(group_uuid)
        if not rows:
            return {"error": "Group not found"}, 404
        return build_groups(rows)[0], 200

    @app.route('/api/assessment-groups/<group_id>/reconcile', methods=['POST'])
    def reconcile_assessment_group(group_id: str) -> ResponseReturnValue:
        """Bring an assessment group to the requested state in one transaction.

        OpenAPI:
        body JsonObject optional Desired group content and targets.
        response 200 JsonObject The reconciled group.
        response 400 Error Invalid reconcile payload.
        response 404 Error No such group.
        """
        group_uuid, err = parse_uuid_or_400(group_id, "group_id")
        if err:
            return err
        if group_uuid is None:
            return {"error": "Internal error"}, 500

        rows = load_group(group_uuid)
        if not rows:
            return {"error": "Group not found"}, 404

        req, parse_err = parse_reconcile_payload(request.get_json() or {})
        if parse_err:
            return parse_err, 400
        if req is None:
            return {"error": "Internal error"}, 500

        group_vuln_id = (rows[0].vuln_id or "").upper()
        if req.vuln_id.upper() != group_vuln_id:
            return {"error": "vuln_id does not match this group's vulnerability"}, 400

        existing_by_key = index_group_rows(rows)
        targets, target_err = resolve_targets(req, existing_by_key)
        if target_err:
            return target_err, 400

        deletion_err = validate_deletions(rows, targets)
        if deletion_err:
            return deletion_err, 400

        try:
            with batch_session():
                result = apply_reconcile(req, rows, targets)
        except GroupInvariantError as e:
            return {"error": str(e)}, 400
        except Exception as e:
            return {"error": f"DB error: {e}"}, 500

        if result["became_custom"] or result["deleted_non_custom"]:
            invalidate_scan_list_cache()

        return {
            "status": "success",
            "group_id": str(group_uuid),
            "updated": result["updated"],
            "created": result["created"],
            "deleted": result["deleted"],
        }, 200

    @app.route('/api/reviews/assessment-groups', methods=['GET'])
    def list_review_assessment_groups() -> ResponseReturnValue:
        """List assessment groups for the review table.

        OpenAPI:
        query variant_id uuid optional Restrict results to one variant.
        query project_id uuid optional Restrict results to one project.
        query origin string optional Restrict results to one origin.
        response 200 JsonArray Assessment groups for review.
        """
        query = select(DBAssessment)
        # The variant/project filters below match against the joined target
        # rather than the assessment; joining once and adding .distinct()
        # keeps the one-row-per-assessment shape build_groups() expects even
        # though the join fans out to one row per matching target.
        joined_targets = False
        variant_ids: list[UUID] | None = None
        variant_id = request.args.get('variant_id')
        if variant_id:
            variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if not joined_targets:
                query = query.join(AssessmentTarget, AssessmentTarget.assessment_id == DBAssessment.id)
                joined_targets = True
            query = query.where(AssessmentTarget.variant_id == variant_uuid)
            variant_ids = [variant_uuid] if variant_uuid else None

        project_id = request.args.get('project_id')
        if project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            project_variant_ids = [v.id for v in DBVariant.get_by_project(project_uuid)] if project_uuid else []
            if not joined_targets:
                query = query.join(AssessmentTarget, AssessmentTarget.assessment_id == DBAssessment.id)
                joined_targets = True
            query = query.where(AssessmentTarget.variant_id.in_(project_variant_ids))
            variant_ids = project_variant_ids

        origin = request.args.get('origin')
        if origin:
            query = query.where(DBAssessment.origin == origin)

        if joined_targets:
            query = query.distinct()

        assessments = list(db.session.execute(query).scalars())
        groups = build_groups(assessments)

        # Enrich with vulnerability texts for front-end tooltips (single DB
        # pass) — the review table spans several CVEs, unlike the vuln-scoped
        # /assessment-groups routes where the caller already knows the texts.
        vuln_ids = {g["vuln_id"] for g in groups if g.get("vuln_id")}
        vuln_texts = fetch_vulnerabilities_texts(vuln_ids, variant_ids=variant_ids)
        for g in groups:
            g["vuln_texts"] = list(map(VulnerabilityText.to_dict, vuln_texts.get(g["vuln_id"], [])))

        return groups, 200

    @app.route('/api/vulnerabilities/<vuln_id>/variants', methods=['GET'])
    def list_variants_by_vuln(vuln_id: str) -> ResponseReturnValue:
        """Return all distinct variants that have a finding for this vulnerability
        (via the Observation → Scan → Variant chain).

        OpenAPI:
        response 200 JsonObject Variants impacted by the vulnerability.
        """
        from ..models.observation import Observation
        from ..models.scan import Scan
        from ..models.variant import Variant as DBVariant
        findings = Finding.get_by_vulnerability(vuln_id)
        seen_variant_ids: set = set()
        variants_out = []
        for finding in findings:
            for obs in Observation.get_by_finding(finding.id):
                scan = db.session.get(Scan, obs.scan_id)
                if scan is None:
                    continue
                if scan.variant_id in seen_variant_ids:
                    continue
                seen_variant_ids.add(scan.variant_id)
                variant = db.session.get(DBVariant, scan.variant_id)
                if variant:
                    variants_out.append({
                        "id": str(variant.id),
                        "name": variant.name,
                        "project_id": str(variant.project_id),
                    })
        return variants_out, 200

    @app.route('/api/vulnerabilities/<vuln_id>/variant-active-packages')
    def list_variant_active_packages(vuln_id: str) -> ResponseReturnValue:
        """For each variant affected by this vulnerability, return the subset of
        the vulnerability's packages still present in that variant's active SBOM.

        Lets the front-end classify deprecated (variant, package) pairs in a
        single request instead of one ``/api/packages`` call per variant.

        OpenAPI:
        query project_id uuid optional Restrict the result to one project.
        response 200 JsonObject Active packages by variant.
        """
        from ..models.observation import Observation
        from ..models.scan import Scan
        from ..models.variant import Variant as DBVariant
        from ..helpers.active_scans import (
            active_sbom_scan_ids_for_variant,
            active_package_ids_for_scans,
        )

        project_uuid: UUID | None = None
        project_id = request.args.get('project_id')
        if project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err

        findings = Finding.get_by_vulnerability(vuln_id)
        # package_id -> string_id for the packages affected by this vulnerability
        pkg_string_by_id: dict[UUID, str] = {}
        for f in findings:
            if f.package_id and f.package:
                pkg_string_by_id[f.package_id] = f.package.string_id

        # Distinct variants and findings for this vuln
        # (Finding -> Observation -> Scan -> Variant).
        seen_variant_ids: set[UUID] = set()
        variant_ids: list[UUID] = []
        finding_ids_by_variant: dict[UUID, set[UUID]] = {}
        for finding in findings:
            for obs in Observation.get_by_finding(finding.id):
                scan = db.session.get(Scan, obs.scan_id)
                if scan is None:
                    continue
                if project_uuid is not None:
                    variant = db.session.get(DBVariant, scan.variant_id)
                    if variant is None or variant.project_id != project_uuid:
                        continue
                finding_ids_by_variant.setdefault(scan.variant_id, set()).add(finding.id)
                if scan.variant_id not in seen_variant_ids:
                    seen_variant_ids.add(scan.variant_id)
                    variant_ids.append(scan.variant_id)

        result: list[dict[str, Any]] = []
        vuln_pkg_ids = set(pkg_string_by_id.keys())
        for vid in variant_ids:
            active_scan_ids = active_sbom_scan_ids_for_variant(vid)
            active_ids = active_package_ids_for_scans(active_scan_ids, restrict_to_package_ids=vuln_pkg_ids)
            active_packages = [sid for pid, sid in pkg_string_by_id.items() if pid in active_ids]
            active_identities = set(db.session.execute(
                db.select(Package.name, Package.version)
                .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                .where(SBOMDocument.scan_id.in_(active_scan_ids))
                .distinct()
            ).all()) if active_scan_ids else set()
            variant_findings: list[dict[str, str | bool]] = []
            for finding in findings:
                if finding.id not in finding_ids_by_variant.get(vid, set()) or finding.package is None:
                    continue
                variant_findings.append({
                    "finding_id": str(finding.id),
                    "package": finding.package.string_id,
                    "outdated": (finding.package.name, finding.package.version) not in active_identities,
                })
            result.append({
                "variant_id": str(vid),
                "active_packages": active_packages,
                "findings": sorted(
                    variant_findings,
                    key=lambda item: (str(item.get("package", "")), str(item.get("finding_id", ""))),
                ),
            })
        return result, 200

    @app.route("/api/vulnerabilities/<vuln_id>/assessments", methods=["POST"])
    def add_assessment(vuln_id: str) -> ResponseReturnValue:
        """Create one or more custom assessments for a vulnerability.

        OpenAPI:
        body JsonObject optional Assessment creation payload.
        response 200 JsonObject Created assessment payload.
        response 400 Error Invalid assessment payload.
        response 500 Error Database error while creating the assessment.
        """
        payload_data = request.get_json()
        if not payload_data:
            return {"error": "Invalid request data"}, 400

        if "vuln_id" not in payload_data:
            payload_data["vuln_id"] = vuln_id
        elif payload_data["vuln_id"] != vuln_id or not isinstance(payload_data["vuln_id"], str):
            return {"error": "Invalid vuln_id"}, 400

        assessment, status = payload_to_assessment(payload_data)
        if status != 200:
            if not isinstance(assessment, dict):
                return {"error": "Internal error"}, 500
            return assessment, status
        if not isinstance(assessment, DBAssessment):
            return {"error": "Internal error"}, 500

        # Resolve variant_id once — same for all packages in this request
        variant_id_raw = payload_data.get('variant_id') or None
        if not variant_id_raw:
            return {"error": "variant_id is required"}, 400
        variant_id, err = parse_uuid_or_400(variant_id_raw, "variant_id")
        if err:
            return err
        if variant_id is None:
            return {"error": "Invalid variant_id"}, 400

        ai_generated = bool(payload_data.get("ai_generated"))
        target_origin = "ai" if ai_generated else "custom"
        if ai_generated and _has_pending_ai(vuln_id, variant_id):
            return {"error": "A pending AI assessment already exists for this variant"}, 409

        # Persist to DB — one Assessment record per package
        # Use a single timestamp so grouped rows share the exact same value.
        # Prefer the timestamp from the payload (allows frontend to synchronise
        # across multiple requests); fall back to server time.
        from datetime import datetime as _dt, timezone as _tz
        shared_timestamp = getattr(assessment, 'timestamp', None) or _dt.now(_tz.utc)

        # Resolve every package up front. Assessments must never create a
        # package: if any referenced package is missing, block the whole request.
        resolved_packages: list[Package] = []
        missing_packages: list[str] = []
        for pkg_string_id in (assessment.packages or []):
            db_pkg = resolve_package(pkg_string_id)
            if db_pkg is None:
                missing_packages.append(pkg_string_id)
            else:
                resolved_packages.append(db_pkg)
        if missing_packages:
            return {
                "error": "Package not found: " + ", ".join(missing_packages)
                + ". Assessments can only be written for existing packages."
            }, 400

        valid_findings, invalid_findings = validate_assessment_findings(
            resolved_packages, vuln_id, variant_id
        )
        if invalid_findings:
            return {
                "error": "Invalid package version for vulnerability and variant: "
                + ", ".join(invalid_findings)
            }, 400

        requested_group_id: UUID | None = None
        if payload_data.get("group_id"):
            requested_group_id, err = parse_uuid_or_400(
                payload_data["group_id"], "group_id")
            if err:
                return err
            if requested_group_id is not None:
                existing_group_rows = load_group(requested_group_id)
                if not existing_group_rows:
                    return {"error": "Group not found"}, 404
                if (existing_group_rows[0].vuln_id or "").upper() != vuln_id.upper():
                    return {"error": "vuln_id does not match this group's vulnerability"}, 400

        created_rows: list[DBAssessment] = []
        try:
            with batch_session():
                for db_pkg in resolved_packages:
                    finding = valid_findings[db_pkg.id]
                    # Always create a new record — never merge with an existing one.
                    # from_vuln_assessment does a find-or-update which would overwrite
                    # previous user assessments on the same (finding, variant).
                    db_a = create_assessment_record(
                        assessment, finding.id, variant_id, timestamp=shared_timestamp,
                        origin=target_origin)
                    created_rows.append(db_a)
        except GroupInvariantError as e:
            return {"error": str(e)}, 400
        except Exception as e:
            return {"error": f"DB error: {e}"}, 500

        # group_id is the row's own id, so no preload step is needed to
        # serialize it.
        created = [row.to_dict() for row in created_rows]

        if not created:
            return {"error": "No valid package found"}, 400

        response_body = {"status": "success", "assessments": created, "assessment": created[0]}
        return response_body, 200

    @app.route("/api/assessments/batch", methods=["POST"])
    def add_assessments_batch() -> ResponseReturnValue:
        """Create multiple custom assessments in a single request.

        OpenAPI:
        body JsonObject optional Batch assessment creation payload.
        response 200 JsonObject Batch creation summary.
        response 400 Error Invalid batch payload.
        """
        payload_data = request.get_json()
        if not payload_data or "assessments" not in payload_data or not isinstance(payload_data["assessments"], list):
            return {"error": "Invalid request data. Expected: {assessments: [...]}"}, 400

        errors: list[dict[str, Any]] = []
        prepared: list[tuple[DBAssessment, UUID, list[Package], dict[UUID, Finding]]] = []
        pkg_cache: dict[str, Package] = {}

        # Validate the complete request before opening the write transaction.
        # A batch represents one user action, so one invalid package/variant
        # relationship must cancel every assessment in that action.
        for item in payload_data["assessments"]:
            if not isinstance(item, dict) or "vuln_id" not in item:
                errors.append({"error": "Invalid assessment data", "item": item})
                continue

            assessment, status = payload_to_assessment(item)
            if status != 200:
                error = assessment.get("error", "Unknown error") if isinstance(assessment, dict) else "Internal error"
                errors.append({"vuln_id": item.get("vuln_id"), "error": error})
                continue
            if not isinstance(assessment, DBAssessment):
                errors.append({"vuln_id": item.get("vuln_id"), "error": "Internal error"})
                continue

            vuln_id = assessment.vuln_id
            variant_id_raw = item.get("variant_id") or None
            if not variant_id_raw:
                errors.append({"vuln_id": vuln_id, "error": "variant_id is required"})
                continue
            variant_id, err = parse_uuid_or_400(variant_id_raw, "variant_id")
            if err:
                errors.append({"vuln_id": vuln_id, "error": "Invalid variant_id"})
                continue
            if variant_id is None:
                errors.append({"vuln_id": vuln_id, "error": "Invalid variant_id"})
                continue

            pkg_list = assessment.packages or []
            if not pkg_list:
                errors.append({"vuln_id": vuln_id, "variant_id": str(variant_id), "error": "No valid package found"})
                continue

            item_packages: list[Package] = []
            item_missing: list[str] = []
            for pkg_string_id in pkg_list:
                db_pkg = pkg_cache.get(pkg_string_id)
                if db_pkg is None:
                    db_pkg = resolve_package(pkg_string_id)
                    if db_pkg is not None:
                        pkg_cache[pkg_string_id] = db_pkg
                if db_pkg is None:
                    item_missing.append(pkg_string_id)
                else:
                    item_packages.append(db_pkg)
            if item_missing:
                errors.append({
                    "vuln_id": vuln_id,
                    "variant_id": str(variant_id),
                    "error": "Package not found: " + ", ".join(item_missing)
                    + ". Assessments can only be written for existing packages.",
                })
                continue

            valid_findings, invalid_findings = validate_assessment_findings(
                item_packages, vuln_id, variant_id
            )
            if invalid_findings:
                errors.append({
                    "vuln_id": vuln_id,
                    "variant_id": str(variant_id),
                    "error": "Invalid package version for vulnerability and variant: "
                    + ", ".join(invalid_findings),
                })
                continue
            prepared.append((assessment, variant_id, item_packages, valid_findings))

        if errors:
            return {
                "status": "error",
                "assessments": [],
                "count": 0,
                "vuln_count": 0,
                "errors": errors,
                "error_count": len(errors),
            }, 400

        results: list[AssessmentDict] = []
        try:
            with batch_session():
                # A batch is one user action but may span several CVEs,
                # several projects and several distinct contents. Each
                # created row is its own group — batching writes never
                # fuses rows together (per-package/per-row fusion at write
                # time is out of scope for this phase).
                created_rows: list[DBAssessment] = []
                for assessment, variant_id, item_packages, valid_findings in prepared:
                    for db_pkg in item_packages:
                        created_rows.append(create_assessment_record(
                            assessment, valid_findings[db_pkg.id].id, variant_id,
                            timestamp=getattr(assessment, "timestamp", None),
                        ))

                # group_id is the row's own id, so no preload step is needed
                # to serialize it.
                results = [row.to_dict() for row in created_rows]
        except Exception as e:
            return {
                "status": "error",
                "assessments": [],
                "count": 0,
                "vuln_count": 0,
                "errors": [{"error": f"DB error: {e}"}],
                "error_count": 1,
            }, 500

        distinct_vulns = len({r.get("vuln_id") for r in results if r.get("vuln_id")})
        response = {
            "status": "success" if results else "error",
            "assessments": results,
            "count": len(results),
            "vuln_count": distinct_vulns
        }
        return response, 200 if results else 400

    @app.route("/api/assessments/<assessment_id>", methods=["PUT", "PATCH"])
    def update_assessment(assessment_id: str) -> ResponseReturnValue:
        """Update a custom assessment or override an automated one.

        OpenAPI:
        body JsonObject optional Assessment update payload.
        response 200 JsonObject Updated assessment payload.
        response 400 Error Invalid assessment update.
        response 404 Error Assessment not found.
        """
        payload_data = request.get_json()
        if not payload_data:
            return {"error": "Invalid request data"}, 400

        existing = DBAssessment.get_by_id(assessment_id)
        if existing is None:
            return {"error": "Assessment not found"}, 404
        if not existing.target_rows or any(
            find_valid_finding(
                target.finding.package_id,
                target.finding.vulnerability_id,
                target.variant_id,
            ) is None
            for target in existing.target_rows
        ):
            return {"error": "Assessment references a package version that is not valid for its variant"}, 400

        was_non_custom = (existing.origin or "") != "custom"
        # Editing a pending AI assessment directly must not silently approve
        # it: keep its origin as "ai" so it stays pending until the user
        # explicitly approves/rejects it via the dedicated endpoints.
        new_origin = "ai" if existing.origin == "ai" else "custom"

        # Reconstruct Assessment DTO for validation
        mem_assess = DBAssessment.from_dict(existing.to_dict())

        if "status" in payload_data and isinstance(payload_data["status"], str):
            if not mem_assess.set_status(payload_data["status"]):
                return {"error": "Invalid status"}, 400
            if mem_assess.status not in ["not_affected", "false_positive"]:
                mem_assess.justification = ""
                mem_assess.impact_statement = ""

        if "status_notes" in payload_data and isinstance(payload_data["status_notes"], str):
            mem_assess.set_status_notes(payload_data["status_notes"], False)

        if "justification" in payload_data and isinstance(payload_data["justification"], str):
            if payload_data["justification"] == "":
                mem_assess.justification = ""
            elif not mem_assess.set_justification(payload_data["justification"]):
                return {"error": "Invalid justification"}, 400
        elif mem_assess.is_justification_required():
            return {"error": "Justification required"}, 400

        if "impact_statement" in payload_data and isinstance(payload_data["impact_statement"], str):
            if payload_data["impact_statement"] == "":
                mem_assess.impact_statement = ""
            else:
                mem_assess.set_not_affected_reason(payload_data["impact_statement"], False)

        if "workaround" in payload_data and isinstance(payload_data["workaround"], str):
            mem_assess.set_workaround(payload_data["workaround"])

        update_timestamp = payload_data.get("update_timestamp", True)
        if not isinstance(update_timestamp, bool):
            return {"error": "update_timestamp must be a boolean"}, 400
        edit_timestamp = None
        if update_timestamp and "timestamp" in payload_data:
            if not isinstance(payload_data["timestamp"], str):
                return {"error": "timestamp must be an ISO 8601 string"}, 400
            try:
                edit_timestamp = datetime.fromisoformat(payload_data["timestamp"].replace("Z", "+00:00"))
            except ValueError:
                return {"error": "Invalid timestamp"}, 400

        existing.update(
            status=mem_assess.status,
            origin=new_origin,
            status_notes=mem_assess.status_notes,
            justification=mem_assess.justification,
            impact_statement=mem_assess.impact_statement,
            workaround=getattr(mem_assess, "workaround", None),
            responses=list(mem_assess.responses or []),
            timestamp=edit_timestamp,
            update_timestamp=update_timestamp,
        )
        # Editing an automated assessment removes it from the scan-history
        # counts (it becomes custom-origin), so refresh the cached list view.
        # A pending AI row that stays "ai" after editing has not changed its
        # scan-history membership, so no cache refresh is needed in that case.
        if was_non_custom and new_origin == "custom":
            invalidate_scan_list_cache()
        return {"status": "success", "assessment": existing.to_dict()}, 200

    @app.route("/api/assessments/<assessment_id>", methods=["DELETE"])
    def delete_assessment(assessment_id: str) -> ResponseReturnValue:
        """Delete an assessment.

        OpenAPI:
        response 200 JsonObject Deletion summary.
        response 404 Error Assessment not found.
        """
        existing = DBAssessment.get_by_id(assessment_id)
        if existing is None:
            return {"error": "Assessment not found"}, 404
        # A non-custom assessment contributes to the scan-history counts, so
        # its removal must invalidate the cached list view.
        was_non_custom = (existing.origin or "") != "custom"
        if existing.origin == "ai":
            return {"error": "Use the AI approve/reject endpoints for pending AI assessments"}, 400
        existing.delete()
        if was_non_custom:
            invalidate_scan_list_cache()
        return {"status": "success", "message": "Assessment deleted successfully"}, 200

    @app.route("/api/assessment-groups/<group_id>/approve", methods=["POST"])
    def approve_ai_group(group_id: str) -> ResponseReturnValue:
        """Approve every AI-origin assessment in a group, converting it to custom.

        OpenAPI:
        response 200 JsonObject Approved assessments.
        response 400 Error Group is not a pending AI group.
        response 404 Error No such group.
        """
        group_uuid, err = parse_uuid_or_400(group_id, "group_id")
        if err:
            return err
        if group_uuid is None:
            return {"error": "Internal error"}, 500
        rows = load_group(group_uuid)
        if not rows:
            return {"error": "Group not found"}, 404
        if any(row.origin != "ai" for row in rows):
            return {"error": "Not a pending AI group"}, 400
        return _approve_rows(rows)

    @app.route("/api/assessments/<assessment_id>/approve", methods=["POST"])
    def approve_ai_assessment(assessment_id: str) -> ResponseReturnValue:
        """Approve a pending AI assessment and every sibling in its group.

        Compatibility wrapper kept for CLI and integration clients written
        against the pre-group API; it resolves the addressed assessment's group
        and behaves exactly like the group endpoint.

        OpenAPI:
        response 200 JsonObject Approved assessments.
        response 400 Error Not a pending AI assessment.
        response 404 Error Assessment not found.
        """
        rows, err = _resolve_pending_ai_rows(assessment_id)
        if err is not None:
            return err
        return _approve_rows(rows)

    @app.route("/api/assessment-groups/<group_id>/reject", methods=["POST"])
    def reject_ai_group(group_id: str) -> ResponseReturnValue:
        """Reject every AI-origin assessment in a group, deleting the whole group.

        OpenAPI:
        response 200 JsonObject Deleted assessment ids.
        response 400 Error Group is not a pending AI group.
        response 404 Error No such group.
        """
        group_uuid, err = parse_uuid_or_400(group_id, "group_id")
        if err:
            return err
        if group_uuid is None:
            return {"error": "Internal error"}, 500
        rows = load_group(group_uuid)
        if not rows:
            return {"error": "Group not found"}, 404
        if any(row.origin != "ai" for row in rows):
            return {"error": "Not a pending AI group"}, 400
        return _reject_rows(rows)

    @app.route("/api/assessments/<assessment_id>/reject", methods=["POST"])
    def reject_ai_assessment(assessment_id: str) -> ResponseReturnValue:
        """Reject a pending AI assessment and every sibling in its group.

        Compatibility wrapper kept for CLI and integration clients written
        against the pre-group API; it resolves the addressed assessment's group
        and behaves exactly like the group endpoint.

        OpenAPI:
        response 200 JsonObject Deleted assessment ids.
        response 400 Error Not a pending AI assessment.
        response 404 Error Assessment not found.
        """
        rows, err = _resolve_pending_ai_rows(assessment_id)
        if err is not None:
            return err
        return _reject_rows(rows)

    @app.route('/api/assessment-groups/<group_id>', methods=['DELETE'])
    def delete_assessment_group(group_id: str) -> ResponseReturnValue:
        """Delete every assessment in a group.

        OpenAPI:
        response 200 JsonObject Ids of the deleted assessments.
        response 404 Error No such group.
        """
        group_uuid, err = parse_uuid_or_400(group_id, "group_id")
        if err:
            return err
        if group_uuid is None:
            return {"error": "Internal error"}, 500
        rows = load_group(group_uuid)
        if not rows:
            return {"error": "Group not found"}, 404
        if any(row.origin == "ai" for row in rows):
            return {"error": "Use the AI approve/reject endpoints for pending AI assessments"}, 400
        deleted_ids = [str(row.id) for row in rows]
        was_non_custom = any((row.origin or "") != "custom" for row in rows)
        with batch_session():
            for row in rows:
                row.delete()
        if was_non_custom:
            invalidate_scan_list_cache()
        return {"status": "success", "deleted_ids": deleted_ids}, 200

    @app.route('/api/assessments/<assessment_id>/group', methods=['POST'])
    def promote_assessment_to_group(assessment_id: str) -> ResponseReturnValue:
        """Return the group an assessment belongs to.

        A group is an assessment, so every assessment already has one: its
        own id. Kept as a POST, and kept idempotent, for compatibility with
        clients that call this to lazily create a group before addressing
        further writes at it.

        OpenAPI:
        response 200 JsonObject The group id the assessment belongs to.
        response 404 Error No such assessment.
        """
        assessment_uuid, err = parse_uuid_or_400(assessment_id, "assessment_id")
        if err:
            return err
        if assessment_uuid is None:
            return {"error": "Internal error"}, 500
        row = DBAssessment.get_by_id(assessment_uuid)
        if row is None:
            return {"error": "Assessment not found"}, 404
        return {"group_id": str(row.id)}, 200


def payload_to_assessment(data: dict) -> "tuple[DBAssessment | dict[str, str], int]":
    """
    Take an object in input and try to convert it to an Assessment DTO.
    Return either (Assessment, 200) or (error_dict, http_code).
    """
    if "packages" not in data or not isinstance(data["packages"], list) or len(data["packages"]) < 1:
        return {"error": "Invalid request data"}, 400

    assessment = DBAssessment.new_dto(data["vuln_id"], data["packages"])

    if "status" not in data or not isinstance(data["status"], str):
        return {"error": "Invalid request data"}, 400

    if assessment.set_status(data["status"]) is False:
        return {"error": "Invalid status"}, 400

    if "status_notes" in data and isinstance(data["status_notes"], str):
        assessment.set_status_notes(data["status_notes"], False)

    if "justification" in data and isinstance(data["justification"], str):
        if not assessment.set_justification(data["justification"]):
            return {"error": "Invalid justification"}, 400
    elif assessment.is_justification_required():
        return {"error": "Justification required"}, 400

    if "impact_statement" in data and isinstance(data["impact_statement"], str):
        assessment.set_not_affected_reason(data["impact_statement"], False)

    if "workaround" in data and isinstance(data["workaround"], str):
        assessment.set_workaround(data["workaround"])

    if "timestamp" in data and isinstance(data["timestamp"], str):
        try:
            assessment.timestamp = datetime.fromisoformat(data["timestamp"])
        except (ValueError, TypeError):
            pass
    if "responses" in data and isinstance(data["responses"], list):
        for response in data["responses"]:
            assessment.add_response(response)
    return assessment, 200

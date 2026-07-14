# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import re
from datetime import datetime
from uuid import UUID

from ..models import Assessment as DBAssessment, Package, Finding
from ..models.assessment import STATUS_TO_SIMPLIFIED
from ..extensions import db, batch_session
from ..models.vulnerability import Vulnerability as DBVuln
from ..models.variant import Variant as DBVariant
from ._scan_helpers import parse_uuid_or_400
from ._scan_queries import VulnerabilityText, fetch_vulnerabilities_texts
from ._scan_diff import invalidate_scan_list_cache
from ..helpers.assessment_io import (
    build_openvex_archive,
    is_openvex_doc,
    import_statements as _import_openvex_statements,
    build_variant_by_name_map,
    import_archive_bytes,
    build_custom_data_export,
    import_custom_data,
)
from ..helpers.assessment_staleness import annotate_assessments_outdated

from flask import request, Flask
from flask.typing import ResponseReturnValue
from sqlalchemy import select

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


def _is_scanner_author(author: str | None) -> bool:
    if not author:
        return True
    a = author.strip().lower()
    if a in _SCANNER_AUTHORS:
        return True
    if _UUID_RE.match(a):
        return True
    return False


def _resolve_package(pkg_string_id: str) -> "Package":
    """Parse 'name@version::supplier' and look up or create the Package record."""
    _parts = pkg_string_id.split("::", 1)
    _base = _parts[0]
    _supplier = _parts[1] if len(_parts) > 1 else ""
    name, version = _base.rsplit("@", 1) if "@" in _base else (_base, "")
    return Package.find_or_create(name, version, supplier=_supplier)


def _create_assessment_record(
    assessment: "DBAssessment",
    finding_id: UUID,
    variant_id: UUID | None,
    timestamp: datetime | None = None,
    origin: str = "custom",
) -> "DBAssessment":
    """Create a single DBAssessment row from a validated DTO.

    Shared between ``add_assessment`` (single) and ``add_assessments_batch``.
    """
    return DBAssessment.create(
        status=assessment.status or "",
        simplified_status=STATUS_TO_SIMPLIFIED.get(assessment.status or "", "Pending Assessment"),
        finding_id=finding_id,
        variant_id=variant_id,
        origin=origin,
        status_notes=assessment.status_notes,
        justification=assessment.justification,
        impact_statement=assessment.impact_statement,
        workaround=getattr(assessment, "workaround", None),
        responses=list(assessment.responses) if assessment.responses else [],
        commit=True,
        timestamp=timestamp,
    )


def _has_pending_ai(vuln_id: str, variant_id: UUID | None) -> bool:
    """True if a pending AI assessment already exists for this (vuln, variant)."""
    for a in DBAssessment.get_by_vulnerability(vuln_id):
        if a.origin == "ai" and a.variant_id == variant_id:
            return True
    return False


def _pending_ai_group(assessment: "DBAssessment") -> list["DBAssessment"]:
    """All pending AI rows sharing the addressed row's (vuln_id, variant_id)."""
    vuln_id = assessment.vuln_id
    return [
        a for a in DBAssessment.get_by_vulnerability(vuln_id)
        if a.origin == "ai" and a.variant_id == assessment.variant_id
    ]


def init_app(app: Flask) -> None:

    def _get_all_db_assessments() -> list["DBAssessment"]:
        return DBAssessment.get_all()

    @app.route('/api/assessments')
    def index_assess() -> ResponseReturnValue:
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')
        if variant_id:
            variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if variant_uuid is None:
                return {"error": "Internal error"}, 500
            assessments = [a.to_dict() for a in DBAssessment.get_by_variant(variant_uuid)]
        elif project_id:
            from ..models.variant import Variant as DBVariant
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if project_uuid is None:
                return {"error": "Internal error"}, 500
            variants = DBVariant.get_by_project(project_uuid)
            variant_ids = [v.id for v in variants]
            if variant_ids:
                assessments = []
                for vid in variant_ids:
                    assessments.extend(a.to_dict() for a in DBAssessment.get_by_variant(vid))
            else:
                assessments = []
        else:
            assessments = [a.to_dict() for a in _get_all_db_assessments()]
        annotate_assessments_outdated(assessments)
        assessments = [a for a in assessments if a.get("origin") != "ai"]
        if request.args.get('format', 'list') == "dict":
            return {a["id"]: a for a in assessments}
        return assessments

    @app.route('/api/assessments/review')
    def review_assessments() -> ResponseReturnValue:
        """Return assessments not linked to any scan (handmade via the web UI).

        Each assessment dict is enriched with a ``vuln_texts`` key mapping to the
        vulnerability's ``texts`` dict so the front-end can display tooltips
        without extra requests.
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
            assessments = DBAssessment.get_handmade([vid])
        elif project_id:
            pid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if pid is None:
                return {"error": "Internal error"}, 500
            variant_ids = [variant.id for variant in DBVariant.get_by_project(pid)]
            assessments = DBAssessment.get_handmade(variant_ids)
        else:
            variant_ids = None
            assessments = DBAssessment.get_handmade()

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

    @app.route('/api/assessments/review/export')
    def export_review_openvex() -> ResponseReturnValue:
        """Export handmade (review) assessments as a .tar.gz containing one
        OpenVEX JSON file per variant (``<variant_name>.json``).
        Assessments without a variant are placed in ``unassigned.json``.
        """
        from ..models.variant import Variant as DBVariant

        handmade = DBAssessment.get_handmade()
        if not handmade:
            return {"error": "No review assessments to export"}, 404

        author = request.args.get('author', 'Savoir-faire Linux')
        variant_names = {str(v.id): v.name for v in DBVariant.get_all()}

        archive_bytes = build_openvex_archive(handmade, variant_names, author)
        return archive_bytes, 200, {
            "Content-Type": "application/gzip",
            "Content-Disposition": "attachment; filename=review_openvex.tar.gz",
        }

    @app.route('/api/assessments/review/import', methods=['POST'])
    def import_review_openvex() -> ResponseReturnValue:
        """Import OpenVEX review assessments from a ``.json`` or ``.tar.gz`` file.

        * **Single .json file** – the filename (without extension) must match
          an existing variant name in the database.
        * **.tar.gz archive** – each ``.json`` entry inside must be named after
          an existing variant.  Entries whose basename does not match a known
          variant are reported as errors.

        Every file is validated as a well-formed OpenVEX document (must contain
        ``@context`` with ``openvex`` and a ``statements`` array).

        Assessments are created with ``origin="custom"``.
        """
        import os

        # ---- retrieve the uploaded file ----
        if not (request.content_type and 'multipart/form-data' in request.content_type):
            return {"error": "Expected multipart/form-data with a file upload"}, 400
        uploaded = request.files.get('file')
        if not uploaded or not uploaded.filename:
            return {"error": "No file uploaded"}, 400

        filename = uploaded.filename

        # ---- build variant-name → variant lookup ----
        all_variants = DBVariant.get_all()
        # The export sanitises names (/ and \ replaced by _), so we store a
        # sanitised-name → variant mapping for reliable round-trip matching.
        variant_by_name: dict[str, "DBVariant"] = {}
        for v in all_variants:
            sanitised = v.name.replace("/", "_").replace("\\", "_")
            variant_by_name[sanitised] = v
            # Also keep the original name in case it differs
            variant_by_name[v.name] = v

        variant_by_name = build_variant_by_name_map()

        # ---- .tar.gz handling ----
        if filename.endswith(".tar.gz") or filename.endswith(".tgz"):
            try:
                total_created, total_errors, total_skipped, found = import_archive_bytes(
                    uploaded.read(), variant_by_name
                )
            except ValueError as exc:
                return {"error": str(exc)}, 400

            if found == 0 and not total_created:
                return {
                    "error": "No valid OpenVEX files matching known variants found in archive",
                    "errors": total_errors,
                }, 400

            return {
                "status": "success",
                "imported": len(total_created),
                "skipped": total_skipped,
                "errors": total_errors,
            }, 200

        # ---- single .json handling ----
        if filename.endswith(".json"):
            import json
            base = os.path.basename(filename)
            variant_name = base[: -len(".json")]
            variant = variant_by_name.get(variant_name)
            if variant is None:
                return {
                    "error": f"No variant found matching filename '{variant_name}'. "
                             f"The JSON filename must correspond to an existing variant name."
                }, 400

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

            created, errors, skipped = _import_openvex_statements(data["statements"], variant.id)
            return {"status": "success", "imported": len(created), "skipped": skipped, "errors": errors}, 200

        return {"error": "Unsupported file type. Please upload a .json or .tar.gz file."}, 400

    @app.route('/api/assessments/review/time-estimates')
    def review_time_estimates() -> ResponseReturnValue:
        """Return vulnerabilities that have non-zero time estimates.

        Each entry contains the vulnerability ID and its three-point estimate
        (optimistic / likely / pessimistic) as ISO 8601 durations plus the
        raw hour values.
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

    @app.route('/api/assessments/review/export-custom-data')
    def export_review_custom_data() -> ResponseReturnValue:
        """Export handmade (review) assessments, custom CVSS scores and time
        estimates as a single JSON file.

        Query parameters:

        * ``variant_id`` – restrict to a single variant.
        * ``project_id`` – restrict to all variants in a project.
        """
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')

        from ..models.project import Project as DBProject

        variant_ids: list[UUID] | None = None
        project_name = None
        if variant_id:
            vid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if vid is None:
                return {"error": "Internal error"}, 500
            variant_ids = [vid]
            variant = DBVariant.get_by_id(vid)
            if variant and variant.project:
                project_name = variant.project.name
        elif project_id:
            pid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if pid is None:
                return {"error": "Internal error"}, 500
            project = DBProject.get_by_id(pid)
            if project:
                project_name = project.name
            variants = DBVariant.get_by_project(pid)
            variant_ids = [v.id for v in variants]

        data = build_custom_data_export(variant_ids)

        if not data["assessments"] and not data["cvss"] and not data["time_estimates"]:
            return {"error": "No custom data to export"}, 404

        import json as _json
        import re as _re
        json_bytes = _json.dumps(data, indent=2)
        safe_name = _re.sub(r'[^\w\-.]', '_', project_name) if project_name else None
        fname = f"custom_data_{safe_name}.json" if safe_name else "custom_data.json"
        return json_bytes, 200, {
            "Content-Type": "application/json",
            "Content-Disposition": f'attachment; filename="{fname}"',
        }

    @app.route('/api/assessments/review/import-custom-data', methods=['POST'])
    def import_review_custom_data() -> ResponseReturnValue:
        """Import assessments, CVSS scores and time estimates from a custom-data
        JSON file.

        Accepts either:

        * ``multipart/form-data`` with a ``file`` field containing a ``.json``
          file.
        * ``application/json`` body with the custom-data payload directly.

        Optional query parameter ``variant_id`` to force all imported
        assessments to a specific variant.
        """
        import json as _json

        variant_id = None
        raw_vid = request.args.get('variant_id')
        if raw_vid:
            variant_id, err = parse_uuid_or_400(raw_vid, "variant_id")
            if err:
                return err

        # Parse the incoming data
        data = None
        if request.content_type and 'multipart/form-data' in request.content_type:
            uploaded = request.files.get('file')
            if not uploaded or not uploaded.filename:
                return {"error": "No file uploaded"}, 400
            try:
                data = _json.load(uploaded.stream)
            except Exception:
                return {"error": "Invalid JSON file"}, 400
        elif request.content_type and 'application/json' in request.content_type:
            data = request.get_json(silent=True)
            if data is None:
                return {"error": "Invalid JSON body"}, 400
        else:
            return {"error": "Expected multipart/form-data or application/json"}, 400

        if not isinstance(data, dict) or "version" not in data:
            return {"error": "Invalid custom-data format. Expected {version, assessments, ...}"}, 400

        variant_by_name = build_variant_by_name_map()
        result = import_custom_data(data, variant_by_name, variant_id)

        status_code = 200 if result["status"] == "success" else 400
        return result, status_code

    @app.route('/api/assessments/<assessment_id>')
    def assess_by_id(assessment_id: str) -> ResponseReturnValue:
        item = DBAssessment.get_by_id(assessment_id)
        if item is None:
            return {"error": "Not found"}, 404
        return item.to_dict(), 200

    @app.route('/api/vulnerabilities/<vuln_id>/assessments')
    def list_assess_by_vuln(vuln_id: str) -> ResponseReturnValue:
        # Get findings for this vulnerability then load their assessments
        findings = Finding.get_by_vulnerability(vuln_id)
        assessments = []
        for f in findings:
            for a in DBAssessment.get_by_finding(f.id):
                assessments.append(a.to_dict())
        annotate_assessments_outdated(assessments)
        if request.args.get('format', 'list') == "dict":
            return {a["id"]: a for a in assessments}
        return assessments, 200

    @app.route('/api/vulnerabilities/<vuln_id>/variants', methods=['GET'])
    def list_variants_by_vuln(vuln_id: str) -> ResponseReturnValue:
        """Return all distinct variants that have a finding for this vulnerability
        (via the Observation → Scan → Variant chain)."""
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

        # Distinct variants with a finding for this vuln (Observation -> Scan -> Variant)
        seen_variant_ids: set[UUID] = set()
        variant_ids: list[UUID] = []
        for finding in findings:
            for obs in Observation.get_by_finding(finding.id):
                scan = db.session.get(Scan, obs.scan_id)
                if scan is None or scan.variant_id in seen_variant_ids:
                    continue
                seen_variant_ids.add(scan.variant_id)
                if project_uuid is not None:
                    variant = db.session.get(DBVariant, scan.variant_id)
                    if variant is None or variant.project_id != project_uuid:
                        continue
                variant_ids.append(scan.variant_id)

        result = []
        vuln_pkg_ids = set(pkg_string_by_id.keys())
        for vid in variant_ids:
            active_ids = active_package_ids_for_scans(
                active_sbom_scan_ids_for_variant(vid),
                restrict_to_package_ids=vuln_pkg_ids,
            )
            active_packages = [sid for pid, sid in pkg_string_by_id.items() if pid in active_ids]
            result.append({"variant_id": str(vid), "active_packages": active_packages})
        return result, 200

    @app.route("/api/vulnerabilities/<vuln_id>/assessments", methods=["POST"])
    def add_assessment(vuln_id: str) -> ResponseReturnValue:
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
        created = []
        try:
            with batch_session():
                for pkg_string_id in (assessment.packages or []):
                    # find_or_create handles both lookup and creation in one query
                    db_pkg = _resolve_package(pkg_string_id)
                    # Ensure vulnerability record exists before creating Finding (FK constraint)
                    DBVuln.get_or_create(vuln_id)
                    finding = Finding.get_or_create(db_pkg.id, vuln_id)
                    # Always create a new record — never merge with an existing one.
                    # from_vuln_assessment does a find-or-update which would overwrite
                    # previous user assessments on the same (finding, variant).
                    db_a = _create_assessment_record(
                        assessment, finding.id, variant_id, timestamp=shared_timestamp,
                        origin=target_origin)
                    created.append(db_a.to_dict())
        except Exception as e:
            return {"error": f"DB error: {e}"}, 500

        if not created:
            return {"error": "No valid package found"}, 400

        response_body = {"status": "success", "assessments": created, "assessment": created[0]}
        return response_body, 200

    @app.route("/api/assessments/batch", methods=["POST"])
    def add_assessments_batch() -> ResponseReturnValue:
        payload_data = request.get_json()
        if not payload_data or "assessments" not in payload_data or not isinstance(payload_data["assessments"], list):
            return {"error": "Invalid request data. Expected: {assessments: [...]}"}, 400

        results = []
        errors = []
        # Cache resolved packages across the batch to avoid repeated SELECTs
        pkg_cache: dict = {}
        finding_cache: dict = {}

        with batch_session():
            for item in payload_data["assessments"]:
                if not isinstance(item, dict) or "vuln_id" not in item:
                    errors.append({"error": "Invalid assessment data", "item": item})
                    continue

                assessment, status = payload_to_assessment(item)
                if status != 200:
                    if not isinstance(assessment, dict):
                        errors.append({"vuln_id": item.get("vuln_id"), "error": "Internal error"})
                        continue
                    errors.append({"vuln_id": item.get("vuln_id"), "error": assessment.get("error", "Unknown error")})
                    continue
                if not isinstance(assessment, DBAssessment):
                    errors.append({"vuln_id": item.get("vuln_id"), "error": "Internal error"})
                    continue

                vuln_id = assessment.vuln_id
                # variant_id is required for every batch item
                variant_id_raw = item.get('variant_id') or None
                if not variant_id_raw:
                    errors.append({"vuln_id": vuln_id, "error": "variant_id is required"})
                    continue
                variant_id, err = parse_uuid_or_400(variant_id_raw, "variant_id")
                if err:
                    errors.append({"vuln_id": vuln_id, "error": "Invalid variant_id"})
                    continue
                pkg_list = assessment.packages or []
                if not pkg_list:
                    errors.append({"vuln_id": vuln_id, "error": "No valid package found"})
                    continue
                for pkg_string_id in pkg_list:
                    try:
                        # Resolve package from cache first, then DB
                        db_pkg = pkg_cache.get(pkg_string_id)
                        if db_pkg is None:
                            db_pkg = _resolve_package(pkg_string_id)
                            pkg_cache[pkg_string_id] = db_pkg
                        # Ensure vulnerability record exists before creating Finding (FK constraint)
                        DBVuln.get_or_create(vuln_id)
                        # Resolve finding from cache first, then DB
                        f_key = (db_pkg.id, vuln_id)
                        finding = finding_cache.get(f_key)
                        if finding is None:
                            finding = Finding.get_or_create(db_pkg.id, vuln_id)
                            finding_cache[f_key] = finding
                        # Always create a new record — never overwrite an existing assessment.
                        # Honour the per-item timestamp so rows added for the same action
                        # (e.g. one assessment across several variants) share a value.
                        db_a = _create_assessment_record(
                            assessment, finding.id, variant_id,
                            timestamp=getattr(assessment, 'timestamp', None))
                        results.append(db_a.to_dict())
                    except Exception as e:
                        errors.append({"vuln_id": vuln_id, "error": str(e)})

        distinct_vulns = len({r.get("vuln_id") for r in results if r.get("vuln_id")})
        response = {
            "status": "success" if results else "error",
            "assessments": results,
            "count": len(results),
            "vuln_count": distinct_vulns
        }
        if errors:
            response["errors"] = errors
            response["error_count"] = len(errors)
        return response, 200 if results else 400

    @app.route("/api/assessments/<assessment_id>", methods=["PUT", "PATCH"])
    def update_assessment(assessment_id: str) -> ResponseReturnValue:
        payload_data = request.get_json()
        if not payload_data:
            return {"error": "Invalid request data"}, 400

        existing = DBAssessment.get_by_id(assessment_id)
        if existing is None:
            return {"error": "Assessment not found"}, 404

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

        existing.update(
            status=mem_assess.status,
            origin=new_origin,
            status_notes=mem_assess.status_notes,
            justification=mem_assess.justification,
            impact_statement=mem_assess.impact_statement,
            workaround=getattr(mem_assess, "workaround", None),
            responses=list(mem_assess.responses or []),
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

    @app.route("/api/assessments/<assessment_id>/approve", methods=["POST"])
    def approve_ai_assessment(assessment_id: str) -> ResponseReturnValue:
        existing = DBAssessment.get_by_id(assessment_id)
        if existing is None:
            return {"error": "Assessment not found"}, 404
        if existing.origin != "ai":
            return {"error": "Not a pending AI assessment"}, 400
        group = _pending_ai_group(existing)
        approved = []
        with batch_session():
            for row in group:
                row.update(origin="custom")
                approved.append(row.to_dict())
        return {"status": "success", "assessments": approved}, 200

    @app.route("/api/assessments/<assessment_id>/reject", methods=["POST"])
    def reject_ai_assessment(assessment_id: str) -> ResponseReturnValue:
        existing = DBAssessment.get_by_id(assessment_id)
        if existing is None:
            return {"error": "Assessment not found"}, 404
        if existing.origin != "ai":
            return {"error": "Not a pending AI assessment"}, 400
        group = _pending_ai_group(existing)
        deleted_ids = [str(row.id) for row in group]
        with batch_session():
            for row in group:
                row.delete()
        return {"status": "success", "deleted": deleted_ids}, 200


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

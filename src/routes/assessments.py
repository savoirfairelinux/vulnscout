#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import request
from datetime import datetime
from ..models.assessment import Assessment as DBAssessment, STATUS_TO_SIMPLIFIED
from ..models.package import Package
from ..models.finding import Finding
from ..views.openvex import OpenVex
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController
from ..helpers.verbose import verbose
from ..extensions import db, batch_session
from ..models.vulnerability import Vulnerability as DBVuln
from ..helpers.openvex_assessments import (
    build_openvex_archive,
    is_openvex_doc,
    import_statements as _import_openvex_statements,
    build_variant_by_name_map,
    import_archive_bytes,
)
from ..models.vulnerability import Vulnerability as DBVuln

OPENVEX_FILE = "/scan/outputs/openvex.json"


def init_app(app):

    if "OPENVEX_FILE" not in app.config:
        app.config["OPENVEX_FILE"] = OPENVEX_FILE

    def _get_all_db_assessments():
        return DBAssessment.get_all()

    def _save_openvex():
        """Re-generate and save the OpenVEX file from current DB state."""
        try:
            import json

            pkgCtrl = PackagesController()
            pkgCtrl._preload_cache()
            vulnCtrl = VulnerabilitiesController(pkgCtrl)
            assessCtrl = AssessmentsController(pkgCtrl, vulnCtrl)

            ctrls = {"packages": pkgCtrl, "vulnerabilities": vulnCtrl, "assessments": assessCtrl}
            vex = OpenVex(ctrls)
            with open(app.config["OPENVEX_FILE"], "w") as f:
                f.write(json.dumps(vex.to_dict(), indent=2))
        except Exception as e:
            verbose(f"[_save_openvex] {e}")

    @app.route('/api/assessments')
    def index_assess():
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')
        if variant_id:
            import uuid
            try:
                variant_uuid = uuid.UUID(variant_id)
            except ValueError:
                return {"error": "Invalid variant_id"}, 400
            assessments = [a.to_dict() for a in DBAssessment.get_by_variant(variant_uuid)]
        elif project_id:
            import uuid
            from ..models.variant import Variant as DBVariant
            try:
                project_uuid = uuid.UUID(project_id)
            except ValueError:
                return {"error": "Invalid project_id"}, 400
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
        if request.args.get('format', 'list') == "dict":
            return {a["id"]: a for a in assessments}
        return assessments

    @app.route('/api/assessments/review')
    def review_assessments():
        """Return assessments not linked to any scan (handmade via the web UI).

        Each assessment dict is enriched with a ``vuln_texts`` key mapping to the
        vulnerability's ``texts`` dict so the front-end can display tooltips
        without extra requests.
        """
        import uuid as _uuid
        from ..models.variant import Variant as DBVariant
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')
        vid = None
        if variant_id:
            try:
                vid = _uuid.UUID(variant_id)
            except ValueError:
                return {"error": "Invalid variant_id"}, 400
            assessments = [a.to_dict() for a in DBAssessment.get_handmade(vid)]
        elif project_id:
            try:
                pid = _uuid.UUID(project_id)
            except ValueError:
                return {"error": "Invalid project_id"}, 400
            variants = DBVariant.get_by_project(pid)
            assessments = []
            for v in variants:
                assessments.extend(a.to_dict() for a in DBAssessment.get_handmade(v.id))
        else:
            assessments = [a.to_dict() for a in DBAssessment.get_handmade()]

        # Enrich with vulnerability texts for front-end tooltips (single DB pass)
        vuln_ids = {a["vuln_id"] for a in assessments if a.get("vuln_id")}
        vuln_texts: dict[str, dict] = {}
        for vid_str in vuln_ids:
            vuln = DBVuln.get_by_id(vid_str)
            if vuln is not None:
                vuln_texts[vid_str] = dict(vuln.texts or {})
        for a in assessments:
            a["vuln_texts"] = vuln_texts.get(a.get("vuln_id", ""), {})

        return assessments

    @app.route('/api/assessments/review/export')
    def export_review_openvex():
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
    def import_review_openvex():
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

        # ---- helpers ----
        def _is_openvex(doc: dict) -> bool:
            ctx = doc.get("@context", "")
            return "openvex" in ctx and isinstance(doc.get("statements"), list)

        def _import_statements(statements: list, variant_id) -> tuple[list, list, int]:
            created: list[dict] = []
            errors: list[dict] = []
            skipped = 0
            for stmt in statements:
                if not isinstance(stmt, dict):
                    continue
                vuln_obj = stmt.get("vulnerability", {})
                vuln_name = vuln_obj.get("name") if isinstance(vuln_obj, dict) else None
                if not vuln_name:
                    errors.append({"error": "Missing vulnerability name", "statement": stmt})
                    continue
                status = stmt.get("status")
                if not status:
                    errors.append({"vuln_id": vuln_name, "error": "Missing status"})
                    continue

                products = stmt.get("products", [])
                pkg_ids = []
                for prod in products:
                    if isinstance(prod, dict) and "@id" in prod:
                        pkg_ids.append(prod["@id"])
                    elif isinstance(prod, str):
                        pkg_ids.append(prod)
                if not pkg_ids:
                    errors.append({"vuln_id": vuln_name, "error": "No products/packages found"})
                    continue

                justification = stmt.get("justification", "")
                impact_statement = stmt.get("impact_statement", "")
                status_notes = stmt.get("status_notes", "")
                workaround = stmt.get("action_statement", "")

                for pkg_string_id in pkg_ids:
                    try:
                        name, version = (pkg_string_id.rsplit("@", 1)
                                         if "@" in pkg_string_id else (pkg_string_id, ""))
                        db_pkg = Package.find_or_create(name, version)
                        DBVuln.get_or_create(vuln_name)
                        finding = Finding.get_or_create(db_pkg.id, vuln_name)

                        # Check for an existing identical assessment to avoid duplicates
                        existing = db.session.execute(
                            db.select(DBAssessment).where(
                                DBAssessment.finding_id == finding.id,
                                DBAssessment.variant_id == variant_id,
                                DBAssessment.status == status,
                            )
                        ).scalar_one_or_none()
                        if existing is not None:
                            skipped += 1
                            continue

                        db_a = DBAssessment.create(
                            status=status,
                            simplified_status=STATUS_TO_SIMPLIFIED.get(status, "Pending Assessment"),
                            finding_id=finding.id,
                            variant_id=variant_id,
                            origin="custom",
                            status_notes=status_notes,
                            justification=justification,
                            impact_statement=impact_statement,
                            workaround=workaround,
                            responses=[],
                            commit=True,
                        )
                        created.append(db_a.to_dict())
                    except Exception as e:
                        errors.append({"vuln_id": vuln_name, "package": pkg_string_id, "error": str(e)})
            return created, errors, skipped
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

            _save_openvex()
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
                data = json.load(uploaded)
            except Exception:
                return {"error": "Invalid JSON file"}, 400

            if not is_openvex_doc(data):
                return {
                    "error": "Not a valid OpenVEX document "
                             "(missing @context with 'openvex' "
                             "or 'statements' array)"
                }, 400

            created, errors, skipped = _import_openvex_statements(data["statements"], variant.id)
            _save_openvex()
            return {"status": "success", "imported": len(created), "skipped": skipped, "errors": errors}, 200

        return {"error": "Unsupported file type. Please upload a .json or .tar.gz file."}, 400

    @app.route('/api/assessments/<assessment_id>')
    def assess_by_id(assessment_id: str):
        item = DBAssessment.get_by_id(assessment_id)
        if item is None:
            return {"error": "Not found"}, 404
        return item.to_dict(), 200

    @app.route('/api/vulnerabilities/<vuln_id>/assessments')
    def list_assess_by_vuln(vuln_id: str):
        # Get findings for this vulnerability then load their assessments
        findings = Finding.get_by_vulnerability(vuln_id)
        assessments = []
        for f in findings:
            for a in DBAssessment.get_by_finding(f.id):
                assessments.append(a.to_dict())
        if request.args.get('format', 'list') == "dict":
            return {a["id"]: a for a in assessments}
        return assessments, 200

    @app.route('/api/vulnerabilities/<vuln_id>/variants', methods=['GET'])
    def list_variants_by_vuln(vuln_id: str):
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

    @app.route("/api/vulnerabilities/<vuln_id>/assessments", methods=["POST"])
    def add_assessment(vuln_id: str):
        payload_data = request.get_json()
        if not payload_data:
            return {"error": "Invalid request data"}, 400

        if "vuln_id" not in payload_data:
            payload_data["vuln_id"] = vuln_id
        elif payload_data["vuln_id"] != vuln_id or not isinstance(payload_data["vuln_id"], str):
            return {"error": "Invalid vuln_id"}, 400

        assessment, status = payload_to_assessment(payload_data)
        if status != 200:
            return assessment, status

        # Resolve variant_id once — same for all packages in this request
        variant_id_raw = payload_data.get('variant_id') or None
        variant_id = None
        if variant_id_raw:
            try:
                import uuid as _uuid
                variant_id = _uuid.UUID(variant_id_raw)
            except (ValueError, AttributeError):
                return {"error": "Invalid variant_id"}, 400

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
                    name, version = pkg_string_id.rsplit("@", 1) if "@" in pkg_string_id else (pkg_string_id, "")
                    db_pkg = Package.find_or_create(name, version)
                    # Ensure vulnerability record exists before creating Finding (FK constraint)
                    DBVuln.get_or_create(vuln_id)
                    finding = Finding.get_or_create(db_pkg.id, vuln_id)
                    # Always create a new record — never merge with an existing one.
                    # from_vuln_assessment does a find-or-update which would overwrite
                    # previous user assessments on the same (finding, variant).
                    db_a = DBAssessment.create(
                        status=assessment.status,
                        simplified_status=STATUS_TO_SIMPLIFIED.get(assessment.status, "Pending Assessment"),
                        finding_id=finding.id,
                        variant_id=variant_id,
                        origin="custom",
                        status_notes=assessment.status_notes,
                        justification=assessment.justification,
                        impact_statement=assessment.impact_statement,
                        workaround=getattr(assessment, "workaround", None),
                        responses=list(assessment.responses) if assessment.responses else [],
                        timestamp=shared_timestamp,
                        commit=True,
                    )
                    created.append(db_a.to_dict())
        except Exception as e:
            return {"error": f"DB error: {e}"}, 500

        if not created:
            return {"error": "No valid package found"}, 400

        _save_openvex()
        response_body = {"status": "success", "assessments": created, "assessment": created[0]}
        return response_body, 200

    @app.route("/api/assessments/batch", methods=["POST"])
    def add_assessments_batch():
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
                    errors.append({"vuln_id": item.get("vuln_id"), "error": assessment.get("error", "Unknown error")})
                    continue

                vuln_id = assessment.vuln_id
                # Parse optional variant_id from the raw item
                variant_id_raw = item.get('variant_id') or None
                variant_id = None
                if variant_id_raw:
                    try:
                        import uuid as _uuid
                        variant_id = _uuid.UUID(variant_id_raw)
                    except (ValueError, AttributeError):
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
                            name, version = (pkg_string_id.rsplit("@", 1)
                                             if "@" in pkg_string_id
                                             else (pkg_string_id, ""))
                            db_pkg = Package.find_or_create(name, version)
                            pkg_cache[pkg_string_id] = db_pkg
                        # Ensure vulnerability record exists before creating Finding (FK constraint)
                        DBVuln.get_or_create(vuln_id)
                        # Resolve finding from cache first, then DB
                        f_key = (db_pkg.id, vuln_id)
                        finding = finding_cache.get(f_key)
                        if finding is None:
                            finding = Finding.get_or_create(db_pkg.id, vuln_id)
                            finding_cache[f_key] = finding
                        # Always create a new record — never overwrite an existing assessment
                        db_a = DBAssessment.create(
                            status=assessment.status,
                            simplified_status=STATUS_TO_SIMPLIFIED.get(assessment.status, "Pending Assessment"),
                            finding_id=finding.id,
                            variant_id=variant_id,
                            origin="custom",
                            status_notes=assessment.status_notes,
                            justification=assessment.justification,
                            impact_statement=assessment.impact_statement,
                            workaround=getattr(assessment, "workaround", None),
                            responses=list(assessment.responses) if assessment.responses else [],
                            commit=True,
                        )
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
        if results:
            _save_openvex()
        return response, 200 if results else 400

    @app.route("/api/assessments/<assessment_id>", methods=["PUT", "PATCH"])
    def update_assessment(assessment_id: str):
        payload_data = request.get_json()
        if not payload_data:
            return {"error": "Invalid request data"}, 400

        existing = DBAssessment.get_by_id(assessment_id)
        if existing is None:
            return {"error": "Assessment not found"}, 404

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
            origin="custom",
            status_notes=mem_assess.status_notes,
            justification=mem_assess.justification,
            impact_statement=mem_assess.impact_statement,
            workaround=getattr(mem_assess, "workaround", None),
            responses=list(mem_assess.responses),
        )
        _save_openvex()
        return {"status": "success", "assessment": existing.to_dict()}, 200

    @app.route("/api/assessments/<assessment_id>", methods=["DELETE"])
    def delete_assessment(assessment_id: str):
        existing = DBAssessment.get_by_id(assessment_id)
        if existing is None:
            return {"error": "Assessment not found"}, 404
        existing.delete()
        return {"status": "success", "message": "Assessment deleted successfully"}, 200


def payload_to_assessment(data):
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

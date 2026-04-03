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
from ..extensions import db
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
        """Return assessments not linked to any scan (handmade via the web UI)."""
        import uuid as _uuid
        variant_id = request.args.get('variant_id')
        vid = None
        if variant_id:
            try:
                vid = _uuid.UUID(variant_id)
            except ValueError:
                return {"error": "Invalid variant_id"}, 400
        assessments = [a.to_dict() for a in DBAssessment.get_handmade(vid)]
        return assessments

    @app.route('/api/assessments/review/export')
    def export_review_openvex():
        """Export handmade (review) assessments as an OpenVEX JSON document."""
        import uuid as _uuid
        import json
        from datetime import datetime as _dt, timezone as _tz

        variant_id = request.args.get('variant_id')
        vid = None
        if variant_id:
            try:
                vid = _uuid.UUID(variant_id)
            except ValueError:
                return {"error": "Invalid variant_id"}, 400

        handmade = DBAssessment.get_handmade(vid)
        author = request.args.get('author', 'Savoir-faire Linux')

        statements = []
        for assess in handmade:
            stmt = assess.to_openvex_dict()
            if stmt is None:
                continue
            statements.append(stmt)

        doc = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://savoirfairelinux.com/sbom/openvex/{}".format(str(_uuid.uuid4())),
            "author": author,
            "timestamp": _dt.now(_tz.utc).isoformat(),
            "version": 1,
            "statements": statements,
        }

        return json.dumps(doc, indent=2), 200, {
            "Content-Type": "application/json",
            "Content-Disposition": "attachment; filename=review_openvex.json",
        }

    @app.route('/api/assessments/review/import', methods=['POST'])
    def import_review_openvex():
        """Import an OpenVEX JSON document and create handmade review assessments."""
        import json

        if request.content_type and 'multipart/form-data' in request.content_type:
            file = request.files.get('file')
            if not file:
                return {"error": "No file uploaded"}, 400
            try:
                data = json.load(file)
            except Exception:
                return {"error": "Invalid JSON file"}, 400
        else:
            data = request.get_json()
            if not data:
                return {"error": "Invalid request data"}, 400

        if "statements" not in data or not isinstance(data["statements"], list):
            return {"error": "Invalid OpenVEX document: missing 'statements' array"}, 400

        # Parse optional variant_id for scoping imported assessments
        variant_id_raw = request.args.get('variant_id')
        variant_id = None
        if variant_id_raw:
            try:
                import uuid as _uuid
                variant_id = _uuid.UUID(variant_id_raw)
            except (ValueError, AttributeError):
                return {"error": "Invalid variant_id"}, 400

        created = []
        errors = []
        for stmt in data["statements"]:
            if not isinstance(stmt, dict):
                continue
            vuln_name = None
            vuln_obj = stmt.get("vulnerability", {})
            if isinstance(vuln_obj, dict):
                vuln_name = vuln_obj.get("name")
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

            for pkg_string_id in pkg_ids:
                try:
                    name, version = pkg_string_id.rsplit("@", 1) if "@" in pkg_string_id else (pkg_string_id, "")
                    db_pkg = Package.find_or_create(name, version)
                    DBVuln.get_or_create(vuln_name)
                    finding = Finding.get_or_create(db_pkg.id, vuln_name)
                    db_a = DBAssessment.create(
                        status=status,
                        simplified_status=STATUS_TO_SIMPLIFIED.get(status, "Pending Assessment"),
                        finding_id=finding.id,
                        variant_id=variant_id,
                        origin="custom",
                        status_notes=stmt.get("status_notes", ""),
                        justification=stmt.get("justification", ""),
                        impact_statement=stmt.get("impact_statement", ""),
                        workaround=stmt.get("action_statement", ""),
                        responses=[],
                        commit=True,
                    )
                    created.append(db_a.to_dict())
                except Exception as e:
                    errors.append({"vuln_id": vuln_name, "package": pkg_string_id, "error": str(e)})

        _save_openvex()
        return {"status": "success", "imported": len(created), "errors": errors}, 200

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
        created = []
        for pkg_string_id in (assessment.packages or []):
            try:
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
                        name, version = pkg_string_id.rsplit("@", 1) if "@" in pkg_string_id else (pkg_string_id, "")
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

        response = {
            "status": "success" if results else "error",
            "assessments": results,
            "count": len(results)
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

#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import request
from datetime import datetime
from ..models.assessment import Assessment as DBAssessment
from ..models.package import Package
from ..models.finding import Finding
from ..views.openvex import OpenVex
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController

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
            vulnCtrl = VulnerabilitiesController(pkgCtrl)
            assessCtrl = AssessmentsController(pkgCtrl, vulnCtrl)

            ctrls = {"packages": pkgCtrl, "vulnerabilities": vulnCtrl, "assessments": assessCtrl}
            vex = OpenVex(ctrls)
            with open(app.config["OPENVEX_FILE"], "w") as f:
                f.write(json.dumps(vex.to_dict(), indent=2))
        except Exception:
            pass

    @app.route('/api/assessments')
    def index_assess():
        assessments = [a.to_dict() for a in _get_all_db_assessments()]
        if request.args.get('format', 'list') == "dict":
            return {a["id"]: a for a in assessments}
        return assessments

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

        # Persist to DB
        for pkg_string_id in (assessment.packages or []):
            try:
                from ..extensions import db
                db_pkg = Package.get_by_string_id(pkg_string_id)
                if db_pkg is None:
                    # Auto-create the package with minimal info derived from 'name@version'
                    name, version = pkg_string_id.rsplit("@", 1) if "@" in pkg_string_id else (pkg_string_id, "")
                    db_pkg = Package.find_or_create(name, version)
                    db.session.commit()
                finding = Finding.get_or_create(db_pkg.id, vuln_id)
                db_a = DBAssessment.from_vuln_assessment(assessment, finding_id=finding.id)
                db.session.commit()
                _save_openvex()
                return {"status": "success", "assessment": db_a.to_dict()}, 200
            except Exception as e:
                return {"error": f"DB error: {e}"}, 500

        return {"error": "No valid package found"}, 400

    @app.route("/api/assessments/batch", methods=["POST"])
    def add_assessments_batch():
        payload_data = request.get_json()
        if not payload_data or "assessments" not in payload_data or not isinstance(payload_data["assessments"], list):
            return {"error": "Invalid request data. Expected: {assessments: [...]}"}, 400

        results = []
        errors = []

        for item in payload_data["assessments"]:
            if not isinstance(item, dict) or "vuln_id" not in item:
                errors.append({"error": "Invalid assessment data", "item": item})
                continue

            assessment, status = payload_to_assessment(item)
            if status != 200:
                errors.append({"vuln_id": item.get("vuln_id"), "error": assessment.get("error", "Unknown error")})
                continue

            vuln_id = assessment.vuln_id
            for pkg_string_id in (assessment.packages or []):
                try:
                    from ..extensions import db
                    db_pkg = Package.get_by_string_id(pkg_string_id)
                    if db_pkg is None:
                        # Auto-create the package with minimal info derived from 'name@version'
                        name, version = pkg_string_id.rsplit("@", 1) if "@" in pkg_string_id else (pkg_string_id, "")
                        db_pkg = Package.find_or_create(name, version)
                        db.session.commit()
                    finding = Finding.get_or_create(db_pkg.id, vuln_id)
                    db_a = DBAssessment.from_vuln_assessment(assessment, finding_id=finding.id)
                    db.session.commit()
                    results.append(db_a.to_dict())
                    break
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

#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import request
import json
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController
from ..views.openvex import OpenVex
from ..models.assessment import VulnAssessment

ASSESSMENTS_FILE = "/scan/tmp/assessments-merged.json"
OPENVEX_FILE = "/scan/outputs/openvex.json"


def init_app(app):

    if "ASSESSMENTS_FILE" not in app.config:
        app.config["ASSESSMENTS_FILE"] = ASSESSMENTS_FILE
    if "OPENVEX_FILE" not in app.config:
        app.config["OPENVEX_FILE"] = OPENVEX_FILE

    def get_assessments():
        with open(app.config["ASSESSMENTS_FILE"], "r") as f:
            return AssessmentsController.from_dict(None, None, json.loads(f.read()))

    def get_all_datas():
        controllers = {}
        with open(app.config["PKG_FILE"], "r") as f:
            controllers["packages"] = PackagesController.from_dict(
                json.loads(f.read())
            )
        with open(app.config["VULNS_FILE"], "r") as f:
            controllers["vulnerabilities"] = VulnerabilitiesController.from_dict(
                controllers["packages"],
                json.loads(f.read())
            )
        with open(app.config["ASSESSMENTS_FILE"], "r") as f:
            controllers["assessments"] = AssessmentsController.from_dict(
                controllers["packages"],
                controllers["vulnerabilities"],
                json.loads(f.read())
            )
        return controllers

    @app.route('/api/assessments')
    def index_assess():
        assessCtrl = get_assessments()
        if assessCtrl is None:
            return {"error": "Internal error"}, 500

        if request.args.get('format', 'list') == "dict":
            return assessCtrl.to_dict()
        return list(assessCtrl.to_dict().values())

    @app.route('/api/assessments/<assessment_id>')
    def assess_by_id(assessment_id: str):
        assessCtrl = get_assessments()
        if assessCtrl is None:
            return {"error": "Internal error"}, 500

        item = assessCtrl.get_by_id(assessment_id)
        if item is None:
            return {"error": "Not found"}, 404
        return item.to_dict(), 200

    @app.route('/api/vulnerabilities/<vuln_id>/assessments')
    def list_assess_by_vuln(vuln_id: str):
        assessCtrl = get_assessments()
        if assessCtrl is None:
            return {"error": "Internal error"}, 500

        if request.args.get('format', 'list') == "dict":
            return {k: v.to_dict() for k, v in assessCtrl.assessments.items() if v.vuln_id == vuln_id}, 200
        return [v.to_dict() for k, v in assessCtrl.assessments.items() if v.vuln_id == vuln_id], 200

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

        ctrls = get_all_datas()
        if ctrls["assessments"] is None:
            return {"error": "Internal error"}, 500
        ctrls["assessments"].add(assessment)

        save_assessments_to_files(ctrls)
        return {"status": "success", "assessment": assessment.to_dict()}, 200

    def save_assessments_to_files(ctrls):
        with open(app.config["ASSESSMENTS_FILE"], "w") as f:
            f.write(json.dumps(ctrls["assessments"].to_dict()))

        vex = OpenVex(ctrls)
        with open(app.config["OPENVEX_FILE"], "w") as f:
            f.write(json.dumps(vex.to_dict(), indent=2))


def payload_to_assessment(data):
    """
    Take an object in input and try to convert it to an VulnAssessment instance.
    Return either VulnAssessment and 200, or object and http responde code
    """
    if "packages" not in data or not isinstance(data["packages"], list) or len(data["packages"]) < 1:
        return {"error": "Invalid request data"}, 400

    assessment = VulnAssessment(data["vuln_id"], data["packages"])

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
        if "workaround_timestamp" in data and isinstance(data["workaround_timestamp"], str):
            assessment.set_workaround(data["workaround"], data["workaround_timestamp"])
        else:
            assessment.set_workaround(data["workaround"])

    if "timestamp" in data and isinstance(data["timestamp"], str):
        assessment.timestamp = data["timestamp"]
    if "last_updated" in data and isinstance(data["last_updated"], str):
        assessment.last_update = data["last_updated"]

    if "responses" in data and isinstance(data["responses"], list):
        for response in data["responses"]:
            assessment.add_response(response)
    return assessment, 200

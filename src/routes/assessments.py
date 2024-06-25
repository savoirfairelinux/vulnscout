from flask import request
import json
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController
from ..models.assessment import VulnAssessment

ASSESSMENTS_FILE = "/scan/tmp/assessments-merged.json"


def init_app(app):

    if "ASSESSMENTS_FILE" not in app.config:
        app.config["ASSESSMENTS_FILE"] = ASSESSMENTS_FILE

    @app.route('/api/assessments')
    def index_assess():
        with open(app.config["ASSESSMENTS_FILE"], "r") as f:
            pkgCtrl = PackagesController()
            vulnCtrl = VulnerabilitiesController(pkgCtrl)
            assessCtrl = AssessmentsController.from_dict(pkgCtrl, vulnCtrl, json.loads(f.read()))

            if request.args.get('format', 'list') == "dict":
                return assessCtrl.to_dict()
            return list(assessCtrl.to_dict().values())

    @app.route("/api/vulnerabilities/<vuln_id>/assessments", methods=["POST"])
    def add_assessment(vuln_id):
        payload_data = request.get_json()
        if not payload_data:
            return {"error": "Invalid request data"}, 400

        if "vuln_id" not in payload_data:
            payload_data["vuln_id"] = vuln_id
        elif payload_data["vuln_id"] != vuln_id:
            return {"error": "Invalid vuln_id"}, 400
        assessment, status = payload_to_assessment(payload_data)
        if status != 200:
            return assessment, status

        data = None
        with open(app.config["ASSESSMENTS_FILE"], "r") as f:
            data = json.loads(f.read())
        if data is None:
            return {"error": "Internal error"}, 500
        assessCtrl = AssessmentsController.from_dict(None, None, data)
        assessCtrl.add(assessment)

        with open(app.config["ASSESSMENTS_FILE"], "w") as f:
            f.write(json.dumps(assessCtrl.to_dict()))

        return {"status": "success"}, 200


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

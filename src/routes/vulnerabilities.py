from flask import request
import json
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..views.time_estimates import TimeEstimates

VULNS_FILE = "/scan/tmp/vulnerabilities-merged.json"
TIME_ESTIMATES_PATH = "/scan/outputs/time_estimates.json"


def init_app(app):

    if "VULNS_FILE" not in app.config:
        app.config["VULNS_FILE"] = VULNS_FILE
    if "TIME_ESTIMATES_PATH" not in app.config:
        app.config["TIME_ESTIMATES_PATH"] = TIME_ESTIMATES_PATH

    @app.route('/api/vulnerabilities')
    def index_vulns():
        with open(app.config["VULNS_FILE"], "r") as f:
            vulnsCtrl = VulnerabilitiesController.from_dict(PackagesController(), json.loads(f.read()))

            if request.args.get('format', 'list') == "dict":
                return vulnsCtrl.to_dict()
            return list(vulnsCtrl.to_dict().values())

    @app.route('/api/vulnerabilities/<id>', methods=['GET', 'PATCH'])
    def update_vuln(id):
        with open(app.config["VULNS_FILE"], "r") as f:
            vulnsCtrl = VulnerabilitiesController.from_dict(PackagesController(), json.loads(f.read()))

        vuln = vulnsCtrl.get(id)
        if vuln:
            if request.method == 'PATCH':
                payload_data = request.get_json()
                if "effort" in payload_data:
                    if not ("optimistic" in payload_data["effort"]
                       and "likely" in payload_data["effort"]
                       and "pessimistic" in payload_data["effort"]):
                        return "Invalid effort values", 400

                    if not vuln.set_effort(
                        payload_data["effort"]["optimistic"],
                        payload_data["effort"]["likely"],
                        payload_data["effort"]["pessimistic"]
                    ):
                        return "Invalid effort values", 400
                with open(app.config["VULNS_FILE"], "w") as f:
                    f.write(json.dumps(vulnsCtrl.to_dict()))
                with open(app.config["TIME_ESTIMATES_PATH"], "w") as f:
                    f.write(json.dumps(TimeEstimates({
                        "packages": None,
                        "vulnerabilities": vulnsCtrl,
                        "assessments": None
                    }).to_dict(), indent=2))

            return vuln.to_dict()
        return "Not found", 404

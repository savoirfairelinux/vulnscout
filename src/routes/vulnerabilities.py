#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import request
import json
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..views.time_estimates import TimeEstimates
from ..models.cvss import CVSS

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

                if "cvss" in payload_data:
                    new_cvss = payload_data["cvss"]
                    required_keys = {"base_score", "vector_string", "version"}
                    if not required_keys.issubset(new_cvss.keys()):
                        return "Invalid CVSS data", 400

                    cvss_obj = CVSS.from_dict(new_cvss)
                    vuln.register_cvss(cvss_obj)

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

    @app.route('/api/vulnerabilities/batch', methods=['PATCH'])
    def update_vulns_batch():
        payload_data = request.get_json()
        if (not payload_data
            or "vulnerabilities" not in payload_data
                or not isinstance(payload_data["vulnerabilities"], list)):
            return {"error": "Invalid request data. Expected: {vulnerabilities: [...]}"}, 400

        with open(app.config["VULNS_FILE"], "r") as f:
            vulnsCtrl = VulnerabilitiesController.from_dict(PackagesController(), json.loads(f.read()))

        results = []
        errors = []

        for item in payload_data["vulnerabilities"]:
            if not isinstance(item, dict) or "id" not in item:
                errors.append({"error": "Invalid vulnerability data", "item": item})
                continue

            vuln = vulnsCtrl.get(item["id"])
            if not vuln:
                errors.append({"id": item["id"], "error": "Vulnerability not found"})
                continue

            if "effort" in item:
                if not ("optimistic" in item["effort"]
                   and "likely" in item["effort"]
                   and "pessimistic" in item["effort"]):
                    errors.append({"id": item["id"], "error": "Invalid effort values"})
                    continue

                if not vuln.set_effort(
                    item["effort"]["optimistic"],
                    item["effort"]["likely"],
                    item["effort"]["pessimistic"]
                ):
                    errors.append({"id": item["id"], "error": "Invalid effort values"})
                    continue

            if "cvss" in item:
                new_cvss = item["cvss"]
                required_keys = {"base_score", "vector_string", "version"}
                if not required_keys.issubset(new_cvss.keys()):
                    errors.append({"id": item["id"], "error": "Invalid CVSS data"})
                    continue

                cvss_obj = CVSS.from_dict(new_cvss)
                vuln.register_cvss(cvss_obj)

            results.append(vuln.to_dict())

        if results:
            with open(app.config["VULNS_FILE"], "w") as f:
                f.write(json.dumps(vulnsCtrl.to_dict()))
            with open(app.config["TIME_ESTIMATES_PATH"], "w") as f:
                f.write(json.dumps(TimeEstimates({
                    "packages": None,
                    "vulnerabilities": vulnsCtrl,
                    "assessments": None
                }).to_dict(), indent=2))

        response = {
            "status": "success" if results else "error",
            "vulnerabilities": results,
            "count": len(results)
        }

        if errors:
            response["errors"] = errors
            response["error_count"] = len(errors)

        return response, 200 if results else 400

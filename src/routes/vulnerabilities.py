from flask import request
import json
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController

VULNS_FILE = "/scan/tmp/vulnerabilities-merged.json"


def init_app(app):

    if "VULNS_FILE" not in app.config:
        app.config["VULNS_FILE"] = VULNS_FILE

    @app.route('/api/vulnerabilities')
    def index_vulns():
        with open(app.config["VULNS_FILE"], "r") as f:
            vulnsCtrl = VulnerabilitiesController.from_dict(PackagesController(), json.loads(f.read()))

            if request.args.get('format', 'list') == "dict":
                return vulnsCtrl.to_dict()
            return list(vulnsCtrl.to_dict().values())

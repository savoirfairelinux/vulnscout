from flask import request
import json
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController

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

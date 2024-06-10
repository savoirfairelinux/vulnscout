from flask import request
import json
from ..controllers.packages import PackagesController

PKG_FILE = "/scan/tmp/packages-merged.json"


def init_app(app):

    if "PKG_FILE" not in app.config:
        app.config["PKG_FILE"] = PKG_FILE

    @app.route('/api/packages')
    def index_pkg():
        with open(app.config["PKG_FILE"], "r") as f:
            pkgCtrl = PackagesController.from_dict(json.loads(f.read()))

            if request.args.get('format', 'list') == "dict":
                return pkgCtrl.to_dict()
            return list(pkgCtrl.to_dict().values())

#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.package import Package


def init_app(app):

    @app.route('/api/packages')
    def index_pkg():
        from flask import request
        pkgs = [pkg.to_dict() for pkg in Package.get_all()]
        if request.args.get('format', 'list') == "dict":
            return {p["name"] + "@" + p["version"]: p for p in pkgs}
        return pkgs

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import jsonify

from ..controllers.projects import ProjectController


def init_app(app):

    @app.route('/api/projects')
    def list_projects():
        projects = ProjectController.get_all()
        return jsonify(ProjectController.serialize_list(projects))

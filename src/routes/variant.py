#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import jsonify

from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController


def init_app(app):

    @app.route('/api/projects/<project_id>/variants')
    def list_variants_by_project(project_id):
        project = ProjectController.get(project_id)
        if project is None:
            return jsonify({"error": "Project not found"}), 404
        variants = VariantController.get_by_project(project_id)
        return jsonify(VariantController.serialize_list(variants))

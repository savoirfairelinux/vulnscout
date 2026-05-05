# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
from flask import jsonify

from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController


def init_app(app):

    @app.route('/api/config')
    def get_config():
        project_name = os.environ.get('PROJECT_NAME', '')
        variant_name = os.environ.get('VARIANT_NAME', 'default')

        project = None
        variant = None

        if project_name:
            projects = ProjectController.get_all()
            project = next((p for p in projects if p.name == project_name), None)
            if project:
                variants = VariantController.get_by_project(project.id)
                variant = next((v for v in variants if v.name == variant_name), None)

        if not project:
            all_projects = ProjectController.get_all()
            project = all_projects[0] if all_projects else None

        return jsonify({
            "project": ProjectController.serialize(project) if project else None,
            "variant": VariantController.serialize(variant) if variant else None,
        })

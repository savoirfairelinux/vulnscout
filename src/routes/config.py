# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
from flask import jsonify, request

from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController


def init_app(app):

    @app.route('/api/config')
    def get_config():
        project_name = os.environ.get('PROJECT_NAME', '')
        variant_name = os.environ.get('VARIANT_NAME', 'default')
        author_name = os.environ.get('AUTHOR_NAME', 'vulnscout')

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
            "author": author_name,
        })

    @app.route('/api/config/nvd-api-key', methods=['GET'])
    def get_nvd_api_key():
        key = os.environ.get('NVD_API_KEY', '')
        if not key:
            return jsonify({"has_key": False, "masked_key": ""})
        # Return masked version: show first 4 and last 4 chars only
        if len(key) <= 8:
            masked = '*' * len(key)
        else:
            masked = key[:4] + '*' * (len(key) - 8) + key[-4:]
        return jsonify({"has_key": True, "masked_key": masked})

    @app.route('/api/config/nvd-api-key', methods=['PUT'])
    def set_nvd_api_key():
        data = request.get_json(silent=True)
        if data is None or "api_key" not in data:
            return {"error": "Missing 'api_key' field"}, 400
        api_key = data["api_key"].strip()
        if api_key:
            os.environ['NVD_API_KEY'] = api_key
        else:
            os.environ.pop('NVD_API_KEY', None)
        return jsonify({"status": "ok", "has_key": bool(api_key)})

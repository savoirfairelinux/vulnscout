# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import jsonify, request

from ..controllers.projects import ProjectController
from ..extensions import db
from ..helpers.scan_configuration import (
    read_scan_configuration, validate_scan_configuration, write_scan_configuration,
)
from ..helpers.scan_filters import is_native_package_name
from ..models.variant import Variant
from ._scan_helpers import parse_uuid_or_400, resolve_active_packages


def init_app(app):

    @app.route('/api/projects/<project_id>/scan-configuration', methods=['GET', 'PUT'])
    def project_scan_configuration(project_id):
        """Read or replace the project's cached native scan preferences.

        OpenAPI:
        path project_id string required Project UUID.
        body JsonObject optional Native exclusion and package exceptions.
        response 200 JsonObject Scan configuration and available native packages.
        response 400 Error Invalid configuration or project UUID.
        response 404 Error Project not found.
        response 500 Error Configuration could not be read or saved.
        """
        project_uuid, error = parse_uuid_or_400(project_id, "project id")
        if project_uuid is None:
            return error
        project = ProjectController.get(project_uuid)
        if project is None:
            return jsonify({"error": "Project not found"}), 404
        configuration = None
        if request.method == 'PUT':
            try:
                configuration = validate_scan_configuration(request.get_json(silent=True))
            except ValueError as validation_error:
                return jsonify({"error": str(validation_error)}), 400
        try:
            if request.method == 'PUT':
                configuration = write_scan_configuration(project.name, configuration)
            else:
                configuration = read_scan_configuration(project.name)
        except (OSError, ValueError):
            app.logger.exception("Unable to access project scan configuration")
            return jsonify({"error": "Unable to access project scan configuration"}), 500
        names: set[str] = set()
        variants = db.session.execute(db.select(Variant).where(Variant.project_id == project_uuid)).scalars()
        for variant in variants:
            packages, _ = resolve_active_packages(variant.id, exclude_kernel=False)
            names.update(
                package.name for package in packages
                if package.name and is_native_package_name(package.name)
            )
        return jsonify({**configuration, "native_packages": sorted(names)})

    @app.route('/api/projects')
    def list_projects():
        """List all projects currently stored in the database.

        OpenAPI:
        response 200 JsonObject Project collection.
        """
        projects = ProjectController.get_all()
        return jsonify(ProjectController.serialize_list(projects))

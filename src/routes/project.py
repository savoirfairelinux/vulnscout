# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import jsonify, request

from ..controllers.projects import ProjectController
from ..extensions import db
from ..helpers.scan_configuration import (
    read_scan_configuration, validate_scan_configuration, write_scan_configuration, write_scan_configurations,
)
from ..models.package import Package
from ..models.scan import Scan
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
from ..models.variant import Variant
from ._scan_helpers import parse_uuid_or_400


def init_app(app):

    @app.route('/api/projects/scan-configurations', methods=['PUT'])
    def project_scan_configurations():
        """Atomically replace preferences for the selected projects.

        OpenAPI:
        body JsonObject required Scan preferences keyed by project UUID.
        response 200 JsonObject Saved preferences keyed by project UUID.
        response 400 Error Invalid project UUID or configuration.
        response 404 Error Project not found.
        response 500 Error Configuration could not be saved.
        """
        values = request.get_json(silent=True)
        if not isinstance(values, dict) or not values:
            return jsonify({"error": "Expected scan configurations keyed by project UUID"}), 400
        projects = {}
        preferences = {}
        for project_id, value in values.items():
            project_uuid, error = parse_uuid_or_400(project_id, "project id")
            if project_uuid is None:
                return error
            project = ProjectController.get(project_uuid)
            if project is None:
                return jsonify({"error": "Project not found"}), 404
            try:
                preferences[project_id] = validate_scan_configuration(value)
            except ValueError as validation_error:
                return jsonify({"error": str(validation_error)}), 400
            projects[project_id] = project.name
        try:
            write_scan_configurations({projects[key]: value for key, value in preferences.items()})
        except (OSError, ValueError):
            app.logger.exception("Unable to save project scan configurations")
            return jsonify({"error": "Unable to save project scan configurations"}), 500
        return jsonify(preferences)

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
        latest_scans = (
            db.select(
                Scan.id,
                db.func.row_number().over(
                    partition_by=Scan.variant_id, order_by=(Scan.timestamp.desc(), Scan.id.desc()),
                ).label("rank"),
            )
            .join(Variant, Variant.id == Scan.variant_id)
            .where(
                Variant.project_id == project_uuid,
                db.or_(Scan.scan_type == "sbom", Scan.scan_type.is_(None)),
            )
        ).subquery()
        names = db.session.execute(
            db.select(Package.name)
            .join(SBOMPackage, SBOMPackage.package_id == Package.id)
            .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
            .join(latest_scans, latest_scans.c.id == SBOMDocument.scan_id)
            .where(latest_scans.c.rank == 1, db.func.lower(db.func.trim(Package.name)).endswith("-native"))
            .distinct()
            .order_by(Package.name)
        ).scalars().all()
        return jsonify({**configuration, "native_packages": names})

    @app.route('/api/projects')
    def list_projects():
        """List all projects currently stored in the database.

        OpenAPI:
        response 200 JsonObject Project collection.
        """
        projects = ProjectController.get_all()
        return jsonify(ProjectController.serialize_list(projects))

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import uuid
import logging

from flask import jsonify, request

from ..controllers.context import ProjectContextController, VariantContextController
from ..extensions import db
from ..helpers.context_io import (
    build_export_document,
    collect_entries,
    extract_entries,
    import_entries,
)
from ..models.project import Project
from ..models.variant import Variant
from ..models.variant_context import VariantContext, ContextFile
from ..routes._scan_helpers import parse_uuid_or_400

logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB


def _get_cache_dir() -> str:
    return os.getenv("VULNSCOUT_CACHE_DIR", "/cache/vulnscout")


def init_app(app):

    @app.route('/api/context', methods=['GET'])
    def get_merged_context():
        """Return merged project and variant context.

        OpenAPI:
        query project_id uuid required Project UUID.
        query variant_id uuid required Variant UUID belonging to the project.
        response 200 JsonObject Merged project and variant context.
        response 400 Error Invalid identifiers or mismatched project and variant.
        response 404 Error Project or variant not found.
        """
        project_id_str = request.args.get('project_id', '')
        variant_id_str = request.args.get('variant_id', '')

        project_uuid, err = parse_uuid_or_400(project_id_str, 'project_id')
        if err:
            return err
        assert project_uuid is not None
        variant_uuid, err = parse_uuid_or_400(variant_id_str, 'variant_id')
        if err:
            return err
        assert variant_uuid is not None

        project = Project.get_by_id(project_uuid)
        if project is None:
            return jsonify({"error": "Project not found"}), 404
        variant = Variant.get_by_id(variant_uuid)
        if variant is None:
            return jsonify({"error": "Variant not found"}), 404
        if variant.project_id != project_uuid:
            return jsonify({"error": "Variant does not belong to the specified project"}), 400

        from ..models.project_context import ProjectContext
        pc = ProjectContext.get_by_project(project_uuid)
        vc = VariantContext.get_by_variant(variant_uuid)

        return jsonify({
            "project_id": str(project_uuid),
            "description": pc.description if pc else None,
            "variant_id": str(variant_uuid),
            "variant_description": vc.variant_description if vc else None,
            "codebase_path": vc.codebase_path if vc else None,
            "environment": vc.environment if vc else None,
            "threat_model": vc.threat_model if vc else None,
            "risks": vc.risks if vc else None,
            "other_info": vc.other_info if vc else None,
            "files": [f.to_dict() for f in vc.files] if vc else [],
        })

    @app.route('/api/projects/<project_id>/context', methods=['GET'])
    def get_project_context(project_id):
        """Return context for a project.

        OpenAPI:
        response 200 JsonObject Project context.
        response 400 Error Invalid project identifier.
        response 404 Error Project not found.
        """
        project_uuid, err = parse_uuid_or_400(project_id, 'project_id')
        if err:
            return err
        assert project_uuid is not None
        project = Project.get_by_id(project_uuid)
        if project is None:
            return jsonify({"error": "Project not found"}), 404
        from ..models.project_context import ProjectContext
        pc = ProjectContext.get_by_project(project_uuid)
        return jsonify({
            "project_id": str(project_uuid),
            "description": pc.description if pc else None,
        })

    @app.route('/api/projects/<project_id>/context', methods=['PUT'])
    def put_project_context(project_id):
        """Create or update context for a project.

        OpenAPI:
        body JsonObject required Project context fields.
        response 200 JsonObject Updated project context.
        response 400 Error Invalid project identifier.
        response 404 Error Project not found.
        """
        project_uuid, err = parse_uuid_or_400(project_id, 'project_id')
        if err:
            return err
        assert project_uuid is not None
        body = request.get_json(silent=True) or {}
        try:
            pc = ProjectContextController.upsert(
                project_uuid, description=body.get('description')
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404
        return jsonify(ProjectContextController.serialize(pc))

    @app.route('/api/variants/<variant_id>/context', methods=['PUT'])
    def put_variant_context(variant_id):
        """Create or update context for a variant.

        OpenAPI:
        body JsonObject required Variant context fields.
        response 200 JsonObject Updated variant context.
        response 400 Error Invalid variant identifier.
        response 404 Error Variant not found.
        """
        variant_uuid, err = parse_uuid_or_400(variant_id, 'variant_id')
        if err:
            return err
        assert variant_uuid is not None
        body = request.get_json(silent=True) or {}
        try:
            vc = VariantContextController.upsert(
                variant_uuid,
                variant_description=body.get('variant_description'),
                codebase_path=body.get('codebase_path'),
                environment=body.get('environment'),
                threat_model=body.get('threat_model'),
                risks=body.get('risks'),
                other_info=body.get('other_info'),
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404
        return jsonify(VariantContextController.serialize(vc))

    @app.route('/api/context/export', methods=['GET'])
    def export_context():
        """Export project and variant context.

        With no filters, exports all context. A single-variant export requires
        both ``project_id`` and ``variant_id``. ``variant_ids`` selects a
        comma-separated set of variants.

        OpenAPI:
        query project_id uuid optional Project UUID for a single-variant export.
        query variant_id uuid optional Variant UUID for a single-variant export.
        query variant_ids string optional Comma-separated variant UUIDs.
        response 200 JsonObject Exported context document.
        response 400 Error Invalid or inconsistent filters.
        response 404 Error Requested project or variant not found.
        """
        project_id_str = request.args.get('project_id')
        variant_id_str = request.args.get('variant_id')
        variant_ids_str = request.args.get('variant_ids')

        project_uuid = None
        variant_uuid = None
        variant_ids: set[uuid.UUID] | None = None
        # Single-variant export requires both identifiers.
        if project_id_str or variant_id_str:
            project_uuid, err = parse_uuid_or_400(project_id_str or '', 'project_id')
            if err:
                return err
            variant_uuid, err = parse_uuid_or_400(variant_id_str or '', 'variant_id')
            if err:
                return err
        elif variant_ids_str is not None:
            # Selective export: comma-separated list of variant UUIDs.
            variant_ids = set()
            for raw in variant_ids_str.split(','):
                raw = raw.strip()
                if not raw:
                    continue
                vid, err = parse_uuid_or_400(raw, 'variant_ids')
                if err:
                    return err
                assert vid is not None
                variant_ids.add(vid)

        try:
            projects = collect_entries(project_uuid, variant_uuid, variant_ids)
        except LookupError as exc:
            return jsonify({"error": str(exc)}), 404
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        return jsonify(build_export_document(projects))

    @app.route('/api/context/import', methods=['POST'])
    def import_context():
        """Import project and variant context atomically.

        OpenAPI:
        body JsonObject required Context export document to import.
        response 200 JsonObject Import result.
        response 400 Error Invalid context document.
        response 500 Error Context could not be persisted.
        """
        body = request.get_json(silent=True)
        try:
            entries = extract_entries(body)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        result = import_entries(entries)

        # Apply all valid entries atomically: a failure part-way through must
        # not leave the database with only some entries persisted.
        try:
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.exception("Failed to commit context import")
            return jsonify({"error": f"Failed to import context: {exc}"}), 500

        return jsonify(result)

    # ------------------------------------------------------------------
    # Supplemental context files (currently hidden from the UI)
    # ------------------------------------------------------------------
    # NOTE: The AI-context page no longer exposes a UI for uploading or
    # deleting supplemental files, so these endpoints (and the ContextFile
    # model / context_files table) are unused by the frontend today. They are
    # intentionally kept for potential future reuse rather than removed, to
    # avoid a destructive schema migration. If this feature is confirmed dead,
    # remove these routes, the ContextFile model, and add a migration dropping
    # the context_files table.
    @app.route('/api/variants/<variant_id>/context/files', methods=['POST'])
    def post_context_file(variant_id):
        """Upload a supplemental context file for a variant.

        Files are limited to 10 MB. The multipart payload accepts a required
        ``file`` field and an optional ``description`` field.

        OpenAPI:
        body multipart required Supplemental file and optional description.
        response 201 JsonObject Uploaded context-file metadata.
        response 400 Error Invalid identifier, missing file, or oversized file.
        response 404 Error Variant not found.
        response 500 Error File could not be stored.
        """
        variant_uuid, err = parse_uuid_or_400(variant_id, 'variant_id')
        if err:
            return err
        assert variant_uuid is not None

        variant = Variant.get_by_id(variant_uuid)
        if variant is None:
            return jsonify({"error": "Variant not found"}), 404

        file = request.files.get('file')
        if file is None or file.filename == '':
            return jsonify({"error": "No file provided"}), 400

        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        if size > MAX_FILE_BYTES:
            max_mb = MAX_FILE_BYTES // (1024 * 1024)
            return jsonify({"error": f"File exceeds maximum size of {max_mb} MB"}), 400

        vc = VariantContext.get_by_variant(variant_uuid)
        if vc is None:
            vc = VariantContext.upsert(variant_uuid)

        description = request.form.get('description')
        if description is not None:
            description = description.strip() or None

        file_id = uuid.uuid4()
        original_name = os.path.basename(file.filename.replace('\\', '/'))

        dest_dir = os.path.join(_get_cache_dir(), "context-files", str(vc.id))
        try:
            os.makedirs(dest_dir, exist_ok=True)
            file_path = os.path.join(dest_dir, str(file_id))
            file.save(file_path)
        except OSError as exc:
            logger.error("Failed to save uploaded file: %s", exc)
            return jsonify({"error": "Failed to store file on server"}), 500

        cf = ContextFile.create(
            vc.id, original_name=original_name, file_path=file_path,
            description=description, id=file_id
        )
        return jsonify(cf.to_dict()), 201

    @app.route('/api/variants/<variant_id>/context/files/<file_id>', methods=['DELETE'])
    def delete_context_file(variant_id, file_id):
        """Delete a supplemental context file.

        OpenAPI:
        response 204 string Context file deleted.
        response 400 Error Invalid variant or file identifier.
        response 404 Error Variant or context file not found.
        """
        variant_uuid, err = parse_uuid_or_400(variant_id, 'variant_id')
        if err:
            return err
        assert variant_uuid is not None
        file_uuid, err = parse_uuid_or_400(file_id, 'file_id')
        if err:
            return err
        assert file_uuid is not None

        variant = Variant.get_by_id(variant_uuid)
        if variant is None:
            return jsonify({"error": "Variant not found"}), 404

        vc = VariantContext.get_by_variant(variant_uuid)
        if vc is None:
            return jsonify({"error": "File not found"}), 404

        cf = ContextFile.get_by_id_and_variant_context(file_uuid, vc.id)
        if cf is None:
            return jsonify({"error": "File not found"}), 404

        file_path = cf.file_path
        from ..extensions import db
        db.session.delete(cf)
        db.session.commit()

        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
        except OSError as exc:
            logger.warning("Could not delete file %s: %s", file_path, exc)

        return '', 204

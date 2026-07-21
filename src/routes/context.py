# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import uuid
import logging

from flask import jsonify, request

from ..controllers.context import ProjectContextController, VariantContextController
from ..extensions import db
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

    def _context_entry(project, variant, pc, vc) -> dict:
        return {
            "project_name": project.name,
            "variant_name": variant.name,
            "description": pc.description if pc else None,
            "variant_description": vc.variant_description if vc else None,
            "codebase_path": vc.codebase_path if vc else None,
            "environment": vc.environment if vc else None,
            "threat_model": vc.threat_model if vc else None,
            "risks": vc.risks if vc else None,
            "other_info": vc.other_info if vc else None,
        }

    @app.route('/api/context/export', methods=['GET'])
    def export_context():
        from ..models.project_context import ProjectContext

        project_id_str = request.args.get('project_id')
        variant_id_str = request.args.get('variant_id')

        # Single-variant export requires both identifiers.
        if project_id_str or variant_id_str:
            project_uuid, err = parse_uuid_or_400(project_id_str or '', 'project_id')
            if err:
                return err
            assert project_uuid is not None
            variant_uuid, err = parse_uuid_or_400(variant_id_str or '', 'variant_id')
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

            pc = ProjectContext.get_by_project(project_uuid)
            vc = VariantContext.get_by_variant(variant_uuid)
            return jsonify([_context_entry(project, variant, pc, vc)])

        # Full export: one entry per variant across all projects.
        entries = []
        for project in Project.get_all():
            pc = ProjectContext.get_by_project(project.id)
            for variant in Variant.get_by_project(project.id):
                vc = VariantContext.get_by_variant(variant.id)
                entries.append(_context_entry(project, variant, pc, vc))
        return jsonify(entries)

    @app.route('/api/context/import', methods=['POST'])
    def import_context():
        body = request.get_json(silent=True)
        if not isinstance(body, list):
            return jsonify({"error": "Request body must be a JSON array of context entries"}), 400

        def _txt(value):
            return value if isinstance(value, str) else None

        imported: list = []
        ignored: list = []
        failed: list = []

        for entry in body:
            if not isinstance(entry, dict):
                failed.append({
                    "project_name": None,
                    "variant_name": None,
                    "reason": "Entry is not a JSON object",
                })
                continue

            project_name = _txt(entry.get('project_name'))
            variant_name = _txt(entry.get('variant_name'))
            ident = {"project_name": project_name, "variant_name": variant_name}

            if not project_name or not variant_name:
                ignored.append({**ident, "reason": "Missing project_name or variant_name"})
                continue

            project = Project.get_by_name(project_name)
            if project is None:
                ignored.append({**ident, "reason": "Project not found"})
                continue
            variant = Variant.get_by_name_and_project(variant_name, project.id)
            if variant is None:
                ignored.append({**ident, "reason": "Variant not found"})
                continue

            description = _txt(entry.get('description'))
            threat_model = _txt(entry.get('threat_model'))
            missing = []
            if not (description and description.strip()):
                missing.append('description')
            if not (threat_model and threat_model.strip()):
                missing.append('threat_model')
            if missing:
                failed.append({
                    **ident,
                    "reason": f"Missing mandatory field(s): {', '.join(missing)}",
                })
                continue

            ProjectContextController.upsert(project.id, description=description, commit=False)
            VariantContextController.upsert(
                variant.id,
                variant_description=_txt(entry.get('variant_description')),
                codebase_path=_txt(entry.get('codebase_path')),
                environment=_txt(entry.get('environment')),
                threat_model=threat_model,
                risks=_txt(entry.get('risks')),
                other_info=_txt(entry.get('other_info')),
                commit=False,
            )
            imported.append(ident)

        # Apply all valid entries atomically: a failure part-way through must
        # not leave the database with only some entries persisted.
        try:
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.exception("Failed to commit context import")
            return jsonify({"error": f"Failed to import context: {exc}"}), 500

        return jsonify({"imported": imported, "ignored": ignored, "failed": failed})

    @app.route('/api/variants/<variant_id>/context/files', methods=['POST'])
    def post_context_file(variant_id):
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

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import uuid
import logging
from datetime import datetime, timezone

from flask import jsonify, request
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import RequestEntityTooLarge

from ..controllers.context import ProjectContextController, VariantContextController
from ..extensions import db
from ..helpers.codebase_reference import CodebaseReference, MAX_FILE_BYTES, validate_reference
from ..helpers.context_io import (
    build_export_document,
    collect_entries,
    extract_entries,
    import_entries,
)
from ..helpers.shared_context import (
    ContextConflict, convert_mode, load_document, response as shared_response,
    save_section, validate_document, write_variant,
)
from ..models.project import Project
from ..models.variant import Variant
from ..models.variant_context import VariantContext, ContextFile
from ..routes._scan_helpers import parse_uuid_or_400

logger = logging.getLogger(__name__)
MAX_REFERENCE_REQUEST_BYTES = MAX_FILE_BYTES + 64 * 1024


def _get_cache_dir() -> str:
    return os.getenv("VULNSCOUT_CACHE_DIR", "/cache/vulnscout")


def init_app(app):

    @app.route('/api/projects/<project_id>/context/shared', methods=['GET', 'PATCH', 'POST'])
    def shared_project_context(project_id):
        """Read shared entries, save one section, or preview editor-mode conversion.

        OpenAPI:
        body JsonObject optional Section update or mode-conversion preview.
        response 200 JsonObject Shared project context or preview.
        response 400 Error Invalid shared entries or scope.
        response 404 Error Project not found.
        response 409 Error Saved project context changed.
        """
        project_uuid, err = parse_uuid_or_400(project_id, 'project_id')
        if err:
            return err
        assert project_uuid is not None
        if Project.get_by_id(project_uuid) is None:
            return jsonify({"error": "Project not found"}), 404
        if request.method == 'GET':
            return jsonify(shared_response(project_uuid))
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"error": "Supply a shared context object"}), 400
        try:
            if request.method == 'POST':
                if set(body) != {'context', 'editor_mode'}:
                    raise ValueError("Supply context and editor_mode only")
                _, _, variants = load_document(project_uuid)
                identifiers = [str(variant.id) for variant in variants]
                validate_document(body.get('context'), set(identifiers))
                if body.get('editor_mode') not in ('stride', 'free'):
                    raise ValueError("editor_mode must be stride or free")
                return jsonify({"context": convert_mode(body['context'], body['editor_mode'], identifiers)})
            return jsonify(save_section(project_uuid, body))
        except ContextConflict as exc:
            db.session.rollback()
            return jsonify({"error": str(exc)}), 409
        except ValueError as exc:
            db.session.rollback()
            return jsonify({"error": str(exc)}), 400

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
            "editor_mode": vc.editor_mode if vc else None,
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
        if not isinstance(body, dict) or body.get('editor_mode') not in (None, 'stride', 'free'):
            return jsonify({"error": "editor_mode must be stride or free."}), 400
        if any(body.get(key) is not None and not isinstance(body[key], str) for key in (
            'variant_description', 'codebase_path', 'environment', 'threat_model', 'risks', 'other_info',
        )):
            return jsonify({"error": "Context fields must be text or null."}), 400
        if Variant.get_by_id(variant_uuid) is None:
            return jsonify({"error": "Variant not found"}), 404
        try:
            vc = VariantContextController.upsert(
                variant_uuid,
                variant_description=body.get('variant_description'),
                codebase_path=body.get('codebase_path'),
                environment=body.get('environment'),
                threat_model=body.get('threat_model'),
                risks=body.get('risks'),
                other_info=body.get('other_info'),
                editor_mode=body.get('editor_mode'),
            )
        except ContextConflict as exc:
            db.session.rollback()
            return jsonify({"error": str(exc)}), 409
        except ValueError as exc:
            db.session.rollback()
            return jsonify({"error": str(exc)}), 400
        return jsonify(VariantContextController.serialize(vc))

    @app.route('/api/variants/<variant_id>/context', methods=['PATCH'])
    def patch_variant_context(variant_id):
        """Update only supplied variant context fields.

        OpenAPI:
        body JsonObject required Changed fields and optional expected field values.
        response 200 JsonObject Updated variant context.
        response 400 Error Invalid identifier, fields or expected values.
        response 404 Error Variant not found.
        response 409 Error Context changed since it was loaded.
        """
        variant_uuid, err = parse_uuid_or_400(variant_id, 'variant_id')
        if err:
            return err
        assert variant_uuid is not None
        body = request.get_json(silent=True)
        fields = (
            'variant_description', 'codebase_path', 'environment',
            'threat_model', 'risks', 'other_info',
            'editor_mode',
        )
        if not isinstance(body, dict) or not body or any(key not in (*fields, 'expected') for key in body):
            return jsonify({"error": "Supply variant context fields to update."}), 400
        expected = body.get('expected', {})
        if (
            not any(key in body for key in fields)
            or any(body[key] is not None and not isinstance(body[key], str) for key in fields if key in body)
            or not isinstance(expected, dict)
            or any(key not in fields or (value is not None and not isinstance(value, str))
                   for key, value in expected.items())
        ):
            return jsonify({"error": "Context fields and expected values must be text or null."}), 400
        if body.get('editor_mode') not in (None, 'stride', 'free') or expected.get('editor_mode') not in (
            None, 'stride', 'free',
        ):
            return jsonify({"error": "editor_mode must be stride, free or null."}), 400
        try:
            variant = Variant.get_by_id(variant_uuid)
            if variant is None:
                return jsonify({"error": "Variant not found"}), 404
            from ..models.project_context import ProjectContext
            pc = ProjectContext.get_by_project(variant.project_id)
            if pc is not None and pc.shared_context is not None:
                vc = write_variant(variant_uuid, {key: body[key] for key in fields if key in body},
                                   partial=True, expected=expected)
                return jsonify(VariantContextController.serialize(vc))
            vc = VariantContextController.get_or_create(variant_uuid)
            if any(getattr(vc, key) != value for key, value in expected.items()):
                return jsonify({"error": (
                    "The saved context changed since it was loaded. Keep a copy of your "
                    "drafts and reload the page before saving this section."
                )}), 409
            values = {key: body[key] for key in fields if key in body}
            if any(getattr(vc, key) != value for key, value in values.items()):
                ProjectContext.advance_revision(variant.project_id, pc.context_revision if pc else 0)
            if any(key != 'editor_mode' and getattr(vc, key) != value for key, value in values.items()):
                values['updated_at'] = datetime.now(timezone.utc)
            statement = db.update(VariantContext).where(
                VariantContext.variant_id == variant_uuid,
                *(getattr(VariantContext, key) == value for key, value in expected.items()),
            ).values(**values).returning(VariantContext.id)
            if db.session.execute(statement).scalar_one_or_none() is None:
                db.session.rollback()
                return jsonify({"error": (
                    "Context changed during the save. Keep your drafts and reload before saving."
                )}), 409
            db.session.commit()
        except ContextConflict as exc:
            db.session.rollback()
            return jsonify({"error": str(exc)}), 409
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

    @app.route('/api/variants/<variant_id>/context/files', methods=['POST'])
    def post_context_file(variant_id):
        """Upload a codebase reference file or ZIP/TAR archive for a variant.

        Files are limited to 10 MB. The multipart payload accepts a required
        ``file`` field and an optional ``description`` field.

        OpenAPI:
        body multipart required Supplemental file and optional description.
        response 201 JsonObject Uploaded context-file metadata.
        response 400 Error Invalid identifier, missing file, or oversized file.
        response 404 Error Variant not found.
        response 413 Error Multipart upload request exceeds its size limit.
        response 500 Error File could not be stored.
        """
        variant_uuid, err = parse_uuid_or_400(variant_id, 'variant_id')
        if err:
            return err
        assert variant_uuid is not None

        variant = Variant.get_by_id(variant_uuid)
        if variant is None:
            return jsonify({"error": "Variant not found"}), 404

        request.max_content_length = MAX_REFERENCE_REQUEST_BYTES
        try:
            file = request.files.get('file')
        except RequestEntityTooLarge:
            return jsonify(error="Codebase reference upload exceeds the 10 MB limit plus multipart overhead."), 413
        if file is None:
            return jsonify({"error": "No file provided"}), 400

        filename = file.filename
        if not filename:
            return jsonify({"error": "No file provided"}), 400

        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        if size > MAX_FILE_BYTES:
            max_mb = MAX_FILE_BYTES // (1024 * 1024)
            return jsonify({"error": f"File exceeds maximum size of {max_mb} MB"}), 400

        description = request.form.get('description')
        if description is not None:
            description = description.strip() or None

        file_id = uuid.uuid4()
        original_name = os.path.basename(filename.replace('\\', '/'))
        try:
            validate_reference(file.stream, original_name)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        vc = VariantContext.get_by_variant(variant_uuid)
        if vc is None:
            vc = VariantContext.upsert(variant_uuid)

        dest_dir = os.path.join(_get_cache_dir(), "context-files", str(vc.id))
        file_path = os.path.join(dest_dir, str(file_id))
        try:
            os.makedirs(dest_dir, exist_ok=True)
            file.save(file_path)
            cf = ContextFile(
                variant_context_id=vc.id, original_name=original_name, file_path=file_path,
                description=description, id=file_id,
            )
            db.session.add(cf)
            VariantContext.touch(variant_uuid, commit=False)
            db.session.commit()
        except (OSError, SQLAlchemyError):
            db.session.rollback()
            logger.exception("Failed to store uploaded codebase reference")
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except OSError:
                logger.exception("Failed to clean up uploaded codebase reference")
            return jsonify({"error": "Failed to store file on server"}), 500

        return jsonify(cf.to_dict()), 201

    @app.route('/api/variants/<variant_id>/context/files/<file_id>/source', methods=['GET'])
    def get_codebase_source(variant_id, file_id):
        """List, read or search a variant's uploaded codebase reference.

        OpenAPI:
        query operation string optional list (default), read, or search.
        query path string optional Exact member path for read.
        query pattern string optional File-path glob for list or search (default *).
        query offset integer optional List offset (default 0).
        query limit integer optional List page size, 1-200 (default 200).
        query start_line integer optional First line for read (default 1).
        query max_lines integer optional Read line count, 1-200 (default 200).
        query query string optional Literal case-sensitive search text, required for search.
        query max_results integer optional Search limit, 1-100 (default 100).
        response 200 JsonObject Source files, line-numbered content, or search matches.
        response 400 Error Invalid parameters or unreadable reference.
        response 404 Error Variant, reference, or source member not found.
        response 500 Error Stored reference is unavailable.
        """
        variant_uuid, err = parse_uuid_or_400(variant_id, 'variant_id')
        if err:
            return err
        assert variant_uuid is not None
        file_uuid, err = parse_uuid_or_400(file_id, 'file_id')
        if err:
            return err
        assert file_uuid is not None
        if Variant.get_by_id(variant_uuid) is None:
            return jsonify(error="Variant not found"), 404
        vc = VariantContext.get_by_variant(variant_uuid)
        cf = ContextFile.get_by_id_and_variant_context(file_uuid, vc.id) if vc else None
        if cf is None:
            return jsonify(error="File not found"), 404

        def integer(name, default, minimum, maximum):
            try:
                value = int(request.args.get(name, default))
            except ValueError as exc:
                raise ValueError(f"Invalid {name}.") from exc
            if not minimum <= value <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}.")
            return value

        try:
            operation = request.args.get("operation", "list")
            pattern = request.args.get("pattern", "*")
            if len(pattern) > 512:
                raise ValueError("File pattern must be at most 512 characters.")
            with open(cf.file_path, "rb") as stream, CodebaseReference(stream, cf.original_name) as reference:
                if operation == "list":
                    result = reference.list_files(
                        pattern, integer("offset", 0, 0, 5000), integer("limit", 200, 1, 200),
                    )
                elif operation == "read":
                    result = reference.read_lines(
                        request.args.get("path", ""),
                        integer("start_line", 1, 1, 10 * 1024 * 1024),
                        integer("max_lines", 200, 1, 200),
                    )
                elif operation == "search":
                    query = request.args.get("query", "")
                    if not query or len(query) > 200:
                        raise ValueError("Search query must contain 1-200 characters.")
                    result = reference.search(query, pattern, integer("max_results", 100, 1, 100))
                else:
                    raise ValueError("Operation must be list, read, or search.")
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        except OSError:
            logger.exception("Could not read stored codebase reference %s", file_id)
            return jsonify(error="Stored codebase reference is unavailable."), 500
        return jsonify({"file_id": file_id, "original_name": cf.original_name, **result})

    @app.route('/api/variants/<variant_id>/context/files/<file_id>', methods=['DELETE'])
    def delete_context_file(variant_id, file_id):
        """Delete an uploaded codebase reference.

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
        db.session.delete(cf)
        VariantContext.touch(variant_uuid, commit=False)
        db.session.commit()

        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
        except OSError as exc:
            logger.warning("Could not delete file %s: %s", file_path, exc)

        return '', 204

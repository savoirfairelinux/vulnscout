# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import uuid
import logging

from flask import jsonify, request
from sqlalchemy.exc import SQLAlchemyError

from ..controllers.context import ProjectContextController, VariantContextController
from ..extensions import db
from ..helpers.codebase_reference import CodebaseReference, validate_reference
from ..helpers.context_io import (
    build_export_document,
    collect_entries,
    extract_entries,
    import_entries,
)
from ..helpers.stride_model import StrideValidationError
from ..models.project import Project
from ..models.variant import Variant
from ..models.variant_context import (
    ContextFile,
    VariantContext,
    default_editor_block,
)
from ..routes._scan_helpers import parse_uuid_or_400

logger = logging.getLogger(__name__)


# Agent-facing variant keys of GET /api/context (besides ``files``).
_AGENT_VARIANT_KEYS = (
    "variant_description", "codebase_path", "environment", "threat_model", "risks", "other_info",
)


# Agent-facing text rendered from the STRIDE model; text writes are rejected.
_STRIDE_TEXT_KEYS = ("threat_model", "risks")
STRIDE_TEXT_READ_ONLY = "is generated from the STRIDE model; edit it in the AI Context page"


def _get_cache_dir() -> str:
    return os.getenv("VULNSCOUT_CACHE_DIR", "/cache/vulnscout")


def init_app(app):

    @app.route('/api/context', methods=['GET'])
    def get_merged_context():
        """Return merged project and variant context.

        OpenAPI:
        query project_id uuid required Project UUID.
        query variant_id uuid required Variant UUID belonging to the project.
        response 200 MergedContext Merged project and variant context.
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

        variant_part = vc.to_dict() if vc else {"files": [], "editor": default_editor_block()}
        return jsonify({
            "project_id": str(project_uuid),
            "description": pc.description if pc else None,
            "variant_id": str(variant_uuid),
            **{key: variant_part.get(key) for key in _AGENT_VARIANT_KEYS},
            "files": variant_part["files"],
            "editor": variant_part["editor"],
        })

    @app.route('/api/projects/<project_id>/context', methods=['GET'])
    def get_project_context(project_id):
        """Return context for a project.

        OpenAPI:
        response 200 ProjectContext Project context.
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
        body ProjectContextUpdate required Project context fields.
        response 200 ProjectContext Updated project context.
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

        A body with ``stride`` is an editor-shape save; otherwise it is a
        full-replacement write of the text fields. The threat model and risks
        are rendered from the STRIDE model and cannot be written as text.

        OpenAPI:
        body VariantContextUpdate required Variant context fields.
        response 200 VariantContext Updated variant context.
        response 400 Error Invalid variant identifier or context fields.
        response 404 Error Variant not found.
        """
        variant_uuid, err = parse_uuid_or_400(variant_id, 'variant_id')
        if err:
            return err
        assert variant_uuid is not None
        body = request.get_json(silent=True) or {}
        try:
            if 'stride' in body:
                vc = VariantContextController.save_editor(variant_uuid, body)
            else:
                text_fields = {key: body.get(key) for key in _STRIDE_TEXT_KEYS if body.get(key) is not None}
                if text_fields:
                    raise StrideValidationError({key: STRIDE_TEXT_READ_ONLY for key in text_fields})
                vc = VariantContextController.upsert(
                    variant_uuid,
                    variant_description=body.get('variant_description'),
                    codebase_path=body.get('codebase_path'),
                    environment=body.get('environment'),
                    other_info=body.get('other_info'),
                )
        except StrideValidationError as exc:
            return jsonify({"error": str(exc), "fields": exc.fields}), 400
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
        response 200 ContextExport Exported context document.
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
        body ContextExport required Context export document to import.
        response 200 ContextImportResult Import result.
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

        The multipart payload accepts a required ``file`` field and an optional
        ``description`` field.

        OpenAPI:
        body multipart required Supplemental file and optional description.
        form file binary required Codebase reference file or ZIP/TAR archive.
        form description string optional Description of this reference.
        response 201 ContextFile Uploaded context-file metadata.
        response 400 Error Invalid identifier or missing file.
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
        if file is None:
            return jsonify({"error": "No file provided"}), 400

        filename = file.filename
        if not filename:
            return jsonify({"error": "No file provided"}), 400

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
            # A variant whose first context is an upload uses its references.
            vc = VariantContext.upsert(variant_uuid, commit=False)
            vc.codebase_source = "references"
            db.session.commit()

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
        response 200 SourceReferenceResult Source files, line-numbered content, or search matches.
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
        response 204 empty Context file deleted.
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

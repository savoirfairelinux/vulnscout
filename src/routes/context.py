# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import io
import os
import uuid
import logging
from contextlib import ExitStack
from datetime import datetime, timezone

from flask import jsonify, request
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.exceptions import RequestEntityTooLarge

from ..controllers.context import ProjectContextController, VariantContextController
from ..extensions import db
from ..helpers import context_draft, host_mounts as host_helper
from ..helpers.datetime_utils import ensure_utc_iso
from ..helpers.codebase_reference import (
    ARCHIVE_SUFFIXES, MAX_ENTRIES, MAX_FILE_BYTES, MAX_RESPONSE_BYTES, CodebaseReference, validate_reference,
)
from ..helpers.codebase_directory import (
    CodebaseDirectory, EmptyCodebaseDirectory, directory_exists, directory_name, directory_path, provision_directory,
)
from ..helpers.context_io import (
    build_export_document,
    collect_entries,
    extract_entries,
    import_entries,
)
from ..helpers.stride_model import StrideValidationError
from ..controllers import host_mounts
from ..helpers.host_mounts import HostHelperError, HostHelperUnavailable
from ..helpers.host_mounts import validate_pattern as validate_mount_pattern
from ..models.host_mount import MOUNT_FILE_ID_PREFIX, HostMount
from ..models.project import Project
from ..models.variant import Variant
from ..models.variant_context import (
    ContextFile,
    VariantContext,
    default_editor_block,
)
from ..routes._scan_helpers import parse_uuid_or_400
from .agent import _access_error

logger = logging.getLogger(__name__)


# Agent-facing variant keys of GET /api/context (besides ``files``).
_AGENT_VARIANT_KEYS = (
    "variant_description", "environment", "threat_model", "risks", "other_info",
)


# Agent-facing text rendered from the STRIDE model; text writes are rejected.
_STRIDE_TEXT_KEYS = ("threat_model", "risks")
STRIDE_TEXT_READ_ONLY = "is generated from the STRIDE model; edit it in the AI Context page"
DIRECTORY_NAME_CONFLICT = (
    "Codebase directory name is already assigned to another variant; use distinct project/variant names."
)
SHELL_REQUEST_BYTES = 64 * 1024


def _get_cache_dir() -> str:
    return os.getenv("VULNSCOUT_CACHE_DIR", "/cache/vulnscout")


def _directory_in_use(name: str, variant_id: uuid.UUID) -> bool:
    return db.session.execute(db.select(VariantContext.id).where(
        VariantContext.codebase_directory == name,
        VariantContext.variant_id != variant_id,
    )).first() is not None


def _register_directory(vc: VariantContext, name: str):
    if vc.codebase_directory is None:
        try:
            db.session.execute(db.update(VariantContext).where(
                VariantContext.id == vc.id, VariantContext.codebase_directory.is_(None)
            ).values(codebase_directory=name, updated_at=datetime.now(timezone.utc)))
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            if not _directory_in_use(name, vc.variant_id):
                raise
            return vc, (jsonify({"error": DIRECTORY_NAME_CONFLICT}), 409)
        db.session.refresh(vc)
    return vc, None


def _directory_context(variant_id: uuid.UUID):
    """Register existing CI source directories on reads, without creating filesystem paths."""
    vc = VariantContext.get_by_variant(variant_id)
    if vc is not None and vc.codebase_directory is not None:
        return vc, None
    variant = Variant.get_by_id(variant_id)
    assert variant is not None
    project = Project.get_by_id(variant.project_id)
    assert project is not None
    name = directory_name(project.name, variant.name)
    try:
        if not directory_exists(_get_cache_dir(), name):
            return vc, None
    except OSError:
        logger.exception("Could not discover codebase directory for variant %s", variant_id)
        return vc, (jsonify({"error": "Could not inspect codebase directory; check its type and permissions."}), 500)
    if _directory_in_use(name, variant_id):
        return vc, (jsonify({"error": DIRECTORY_NAME_CONFLICT}), 409)
    candidates = db.session.execute(db.select(Project.name, Variant.name).select_from(Variant).join(
        Project, Variant.project_id == Project.id
    ).outerjoin(VariantContext, VariantContext.variant_id == Variant.id).where(
        Variant.id != variant_id, VariantContext.codebase_directory.is_(None)
    )).all()
    if any(directory_name(project_name, variant_name) == name for project_name, variant_name in candidates):
        return vc, (jsonify({
            "error": "Ambiguous codebase directory name; rename the variants or explicitly provision its owner.",
        }), 409)
    return _register_directory(vc or VariantContext.get_or_create(variant_id), name)


def _variant_uuid_or_error(variant_id):
    """(variant UUID, None) for an existing variant, else (None, error response)."""
    variant_uuid, err = parse_uuid_or_400(variant_id, 'variant_id')
    if err or variant_uuid is None:
        return None, err
    if Variant.get_by_id(variant_uuid) is None:
        return None, (jsonify({"error": "Variant not found"}), 404)
    return variant_uuid, None


def _revision(vc) -> str | None:
    return ensure_utc_iso(vc.updated_at) if vc is not None else None


def _draft_dir(vc) -> str:
    return context_draft.context_dir(_get_cache_dir(), vc.id)


def _draft_body(draft: dict, status: str, values, conflicts: list, renumbered: dict, saved_at, revision) -> dict:
    return {
        "revision": revision,
        "source": draft.get("source"), "status": status, "values": values, "conflicts": conflicts,
        "renumbered": renumbered, "base_updated_at": draft.get("base_updated_at"),
        "saved_updated_at": saved_at, "created_at": draft.get("created_at"), "updated_at": draft.get("updated_at"),
    }


def _integer(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(request.args.get(name, default))
    except ValueError as exc:
        raise ValueError(f"Invalid {name}.") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return value


def _fit_source_page(body: dict, key: str, offset: int = 0) -> dict | None:
    entries = body[key]
    reason = "Source response limited to 64 KiB."
    page = {**body, "truncated": True, "message": " ".join(filter(None, (body.get("message"), reason)))}
    lo, hi = 1, len(entries)
    result = None
    while lo <= hi:
        n = (lo + hi) // 2
        candidate = {**page, key: entries[:n]}
        if key == "files":
            candidate["next_offset"] = offset + n if offset + n < body["total"] else None
        if len(jsonify(candidate).get_data()) <= MAX_RESPONSE_BYTES:
            result = candidate
            lo = n + 1
        else:
            hi = n - 1
    return result


def _browse_reference(file_path: str, name: str, label: str, *,
                      directory_variant: uuid.UUID | None = None) -> tuple[dict, int]:
    """List, read or search a stored file or archive as the request's query asks."""
    try:
        directory = directory_variant is not None
        operation = request.args.get("operation", "list")
        position = request.args.get("position")
        if position is not None and (not directory or operation != "read"):
            raise ValueError("A read position is only supported for directory or mount reads.")
        pattern = request.args.get("pattern", "*")
        if len(pattern) > 512:
            raise ValueError("File pattern must be at most 512 characters.")
        folder = request.args.get("folder", "")
        if folder and (not directory or operation not in ("children", "list")):
            raise ValueError("folder is only supported for listings of directories or attached host folders.")
        if operation == "children" and not directory:
            raise ValueError("Shallow listings require a directory or mount.")
        if directory and operation not in ("list", "read", "children", "search_file", "search"):
            raise ValueError("Unsupported source operation.")
        if not directory and operation not in ("list", "read", "search"):
            raise ValueError("Operation must be list, read, or search.")
        with ExitStack() as stack:
            reference: CodebaseReference
            if directory:
                source = stack.enter_context(CodebaseDirectory(file_path, name, folder=folder,
                                                               index=operation in ("list", "search")))
                reference = source
            else:
                stream = stack.enter_context(open(file_path, "rb"))
                reference = stack.enter_context(CodebaseReference(stream, name))
            if operation == "list":
                offset = _integer("offset", 0, 0, MAX_ENTRIES)
                result = reference.list_files(pattern, offset, _integer("limit", 200, 1, 200))
                if folder:
                    for entry in result["files"]:
                        entry["path"] = source.folder + "/" + entry["path"]
            elif operation == "children" and directory:
                result = source.list_children(str(directory_variant), request.args.get("cursor", ""),
                                              _integer("limit", 50, 1, 200))
            elif operation == "search_file" and directory:
                result = source.search_file(str(directory_variant), request.args.get("path", ""),
                                            request.args.get("query", ""), request.args.get("cursor", ""))
            elif operation == "read":
                path = request.args.get("path", "")
                start = _integer("start_line", 1, 1, 10 * 1024 * 1024)
                lines = _integer("max_lines", 200, 1, 200)
                try:
                    if position is not None:
                        if start != 1:
                            raise ValueError("Use position or start_line, not both.")
                        result = source.read_match(str(directory_variant), path, position, lines)
                    else:
                        result = reference.read_lines(path, start, lines)
                except FileNotFoundError as exc:
                    raise LookupError("Source file not found or excluded.") from exc
            else:
                query = request.args.get("query", "")
                if not query or len(query) > 200:
                    raise ValueError("Search query must contain 1-200 characters.")
                result = reference.search(query, pattern, _integer("max_results", 100, 1, 100))
            if directory:
                result = {"file_id": "directory", "original_name": "Codebase directory", **result}
                if len(jsonify(result).get_data()) > MAX_RESPONSE_BYTES:
                    if operation == "list":
                        page = _fit_source_page(result, "files", offset)
                        if page is not None:
                            return page, 200
                    raise ValueError("Source response exceeds 64 KB; reduce limit or max_lines.")
    except host_helper.protocol.HelperError as exc:
        return {"error": exc.message}, host_helper.HTTP_STATUS[exc.code]
    except LookupError as exc:
        return {"error": str(exc)}, 404
    except ValueError as exc:
        return {"error": str(exc)}, 400
    except OSError:
        logger.exception("Could not read stored %s %s", label, file_path)
        if directory:
            return {"error": "Codebase directory is missing or unreadable; check its mount and permissions."}, 400
        return {"error": f"Stored {label} is unavailable."}, 500
    return result, 200


def _browse_mount(variant_uuid: uuid.UUID, file_id: str) -> tuple[dict, int]:
    """List or read an attached host folder through the host folder helper."""
    try:
        alias = host_mounts.mount_alias(file_id)
        assert alias is not None
        operation = request.args.get("operation", "list")
        pattern = request.args.get("pattern", "*")
        if len(pattern) > 512:
            raise ValueError("File pattern must be at most 512 characters.")
        if operation in ("list", "search"):
            validate_mount_pattern(pattern)
        folder = request.args.get("folder", "")
        if len(folder) > 1024:
            raise ValueError("folder must be at most 1024 characters.")
        params: dict
        if "position" in request.args and operation != "read":
            raise ValueError("A read position is only supported for read.")
        if operation == "list":
            params = {"pattern": pattern, "folder": folder, "offset": _integer("offset", 0, 0, MAX_ENTRIES),
                      "limit": _integer("limit", 200, 1, 200)}
        elif operation == "children":
            params = {"folder": folder, "cursor": request.args.get("cursor", ""),
                      "limit": _integer("limit", 50, 1, 200)}
        elif operation == "read":
            params = {"path": request.args.get("path", ""),
                      "start_line": _integer("start_line", 1, 1, 10 * 1024 * 1024),
                      "max_lines": _integer("max_lines", 200, 1, 200)}
            if "position" in request.args:
                if folder:
                    raise ValueError("Use an exact path, not folder, for a positioned read.")
                params["position"] = request.args["position"]
        elif operation == "search_file":
            if folder:
                raise ValueError("Use an exact path, not folder, for single-file search.")
            params = {key: request.args.get(key, "") for key in ("path", "query", "cursor")}
        elif operation == "search":
            query = request.args.get("query", "")
            if not query or len(query) > 200:
                raise ValueError("Search query must contain 1-200 characters.")
            params = {"query": query, "pattern": pattern, "folder": folder,
                      "max_results": _integer("max_results", 100, 1, 100)}
        else:
            raise ValueError("Unsupported source operation.")
        result = host_mounts.browse(variant_uuid, alias, operation, params)
    except LookupError as exc:
        return {"error": str(exc)}, 404
    except ValueError as exc:
        return {"error": str(exc)}, 400
    except HostHelperUnavailable as exc:
        return {"error": exc.message, "helper_available": False}, 503
    except HostHelperError as exc:
        return {"error": exc.message, "code": exc.code}, exc.http_status
    body = {"file_id": file_id, "original_name": f"Host folder {alias}", **result}
    if len(jsonify(body).get_data()) > MAX_RESPONSE_BYTES:
        if operation in ("list", "search"):
            key = "files" if operation == "list" else "matches"
            page = _fit_source_page(body, key, params.get("offset", 0))
            if page is not None:
                return page, 200
        if operation == "read" and "position" not in params and body["content"]:
            # Fit complete lines first. Only shorten a line if it cannot fit alone.
            content = body["content"]
            start = body["start_line"]
            lines = list(io.StringIO(content))
            lo, hi = 0, len(lines)
            while lo < hi:
                n = (lo + hi + 1) // 2
                end = start + n - 1
                page = {**body, "content": "".join(lines[:n]), "end_line": end,
                        "next_line": end + 1 if end < body["total_lines"] else None}
                if len(jsonify(page).get_data()) <= MAX_RESPONSE_BYTES:
                    lo = n
                else:
                    hi = n - 1
            if lo:
                end = start + lo - 1
                return {**body, "content": "".join(lines[:lo]), "end_line": end,
                        "next_line": end + 1 if end < body["total_lines"] else None}, 200
            body.update(partial_line=True, end_line=start, next_line=start + 1 if start < body["total_lines"] else None)
            lo, hi = 0, len(lines[0])
            while lo < hi:
                n = (lo + hi + 1) // 2
                body["content"] = lines[0][:n]
                if len(jsonify(body).get_data()) <= MAX_RESPONSE_BYTES:
                    lo = n
                else:
                    hi = n - 1
            body["content"] = lines[0][:lo]
            return body, 200
        return {"error": "Source response exceeds 64 KB; reduce limit, max_lines or max_results."}, 400
    return body, 200


def _import_name(filename: str) -> str | None:
    """Base name of an uploaded import source, or None when it is unsafe to store."""
    name = os.path.basename(filename.replace('\\', '/'))
    if name in ("", ".", "..") or any(ord(char) < 32 for char in name) or len(name.encode("utf-8")) > 255:
        return None
    return name


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
        response 409 Error Existing codebase directory ownership is ambiguous or conflicts.
        response 500 Error Existing codebase directory could not be inspected.
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
        vc, err = _directory_context(variant_uuid)
        if err:
            return err

        variant_part = vc.to_dict() if vc else {"files": [], "editor": default_editor_block()}
        return jsonify({
            "project_id": str(project_uuid),
            "description": pc.description if pc else None,
            "variant_id": str(variant_uuid),
            **{key: variant_part.get(key) for key in _AGENT_VARIANT_KEYS},
            "files": variant_part["files"],
            "editor": variant_part["editor"],
            "codebase_directory": variant_part.get("codebase_directory"),
            "mounts": [{"alias": mount.alias, "file_id": mount.file_id}
                       for mount in HostMount.get_by_variant(variant_uuid)],
        })

    @app.route('/api/variants/<variant_id>/context/directory', methods=['GET', 'POST'])
    def codebase_directory(variant_id):
        """Inspect or provision the variant's server-side source directory.

        GET discovers existing CI directories; POST also creates missing directories on demand.
        Both expose directories to agents without saving context drafts.

        OpenAPI:
        response 200 CodebaseDirectory Directory path and availability.
        response 400 Error Invalid variant identifier.
        response 404 Error Variant not found.
        response 409 Error Directory name ownership conflicts or is ambiguous.
        response 500 Error Directory could not be inspected or provisioned.
        """
        variant_uuid, err = _variant_uuid_or_error(variant_id)
        if err:
            return err
        cache_dir = _get_cache_dir()
        if request.method == 'POST':
            assert variant_uuid is not None
            vc = VariantContext.get_or_create(variant_uuid)
            name = vc.codebase_directory
            if name is None:
                variant = Variant.get_by_id(variant_uuid)
                assert variant is not None
                project = Project.get_by_id(variant.project_id)
                assert project is not None
                name = directory_name(project.name, variant.name)
            if _directory_in_use(name, variant_uuid):
                return jsonify({"error": DIRECTORY_NAME_CONFLICT}), 409
            try:
                provision_directory(cache_dir, name)
            except (OSError, ValueError):
                logger.exception("Could not provision codebase directory for variant %s", variant_id)
                return jsonify({
                    "error": "Could not create codebase directory; check cache ownership and permissions.",
                }), 500
            vc, err = _register_directory(vc, name)
        else:
            vc, err = _directory_context(variant_uuid)
        if err:
            return err
        if vc is None or vc.codebase_directory is None:
            return jsonify({"path": None, "file_id": "directory", "status": "not_created",
                            "message": "No codebase directory provisioned. Create it on demand.",
                            "file_count": None, "directory_count": None})
        path = directory_path(cache_dir, vc.codebase_directory)
        status, message = "ready", "Directory is available. Only eligible source files are exposed."
        file_count: int | None = None
        directory_count: int | None = None
        reference = CodebaseDirectory(cache_dir, vc.codebase_directory)
        try:
            with reference:
                file_count, directory_count = len(reference.entries), reference.directory_count
        except EmptyCodebaseDirectory as exc:
            status, message = "unavailable", str(exc)
            file_count, directory_count = 0, reference.directory_count
        except FileNotFoundError:
            status, message = "missing", "Codebase directory is missing; restore its mount or recreate it."
        except OSError:
            logger.exception("Codebase directory is unreadable: %s", path)
            status, message = "unreadable", "Codebase directory is unreadable; check its mount and permissions."
        except ValueError as exc:
            status, message = "unavailable", str(exc)
        return jsonify({"path": path, "file_id": "directory", "status": status, "message": message,
                        "file_count": file_count, "directory_count": directory_count})

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
                    environment=body.get('environment'),
                    other_info=body.get('other_info'),
                )
        except StrideValidationError as exc:
            return jsonify({"error": str(exc), "fields": exc.fields}), 400
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404
        return jsonify(VariantContextController.serialize(vc))

    @app.route('/api/variants/<variant_id>/context/draft', methods=['GET'])
    def get_context_draft(variant_id):
        """Return the variant's pending AI threat-model draft against the saved model.

        A draft built on an older saved revision is rebased on read; when the
        same rows or fields changed on both sides it is reported as a conflict.

        OpenAPI:
        response 200 ContextDraft Pending draft and its status against the saved model.
        response 204 empty No pending draft for this variant.
        response 400 Error Invalid variant identifier.
        response 404 Error Variant not found.
        response 500 Error Rebased draft could not be stored.
        """
        variant_uuid, err = _variant_uuid_or_error(variant_id)
        if err:
            return err
        vc = VariantContext.get_by_variant(variant_uuid)
        if vc is None:
            return "", 204
        try:
            with context_draft.lock_for(vc.id):
                directory = _draft_dir(vc)
                draft = context_draft.read_draft(directory)
                revision = context_draft.revision(directory)
                if draft is None:
                    return "", 204
                db.session.refresh(vc)
                saved_at = _revision(vc)
                previous = draft.get("renumbered") or {}
                if draft.get("base_updated_at") == saved_at:
                    status = "rebased" if draft.get("rebased") else "current"
                    return jsonify(_draft_body(draft, status, draft["values"], [], previous, saved_at, revision))
                saved = context_draft.saved_values(vc)
                values, conflicts, moved = context_draft.rebase(draft["base_values"], saved, draft["values"])
                renumbered = {old: moved.get(current, current) for old, current in previous.items()}
                renumbered.update({old: new for old, new in moved.items() if old not in previous.values()})
                if not conflicts:
                    draft = {**draft, "base_updated_at": saved_at, "base_values": saved, "values": values,
                             "renumbered": renumbered, "rebased": True}
                    context_draft.write_draft(directory, draft, revision=revision)
                status = "conflict" if conflicts else "rebased"
                return jsonify(_draft_body(draft, status, values, conflicts, renumbered, saved_at, revision))
        except OSError:
            logger.exception("Failed to store the rebased AI context draft")
            return jsonify({"error": "Failed to store the rebased draft on server"}), 500

    @app.route('/api/variants/<variant_id>/context/draft', methods=['PUT'])
    def put_context_draft(variant_id):
        """Store an AI threat-model draft for review; the saved context is unchanged.

        OpenAPI:
        body ContextDraftUpdate required Draft values and the saved revision they were built on.
        response 200 ContextDraft Stored draft.
        response 400 Error Invalid identifier or draft values.
        response 404 Error Variant not found.
        response 409 Error The saved context changed since base_updated_at.
        response 409 Error The import source changed since import_revision.
        response 500 Error Draft could not be stored.
        """
        variant_uuid, err = _variant_uuid_or_error(variant_id)
        if err:
            return err
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({
                "error": "Request body must be a JSON object.", "fields": {"body": "must be an object"},
            }), 400
        source = body.get("source")
        if not isinstance(source, str) or not source.strip() or len(source) > 255:
            return jsonify({"error": "source must contain 1-255 characters.",
                            "fields": {"source": "must contain 1-255 characters"}}), 400
        if "import_revision" in body and (
                not isinstance(body["import_revision"], str) or not 1 <= len(body["import_revision"]) <= 128):
            return jsonify({"error": "import_revision must be the revision of the document read."}), 400
        try:
            values = context_draft.normalize_values(body.get("values"))
        except StrideValidationError as exc:
            return jsonify({"error": str(exc), "fields": exc.fields}), 400
        vc = VariantContext.get_by_variant(variant_uuid)
        if body.get("base_updated_at") != _revision(vc):
            return jsonify({"error": "The variant context changed since base_updated_at; read it again.",
                            "updated_at": _revision(vc)}), 409
        try:
            if vc is None:
                vc = VariantContext.get_or_create(variant_uuid)
            directory = _draft_dir(vc)
            with context_draft.lock_for(vc.id):
                db.session.refresh(vc)
                if body.get("base_updated_at") != _revision(vc):
                    return jsonify({"error": "The variant context changed since base_updated_at; read it again.",
                                    "updated_at": _revision(vc)}), 409
                if ("import_revision" in body
                        and body["import_revision"] != context_draft.import_revision(directory)):
                    return jsonify({"error": "The import source changed. Start a new import."}), 409
                previous = context_draft.read_draft(directory) or {}
                now = ensure_utc_iso(datetime.now(timezone.utc))
                draft = {
                    "source": source.strip(), "created_at": previous.get("created_at", now), "updated_at": now,
                    "base_updated_at": _revision(vc), "base_values": context_draft.saved_values(vc),
                    "values": values,
                }
                context_draft.write_draft(directory, draft)
                revision = context_draft.revision(directory)
        except (OSError, SQLAlchemyError):
            db.session.rollback()
            logger.exception("Failed to store the AI context draft")
            return jsonify({"error": "Failed to store the draft on server"}), 500
        return jsonify(_draft_body(draft, "current", values, [], {}, _revision(vc), revision))

    @app.route('/api/variants/<variant_id>/context/draft', methods=['DELETE'])
    def delete_context_draft(variant_id):
        """Discard the variant's AI draft and its import source.

        OpenAPI:
        body ContextDraftDelete required Revision of the reviewed draft or uploaded import.
        response 204 empty Draft and import source deleted (or there were none).
        response 400 Error Invalid variant identifier.
        response 404 Error Variant not found.
        response 409 Error A newer draft or import source replaced the reviewed version.
        response 500 Error Draft could not be deleted.
        """
        variant_uuid, err = _variant_uuid_or_error(variant_id)
        if err:
            return err
        body = request.get_json(silent=True)
        if (not isinstance(body, dict) or "revision" not in body
                or (body["revision"] is not None and not isinstance(body["revision"], str))):
            return jsonify({"error": "revision must be the reviewed revision, or null when none existed."}), 400
        vc = VariantContext.get_by_variant(variant_uuid)
        if vc is not None:
            try:
                with context_draft.lock_for(vc.id):
                    directory = _draft_dir(vc)
                    revision = context_draft.revision(directory)
                    if revision is not None and body["revision"] != revision:
                        return jsonify({
                            "error": "The AI draft or import source changed. Reload it before discarding.",
                        }), 409
                    context_draft.delete_draft(directory)
            except OSError:
                logger.exception("Failed to delete the AI context draft")
                return jsonify({"error": "Failed to delete the draft on server"}), 500
        return "", 204

    @app.route('/api/variants/<variant_id>/context/import-source', methods=['POST'])
    def post_import_source(variant_id):
        """Store the document the agent drafts a threat model from.

        It is temporary: it is not a codebase reference, replaces any previous
        import source and AI draft of the variant, and leaves the saved context
        (and its updated_at) unchanged.

        OpenAPI:
        body multipart required Document to import.
        form file binary required A text, Markdown, YAML/JSON or PDF document, or a ZIP/TAR archive of them (10 MB).
        response 201 ImportSource Stored import source.
        response 400 Error Invalid identifier, missing or unsafe file name, or unreadable document.
        response 404 Error Variant not found.
        response 413 Error Document or multipart request exceeds the upload size limit.
        response 500 Error File could not be stored.
        """
        variant_uuid, err = _variant_uuid_or_error(variant_id)
        if err:
            return err
        request_limit = MAX_FILE_BYTES + 64 * 1024
        if request.max_content_length is None or request.max_content_length > request_limit:
            request.max_content_length = request_limit
        try:
            file = request.files.get('file')
        except RequestEntityTooLarge:
            return jsonify({"error": "Document upload exceeds the request size limit."}), 413
        if file is None or not file.filename:
            return jsonify({"error": "No file provided"}), 400
        name = _import_name(file.filename)
        if name is None:
            return jsonify({"error": "Invalid file name."}), 400
        try:
            file.stream.seek(0, os.SEEK_END)
            size = file.stream.tell()
            file.stream.seek(0)
            if size > MAX_FILE_BYTES:
                return jsonify({"error": "Document exceeds the source size limit of 10 MB."}), 413
            validate_reference(file.stream, name)
            if not name.lower().endswith(ARCHIVE_SUFFIXES):
                with CodebaseReference(file.stream, name) as reference:
                    reference.text(name)
                file.stream.seek(0)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        try:
            vc = VariantContext.get_by_variant(variant_uuid) or VariantContext.get_or_create(variant_uuid)
            directory = _draft_dir(vc)
            with context_draft.lock_for(vc.id):
                context_draft.delete_draft(directory)
                folder = os.path.join(directory, context_draft.IMPORT_DIR)
                os.makedirs(folder, exist_ok=True)
                path = os.path.join(folder, name)
                file.save(path)
                size = os.path.getsize(path)
                revision = context_draft.revision(directory)
        except (OSError, SQLAlchemyError):
            db.session.rollback()
            logger.exception("Failed to store the import source")
            return jsonify({"error": "Failed to store file on server"}), 500
        return jsonify({"name": name, "size": size, "revision": revision}), 201

    @app.route('/api/variants/<variant_id>/context/import-source/source', methods=['GET'])
    def get_import_source(variant_id):
        """List, read or search the variant's import source.

        OpenAPI:
        query operation string optional list (default), read, or search.
        query revision string optional Import revision to read; rejects replacement documents.
        query path string optional Exact member path for read.
        query pattern string optional File-path glob for list or search (default *).
        query offset integer optional List offset (default 0).
        query limit integer optional List page size, 1-200 (default 200).
        query start_line integer optional First line for read (default 1).
        query max_lines integer optional Read line count, 1-200 (default 200).
        query query string optional Literal case-sensitive search text, required for search.
        query max_results integer optional Search limit, 1-100 (default 100).
        response 200 ImportSourceResult Files, line-numbered content (PDF pages marked), or search matches.
        response 400 Error Invalid parameters or unreadable document.
        response 404 Error Variant, import source, or member not found.
        response 409 Error The import source changed since revision.
        response 500 Error Stored import source is unavailable.
        """
        variant_uuid, err = _variant_uuid_or_error(variant_id)
        if err:
            return err
        vc = VariantContext.get_by_variant(variant_uuid)
        if vc is None:
            return jsonify({"error": "No import source uploaded."}), 404
        try:
            with context_draft.lock_for(vc.id):
                directory = _draft_dir(vc)
                revision = context_draft.import_revision(directory)
                if "revision" in request.args and request.args["revision"] != revision:
                    return jsonify({"error": "The import source changed. Start a new import."}), 409
                path = context_draft.import_source_path(directory)
                if path is None:
                    return jsonify({"error": "No import source uploaded."}), 404
                name = os.path.basename(path)
                body, status = _browse_reference(path, name, "import source")
        except OSError:
            logger.exception("Failed to read the import source")
            return jsonify({"error": "Stored import source is unavailable."}), 500
        if status != 200:
            return jsonify(body), status
        return jsonify({"name": name, "revision": revision, **body})

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
            # Created without paths, so the variant uses its references.
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

    @app.route('/api/variants/<variant_id>/context/shell', methods=['POST'])
    def run_codebase_shell(variant_id):
        """Run an isolated shell against a filtered snapshot of one approved host attachment."""
        if error := _access_error():
            return error
        variant_uuid, err = parse_uuid_or_400(variant_id, 'variant_id')
        if err:
            return err
        assert variant_uuid is not None
        if Variant.get_by_id(variant_uuid) is None:
            return jsonify(error="Variant not found"), 404
        limit = SHELL_REQUEST_BYTES
        if request.max_content_length is not None:
            limit = min(limit, request.max_content_length)
        # A terminated WSGI stream can lack Content-Length. Read one extra
        # byte to distinguish a full valid body from a truncated JSON prefix.
        request.max_content_length = limit + 1 if request.content_length is None else limit
        try:
            if len(request.get_data()) > limit:
                raise RequestEntityTooLarge()
        except RequestEntityTooLarge:
            return jsonify(error="Shell request exceeds the request size limit."), 413
        try:
            body = request.get_json(silent=True)
        except RecursionError:
            return jsonify(error="Invalid shell request."), 400
        if not isinstance(body, dict) or set(body) - {"file_id", "folder", "command"}:
            return jsonify(error="Invalid shell request."), 400
        file_id, folder, command = body.get("file_id"), body.get("folder", ""), body.get("command")
        if (not isinstance(file_id, str) or not isinstance(folder, str) or not isinstance(command, str)
                or not command or len(command) > 4096 or "\x00" in command or len(folder) > 1024):
            return jsonify(error="Invalid shell source, folder or command."), 400
        if file_id == "directory":
            return jsonify(error="Use directory browsing, read or search, or an approved host attachment "
                                 "(mount:<alias>) for shell inspection."), 409
        if not file_id.startswith(MOUNT_FILE_ID_PREFIX):
            return jsonify(error="Shell inspection requires an approved host attachment (mount:<alias>)."), 400
        try:
            alias = host_mounts.mount_alias(file_id)
            assert alias is not None
            mount = HostMount.get(variant_uuid, alias)
            if mount is None:
                return jsonify(error="Attached host folder not found."), 404
            host_mounts._activate(host_mounts._binding(mount))
            result = host_helper.call("shell", timeout=60, source="mount", variant_id=str(variant_uuid),
                                      alias=alias, mount_path=mount.host_path, folder=folder, command=command)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        except HostHelperUnavailable as exc:
            return jsonify(error=exc.message), 503
        except HostHelperError as exc:
            return jsonify(error=exc.message, code=exc.code), exc.http_status
        return jsonify({"file_id": file_id, "folder": folder, **result})

    @app.route('/api/variants/<variant_id>/context/files/<file_id>/source', methods=['GET'])
    def get_codebase_source(variant_id, file_id):
        """List or read an upload, the active directory (file_id=directory) or a host folder.

        Host folders attached to the variant use file_id=mount:<alias> and are served
        read-only by the host folder helper.

        OpenAPI:
        path file_id string required Upload UUID, directory for the active server directory, or mount:<alias>.
        query operation string optional List (default), read, search, children or search_file.
        query path string optional Exact member path for read or search_file.
        query position string optional Signed search match position for a bounded directory or mount context read.
        query query string optional Literal for search or search_file. search_file matches CVE IDs as whole tokens.
        query pattern string optional File-path glob for list or search (default *).
        query max_results integer optional Search match limit, 1-100 (default 100).
        query folder string optional Sub-folder for tree listings or legacy mount searches.
        query cursor string optional Opaque continuation for the same shallow listing or single-file search.
        query offset integer optional List offset (default 0).
        query limit integer optional List page size, 1-200 (default 200).
        query start_line integer optional First line for read (default 1).
        query max_lines integer optional Read line count, 1-200 (default 200).
        response 200 SourceReferenceResult Source files or line-numbered content.
        response 400 Error Invalid parameters or unreadable reference.
        response 404 Error Variant, reference, or source member not found.
        response 409 Error Directory name ownership conflicts or is ambiguous, or host folder unavailable.
        response 500 Error Stored reference is unavailable.
        response 503 Error Host folder helper is not running.
        response 504 Error Host folder helper response timed out; lookup incomplete.
        """
        variant_uuid, err = parse_uuid_or_400(variant_id, 'variant_id')
        if err:
            return err
        assert variant_uuid is not None
        if file_id.startswith(MOUNT_FILE_ID_PREFIX):
            if error := _access_error():
                return error
            if Variant.get_by_id(variant_uuid) is None:
                return jsonify(error="Variant not found"), 404
            body, status = _browse_mount(variant_uuid, file_id)
            return jsonify(body), status
        if file_id == "directory":
            if Variant.get_by_id(variant_uuid) is None:
                return jsonify(error="Variant not found"), 404
            vc, err = _directory_context(variant_uuid)
            if err:
                return err
            if vc is None or vc.codebase_directory is None:
                return jsonify(error=(
                    "No codebase directory found. Create its expected cache folder or use AI Context."
                )), 404
            body, status = _browse_reference(
                _get_cache_dir(), vc.codebase_directory, "codebase directory",
                directory_variant=variant_uuid,
            )
            return jsonify(body), status
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

        body, status = _browse_reference(cf.file_path, cf.original_name, "codebase reference")
        if status != 200:
            return jsonify(body), status
        return jsonify({"file_id": file_id, "original_name": cf.original_name, **body})

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

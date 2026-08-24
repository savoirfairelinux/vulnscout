# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import Flask, Response, copy_current_request_context, request, make_response, send_file
from flask.typing import ResponseReturnValue
import atexit
from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
import mimetypes
import re
import tempfile
import threading
import time
import traceback
import uuid
import zipfile
from datetime import date
from PIL import Image
from ..controllers import ControllersCache
from ..models.project import Project
from ..models.variant import Variant
from ..views.templates import Templates, find_asset
from ..views.cyclonedx import CycloneDx
from ..views.spdx import SPDX
from ..views.spdx3 import SPDX3
from ..views.openvex import OpenVex
from ..helpers.export_scope import ExportScope, compute_export_scope
from ._scan_helpers import parse_uuid_or_400
from typing import BinaryIO, Callable, cast, Dict, List, Optional


# You can associate specific files to specific categories
# "example.adoc": ["misc", "category_name"]
CategoriesDictionary: Dict[str, List[str]] = {}
ASCIIDOC_MIME = "text/asciidoc"
_export_jobs: Dict[str, Dict[str, object]] = {}
_export_jobs_lock = threading.Lock()
EXPORT_JOB_TTL_SECONDS = 3600
EXPORT_MAX_WORKERS = 2
EXPORT_MAX_QUEUED_JOBS = 4
EXPORT_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
EXPORT_MAX_RETAINED_ARCHIVE_BYTES = 512 * 1024 * 1024
_export_executor = ThreadPoolExecutor(max_workers=EXPORT_MAX_WORKERS, thread_name_prefix="document-export")
_export_capacity = threading.BoundedSemaphore(EXPORT_MAX_WORKERS + EXPORT_MAX_QUEUED_JOBS)
_sync_export_capacity = threading.BoundedSemaphore(EXPORT_MAX_WORKERS)


# Directories searched for user-provided templates, most-preferred first. This
# mirrors ``Templates.external_loader`` so an imported template is picked up by
# the renderer. The first writable location is used when importing.
TEMPLATE_UPLOAD_DIRS: List[str] = [
    "/cache/vulnscout/templates",
    ".vulnscout/templates",
    "templates",
    "/scan/templates",
]

# Extensions accepted when importing a custom report template.
ALLOWED_TEMPLATE_EXTENSIONS = {
    "adoc", "asciidoc", "html", "htm", "md", "markdown",
    "csv", "txt", "json", "xml", "tex", "j2", "jinja", "jinja2",
}


def sanitize_template_filename(filename: Optional[str]) -> Optional[str]:
    """Return a safe basename for an uploaded template, or ``None`` if invalid.

    Strips any directory components (guarding against path traversal) and only
    accepts a known set of template extensions.
    """
    name = os.path.basename((filename or "").strip())
    if not name or name.startswith(".") or ".." in name:
        return None
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_TEMPLATE_EXTENSIONS:
        return None
    return name


def writable_templates_dir() -> Optional[str]:
    """Return the first templates directory that can be created and written to."""
    for candidate in TEMPLATE_UPLOAD_DIRS:
        try:
            os.makedirs(candidate, exist_ok=True)
        except OSError:
            continue
        if os.access(candidate, os.W_OK):
            return candidate
    return None


def writable_assets_dir() -> Optional[str]:
    """Return the first ``<templates>/assets`` directory that is writable."""
    for candidate in TEMPLATE_UPLOAD_DIRS:
        assets_candidate = os.path.join(candidate, "assets")
        try:
            os.makedirs(assets_candidate, exist_ok=True)
        except OSError:
            continue
        if os.access(assets_candidate, os.W_OK):
            return assets_candidate
    return None


def list_assets() -> List[Dict[str, object]]:
    """Return the image assets found in template asset directories.

    Directories follow the same preference order as template loading. An asset
    with the same name in a higher-priority directory is listed only once.
    """
    assets: List[Dict[str, object]] = []
    seen_names = set()
    for candidate in TEMPLATE_UPLOAD_DIRS:
        assets_dir = os.path.join(candidate, "assets")
        try:
            names = os.listdir(assets_dir)
        except OSError:
            continue
        for name in sorted(names):
            path = os.path.join(assets_dir, name)
            extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if (
                name in seen_names
                or extension not in UPLOADABLE_ASSET_EXTENSIONS
                or not os.path.isfile(path)
            ):
                continue
            seen_names.add(name)
            assets.append({"id": name, "extension": extension, "is_template": False, "category": ["assets"]})
    return assets


# Maximum size accepted for an uploaded report image asset. Flask's
# MAX_CONTENT_LENGTH rejects oversized multipart bodies before parsing; the
# bounded stream read below is a secondary guard for this per-file limit.
MAX_ASSET_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MiB

# Raster formats accepted for *uploads*, mapped to the format name Pillow
# reports back after decoding. SVG is deliberately excluded here: as XML it
# can carry <script>, external entity references and other active content
# that a filename-extension or even a well-formedness check would not catch.
# (Manually placed SVG assets outside this upload endpoint are unaffected —
# see ALLOWED_ASSET_EXTENSIONS in views.templates.)
_UPLOAD_RASTER_FORMATS: Dict[str, str] = {
    "png": "PNG",
    "jpg": "JPEG",
    "jpeg": "JPEG",
    "gif": "GIF",
    "webp": "WEBP",
}
UPLOADABLE_ASSET_EXTENSIONS = frozenset(_UPLOAD_RASTER_FORMATS)


def sanitize_asset_filename(filename: Optional[str]) -> Optional[str]:
    """Return a safe basename for an uploaded asset, or ``None`` if invalid.

    Only a plain filename with an allowed raster-image extension is accepted.
    Any directory component or path-traversal sequence is rejected.
    """
    name = os.path.basename((filename or "").strip())
    if not name or name.startswith(".") or ".." in name:
        return None
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in UPLOADABLE_ASSET_EXTENSIONS:
        return None
    return name


def validate_raster_image(data: bytes, ext: str) -> bool:
    """Decode *data* and confirm it is a genuine raster image matching *ext*.

    Trusting a file's declared extension alone lets an attacker persist
    arbitrary content (or an oversized decompression-bomb-style payload) that
    is then handed to downstream image/PDF converters. Decoding the pixel
    data with Pillow's ``verify()`` and cross-checking the detected format
    against the declared extension ensures only well-formed images of the
    expected type are accepted.
    """
    expected_format = _UPLOAD_RASTER_FORMATS.get(ext)
    if expected_format is None:
        return False
    try:
        with Image.open(io.BytesIO(data)) as probe:
            probe.verify()
        # verify() leaves the file object unusable for further access, so a
        # fresh handle is needed to read back the detected format safely.
        with Image.open(io.BytesIO(data)) as probe:
            probe.load()
            return probe.format == expected_format
    except Exception:
        return False


def guess_mime_type(doc_name: Optional[str]) -> Optional[str]:
    if doc_name is None:
        return None
    if "." not in doc_name:
        doc_name = f"some.{doc_name}"
    guess = mimetypes.guess_type(doc_name)[0]
    if guess is not None:
        return guess
    if doc_name.endswith((".adoc", ".asciidoc")):
        return ASCIIDOC_MIME
    return "application/octet-stream"


def _download_filename(response: Response, fallback: str) -> str:
    disposition = response.headers.get("Content-Disposition", "")
    match = re.search(r'filename="?([^";]+)', disposition)
    return os.path.basename(match.group(1)) if match else fallback


def _safe_archive_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return safe or "export"


def _normalize_document(doc: Dict[str, object]) -> None:
    doc_id = str(doc["id"])
    if "extension" not in doc:
        doc["extension"] = doc_id.rsplit(".", 1)[-1] if "." in doc_id else "bin"
        if doc["extension"] in ["adoc", "asciidoc"]:
            doc["extension"] = "adoc | pdf | html"

    categories = doc.setdefault("category", [])
    if not isinstance(categories, list):
        return
    for category in CategoriesDictionary.get(doc_id, []):
        if category not in categories:
            categories.append(category)


def _list_documents() -> List[Dict[str, object]]:
    controllers = ControllersCache()
    controllers.vulnerabilities = None  # type: ignore
    docs = Templates(controllers).list_documents()
    docs.extend([
        {"id": "SPDX 2.3", "extension": "json | xml", "is_template": False, "category": ["sbom"]},
        {"id": "SPDX 3.0", "extension": "json", "is_template": False, "category": ["sbom"]},
        {"id": "CycloneDX 1.4", "extension": "json", "is_template": False, "category": ["sbom"]},
        {"id": "CycloneDX 1.5", "extension": "json", "is_template": False, "category": ["sbom"]},
        {"id": "CycloneDX 1.6", "extension": "json", "is_template": False, "category": ["sbom"]},
        {"id": "OpenVex", "extension": "json", "is_template": False, "category": ["sbom"]},
    ])
    docs.extend(list_assets())

    for doc in docs:
        _normalize_document(doc)
    return docs


def _export_metadata(app: Flask) -> Dict[str, str | float]:
    metadata: Dict[str, str | float] = {
        "author": request.args.get("author") or os.getenv('AUTHOR_NAME', 'Savoir-faire Linux') or '',
        "client_name": request.args.get("client_name") or os.getenv('CLIENT_NAME', "") or '',
        "export_date": request.args.get("export_date") or date.today().isoformat(),
        "ignore_before": request.args.get("ignore_before") or "1970-01-01T00:00",
        "only_epss_greater": 0.0,
        "scan_date": app.config["SCAN_DATE"] or "unknown date",
    }
    try:
        metadata["only_epss_greater"] = float(request.args.get("only_epss_greater") or "0.0")
    except ValueError:
        pass
    return metadata


def _render_template_document(
    doc_name: str,
    base_mime: str,
    expected_mime: str,
    templ: Templates,
    metadata: Dict[str, str | float],
) -> Response:
    content = templ.render(doc_name, **metadata)
    if base_mime == expected_mime:
        response = make_response(content)
        response.headers["Content-Type"] = base_mime
        response.headers["Content-Disposition"] = f"attachment; filename={doc_name}"
        return response
    if base_mime == ASCIIDOC_MIME and expected_mime == "application/pdf":
        response = make_response(templ.adoc_to_pdf(content))
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f"attachment; filename={doc_name}.pdf"
        return response
    if base_mime == ASCIIDOC_MIME and expected_mime == "text/html":
        response = make_response(templ.adoc_to_html(content))
        response.headers["Content-Type"] = "text/html"
        response.headers["Content-Disposition"] = f"attachment; filename={doc_name}.html"
        return response
    return make_response({"error": f"Cannot convert {base_mime} to {expected_mime}"}, 400)


def _render_document(
    app: Flask,
    doc_name: str,
    extension: Optional[str],
    scope: ExportScope | None,
) -> Response:
    base_mime = guess_mime_type(doc_name)
    if base_mime is None:
        return make_response({"error": "Unsupported document type"}, 400)
    expected_mime = guess_mime_type(extension) or base_mime

    asset_path = find_asset(doc_name)
    if asset_path is not None:
        return send_file(
            asset_path,
            mimetype=base_mime,
            as_attachment=True,
            download_name=doc_name,
        )

    metadata = _export_metadata(app)
    ctrls = ControllersCache(scope=scope)
    ctrls.packages._preload_cache()

    if (
        doc_name.startswith("CycloneDX ")
        or doc_name == "OpenVex"
        or doc_name.startswith("SPDX")
    ):
        return make_response(handle_sbom_exports(doc_name, ctrls, expected_mime, metadata))
    return _render_template_document(doc_name, base_mime, expected_mime, Templates(ctrls), metadata)


def _select_project_variants(
    project_uuid: uuid.UUID,
    raw_variant_ids: object,
) -> tuple[list[Variant] | None, ResponseReturnValue | None]:
    project_variants = Variant.get_by_project(project_uuid)
    if not project_variants:
        return None, ({"error": "The selected project has no variants"}, 400)
    if raw_variant_ids is None:
        return project_variants, None
    if not isinstance(raw_variant_ids, list) or not raw_variant_ids:
        return None, ({"error": "variant_ids must contain at least one variant"}, 400)

    selected_variant_ids = set()
    for raw_variant_id in raw_variant_ids:
        if not isinstance(raw_variant_id, str):
            return None, ({"error": "variant_ids must contain UUID strings"}, 400)
        selected_variant_id, err = parse_uuid_or_400(raw_variant_id, "variant_ids")
        if err is not None:
            return None, err
        selected_variant_ids.add(selected_variant_id)
    if not selected_variant_ids.issubset({variant.id for variant in project_variants}):
        return None, ({"error": "Every selected variant must belong to the selected project"}, 400)
    return [variant for variant in project_variants if variant.id in selected_variant_ids], None


def _document_selection_catalog() -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    allowed: set[tuple[str, str]] = set()
    sbom_selections: set[tuple[str, str]] = set()
    for doc in _list_documents():
        categories = doc.get("category")
        if isinstance(categories, list) and "assets" in categories:
            continue
        document_selections = {
            (str(doc["id"]), extension.strip())
            for extension in str(doc["extension"]).split("|")
        }
        allowed.update(document_selections)
        if isinstance(categories, list) and "sbom" in categories:
            sbom_selections.update(document_selections)
    return allowed, sbom_selections


def _parse_document_selection(
    item: object,
    allowed: set[tuple[str, str]],
) -> tuple[tuple[str, str] | None, ResponseReturnValue | None]:
    if not isinstance(item, dict):
        return None, ({"error": "Each document selection must be an object"}, 400)
    name = item.get("name")
    extension = item.get("extension")
    if not isinstance(name, str) or not name or not isinstance(extension, str) or not extension:
        return None, ({"error": "Each document requires a name and extension"}, 400)
    if (name, extension) not in allowed:
        return None, ({"error": f"Unsupported document selection: {name} ({extension})"}, 400)
    return (name, extension), None


def _validate_document_selections(
    requested_docs: object,
    mode: object,
) -> tuple[list[tuple[str, str]] | None, ResponseReturnValue | None]:
    if not isinstance(requested_docs, list) or not requested_docs or len(requested_docs) > 100:
        return None, ({"error": "documents must contain between 1 and 100 selections"}, 400)

    allowed, sbom_selections = _document_selection_catalog()
    selections: list[tuple[str, str]] = []
    for item in requested_docs:
        selection, selection_error = _parse_document_selection(item, allowed)
        if selection_error is not None:
            return None, selection_error
        assert selection is not None
        selections.append(selection)

    selected_sboms = [selection for selection in selections if selection in sbom_selections]
    if selected_sboms and len(selected_sboms) != len(selections):
        return None, ({"error": "Reports and SBOM files must be exported separately"}, 400)
    if selected_sboms and mode != "per_variant":
        return None, ({"error": "SBOM files must be exported per variant as a ZIP archive"}, 400)
    return selections, None


class ExportGenerationError(Exception):
    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class _SizeLimitedArchive:
    def __init__(self, output: BinaryIO, max_bytes: int) -> None:
        self.output = output
        self.max_bytes = max_bytes
        self.size = 0

    def write(self, data: bytes) -> int:
        end = self.tell() + len(data)
        self.size = max(self.size, end)
        if self.size > self.max_bytes:
            raise ExportGenerationError("Export archive exceeds the maximum allowed size", 413)
        return self.output.write(data)

    def tell(self) -> int:
        return self.output.tell()

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return self.output.seek(offset, whence)

    def flush(self) -> None:
        self.output.flush()


def _delete_archive(job: Dict[str, object]) -> None:
    archive_path = job.get("archive_path")
    if isinstance(archive_path, str):
        try:
            os.remove(archive_path)
        except FileNotFoundError:
            pass


def _prune_export_jobs() -> None:
    cutoff = time.monotonic() - EXPORT_JOB_TTL_SECONDS
    expired = []
    for job_id, job in _export_jobs.items():
        finished_at = job.get("finished_at")
        if isinstance(finished_at, float) and finished_at < cutoff:
            expired.append(job_id)
    for job_id in expired:
        _delete_archive(_export_jobs.pop(job_id))


def _reserve_retained_archive(archive_bytes: int) -> None:
    retained = [
        (job_id, job) for job_id, job in _export_jobs.items()
        if isinstance(job.get("archive_path"), str)
    ]

    def finished_at(item: tuple[str, Dict[str, object]]) -> float:
        value = item[1].get("finished_at")
        return value if isinstance(value, float) else 0.0

    retained.sort(key=finished_at)
    retained_bytes = sum(
        os.path.getsize(str(job["archive_path"]))
        for _, job in retained
        if os.path.isfile(str(job["archive_path"]))
    )
    for job_id, job in retained:
        if retained_bytes + archive_bytes <= EXPORT_MAX_RETAINED_ARCHIVE_BYTES:
            break
        path = str(job["archive_path"])
        if os.path.isfile(path):
            retained_bytes -= os.path.getsize(path)
        _delete_archive(_export_jobs.pop(job_id))


def _unique_archive_path(path: str, used_paths: set[str]) -> str:
    candidate = path
    stem, extension = os.path.splitext(path)
    index = 2
    while candidate in used_paths:
        candidate = f"{stem}_{index}{extension}"
        index += 1
    used_paths.add(candidate)
    return candidate


def _cleanup_export_archives() -> None:
    with _export_jobs_lock:
        for job in _export_jobs.values():
            _delete_archive(job)


atexit.register(_cleanup_export_archives)


def _build_export_archive(
    app: Flask,
    scopes: list[tuple[Variant | None, ExportScope | None]],
    selections: list[tuple[str, str]],
    archive: BinaryIO,
    progress: Callable[[int, int, str], None] | None = None,
) -> None:
    total = len(scopes) * len(selections)
    current = 0
    used_paths: set[str] = set()
    limited_archive = _SizeLimitedArchive(archive, EXPORT_MAX_ARCHIVE_BYTES)
    with zipfile.ZipFile(cast(BinaryIO, limited_archive), "w", compression=zipfile.ZIP_DEFLATED) as output:
        for variant, scope in scopes:
            for doc_name, extension in selections:
                current += 1
                element_name = (
                    f"{variant.name}: {doc_name} ({extension})"
                    if variant is not None
                    else f"{doc_name} ({extension})"
                )
                if progress is not None:
                    progress(current, total, element_name)
                rendered = _render_document(app, doc_name, extension, scope)
                if rendered.status_code >= 400:
                    message = rendered.get_json(silent=True) or {}
                    raise ExportGenerationError(
                        message.get("error", f"Failed to export {doc_name}"),
                        rendered.status_code,
                    )
                fallback = f"{_safe_archive_name(doc_name)}.{_safe_archive_name(extension)}"
                filename = _download_filename(rendered, fallback)
                if variant is not None:
                    filename = f"{_safe_archive_name(variant.name)}/{filename}"
                filename = _unique_archive_path(filename, used_paths)
                output.writestr(filename, rendered.get_data())


def init_app(app: Flask) -> None:

    @app.route('/api/documents', methods=['GET'])
    def index_docs() -> ResponseReturnValue:
        """List available report templates and SBOM export formats.

        OpenAPI:
        response 200 JsonObject Available document descriptors.
        response 500 Error Document discovery failed.
        """
        try:
            return _list_documents()
        except Exception as e:
            print(e)
            return {"error": str(e)}, 500

    @app.route('/api/documents/templates', methods=['POST'])
    def upload_template() -> ResponseReturnValue:
        """Import a custom report template uploaded from the Export tab.

        Expects a ``multipart/form-data`` request with a single ``file`` field.
        The template is saved under the first writable templates directory so it
        becomes available as a "custom" report.

        OpenAPI:
        body multipart optional Multipart request containing a template file.
        response 201 JsonObject Imported template descriptor.
        response 400 Error Invalid upload request.
        response 500 Error Template storage failed.
        """
        if not (request.content_type and 'multipart/form-data' in request.content_type):
            return {"error": "Expected multipart/form-data with a file upload."}, 400

        uploaded = request.files.get('file')
        if uploaded is None or not uploaded.filename:
            return {"error": "No file uploaded."}, 400

        safe_name = sanitize_template_filename(uploaded.filename)
        if safe_name is None:
            allowed = ", ".join(sorted(ALLOWED_TEMPLATE_EXTENSIONS))
            return {"error": f"Unsupported template file. Allowed extensions: {allowed}."}, 400

        target_dir = writable_templates_dir()
        if target_dir is None:
            return {"error": "No writable templates directory available on the server."}, 500

        try:
            uploaded.save(os.path.join(target_dir, safe_name))
        except OSError as e:
            print(e, flush=True)
            return {"error": f"Failed to save template: {e}"}, 500

        return {"id": safe_name, "category": ["custom"], "message": "Template imported."}, 201

    @app.route('/api/documents/assets', methods=['POST'])
    def upload_asset() -> ResponseReturnValue:
        """Upload an image asset for use in report templates.

        Expects a ``multipart/form-data`` request with a single ``file`` field.
        Accepted extensions: png, jpg, jpeg, gif, webp (SVG is not accepted
        through this endpoint, see :data:`UPLOADABLE_ASSET_EXTENSIONS`).

        The upload is capped at :data:`MAX_ASSET_UPLOAD_BYTES` and the decoded
        content must be a genuine raster image matching the declared
        extension (see :func:`validate_raster_image`) before it is persisted.

        The file is saved into the first writable
        ``<templates_dir>/assets/`` directory so :func:`~src.views.templates.find_asset`
        and :func:`~src.views.templates.embed_image` can locate it at render time.
        """
        if not (request.content_type and 'multipart/form-data' in request.content_type):
            return {"error": "Expected multipart/form-data with a file upload."}, 400

        uploaded = request.files.get('file')
        if uploaded is None or not uploaded.filename:
            return {"error": "No file uploaded."}, 400

        safe_name = sanitize_asset_filename(uploaded.filename)
        if safe_name is None:
            allowed = ", ".join(sorted(UPLOADABLE_ASSET_EXTENSIONS))
            return {"error": f"Unsupported image file. Allowed extensions: {allowed}."}, 400

        # MAX_CONTENT_LENGTH bounds multipart parsing and temporary storage.
        # Keep a per-file bound as a secondary guard for this endpoint.
        data = uploaded.stream.read(MAX_ASSET_UPLOAD_BYTES + 1)
        if len(data) > MAX_ASSET_UPLOAD_BYTES:
            max_mib = MAX_ASSET_UPLOAD_BYTES // (1024 * 1024)
            return {"error": f"Image exceeds the maximum allowed size of {max_mib} MiB."}, 413

        ext = safe_name.rsplit(".", 1)[-1].lower()
        if not validate_raster_image(data, ext):
            return {"error": "Uploaded file is not a valid image matching its extension."}, 400

        target_dir = writable_assets_dir()
        if target_dir is None:
            return {"error": "No writable assets directory available on the server."}, 500

        try:
            with open(os.path.join(target_dir, safe_name), "wb") as f:
                f.write(data)
        except OSError as e:
            print(e, flush=True)
            return {"error": f"Failed to save asset: {e}"}, 500

        return {"name": safe_name, "message": "Asset uploaded."}, 201

    @app.route('/api/documents/export', methods=['POST'])
    def export_documents() -> ResponseReturnValue:
        """Render selected documents for every variant of one project."""
        body = request.get_json(silent=True) or {}
        raw_project_id = body.get("project_id")
        if not isinstance(raw_project_id, str):
            return {"error": "project_id is required"}, 400
        project_uuid, err = parse_uuid_or_400(raw_project_id, "project_id")
        if err is not None:
            return err
        assert project_uuid is not None
        project = Project.get_by_id(project_uuid)
        if project is None:
            return {"error": "Project not found"}, 404

        mode = body.get("mode")
        if mode not in {"consolidated", "per_variant"}:
            return {"error": "mode must be 'consolidated' or 'per_variant'"}, 400

        selections, document_error = _validate_document_selections(body.get("documents"), mode)
        if document_error is not None:
            return document_error
        assert selections is not None

        variants, selection_error = _select_project_variants(project_uuid, body.get("variant_ids"))
        if selection_error is not None:
            return selection_error
        assert variants is not None

        scopes: list[tuple[Variant | None, ExportScope | None]] = (
            [(None, compute_export_scope(variant_ids=[variant.id for variant in variants]))]
            if mode == "consolidated"
            else [(variant, compute_export_scope(variant_id=variant.id)) for variant in variants]
        )
        project_name = _safe_archive_name(project.name)
        suffix = "consolidated" if mode == "consolidated" else "by_variant"
        filename = f"{project_name}_{suffix}_export.zip"

        if body.get("async") is True:
            if not _export_capacity.acquire(blocking=False):
                response = make_response({"error": "Export queue is full; retry later"}, 503)
                response.headers["Retry-After"] = "5"
                return response

            job_id = str(uuid.uuid4())
            with _export_jobs_lock:
                _prune_export_jobs()
                _export_jobs[job_id] = {
                    "status": "running",
                    "current": 0,
                    "total": len(scopes) * len(selections),
                    "progress": "Queued",
                    "logs": [],
                    "error": None,
                    "filename": filename,
                }

            @copy_current_request_context
            def generate_archive() -> None:
                def update_progress(current: int, total: int, element_name: str) -> None:
                    message = f"Generating {current} of {total} element: {element_name}"
                    with _export_jobs_lock:
                        job = _export_jobs[job_id]
                        job.update({"current": current, "total": total, "progress": message})
                        logs = job["logs"]
                        assert isinstance(logs, list)
                        logs.append(message)

                archive_path: str | None = None
                try:
                    with tempfile.NamedTemporaryFile(
                        prefix="vulnscout_export_", suffix=".zip", delete=False
                    ) as archive:
                        archive_path = archive.name
                        _build_export_archive(app, scopes, selections, cast(BinaryIO, archive), update_progress)
                    with _export_jobs_lock:
                        _prune_export_jobs()
                        _reserve_retained_archive(os.path.getsize(archive_path))
                        _export_jobs[job_id].update({
                            "status": "done",
                            "progress": "Export ready",
                            "archive_path": archive_path,
                            "finished_at": time.monotonic(),
                        })
                    archive_path = None
                except (ExportGenerationError, FileNotFoundError) as exc:
                    message = str(exc)
                    if isinstance(exc, FileNotFoundError):
                        message = "Required conversion tool was not found"
                    with _export_jobs_lock:
                        _export_jobs[job_id].update({
                            "status": "error",
                            "error": message,
                            "progress": "Export failed",
                            "finished_at": time.monotonic(),
                        })
                except Exception:
                    app.logger.exception("Export job %s failed", job_id)
                    with _export_jobs_lock:
                        _export_jobs[job_id].update({
                            "status": "error",
                            "error": "Export generation failed",
                            "progress": "Export failed",
                            "finished_at": time.monotonic(),
                        })
                finally:
                    if archive_path is not None:
                        _delete_archive({"archive_path": archive_path})

            try:
                future = _export_executor.submit(generate_archive)
            except RuntimeError:
                with _export_jobs_lock:
                    del _export_jobs[job_id]
                _export_capacity.release()
                return {"error": "Export service is unavailable"}, 503
            future.add_done_callback(lambda _future: _export_capacity.release())
            return {"job_id": job_id}, 202

        if not _sync_export_capacity.acquire(blocking=False):
            response = make_response({"error": "Export service is busy; retry later"}, 503)
            response.headers["Retry-After"] = "5"
            return response
        try:
            try:
                archive = tempfile.SpooledTemporaryFile(max_size=10 * 1024 * 1024)
                _build_export_archive(app, scopes, selections, cast(BinaryIO, archive))
            except ExportGenerationError as exc:
                return {"error": str(exc)}, exc.status_code
            except FileNotFoundError:
                return {"error": "Required conversion tool was not found"}, 503
        finally:
            _sync_export_capacity.release()

        archive.seek(0)
        return send_file(
            cast(BinaryIO, archive),
            mimetype="application/zip",
            as_attachment=True,
            download_name=filename,
        )

    @app.route('/api/documents/export/<job_id>', methods=['GET'])
    def export_status(job_id: str) -> ResponseReturnValue:
        with _export_jobs_lock:
            _prune_export_jobs()
            job = _export_jobs.get(job_id)
            if job is None:
                return {"error": "Export job not found"}, 404
            return {key: value for key, value in job.items() if key not in {"archive", "filename", "finished_at"}}

    @app.route('/api/documents/export/<job_id>/download', methods=['GET'])
    def download_export(job_id: str) -> ResponseReturnValue:
        with _export_jobs_lock:
            _prune_export_jobs()
            job = _export_jobs.get(job_id)
            if job is None:
                return {"error": "Export job not found"}, 404
            if job["status"] != "done" or "archive_path" not in job:
                return {"error": "Export is not ready"}, 409
            archive_path = job["archive_path"]
            if not isinstance(archive_path, str):
                return {"error": "Export archive is invalid"}, 500
            try:
                archive = open(archive_path, "rb")
            except FileNotFoundError:
                _delete_archive(_export_jobs.pop(job_id))
                return {"error": "Export archive is no longer available"}, 410
            filename = str(_export_jobs.pop(job_id)["filename"])
            os.remove(archive_path)
        return send_file(archive, mimetype="application/zip", as_attachment=True, download_name=filename)

    @app.route('/api/documents/<doc_name>', methods=['GET'])
    def doc_by_name(doc_name: str) -> ResponseReturnValue:
        """Render or export a document template or SBOM format.

        OpenAPI:
        query ext string optional Output extension or conversion target.
        query author string optional Author metadata injected into the document.
        query client_name string optional Client metadata injected into the document.
        query export_date string optional Export date override.
        query ignore_before string optional Lower bound for historical data inclusion.
        query only_epss_greater number optional Minimum EPSS threshold to include.
        query variant_id uuid optional Restrict export to a single variant.
        query project_id uuid optional Restrict export to a single project.
        response 200 JsonObject Exported document payload or download response.
        response 400 Error Invalid export request.
        response 503 Error Required conversion tool not available.
        """
        try:
            # Resolve the optional project/variant scope from the "Project &
            # Variant" selection. It applies to BOTH SBOM/VEX exports and
            # reports (templates) so that every document only contains the
            # in-scope data. variant_id takes precedence; project_id alone
            # means "All variants" of that project. No selection => global.
            variant_id = request.args.get("variant_id")
            project_id = request.args.get("project_id")
            scope = None
            if variant_id:
                variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
                if err is not None:
                    return err
                scope = compute_export_scope(variant_id=variant_uuid)
            elif project_id:
                project_uuid, err = parse_uuid_or_400(project_id, "project_id")
                if err is not None:
                    return err
                scope = compute_export_scope(project_id=project_uuid)
            return _render_document(app, doc_name, request.args.get("ext"), scope)
        except FileNotFoundError as e:
            print(e, flush=True)
            return {"error": f"Required conversion tool not found: {e.filename}"}, 503
        except Exception as e:
            print(e, traceback.format_exc(), flush=True)
            return {"error": str(e)}, 500


def handle_sbom_exports(
    doc_name: str,
    ctrls: ControllersCache,
    expected_mime: Optional[str],
    metadata: Dict[str, str | float],
) -> ResponseReturnValue:
    author = str(metadata["author"])
    if doc_name.startswith("CycloneDX"):
        cdx = CycloneDx(ctrls)
        if expected_mime == "application/json":
            content = None
            if doc_name == "CycloneDX 1.4":
                content = cdx.output_as_json(4, metadata["author"])
            if doc_name == "CycloneDX 1.5":
                content = cdx.output_as_json(5, author)
            if doc_name == "CycloneDX 1.6":
                content = cdx.output_as_json(6, author)

            if content is not None:
                new_name = doc_name.lower().replace(' ', '_v').replace('.', '_')
                return content, 200, {
                    "Content-Type": expected_mime,
                    "Content-Disposition": f"attachment; filename={new_name}.json"
                }

    if doc_name.startswith("SPDX"):
        if doc_name == "SPDX 2.3":
            spdx = SPDX(ctrls)
            if expected_mime == "application/json":
                content = spdx.output_as_json(author)
                if content is not None:
                    new_name = doc_name.lower().replace(' ', '_v').replace('.', '_')
                    return content, 200, {
                        "Content-Type": expected_mime,
                        "Content-Disposition": f"attachment; filename={new_name}.json"
                    }
            if expected_mime in {"application/xml", "text/xml"}:
                content = spdx.output_as_xml(author)
                if content is not None:
                    new_name = doc_name.lower().replace(' ', '_v').replace('.', '_')
                    return content, 200, {
                        "Content-Type": expected_mime,
                        "Content-Disposition": f"attachment; filename={new_name}.xml"
                    }
        elif doc_name == "SPDX 3.0":
            spdx3 = SPDX3(ctrls)
            if expected_mime == "application/json":
                content = spdx3.output_as_json(author)
                if content is not None:
                    new_name = doc_name.lower().replace(' ', '_v').replace('.', '_')
                    return content, 200, {
                        "Content-Type": expected_mime,
                        "Content-Disposition": f"attachment; filename={new_name}.json"
                    }

    if doc_name == "OpenVex" and expected_mime == "application/json":
        opvx = OpenVex(ctrls)
        return json.dumps(opvx.to_dict(True, author), indent=2), 200, {
            "Content-Type": expected_mime,
            "Content-Disposition": "attachment; filename=openvex.json"
        }

    return {"error": f"Cannot export {doc_name} to {expected_mime}"}, 400

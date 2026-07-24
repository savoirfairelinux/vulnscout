# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import Flask, request, make_response, send_file
from flask.typing import ResponseReturnValue
import io
import json
import os
import mimetypes
import traceback
from datetime import date
from PIL import Image
from ..controllers import ControllersCache
from ..views.templates import Templates, find_asset
from ..views.cyclonedx import CycloneDx
from ..views.spdx import SPDX
from ..views.spdx3 import SPDX3
from ..views.openvex import OpenVex
from ..helpers.export_scope import compute_export_scope
from ._scan_helpers import parse_uuid_or_400
from typing import Dict, List, Optional


# You can associate specific files to specific categories
# "example.adoc": ["misc", "category_name"]
CategoriesDictionary: Dict[str, List[str]] = {}


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
    if doc_name.endswith(".adoc") or doc_name.endswith(".asciidoc"):
        return "text/asciidoc"
    return "application/octet-stream"


def init_app(app: Flask) -> None:

    @app.route('/api/documents', methods=['GET'])
    def index_docs() -> ResponseReturnValue:
        """List available report templates and SBOM export formats.

        OpenAPI:
        response 200 JsonObject Available document descriptors.
        response 500 Error Document discovery failed.
        """
        controllers = ControllersCache()
        controllers.vulnerabilities = None  # type: ignore
        # to avoid pre-loading cache, TODO change that, maybe by moving list_documents somewhere else
        templ = Templates(controllers)
        try:
            docs = templ.list_documents()

            docs.append({"id": "SPDX 2.3", "extension": "json | xml", "is_template": False, "category": ["sbom"]})
            docs.append({"id": "SPDX 3.0", "extension": "json", "is_template": False, "category": ["sbom"]})
            docs.append({"id": "CycloneDX 1.4", "extension": "json", "is_template": False, "category": ["sbom"]})
            docs.append({"id": "CycloneDX 1.5", "extension": "json", "is_template": False, "category": ["sbom"]})
            docs.append({"id": "CycloneDX 1.6", "extension": "json", "is_template": False, "category": ["sbom"]})
            docs.append({"id": "OpenVex", "extension": "json", "is_template": False, "category": ["sbom"]})
            docs.extend(list_assets())

            for doc in docs:
                if "extension" not in doc:
                    if "." in doc["id"]:
                        doc["extension"] = doc["id"].split(".")[-1]
                    else:
                        doc["extension"] = "bin"
                    if doc["extension"] in ["adoc", "asciidoc"]:
                        doc["extension"] = "adoc | pdf | html"

                    if doc["id"] in CategoriesDictionary:
                        for cat in CategoriesDictionary[doc["id"]]:
                            if cat not in doc["category"]:
                                doc["category"].append(cat)

            return docs
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
            base_mime = guess_mime_type(doc_name)
            if base_mime is None:
                return {"error": "Unsupported document type"}, 400
            expected_mime = guess_mime_type(request.args.get("ext")) or base_mime

            asset_path = find_asset(doc_name)
            if asset_path is not None:
                return send_file(
                    asset_path,
                    mimetype=base_mime,
                    as_attachment=True,
                    download_name=doc_name,
                )

            metadata: Dict[str, str | float] = {
                "author": request.args.get("author") or os.getenv('AUTHOR_NAME', 'Savoir-faire Linux') or '',
                "client_name": request.args.get("client_name") or os.getenv('CLIENT_NAME', "") or '',
                "export_date": request.args.get("export_date") or date.today().isoformat(),
                "ignore_before": request.args.get("ignore_before") or "1970-01-01T00:00",
                "only_epss_greater": 0.0,
                "scan_date": app.config["SCAN_DATE"] or "unknown date"  # don't use actual datetime by default.
            }
            try:
                metadata["only_epss_greater"] = float(request.args.get("only_epss_greater") or "0.0")
            except ValueError:
                pass

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

            ctrls = ControllersCache(scope=scope)
            ctrls.packages._preload_cache()

            if (
                doc_name.startswith("CycloneDX ")
                or doc_name == "OpenVex"
                or doc_name.startswith("SPDX")
            ):
                return handle_sbom_exports(doc_name, ctrls, expected_mime, metadata)

            templ = Templates(ctrls)
            content = templ.render(doc_name, **metadata)

            if base_mime == expected_mime:
                return content, 200, {
                    "Content-Type": base_mime,
                    "Content-Disposition": f"attachment; filename={doc_name}"
                }

            if base_mime == "text/asciidoc" and expected_mime == "application/pdf":
                resp = make_response(templ.adoc_to_pdf(content))
                resp.headers["Content-Type"] = "application/pdf"
                resp.headers["Content-Disposition"] = f"attachment; filename={doc_name}.pdf"
                return resp

            if base_mime == "text/asciidoc" and expected_mime == "text/html":
                resp = make_response(templ.adoc_to_html(content))
                resp.headers["Content-Type"] = "text/html"
                resp.headers["Content-Disposition"] = f"attachment; filename={doc_name}.html"
                return resp

            return {"error": f"Cannot convert {base_mime} to {expected_mime}"}, 400
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
            if expected_mime == "text/xml":
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

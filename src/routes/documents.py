# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import Flask, request, make_response
from flask.typing import ResponseReturnValue
import json
import os
import mimetypes
import traceback
from datetime import date
from ..controllers import ControllersCache
from ..views.templates import Templates
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

    @app.route('/api/documents/<doc_name>', methods=['GET'])
    def doc_by_name(doc_name: str) -> ResponseReturnValue:
        ctrls = ControllersCache()
        ctrls.packages._preload_cache()
        templ = Templates(ctrls)
        try:
            base_mime = guess_mime_type(doc_name)
            if base_mime is None:
                return {"error": "Unsupported document type"}, 400
            expected_mime = guess_mime_type(request.args.get("ext")) or base_mime
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

            if (
                doc_name.startswith("CycloneDX ")
                or doc_name == "OpenVex"
                or doc_name.startswith("SPDX")
            ):
                # SBOM/VEX exports are scoped to the current project/variant
                # when the frontend passes variant_id / project_id.  Reports
                # (templates) keep their global, unscoped data.
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

                if scope is not None:
                    scoped_ctrls = ControllersCache(scope=scope)
                    scoped_ctrls.packages._preload_cache()
                else:
                    scoped_ctrls = ctrls
                return handle_sbom_exports(doc_name, scoped_ctrls, expected_mime, metadata)

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

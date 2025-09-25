#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import request, make_response
import json
import os
import mimetypes
import traceback
from datetime import date
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController
from ..views.templates import Templates
from ..views.cyclonedx import CycloneDx
from ..views.spdx import SPDX
from ..views.spdx3 import SPDX3
from ..views.openvex import OpenVex
from typing import Dict, List


# You can associate specific files to specific categories
# "example.adoc": ["misc", "category_name"]
CategoriesDictionary: Dict[str, List[str]] = {}


def guess_mime_type(doc_name):
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


def init_app(app):

    def get_all_datas():
        controllers = {}
        with open(app.config["PKG_FILE"], "r") as f:
            controllers["packages"] = PackagesController.from_dict(
                json.loads(f.read())
            )
        with open(app.config["VULNS_FILE"], "r") as f:
            controllers["vulnerabilities"] = VulnerabilitiesController.from_dict(
                controllers["packages"],
                json.loads(f.read())
            )
        with open(app.config["ASSESSMENTS_FILE"], "r") as f:
            controllers["assessments"] = AssessmentsController.from_dict(
                controllers["packages"],
                controllers["vulnerabilities"],
                json.loads(f.read())
            )
        return controllers

    @app.route('/api/documents', methods=['GET'])
    def index_docs():
        templ = Templates({"packages": [], "vulnerabilities": [], "assessments": []})
        try:
            docs = templ.list_documents()

            docs.append({"id": "SPDX 2.3", "extension": "json | xml", "is_template": False, "category": ["sbom"]})
            docs.append({"id": "SPDX 3.0", "extension": "json | xml", "is_template": False, "category": ["sbom"]})
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
    def doc_by_name(doc_name):
        ctrls = get_all_datas()
        templ = Templates(ctrls)
        try:
            base_mime = guess_mime_type(doc_name)
            expected_mime = guess_mime_type(request.args.get("ext")) or base_mime
            metadata = {
                "author": request.args.get("author") or os.getenv('AUTHOR_NAME', 'Savoir-faire Linux'),
                "client_name": request.args.get("client_name") or "",
                "export_date": request.args.get("export_date") or date.today().isoformat(),
                "ignore_before": request.args.get("ignore_before") or "1970-01-01T00:00",
                "only_epss_greater": 0.0,
                "scan_date": app.config["SCAN_DATE"] or "unknown date"  # don't use actual datetime by default.
            }
            try:
                metadata["only_epss_greater"] = float(request.args.get("only_epss_greater") or "0.0")
            except Exception:
                pass

            if (
                doc_name.startswith("CycloneDX ")
                or doc_name == "OpenVex"
                or doc_name.startswith("SPDX")
            ):
                return handle_sbom_exports(doc_name, ctrls, expected_mime, metadata)

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
        except Exception as e:
            print(e, traceback.format_exc(), flush=True)
            return {"error": str(e)}, 500


def handle_sbom_exports(doc_name, ctrls, expected_mime, metadata):
    if doc_name.startswith("CycloneDX"):
        cdx = CycloneDx(ctrls)
        if expected_mime == "application/json":
            content = None
            if doc_name == "CycloneDX 1.4":
                content = cdx.output_as_json(4, metadata["author"])
            if doc_name == "CycloneDX 1.5":
                content = cdx.output_as_json(5, metadata["author"])
            if doc_name == "CycloneDX 1.6":
                content = cdx.output_as_json(6, metadata["author"])

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
                content = spdx.output_as_json(metadata["author"])
                if content is not None:
                    new_name = doc_name.lower().replace(' ', '_v').replace('.', '_')
                    return content, 200, {
                        "Content-Type": expected_mime,
                        "Content-Disposition": f"attachment; filename={new_name}.json"
                    }
            if expected_mime == "text/xml":
                content = spdx.output_as_xml(metadata["author"])
                if content is not None:
                    new_name = doc_name.lower().replace(' ', '_v').replace('.', '_')
                    return content, 200, {
                        "Content-Type": expected_mime,
                        "Content-Disposition": f"attachment; filename={new_name}.xml"
                    }
        elif doc_name == "SPDX 3.0":
            spdx3 = SPDX3(ctrls)
            if expected_mime == "application/json":
                content = spdx3.output_as_json(metadata["author"])
                if content is not None:
                    new_name = doc_name.lower().replace(' ', '_v').replace('.', '_')
                    return content, 200, {
                        "Content-Type": expected_mime,
                        "Content-Disposition": f"attachment; filename={new_name}.json"
                    }
            if expected_mime == "text/xml":
                content = spdx3.output_as_xml(metadata["author"])
                if content is not None:
                    new_name = doc_name.lower().replace(' ', '_v').replace('.', '_')
                    return content, 200, {
                        "Content-Type": expected_mime,
                        "Content-Disposition": f"attachment; filename={new_name}.xml"
                    }

    if doc_name == "OpenVex" and expected_mime == "application/json":
        opvx = OpenVex(ctrls)
        return json.dumps(opvx.to_dict(True, metadata["author"]), indent=2), 200, {
            "Content-Type": expected_mime,
            "Content-Disposition": "attachment; filename=openvex.json"
        }

    return {"error": f"Cannot export {doc_name} to {expected_mime}"}, 400

from flask import request
import json
import mimetypes
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController
from ..views.templates import Templates
from ..views.cyclonedx import CycloneDx
from ..views.openvex import OpenVex


CategoriesDictionary = {
    "summary.adoc": ["recommended"],
    "vulnerabilities.csv": ["misc"]
}


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

            # docs.append({"id": "SPDX 2.4", "extension": "json|xml", "is_template": False, "category": ["sbom"]})
            # docs.append({"id": "SPDX 3.0", "extension": "json|xml", "is_template": False, "category": ["sbom"]})
            docs.append({"id": "CycloneDX 1.4", "extension": "json|xml", "is_template": False, "category": ["sbom"]})
            docs.append({"id": "CycloneDX 1.5", "extension": "json|xml", "is_template": False, "category": ["sbom"]})
            docs.append({"id": "CycloneDX 1.6", "extension": "json|xml", "is_template": False, "category": ["sbom"]})
            docs.append({"id": "OpenVex", "extension": "json", "is_template": False, "category": ["sbom"]})

            for doc in docs:
                if "extension" not in doc:
                    if "." in doc["id"]:
                        doc["extension"] = doc["id"].split(".")[-1]
                    else:
                        doc["extension"] = "bin"

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

            if doc_name.startswith("CycloneDX "):
                return handle_sbom_exports(doc_name, ctrls, expected_mime)

            content = templ.render(doc_name)

            if base_mime == expected_mime:
                return content, 200, {
                    "Content-Type": base_mime,
                    "Content-Disposition": f"attachment; filename={doc_name}"
                }

            return {"error": f"Cannot convert {base_mime} to {expected_mime}"}, 400
        except Exception as e:
            print(e)
            return {"error": str(e)}, 500


def handle_sbom_exports(doc_name, ctrls, expected_mime):
    if doc_name.startswith("CycloneDX"):
        cdx = CycloneDx(ctrls)
        if expected_mime == "application/json":
            content = None
            if doc_name == "CycloneDX 1.4":
                content = cdx.output_as_json(4)
            if doc_name == "CycloneDX 1.5":
                content = cdx.output_as_json(5)
            if doc_name == "CycloneDX 1.6":
                content = cdx.output_as_json(6)

            if content is not None:
                new_name = doc_name.lower().replace(' ', '_v').replace('.', '_')
                return content, 200, {
                    "Content-Type": expected_mime,
                    "Content-Disposition": f"attachment; filename={new_name}.json"
                }

    if doc_name == "OpenVex" and expected_mime == "application/json":
        opvx = OpenVex(ctrls)
        return json.dumps(opvx.to_dict(True), indent=2), 200, {
            "Content-Type": expected_mime,
            "Content-Disposition": "attachment; filename=openvex.json"
        }

    return {"error": f"Cannot export {doc_name} to {expected_mime}"}, 400

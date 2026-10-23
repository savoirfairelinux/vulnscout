# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import re
from io import BytesIO

import pytest
from jsonschema.exceptions import ValidationError
from openapi_schema_validator import OAS30Validator
from openapi_spec_validator import validate

from src.bin.webapp import create_app
from src.extensions import db
from src.models.assessment import Assessment
from src.models.assessment_target import AssessmentTarget
from src.models.finding import Finding
from src.models.observation import Observation
from src.models.package import Package
from src.models.project import Project
from src.models.scan import Scan
from src.models.sbom_document import SBOMDocument
from src.models.sbom_package import SBOMPackage
from src.models.variant import Variant


@pytest.fixture()
def init_status_file(tmp_path):
    status_path = tmp_path / "status.txt"
    status_path.write_text("4 merging something")
    return status_path


@pytest.fixture()
def app(init_status_file, monkeypatch):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("FLASK_TESTING", "true")
    application = create_app()
    application.config.update({
        "TESTING": True,
        "SCAN_FILE": init_status_file,
    })
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


def test_openapi_spec_is_available_before_scan_completion(client):
    response = client.get("/api/openapi")
    assert response.status_code == 200
    assert response.content_type == "application/json"

    data = json.loads(response.data)
    assert data["openapi"] == "3.0.3"
    assert data["info"]["title"] == "VulnScout REST API"
    assert "components" in data
    assert "schemas" in data["components"]
    assert "JsonObject" in data["components"]["schemas"]
    assert "Error" in data["components"]["schemas"]


def test_openapi_json_alias_returns_same_document(client):
    canonical = client.get("/api/openapi")
    root_alias = client.get("/api")
    alias = client.get("/api/openapi.json")
    assert canonical.status_code == 200
    assert root_alias.status_code == 200
    assert alias.status_code == 200
    assert json.loads(canonical.data) == json.loads(root_alias.data)
    assert json.loads(canonical.data) == json.loads(alias.data)


def test_openapi_swagger_ui_is_available_before_scan_completion(client):
    response = client.get("/api/openapi/ui")
    assert response.status_code == 200
    assert response.content_type.startswith("text/html")

    content = response.data.decode("utf-8")
    assert "SwaggerUIBundle" in content
    assert 'url: "/api/openapi"' in content


def test_openapi_spec_lists_registered_api_paths(client):
    response = client.get("/api/openapi")
    data = json.loads(response.data)

    assert "/api/openapi" in data["paths"]
    assert "/api" in data["paths"]
    assert "/api/openapi.json" in data["paths"]
    assert "/api/openapi/ui" in data["paths"]
    assert "/api/version" in data["paths"]
    assert "/api/assessments" in data["paths"]
    assert "/api/vulnerabilities/{vuln_id}/assessments" in data["paths"]

    assessment_ops = data["paths"]["/api/assessments/{assessment_id}"]
    assert sorted(assessment_ops) == ["delete", "get", "patch", "put"]


def test_openapi_spec_includes_every_registered_api_operation(app, client):
    data = json.loads(client.get("/api/openapi").data)
    documented = {
        (path, method.upper())
        for path, path_item in data["paths"].items()
        for method in path_item
    }
    visible_methods = {"GET", "POST", "PUT", "PATCH", "DELETE"}
    registered = {
        (re.sub(r"<(?:(?:[^:<>]+):)?([^<>]+)>", r"{\1}", rule.rule), method)
        for rule in app.url_map.iter_rules()
        if rule.rule == "/api" or rule.rule.startswith("/api/")
        for method in (rule.methods or set()) & visible_methods
    }

    assert documented == registered


def test_openapi_operation_ids_are_unique(client):
    data = json.loads(client.get("/api/openapi").data)
    operation_ids = [
        operation["operationId"]
        for path_item in data["paths"].values()
        for operation in path_item.values()
    ]

    assert len(operation_ids) == len(set(operation_ids))
    assert data["paths"]["/api"]["get"]["operationId"] == "api.get"
    assert data["paths"]["/api/openapi"]["get"]["operationId"] == "api_openapi.get"
    assert data["paths"]["/api/openapi.json"]["get"]["operationId"] == "api_openapi_json.get"


def test_openapi_spec_marks_scan_blocked_routes(client):
    response = client.get("/api/openapi")
    data = json.loads(response.data)

    package_get = data["paths"]["/api/packages"]["get"]
    assert "503" in package_get["responses"]

    version_get = data["paths"]["/api/version"]["get"]
    assert "503" not in version_get["responses"]

    scan_status_get = data["paths"]["/api/scan/status"]["get"]
    assert "503" not in scan_status_get["responses"]


def test_openapi_spec_exposes_typed_schemas_for_core_routes(client):
    response = client.get("/api/openapi")
    data = json.loads(response.data)

    config_patch = data["paths"]["/api/config"]["patch"]
    config_schema = config_patch["requestBody"]["content"]["application/json"]["schema"]
    assert config_schema["$ref"] == "#/components/schemas/ConfigUpdate"

    projects_post = data["paths"]["/api/projects"]["post"]
    project_schema = projects_post["requestBody"]["content"]["application/json"]["schema"]
    assert project_schema["$ref"] == "#/components/schemas/NameRequest"

    packages_get = data["paths"]["/api/packages"]["get"]
    package_schema = packages_get["responses"]["200"]["content"]["application/json"]["schema"]
    assert package_schema["$ref"] == "#/components/schemas/PackageCollection"


def test_openapi_spec_reads_parameter_annotations_from_docstrings(client):
    response = client.get("/api/openapi")
    data = json.loads(response.data)

    package_parameters = data["paths"]["/api/packages"]["get"]["parameters"]
    package_parameter_names = {item["name"] for item in package_parameters if item["in"] == "query"}
    expected_parameters = {
        "variant_id", "project_id", "compare_variant_id", "variant_ids", "operation", "format",
    }
    assert expected_parameters <= package_parameter_names

    config_patch = data["paths"]["/api/config"]["patch"]
    error_schema = config_patch["responses"]["400"]["content"]["application/json"]["schema"]
    assert error_schema["$ref"] == "#/components/schemas/Error"


def test_openapi_spec_exposes_multipart_upload_routes(client):
    response = client.get("/api/openapi")
    data = json.loads(response.data)

    sbom_upload = data["paths"]["/api/sbom/upload"]["post"]
    assert "multipart/form-data" in sbom_upload["requestBody"]["content"]

    openvex_import = data["paths"]["/api/assessments/review/import"]["post"]
    assert "multipart/form-data" in openvex_import["requestBody"]["content"]

    context_file_upload = data["paths"]["/api/variants/{variant_id}/context/files"]["post"]
    assert "multipart/form-data" in context_file_upload["requestBody"]["content"]


def test_openapi_spec_documents_context_and_vulnerability_helpers(client):
    data = json.loads(client.get("/api/openapi").data)

    context_get = data["paths"]["/api/context"]["get"]
    context_parameters = {parameter["name"]: parameter for parameter in context_get["parameters"]}
    assert context_parameters["project_id"]["required"] is True
    assert context_parameters["variant_id"]["required"] is True

    context_import = data["paths"]["/api/context/import"]["post"]
    assert context_import["requestBody"]["required"] is True

    match_condition = data["paths"]["/api/vulnerabilities/match-condition"]["post"]
    assert match_condition["requestBody"]["required"] is True
    assert "400" in match_condition["responses"]

    description_search = data["paths"]["/api/vulnerabilities/search-descriptions"]["post"]
    parameter_names = {parameter["name"] for parameter in description_search["parameters"]}
    assert parameter_names == {"project_id", "variant_id"}


def test_complete_spec_validates_against_openapi_30(client):
    validate(client.get("/api/openapi").get_json())


@pytest.mark.parametrize("path,statuses", [
    ("/api/operations", {"202", "400", "404", "409", "503"}),
    ("/api/documents/export", {"200", "202", "400", "404", "500", "503"}),
    ("/api/agent/messages", {"200", "400", "403", "409", "503"}),
])
def test_explicit_success_statuses_do_not_get_fictional_defaults(client, path, statuses):
    responses = client.get("/api/openapi").get_json()["paths"][path]["post"]["responses"]
    assert set(responses) == statuses


def test_204_response_has_no_content_or_extra_200(client):
    responses = client.get("/api/openapi").get_json()["paths"][
        "/api/variants/{variant_id}/context/files/{file_id}"
    ]["delete"]["responses"]
    assert "200" not in responses
    assert "content" not in responses["204"]


@pytest.mark.parametrize("path,parameter,is_uuid", [
    ("/api/projects/{project_id}/variants", "project_id", True),
    ("/api/variants/{variant_id}/context", "variant_id", True),
    ("/api/assessments/{assessment_id}", "assessment_id", True),
    ("/api/vulnerabilities/{id}", "id", False),
    ("/api/vulnerabilities/{cve_id}/nvd-refresh", "cve_id", False),
    ("/api/vulnerabilities/{ghsa_id}/ghsa-refresh", "ghsa_id", False),
    ("/api/operations/{op_id}/cancel", "op_id", False),
    ("/api/operations/queue/{queue_id}/cancel", "queue_id", False),
    ("/api/documents/export/{op_id}/download", "op_id", False),
])
def test_identifier_formats_match_the_domain(client, path, parameter, is_uuid):
    operation = next(iter(client.get("/api/openapi").get_json()["paths"][path].values()))
    params = [p for p in operation["parameters"] if p["in"] == "path" and p["name"] == parameter]
    assert len(params) == 1
    assert (params[0]["schema"].get("format") == "uuid") is is_uuid


@pytest.mark.parametrize("path,required,file_field,multiple", [
    ("/api/documents/assets", {"file"}, "file", False),
    ("/api/documents/templates", {"file"}, "file", False),
    ("/api/sbom/upload", {"files", "project_id", "variant_id"}, "files", True),
    ("/api/variants/{variant_id}/context/files", {"file"}, "file", False),
    ("/api/assessments/review/import", {"file", "variant_id"}, "file", False),
    ("/api/assessments/review/export-update", {"file", "project_id", "variant_id"}, "file", False),
    ("/api/assessments/review/import-custom-data", {"file", "project_id"}, "file", False),
])
def test_multipart_schemas_render_required_upload_controls(client, path, required, file_field, multiple):
    body = client.get("/api/openapi").get_json()["paths"][path]["post"]["requestBody"]
    assert body["required"] is True
    schema = body["content"]["multipart/form-data"]["schema"]
    assert set(schema["required"]) == required
    file_schema = schema["properties"][file_field]
    if multiple:
        assert file_schema["type"] == "array"
        file_schema = file_schema["items"]
    assert file_schema["type"] == "string"
    assert file_schema["format"] == "binary"


def test_alternative_import_media_types_and_bodyless_actions(client):
    paths = client.get("/api/openapi").get_json()["paths"]
    custom_import = paths["/api/assessments/review/import-custom-data"]["post"]["requestBody"]
    assert set(custom_import["content"]) == {"application/json", "multipart/form-data"}
    assert "requestBody" not in paths["/api/operations/{op_id}/cancel"]["post"]
    assert "requestBody" not in paths["/api/agent/provider"]["delete"]
    assert "requestBody" in paths["/api/agent/provider"]["post"]
    assert "requestBody" not in paths["/api/projects/{project_id}/scan-configuration"]["get"]
    assert paths["/api/projects/{project_id}/scan-configuration"]["put"]["requestBody"]["required"]


@pytest.mark.parametrize("path", [
    "/api/custom-assessments", "/api/assessment-reviews", "/api/assessments/review/export-custom-data",
])
def test_repeated_variant_filters_are_arrays(client, path):
    operation = client.get("/api/openapi").get_json()["paths"][path]["get"]
    parameter = next(p for p in operation["parameters"] if p["name"] == "variant_id")
    assert parameter["schema"] == {"type": "array", "items": {"type": "string", "format": "uuid"}}


@pytest.mark.parametrize("path,method,status,media_types", [
    ("/api/events/stream", "get", "200", {"text/event-stream"}),
    ("/api/agent/messages", "post", "200", {"application/json", "application/x-ndjson"}),
    ("/api/documents/export", "post", "200", {"application/zip"}),
    ("/api/documents/export/{op_id}/download", "get", "200", {"application/zip"}),
    ("/api/assessments/review/export", "get", "200", {"application/json"}),
    ("/api/assessments/review/export-custom-data", "get", "200", {"application/json"}),
    ("/api/assessments/review/export-update", "post", "200", {"application/json"}),
])
def test_stream_and_download_media_types(client, path, method, status, media_types):
    response = client.get("/api/openapi").get_json()["paths"][path][method]["responses"][status]
    assert set(response["content"]) == media_types


def test_agent_contract_models_local_access_and_session_without_scan_gate(client):
    paths = client.get("/api/openapi").get_json()["paths"]
    for path, methods in paths.items():
        if not (path == "/api/agent" or path.startswith("/api/agent/")):
            continue
        for operation in methods.values():
            assert "403" in operation["responses"]
            assert operation["responses"].get("503", {}).get("description") != "Scan not finished"
            parameters = {(p["in"], p["name"]): p for p in operation["parameters"]}
            assert ("cookie", "vulnscout_agent") in parameters
            assert parameters["header", "X-Agent-Thread"]["schema"]["format"] == "uuid"


def _assert_payload_matches(spec, schema, payload):
    OAS30Validator({"allOf": [schema], "components": spec["components"]}).validate(payload)


def test_review_body_requires_verdict_rationale_target_and_fingerprint(client):
    spec = client.get("/api/openapi").get_json()
    schema = spec["paths"]["/api/assessments/{assessment_id}/review"]["put"][
        "requestBody"
    ]["content"]["application/json"]["schema"]
    valid = {
        "variant_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "package": "cairo@1.16.0",
        "status": "fixed",
        "rationale": "The fix is present.",
        "expected_assessment_fingerprint": "abc",
    }
    _assert_payload_matches(spec, schema, valid)
    for name in ("variant_id", "status", "rationale", "expected_assessment_fingerprint"):
        invalid = {key: value for key, value in valid.items() if key != name}
        with pytest.raises(ValidationError, match="required"):
            _assert_payload_matches(spec, schema, invalid)


@pytest.fixture()
def contract_data(app):
    app._INT_SCAN_FINISHED = True
    with app.app_context():
        db.create_all()
        project = Project.create("Swagger contract")
        variant = Variant.create("default", project.id)
        scan = Scan.create("Contract scan", variant.id)
        package = Package.find_or_create("example", "1.0", [], ["pkg:generic/example@1.0"], "")
        db.session.commit()
        from src.models.vulnerability import Vulnerability
        Vulnerability.create_record(id="CVE-2024-1234", description="Contract example", status="high")
        db.session.commit()
        finding = Finding.get_or_create(package.id, "CVE-2024-1234")
        Observation.create(finding.id, scan.id)
        document = SBOMDocument.create(path="example.json", source_name="cdx", scan_id=scan.id)
        SBOMPackage.create(document.id, package.id)
        assessment = Assessment(status="fixed", origin="custom", responses=[])
        db.session.add(assessment)
        db.session.flush()
        db.session.add(AssessmentTarget(
            assessment_id=assessment.id, variant_id=variant.id, finding_id=finding.id,
        ))
        db.session.commit()
        return {
            "project_id": str(project.id), "variant_id": str(variant.id),
            "scan_id": str(scan.id), "assessment_id": str(assessment.id),
        }


@pytest.mark.parametrize("path", [
    "/api/version",
    "/api/scan/status",
    "/api/projects",
    "/api/variants",
    "/api/projects/{project_id}/variants",
    "/api/packages",
    "/api/packages?format=dict",
    "/api/vulnerabilities",
    "/api/vulnerabilities?format=list",
    "/api/vulnerabilities?format=compact",
    "/api/vulnerabilities/CVE-2024-1234",
    "/api/vulnerabilities/CVE-2024-1234/variant-snapshots",
    "/api/assessments",
    "/api/assessments?format=dict",
    "/api/assessments?format=compact",
    "/api/assessments/{assessment_id}",
    "/api/assessments/{assessment_id}/reviews",
    "/api/assessment-reviews",
    "/api/custom-assessments",
    "/api/scans",
    "/api/projects/{project_id}/scans",
    "/api/variants/{variant_id}/scans",
    "/api/scans/{scan_id}/diff",
    "/api/scans/{scan_id}/global-result",
    "/api/scans/{scan_id}/export-diff",
    "/api/scans/{scan_id}/export-result",
    "/api/scans/export",
    "/api/config",
    "/api/config/nvd-api-key",
    "/api/documents",
    "/api/operations",
    "/api/projects/{project_id}/context",
    "/api/context?project_id={project_id}&variant_id={variant_id}",
    "/api/context/export",
    "/api/package-dependencies?variant_id={variant_id}",
    "/api/package-dependencies?variant_id={variant_id}&counts=1",
    "/api/empty-scans",
    "/api/orphaned-vulnerabilities",
    "/api/outdated-data",
])
def test_documented_schemas_match_nonempty_runtime_responses(client, contract_data, path):
    spec = client.get("/api/openapi").get_json()
    response = client.get(path.format(**contract_data))
    assert response.status_code == 200, response.get_data(as_text=True)
    template = path.split("?")[0]
    if template.startswith("/api/vulnerabilities/CVE-2024-1234"):
        template = template.replace("CVE-2024-1234", "{id}")
    schema = spec["paths"][template]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    _assert_payload_matches(spec, schema, response.get_json())


def test_spec_server_respects_deployment_prefix(client):
    spec = client.get("/api/openapi", environ_overrides={"SCRIPT_NAME": "/vulnscout"}).get_json()
    assert spec["servers"][0]["url"] == "/vulnscout/"


@pytest.mark.parametrize("path", [
    "/api/documents/assets", "/api/documents/templates", "/api/sbom/upload",
    "/api/assessments/review/import", "/api/assessments/review/export-update",
])
def test_multipart_only_routes_reject_json_as_documented(client, contract_data, path):
    spec = client.get("/api/openapi").get_json()
    response = client.post(path, json={"file": "not a multipart upload"})
    assert response.status_code == 400
    operation = spec["paths"][path]["post"]
    assert set(operation["requestBody"]["content"]) == {"multipart/form-data"}
    _assert_payload_matches(
        spec, operation["responses"]["400"]["content"]["application/json"]["schema"], response.get_json(),
    )


@pytest.mark.parametrize("kind", ["template", "asset", "context"])
def test_uploaded_file_responses_match_schemas(client, contract_data, monkeypatch, tmp_path, kind):
    from src.routes import context, documents
    spec = client.get("/api/openapi").get_json()
    if kind == "template":
        monkeypatch.setattr(documents, "writable_templates_dir", lambda: str(tmp_path))
        path = "/api/documents/templates"
        upload = (BytesIO(b"= Example report\n"), "example.adoc")
    elif kind == "asset":
        from PIL import Image
        image = BytesIO()
        Image.new("RGB", (1, 1)).save(image, format="PNG")
        image.seek(0)
        monkeypatch.setattr(documents, "writable_assets_dir", lambda: str(tmp_path))
        path = "/api/documents/assets"
        upload = (image, "example.png")
    else:
        monkeypatch.setattr(context, "_get_cache_dir", lambda: str(tmp_path))
        path = "/api/variants/{variant_id}/context/files"
        upload = (BytesIO(b"int main(void) { return 0; }\n"), "example.c")
    response = client.post(path.format(**contract_data), data={"file": upload})
    assert response.status_code == 201, response.get_data(as_text=True)
    schema = spec["paths"][path]["post"]["responses"]["201"]["content"]["application/json"]["schema"]
    _assert_payload_matches(spec, schema, response.get_json())
    if kind == "context":
        delete_path = path.format(**contract_data) + "/" + response.get_json()["id"]
        deleted = client.delete(delete_path)
        assert deleted.status_code == 204
        assert deleted.data == b""


def test_stored_review_matches_its_request_and_response_contract(client, contract_data):
    spec = client.get("/api/openapi").get_json()
    assessment_path = "/api/assessments/" + contract_data["assessment_id"]
    assessment = client.get(assessment_path).get_json()
    payload = {
        "variant_id": contract_data["variant_id"], "package": "example@1.0",
        "status": "fixed", "rationale": "The implementation contains the fix.",
        "expected_assessment_fingerprint": assessment["assessment_fingerprint"],
    }
    operation = spec["paths"]["/api/assessments/{assessment_id}/review"]["put"]
    _assert_payload_matches(spec, operation["requestBody"]["content"]["application/json"]["schema"], payload)
    response = client.put(assessment_path + "/review", json=payload)
    assert response.status_code == 200, response.get_data(as_text=True)
    _assert_payload_matches(
        spec, operation["responses"]["200"]["content"]["application/json"]["schema"], response.get_json(),
    )


def test_runtime_sse_matches_its_documented_media_type(client):
    spec = client.get("/api/openapi").get_json()
    response = client.get("/api/events/stream", buffered=False)
    try:
        assert response.status_code == 200
        operation = spec["paths"]["/api/events/stream"]["get"]
        assert response.mimetype in operation["responses"]["200"]["content"]
        frame = next(response.response).decode()
        assert "event: snapshot" in frame
    finally:
        response.close()


@pytest.mark.parametrize("streaming", [False, True])
def test_runtime_agent_replies_match_documented_media_types(client, monkeypatch, tmp_path, streaming):
    from src.routes import agent
    mcp_path = tmp_path / "server.py"
    mcp_path.write_text("")
    monkeypatch.setattr(agent, "_mcp_path", lambda: mcp_path)
    monkeypatch.setattr(agent, "_container_gateway", lambda: None)
    monkeypatch.setattr(agent, "_load_env_credentials_nonblocking", lambda root: None)
    monkeypatch.setattr(agent, "_scope_for_context", lambda context: None)
    monkeypatch.setattr(agent, "_conversation", lambda: ("contract-session", agent.Conversation()))

    async def reply(conversation, prompt, path, model, scope, publish=None):
        if publish:
            publish({"type": "delta", "text": "Hello."})
        return "Hello.", {"cost": None, "input_tokens": 3, "output_tokens": 2}

    monkeypatch.setattr(agent, "_reply", reply)
    spec = client.get("/api/openapi").get_json()
    operation = spec["paths"]["/api/agent/messages"]["post"]
    payload = {"message": "Hello"}
    _assert_payload_matches(spec, operation["requestBody"]["content"]["application/json"]["schema"], payload)
    media_type = "application/x-ndjson" if streaming else "application/json"
    response = client.post("/api/agent/messages", json=payload, headers={"Accept": media_type})
    try:
        assert response.status_code == 200
        assert response.mimetype == media_type
        if streaming:
            events = [json.loads(line) for line in response.get_data(as_text=True).splitlines()]
            assert events[-1]["type"] == "done"
            assert events[-1]["reply"] == "Hello."
        else:
            _assert_payload_matches(
                spec, operation["responses"]["200"]["content"][media_type]["schema"], response.get_json(),
            )
    finally:
        response.close()

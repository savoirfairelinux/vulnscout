# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json

import pytest

from src.bin.webapp import create_app


@pytest.fixture()
def init_status_file(tmp_path):
    status_path = tmp_path / "status.txt"
    status_path.write_text("4 merging something")
    return status_path


@pytest.fixture()
def app(init_status_file):
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
    assert "url: '/api/openapi'" in content


def test_openapi_spec_lists_registered_api_paths(client):
    response = client.get("/api/openapi")
    data = json.loads(response.data)

    assert "/api/openapi" in data["paths"]
    assert "/api/openapi.json" in data["paths"]
    assert "/api/openapi/ui" in data["paths"]
    assert "/api/version" in data["paths"]
    assert "/api/assessments" in data["paths"]
    assert "/api/vulnerabilities/{vuln_id}/assessments" in data["paths"]

    assessment_ops = data["paths"]["/api/assessments/{assessment_id}"]
    assert sorted(assessment_ops) == ["delete", "get", "patch", "put"]


def test_openapi_spec_marks_scan_blocked_routes(client):
    response = client.get("/api/openapi")
    data = json.loads(response.data)

    package_get = data["paths"]["/api/packages"]["get"]
    assert "503" in package_get["responses"]

    version_get = data["paths"]["/api/version"]["get"]
    assert "503" not in version_get["responses"]


def test_openapi_spec_exposes_typed_schemas_for_core_routes(client):
    response = client.get("/api/openapi")
    data = json.loads(response.data)

    config_patch = data["paths"]["/api/config"]["patch"]
    assert config_patch["requestBody"]["content"]["application/json"]["schema"]["$ref"] == "#/components/schemas/JsonObject"

    projects_post = data["paths"]["/api/projects"]["post"]
    assert projects_post["requestBody"]["content"]["application/json"]["schema"]["$ref"] == "#/components/schemas/JsonObject"

    packages_get = data["paths"]["/api/packages"]["get"]
    assert packages_get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"] == "#/components/schemas/JsonObject"


def test_openapi_spec_reads_parameter_annotations_from_docstrings(client):
    response = client.get("/api/openapi")
    data = json.loads(response.data)

    package_parameters = data["paths"]["/api/packages"]["get"]["parameters"]
    package_parameter_names = {item["name"] for item in package_parameters if item["in"] == "query"}
    assert {"variant_id", "project_id", "compare_variant_id", "variant_ids", "operation", "format"} <= package_parameter_names

    config_patch = data["paths"]["/api/config"]["patch"]
    assert config_patch["responses"]["400"]["content"]["application/json"]["schema"]["$ref"] == "#/components/schemas/Error"


def test_openapi_spec_exposes_multipart_upload_routes(client):
    response = client.get("/api/openapi")
    data = json.loads(response.data)

    sbom_upload = data["paths"]["/api/sbom/upload"]["post"]
    assert "multipart/form-data" in sbom_upload["requestBody"]["content"]

    openvex_import = data["paths"]["/api/assessments/review/import"]["post"]
    assert "multipart/form-data" in openvex_import["requestBody"]["content"]
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from flask import Flask

from src.helpers.openapi import build_openapi_spec


def _operation(docstring, method="POST"):
    app = Flask(__name__)

    def view():
        return {}

    view.__doc__ = docstring
    app.add_url_rule("/api/example", view_func=view, methods=[method])
    return build_openapi_spec(app)["paths"]["/api/example"][method.lower()]


def test_field_body_annotations_accumulate_without_overwriting():
    operation = _operation("""Create a review.

    OpenAPI:
    body variant_id uuid required Target variant.
    body package string optional Package string identifier.
    body status string required Independent verdict.
    body rationale string required Independent reasoning.
    body expected_assessment_fingerprint string required Observed fingerprint.
    response 200 object Stored review.
    """)
    body = operation["requestBody"]
    assert body["required"] is True
    schema = body["content"]["application/json"]["schema"]
    assert set(schema["properties"]) == {
        "variant_id", "package", "status", "rationale", "expected_assessment_fingerprint",
    }
    assert set(schema["required"]) == {
        "variant_id", "status", "rationale", "expected_assessment_fingerprint",
    }
    assert schema["properties"]["variant_id"]["format"] == "uuid"
    assert schema["properties"]["rationale"]["description"] == "Independent reasoning."


@pytest.mark.parametrize("reverse", [False, True])
def test_named_body_and_extra_fields_merge_in_either_order(reverse):
    lines = [
        "body NameRequest required Name payload.",
        "body variant_id uuid required Target variant.",
    ]
    operation = _operation("Create an example.\nOpenAPI:\n" + "\n".join(lines[::-1] if reverse else lines))
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert schema["allOf"][0] == {"$ref": "#/components/schemas/NameRequest"}
    assert schema["allOf"][1]["required"] == ["variant_id"]
    assert schema["allOf"][1]["properties"]["variant_id"]["format"] == "uuid"


def test_optional_fields_do_not_require_a_body():
    operation = _operation("Update.\nOpenAPI:\nbody note string optional Additional note.")
    assert operation["requestBody"]["required"] is False
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert "required" not in schema


def test_unannotated_actions_have_no_invented_body_or_created_status():
    operation = _operation("Trigger an action.")
    assert "requestBody" not in operation
    assert set(operation["responses"]) == {"200", "503"}


@pytest.mark.parametrize("annotation", [
    "body MisspelledSchema required Payload.",
    "response 200 MisspelledSchema Payload.",
    "body field uuid required",
])
def test_invalid_schema_annotations_fail_explicitly(annotation):
    with pytest.raises(ValueError, match="OpenAPI"):
        _operation("Example.\nOpenAPI:\n" + annotation)


def test_method_scoped_annotations_do_not_leak_to_other_methods():
    doc = """Example.
    OpenAPI:
    POST body NameRequest required Created object.
    POST response 201 Project Created project.
    DELETE response 204 empty Deleted project.
    """
    assert "requestBody" not in _operation(doc, "DELETE")
    assert set(_operation(doc, "DELETE")["responses"]) == {"204", "503"}
    assert set(_operation(doc, "POST")["responses"]) == {"201", "503"}


def test_non_api_rules_are_excluded_and_converter_types_are_preserved():
    app = Flask(__name__)
    app.add_url_rule("/private", endpoint="private", view_func=lambda: {})
    app.add_url_rule("/api/items/<int:count>/<float:ratio>/<uuid:key>", endpoint="items", view_func=lambda: {})
    spec = build_openapi_spec(app)
    assert "/private" not in spec["paths"]
    params = spec["paths"]["/api/items/{count}/{ratio}/{key}"]["get"]["parameters"]
    assert [p["schema"] for p in params] == [
        {"type": "integer"}, {"type": "number", "format": "float"}, {"type": "string", "format": "uuid"},
    ]


def test_repeated_response_annotations_combine_media_types():
    operation = _operation("""Download.
    OpenAPI:
    response 200 html HTML report.
    response 200 pdf PDF report.
    response 200 plain Text report.
    """)
    assert set(operation["responses"]["200"]["content"]) == {"text/html", "application/pdf", "text/plain"}

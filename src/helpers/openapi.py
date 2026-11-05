# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import os
import re
from collections.abc import Callable
from typing import Any

from flask import Flask, has_request_context, request
from werkzeug.routing import Rule

from .openapi_schemas import SCHEMAS

_PATH_PARAM_RE = re.compile(r"<(?:(?P<converter>[^:<>]+):)?(?P<name>[^<>]+)>")
_VISIBLE_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_DOC_OPENAPI_MARKER = "OpenAPI:"
_COMPONENT_SCHEMAS = {"JsonObject", "JsonArray", "Error"} | SCHEMAS.keys()
_SCAN_EXEMPT_PATHS = {
    "/api",
    "/api/openapi",
    "/api/openapi.json",
    "/api/openapi/ui",
    "/api/scan/status",
    "/api/version",
    "/api/events/stream",
}


def build_openapi_spec(app: Flask) -> dict[str, Any]:
    paths: dict[str, dict[str, Any]] = {}
    rules = sorted(
        app.url_map.iter_rules(),
        key=lambda entry: (entry.rule, sorted(entry.methods or set())),
    )
    for rule in rules:
        if rule.rule != "/api" and not rule.rule.startswith("/api/"):
            continue
        methods = sorted((rule.methods or set()) & _VISIBLE_METHODS)
        if not methods:
            continue
        path_item = paths.setdefault(_normalize_rule_path(rule.rule), {})
        for method in methods:
            path_item[method.lower()] = _build_operation(app, rule, method)

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "VulnScout REST API",
            "version": os.getenv("VULNSCOUT_VERSION", "unknown"),
            "description": (
                "OpenAPI export generated from currently registered Flask /api routes. "
                "Operation descriptions are derived from route docstrings when present."
            ),
        },
        "servers": [{
            "url": (request.script_root if has_request_context() else "") + "/",
            "description": "Current VulnScout server",
        }],
        "paths": paths,
        "components": {
            "schemas": {
                **SCHEMAS,
                "JsonObject": {"type": "object", "additionalProperties": True},
                "JsonArray": {"type": "array", "items": {}},
                "Error": {
                    "type": "object",
                    "properties": {"error": {"type": "string"}},
                    "required": ["error"],
                },
            },
        },
    }


def _build_operation(app: Flask, rule: Rule, method: str) -> dict[str, Any]:
    view_func = app.view_functions[rule.endpoint]
    summary, description, metadata = _parse_docstring(view_func, method)
    path = _normalize_rule_path(rule.rule)
    if path == "/api/agent" or path.startswith("/api/agent/"):
        metadata["parameters"].extend([
            {
                "name": "X-Agent-Thread",
                "in": "header",
                "required": False,
                "schema": {"type": "string", "format": "uuid"},
                "description": "Isolate a conversation within the browser's agent session.",
            },
            {
                "name": "vulnscout_agent",
                "in": "cookie",
                "required": False,
                "schema": {"type": "string"},
                "description": "Session cookie set automatically by the agent endpoints.",
            },
        ])
        for status, message in {
            "400": "Invalid conversation header, provider configuration, or request payload.",
            "403": "Agent access requires localhost and a same-origin request.",
        }.items():
            metadata["responses"].setdefault(
                status, {"description": message, "content": _json_content(_schema_ref("Error"))},
            )
    operation: dict[str, Any] = {
        "operationId": _build_operation_id(path, method),
        "summary": summary or _build_summary(rule.rule, method),
        "tags": [_build_tag(rule.rule)],
        "responses": _build_responses(path, metadata),
    }
    if description:
        operation["description"] = description

    parameters_by_key = {
        (parameter["in"], parameter["name"]): parameter
        for parameter in _build_path_parameters(rule) + metadata["parameters"]
    }
    parameters = list(parameters_by_key.values())
    if parameters:
        operation["parameters"] = parameters

    if metadata["requestBody"] is not None and method != "GET":
        operation["requestBody"] = metadata["requestBody"]
    return operation


def _build_operation_id(path: str, method: str) -> str:
    """Return a stable ID unique to one normalized path and HTTP method."""
    path_id = re.sub(r"[^A-Za-z0-9]+", "_", path.strip("/")).strip("_") or "root"
    return f"{path_id}.{method.lower()}"


def _build_path_parameters(rule: Rule) -> list[dict[str, Any]]:
    parameters: list[dict[str, Any]] = []
    for match in _PATH_PARAM_RE.finditer(rule.rule):
        name = match.group("name")
        converter = match.group("converter") or "string"
        parameters.append({
            "name": name,
            "in": "path",
            "required": True,
            "schema": _converter_to_schema(name, converter),
        })
    return parameters


def _converter_to_schema(name: str, converter: str) -> dict[str, Any]:
    if converter == "int":
        return {"type": "integer"}
    if converter == "float":
        return {"type": "number", "format": "float"}
    if converter == "uuid" or name in {
        "project_id", "variant_id", "assessment_id", "finding_id", "scan_id", "file_id",
    }:
        return {"type": "string", "format": "uuid"}
    return {"type": "string"}


def _build_summary(path: str, method: str) -> str:
    path_label = _normalize_rule_path(path).removeprefix("/api/")
    path_label = path_label.replace("/", " ").replace("{", "").replace("}", "")
    return f"{method.title()} {path_label}".strip()


def _build_tag(path: str) -> str:
    if path == "/api":
        return "system"
    suffix = path.removeprefix("/api/")
    system_paths = {"version", "openapi", "openapi.json", "openapi/ui", "scan/status"}
    if not suffix or suffix in system_paths:
        return "system"
    return suffix.split("/", 1)[0]


def _build_responses(path: str, metadata: dict[str, Any]) -> dict[str, Any]:
    responses = dict(metadata["responses"])
    if not any(status.startswith("2") for status in responses):
        responses["200"] = _build_success_response(path)
    if path not in _SCAN_EXEMPT_PATHS and not (path == "/api/agent" or path.startswith("/api/agent/")):
        responses.setdefault("503", {
            "description": "Scan not finished",
            "content": _json_content(_schema_ref("Error")),
        })
    return responses


def _build_success_response(path: str) -> dict[str, Any]:
    response: dict[str, Any] = {"description": "Successful response"}
    if path == "/api/openapi/ui":
        response["content"] = {"text/html": {"schema": {"type": "string"}}}
    else:
        response["content"] = _json_content(_schema_ref("JsonObject"))
    return response


def _json_content(schema: dict[str, Any]) -> dict[str, Any]:
    return {"application/json": {"schema": schema}}


def _schema_ref(name: str) -> dict[str, Any]:
    return {"$ref": f"#/components/schemas/{name}"}


def _schema_from_token(token: str) -> dict[str, Any]:
    if token.endswith("[]"):
        return {"type": "array", "items": _schema_from_token(token[:-2])}
    if token.endswith("Map") and token not in _COMPONENT_SCHEMAS:
        return {"type": "object", "additionalProperties": _schema_from_token(token[:-3])}
    primitive_schemas: dict[str, dict[str, Any]] = {
        "string": {"type": "string"},
        "integer": {"type": "integer"},
        "number": {"type": "number"},
        "boolean": {"type": "boolean"},
        "object": {"type": "object", "additionalProperties": True},
        "uuid": {"type": "string", "format": "uuid"},
        "binary": {"type": "string", "format": "binary"},
        "html": {"type": "string"},
        "multipart": {"type": "object", "properties": {}},
        "sse": {"type": "string"},
        "ndjson": {"type": "string"},
        "plain": {"type": "string"},
        "csv": {"type": "string"},
        "adoc": {"type": "string"},
        "markdown": {"type": "string"},
        "xml": {"type": "string"},
        "text-xml": {"type": "string"},
        "zip": {"type": "string", "format": "binary"},
        "pdf": {"type": "string", "format": "binary"},
        "image": {"type": "string", "format": "binary"},
        "empty": {},
    }
    if token in primitive_schemas:
        return primitive_schemas[token]
    if token in _COMPONENT_SCHEMAS:
        return _schema_ref(token)
    raise ValueError(f"Unknown OpenAPI schema token: {token}")


def _media_type_for_token(token: str) -> str:
    return {
        "html": "text/html",
        "multipart": "multipart/form-data",
        "binary": "application/octet-stream",
        "sse": "text/event-stream",
        "ndjson": "application/x-ndjson",
        "zip": "application/zip",
        "pdf": "application/pdf",
        "image": "image/*",
        "plain": "text/plain",
        "csv": "text/csv",
        "adoc": "text/asciidoc",
        "markdown": "text/markdown",
        "xml": "application/xml",
        "text-xml": "text/xml",
    }.get(token, "application/json")


def _parse_docstring(view_func: Callable[..., Any], method: str) -> tuple[str, str, dict[str, Any]]:
    doc = (view_func.__doc__ or "").strip()
    metadata: dict[str, Any] = {
        "parameters": [],
        "requestBody": None,
        "responses": {},
    }
    if not doc:
        return "", "", metadata

    raw_lines = [line.strip() for line in doc.splitlines()]
    try:
        marker_idx = raw_lines.index(_DOC_OPENAPI_MARKER)
    except ValueError:
        marker_idx = -1
    prose_lines = raw_lines if marker_idx == -1 else raw_lines[:marker_idx]
    annotation_lines = [] if marker_idx == -1 else raw_lines[marker_idx + 1:]
    prose_lines = [line for line in prose_lines if line]
    summary = prose_lines[0] if prose_lines else ""
    description = "\n".join(prose_lines[1:]) if len(prose_lines) > 1 else ""
    fields: list[Any] = []

    for line in annotation_lines:
        if not line:
            continue
        if line.split(maxsplit=1)[0] in _VISIBLE_METHODS:
            annotation_method, _, line = line.partition(" ")
            if annotation_method != method:
                continue
        parsed = _parse_openapi_annotation(line)
        if parsed is None:
            continue
        kind, payload = parsed
        if kind == "parameter":
            metadata["parameters"].append(payload)
        elif kind == "requestBody":
            body = metadata["requestBody"]
            if body is None:
                metadata["requestBody"] = payload
            else:
                body["required"] |= payload["required"]
                body["content"].update(payload["content"])
                body["description"] = payload["description"]
        elif kind == "field":
            fields.append(payload)
        elif kind == "response":
            response = payload["response"]
            existing = metadata["responses"].setdefault(payload["status"], response)
            if "content" in response:
                existing.setdefault("content", {}).update(response["content"])
    for field in fields:
        _add_request_field(metadata, field)
    return summary, description, metadata


def _add_request_field(metadata: dict[str, Any], field: Any) -> None:
    media_type, name, schema, required = field
    if metadata["requestBody"] is None:
        metadata["requestBody"] = {"required": False, "content": {}}
    body = metadata["requestBody"]
    media = body["content"].setdefault(
        media_type, {"schema": {"type": "object", "properties": {}}},
    )
    body_schema = media["schema"]
    if "$ref" in body_schema:
        body_schema = {"allOf": [body_schema, {"type": "object", "properties": {}}]}
        media["schema"] = body_schema
    if "allOf" in body_schema:
        body_schema = body_schema["allOf"][-1]
    body_schema.setdefault("properties", {})[name] = schema
    if required:
        required_fields = body_schema.setdefault("required", [])
        if name not in required_fields:
            required_fields.append(name)
        body["required"] = True


def _parse_openapi_annotation(line: str) -> tuple[str, Any] | None:
    parts = line.split()
    if len(parts) < 4:
        return None
    annotation_type = parts[0].lower()
    if annotation_type in {"path", "query", "header", "cookie"}:
        name, schema_token = parts[1], parts[2]
        return "parameter", {
            "name": name,
            "in": annotation_type,
            "required": annotation_type == "path" or _parse_required_token(parts[3]),
            "schema": _schema_from_token(schema_token),
            "description": " ".join(parts[4:]) if len(parts) > 4 else "",
        }
    if annotation_type == "form" or (
        annotation_type == "body" and parts[2].lower() not in {
            "required", "optional", "true", "false", "yes", "no",
        }
    ):
        if len(parts) < 5:
            raise ValueError(f"Invalid OpenAPI field annotation: {line}")
        name, schema_token, required_token = parts[1:4]
        schema = _schema_from_token(schema_token)
        if "$ref" in schema:
            schema = {"allOf": [schema]}
        schema["description"] = " ".join(parts[4:])
        return "field", (
            "multipart/form-data" if annotation_type == "form" else "application/json",
            name, schema, _parse_required_token(required_token),
        )
    if annotation_type == "body":
        schema_token = parts[1]
        media_type = _media_type_for_token(schema_token)
        return "requestBody", {
            "required": _parse_required_token(parts[2]),
            "description": " ".join(parts[3:]) if len(parts) > 3 else "",
            "content": {media_type: {"schema": _schema_from_token(schema_token)}},
        }
    if annotation_type == "response":
        status, schema_token = parts[1], parts[2]
        media_type = _media_type_for_token(schema_token)
        response: dict[str, Any] = {
            "description": " ".join(parts[3:]) if len(parts) > 3 else "Successful response",
        }
        if status not in {"204", "304"} and schema_token != "empty":
            response["content"] = {media_type: {"schema": _schema_from_token(schema_token)}}
        return "response", {"status": status, "response": response}
    return None


def _parse_required_token(token: str) -> bool:
    return token.lower() in {"required", "true", "yes"}


def _normalize_rule_path(rule_path: str) -> str:
    return _PATH_PARAM_RE.sub(lambda match: "{" + match.group("name") + "}", rule_path)

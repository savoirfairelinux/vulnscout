# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import os
import re
from collections.abc import Callable
from typing import Any

from flask import Flask
from werkzeug.routing import Rule

_PATH_PARAM_RE = re.compile(r"<(?:(?P<converter>[^:<>]+):)?(?P<name>[^<>]+)>")
_VISIBLE_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_DOC_OPENAPI_MARKER = "OpenAPI:"
_COMPONENT_SCHEMAS = {"JsonObject", "Error"}
_SCAN_EXEMPT_PATHS = {
    "/api",
    "/api/openapi",
    "/api/openapi.json",
    "/api/openapi/ui",
    "/api/scan/status",
    "/api/version",
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
        "servers": [{"url": "/", "description": "Current VulnScout server"}],
        "paths": paths,
        "components": {
            "schemas": {
                "JsonObject": {"type": "object", "additionalProperties": True},
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
    summary, description, metadata = _parse_docstring(view_func)
    path = _normalize_rule_path(rule.rule)
    operation: dict[str, Any] = {
        "operationId": _build_operation_id(path, method),
        "summary": summary or _build_summary(rule.rule, method),
        "tags": [_build_tag(rule.rule)],
        "responses": _build_responses(path, method, metadata),
    }
    if description:
        operation["description"] = description

    parameters = _build_path_parameters(rule) + metadata["parameters"]
    if parameters:
        operation["parameters"] = parameters

    if metadata["requestBody"] is not None:
        operation["requestBody"] = metadata["requestBody"]
    elif method in {"POST", "PUT", "PATCH"}:
        operation["requestBody"] = {
            "required": False,
            "content": _json_content(_schema_ref("JsonObject")),
        }
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
    if converter == "uuid" or name.endswith("_id"):
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


def _build_responses(path: str, method: str, metadata: dict[str, Any]) -> dict[str, Any]:
    success_status = "201" if method == "POST" else "200"
    responses = dict(metadata["responses"])
    responses.setdefault(success_status, _build_success_response(path))
    if path not in _SCAN_EXEMPT_PATHS:
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
    primitive_schemas: dict[str, dict[str, Any]] = {
        "string": {"type": "string"},
        "integer": {"type": "integer"},
        "number": {"type": "number"},
        "boolean": {"type": "boolean"},
        "object": {"type": "object", "additionalProperties": True},
        "uuid": {"type": "string", "format": "uuid"},
        "binary": {"type": "string", "format": "binary"},
        "html": {"type": "string"},
        "multipart": {"type": "object", "additionalProperties": True},
    }
    if token in primitive_schemas:
        return primitive_schemas[token]
    if token in _COMPONENT_SCHEMAS:
        return _schema_ref(token)
    return {"type": "object", "additionalProperties": True}


def _media_type_for_token(token: str) -> str:
    if token == "html":
        return "text/html"
    if token == "multipart":
        return "multipart/form-data"
    if token == "binary":
        return "application/octet-stream"
    return "application/json"


def _parse_docstring(view_func: Callable[..., Any]) -> tuple[str, str, dict[str, Any]]:
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

    for line in annotation_lines:
        if not line:
            continue
        parsed = _parse_openapi_annotation(line)
        if parsed is None:
            continue
        kind, payload = parsed
        if kind == "parameter":
            metadata["parameters"].append(payload)
        elif kind == "requestBody":
            metadata["requestBody"] = payload
        elif kind == "response":
            metadata["responses"][payload["status"]] = payload["response"]
    return summary, description, metadata


def _parse_openapi_annotation(line: str) -> tuple[str, Any] | None:
    parts = line.split()
    if len(parts) < 4:
        return None
    annotation_type = parts[0].lower()
    if annotation_type in {"query", "header", "cookie"}:
        name, schema_token = parts[1], parts[2]
        return "parameter", {
            "name": name,
            "in": annotation_type,
            "required": _parse_required_token(parts[3]),
            "schema": _schema_from_token(schema_token),
            "description": " ".join(parts[4:]) if len(parts) > 4 else "",
        }
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
        response = {
            "description": " ".join(parts[3:]) if len(parts) > 3 else "Successful response",
            "content": {media_type: {"schema": _schema_from_token(schema_token)}},
        }
        return "response", {"status": status, "response": response}
    return None


def _parse_required_token(token: str) -> bool:
    return token.lower() in {"required", "true", "yes"}


def _normalize_rule_path(rule_path: str) -> str:
    return _PATH_PARAM_RE.sub(lambda match: "{" + match.group("name") + "}", rule_path)

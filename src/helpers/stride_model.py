# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Validation of the per-variant structured STRIDE threat model.

``normalize_stride_model`` returns a canonical copy of a raw JSON-like model and
collects every rule break into a single ``StrideValidationError`` so the UI can
mark all invalid cells at once. Inputs are never mutated.
"""

from __future__ import annotations

import re
from typing import Any, Optional

STRIDE_CATEGORIES: tuple[str, ...] = (
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
)
CATEGORY_LABELS: dict[str, str] = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "information_disclosure": "Information disclosure",
    "denial_of_service": "Denial of service",
    "elevation_of_privilege": "Elevation of privilege",
}
RATINGS: tuple[str, ...] = ("low", "medium", "high")
RATING_LABELS: dict[str, str] = {"low": "Low", "medium": "Medium", "high": "High"}
MAX_ROWS = 500
MAX_TEXT = 20000
SYSTEM_KEYS: tuple[str, ...] = ("scope", "actors", "entry_points", "trust_boundaries")

_COMPONENT_ID = re.compile(r"^C[1-9]\d*$")
_INTERACTION_ID = re.compile(r"^I[1-9]\d*$")
_THREAT_ID = re.compile(r"^T[1-9]\d*$")


class StrideValidationError(ValueError):
    """Raised when a STRIDE model breaks a rule; ``fields`` maps path to message."""

    def __init__(self, fields: dict[str, str]):
        self.fields = dict(fields)
        super().__init__("; ".join(f"{path}: {msg}" for path, msg in self.fields.items()))


def empty_stride_model() -> dict[str, Any]:
    return {
        "components": [],
        "interactions": [],
        "threats": [],
        "notes": "",
        "risks": [],
        "risk_notes": "",
    }


class _Errors:
    """Accumulates ``path -> message`` problems, keeping the first per path."""

    def __init__(self) -> None:
        self.fields: dict[str, str] = {}

    def add(self, path: str, message: str) -> None:
        self.fields.setdefault(path, message)

    def raise_if_any(self) -> None:
        if self.fields:
            raise StrideValidationError(self.fields)


def _text(value: object, path: str, errs: _Errors, required: bool = False) -> str:
    """Return a validated text value ('' when missing)."""
    if value is None:
        value = ""
    if not isinstance(value, str):
        errs.add(path, "must be a string")
        return ""
    if len(value) > MAX_TEXT:
        errs.add(path, f"must be at most {MAX_TEXT} characters")
    if required and not value.strip():
        errs.add(path, "is required")
    return value


def _rows(raw: object, key: str, errs: _Errors) -> list[dict[str, Any]]:
    """Return the rows of a list field, flagging non-list/oversized/non-object input."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        errs.add(key, "must be a list")
        return []
    if len(raw) > MAX_ROWS:
        errs.add(key, f"must have at most {MAX_ROWS} rows")
        return []
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(raw):
        if isinstance(row, dict):
            rows.append(row)
        else:
            errs.add(f"{key}[{index}]", "must be an object")
            rows.append({})
    return rows


def _row_id(row: dict[str, Any], path: str, pattern: re.Pattern[str], seen: set[str], errs: _Errors) -> str:
    value = row.get("id")
    if not isinstance(value, str) or not pattern.match(value):
        errs.add(path, f"must match {pattern.pattern}")
        return ""
    if value in seen:
        errs.add(path, "is duplicated")
    seen.add(value)
    return value


def _ref(row: dict[str, Any], key: str, path: str, known: set[str], errs: _Errors) -> str:
    value = row.get(key)
    if not isinstance(value, str) or value not in known:
        errs.add(path, "references an unknown id")
        return value if isinstance(value, str) else ""
    return value


def _components(raw: object, errs: _Errors) -> tuple[list[dict[str, Any]], set[str]]:
    seen: set[str] = set()
    out = []
    for i, row in enumerate(_rows(raw, "components", errs)):
        p = f"components[{i}]"
        out.append({
            "id": _row_id(row, f"{p}.id", _COMPONENT_ID, seen, errs),
            "name": _text(row.get("name"), f"{p}.name", errs, required=True),
            "description": _text(row.get("description"), f"{p}.description", errs),
            "trust_zone": _text(row.get("trust_zone"), f"{p}.trust_zone", errs),
        })
    return out, seen


def _interactions(raw: object, component_ids: set[str], errs: _Errors) -> tuple[list[dict[str, Any]], set[str]]:
    seen: set[str] = set()
    out = []
    for i, row in enumerate(_rows(raw, "interactions", errs)):
        p = f"interactions[{i}]"
        out.append({
            "id": _row_id(row, f"{p}.id", _INTERACTION_ID, seen, errs),
            "name": _text(row.get("name"), f"{p}.name", errs),
            "source_id": _ref(row, "source_id", f"{p}.source_id", component_ids, errs),
            "destination_id": _ref(row, "destination_id", f"{p}.destination_id", component_ids, errs),
            "interface": _text(row.get("interface"), f"{p}.interface", errs),
            "data": _text(row.get("data"), f"{p}.data", errs),
            "trust_boundary": _text(row.get("trust_boundary"), f"{p}.trust_boundary", errs),
        })
    return out, seen


def _target_ids(value: object, path: str, known: set[str], errs: _Errors) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        errs.add(path, "must be a list of ids")
        return []
    if any(v not in known for v in value):
        errs.add(path, "references an unknown id")
    return list(value)


def _threats(raw: object, target_pool: set[str], errs: _Errors) -> tuple[list[dict[str, Any]], set[str]]:
    seen: set[str] = set()
    out = []
    for i, row in enumerate(_rows(raw, "threats", errs)):
        p = f"threats[{i}]"
        category = row.get("category")
        if category not in STRIDE_CATEGORIES:
            errs.add(f"{p}.category", f"must be one of {', '.join(STRIDE_CATEGORIES)}")
        out.append({
            "id": _row_id(row, f"{p}.id", _THREAT_ID, seen, errs),
            "category": category if isinstance(category, str) else "",
            "description": _text(row.get("description"), f"{p}.description", errs),
            "target_ids": _target_ids(row.get("target_ids"), f"{p}.target_ids", target_pool, errs),
        })
    return out, seen


def _rating(value: object, path: str, errs: _Errors) -> Optional[str]:
    if value is None:
        return None
    if value not in RATINGS:
        errs.add(path, f"must be one of {', '.join(RATINGS)} or null")
        return None
    return str(value)


def _risks(raw: object, threat_ids: set[str], errs: _Errors) -> list[dict[str, Any]]:
    out = []
    for i, row in enumerate(_rows(raw, "risks", errs)):
        p = f"risks[{i}]"
        out.append({
            "threat_id": _ref(row, "threat_id", f"{p}.threat_id", threat_ids, errs),
            "likelihood": _rating(row.get("likelihood"), f"{p}.likelihood", errs),
            "impact": _rating(row.get("impact"), f"{p}.impact", errs),
            "mitigation": _text(row.get("mitigation"), f"{p}.mitigation", errs),
            "residual": _text(row.get("residual"), f"{p}.residual", errs),
        })
    return out


def normalize_stride_model(raw: object) -> dict[str, Any]:
    """Return a canonical copy of ``raw`` or raise ``StrideValidationError``."""
    if not isinstance(raw, dict):
        raise StrideValidationError({"model": "must be an object"})
    errs = _Errors()
    components, component_ids = _components(raw.get("components"), errs)
    interactions, interaction_ids = _interactions(raw.get("interactions"), component_ids, errs)
    threats, threat_ids = _threats(raw.get("threats"), component_ids | interaction_ids, errs)
    model = {
        "components": components,
        "interactions": interactions,
        "threats": threats,
        "notes": _text(raw.get("notes"), "notes", errs),
        "risks": _risks(raw.get("risks"), threat_ids, errs),
        "risk_notes": _text(raw.get("risk_notes"), "risk_notes", errs),
    }
    errs.raise_if_any()
    return model


def normalize_system(raw: object) -> dict[str, Optional[str]]:
    """Keep only the four system-description keys (string or ``None``)."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise StrideValidationError({"system": "must be an object"})
    errs = _Errors()
    out: dict[str, Optional[str]] = {}
    for key in SYSTEM_KEYS:
        value = raw.get(key)
        out[key] = None if value is None else _text(value, f"system.{key}", errs)
    errs.raise_if_any()
    return out

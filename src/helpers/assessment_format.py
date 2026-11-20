# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Validation of the project-level presentation format for AI assessment text.

The format only orders, labels and lays out the text an agent writes; the
assessment skill bounds what it may change. ``normalize_assessment_format``
returns a canonical copy, or ``None`` for the skill's default presentation, and
reports every problem at once through ``StrideValidationError`` so the AI
Context page can mark each invalid field, like other context saves.
"""

from __future__ import annotations

import re
from typing import Any

from .stride_model import StrideValidationError

FIELD = "assessment_format"
SECTION_IDS: tuple[str, ...] = ("confidence", "verdict", "evidence", "reachability", "remediation")
LAYOUTS: tuple[str, ...] = ("inline", "lines")
DEFAULT_LAYOUT = "inline"
MAX_LABEL = 40
MAX_STYLE_NOTES = 500

_TOP_KEYS = frozenset({"sections", "layout", "style_notes"})
_SECTION_KEYS = frozenset({"id", "enabled", "label"})
# C0/C1 controls (and DEL); newlines and tabs are kept only in style notes.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_CONTROL_KEEP_BREAKS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _clean(value: object, path: str, limit: int, errors: dict[str, str], *, multiline: bool = False) -> str | None:
    """Return the stripped text without control characters, or None when blank."""
    if value is None:
        return None
    if not isinstance(value, str):
        errors.setdefault(path, "must be a string")
        return None
    text = (_CONTROL_KEEP_BREAKS if multiline else _CONTROL).sub("", value).strip()
    if len(text) > limit:
        errors.setdefault(path, f"must be at most {limit} characters")
        return None
    return text or None


def _sections(raw: object, errors: dict[str, str]) -> list[dict[str, Any]]:
    path = f"{FIELD}.sections"
    if not isinstance(raw, list):
        errors.setdefault(path, "must be a list")
        return []
    sections: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, row in enumerate(raw):
        row_path = f"{path}[{index}]"
        if not isinstance(row, dict):
            errors.setdefault(row_path, "must be an object")
            continue
        for key in sorted(set(row) - _SECTION_KEYS):
            errors.setdefault(f"{row_path}.{key}", "is not a supported field")
        section_id = row.get("id")
        if not isinstance(section_id, str) or section_id not in SECTION_IDS:
            errors.setdefault(f"{row_path}.id", f"must be one of: {', '.join(SECTION_IDS)}")
            continue
        if section_id in seen:
            errors.setdefault(f"{row_path}.id", "is duplicated")
            continue
        seen.add(section_id)
        enabled = row.get("enabled", True)
        if not isinstance(enabled, bool):
            errors.setdefault(f"{row_path}.enabled", "must be a boolean")
        section: dict[str, Any] = {"id": section_id, "enabled": bool(enabled)}
        label = _clean(row.get("label"), f"{row_path}.label", MAX_LABEL, errors)
        if label is not None:
            section["label"] = label
        sections.append(section)
    return sections


def normalize_assessment_format(raw: object) -> dict[str, Any] | None:
    """Validate *raw* and return its canonical form; ``None`` means the default presentation.

    Raises
    ------
    StrideValidationError
        With ``assessment_format.<path>`` keys for every invalid value.
    """
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise StrideValidationError({FIELD: "must be an object or null"})
    errors: dict[str, str] = {}
    for key in sorted(set(raw) - _TOP_KEYS):
        errors.setdefault(f"{FIELD}.{key}", "is not a supported field")
    sections = _sections(raw.get("sections"), errors)
    layout = raw.get("layout", DEFAULT_LAYOUT)
    if layout not in LAYOUTS:
        errors.setdefault(f"{FIELD}.layout", f"must be one of: {', '.join(LAYOUTS)}")
    style_notes = _clean(raw.get("style_notes"), f"{FIELD}.style_notes", MAX_STYLE_NOTES, errors, multiline=True)
    if errors:
        raise StrideValidationError(errors)
    result: dict[str, Any] = {"sections": sections, "layout": layout}
    if style_notes is not None:
        result["style_notes"] = style_notes
    return result

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""AI threat-model drafts, kept in the cache next to a variant's references.

A draft is a full proposed model built on one saved revision. ``rebase`` merges
it onto a newer saved model so loading it never reverts someone else's save.
"""

import contextlib
import json
import os
import re
import shutil
import tempfile
import threading
import typing
from typing import Any, Optional

from .stride_model import SYSTEM_KEYS, StrideValidationError, empty_stride_model

if typing.TYPE_CHECKING:
    from ..models.variant_context import VariantContext

TEXT_KEYS = ("variant_description", "environment", "other_info")
SECTIONS = ("components", "interactions", "threats", "risks")
PREFIX = {"components": "C", "interactions": "I", "threats": "T", "risks": "R"}
_REFS = {"interactions": ("source_id", "destination_id"), "threats": ("target_ids",), "risks": ("threat_ids",)}
DRAFT_NAME = "draft.json"
IMPORT_DIR = "import"
_ROW_PATH = re.compile(r"^(components|interactions|threats|risks)\[(\d+)\](.*)$")
_ROW_ID = re.compile(r"^[CITR]([1-9]\d*)$")

Values = dict[str, Any]

# The backend runs a single Flask process, so an in-process lock serializes each
# variant's draft read-modify-write. Several worker processes would need a file lock.
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def lock_for(vc_id: object) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(str(vc_id), threading.Lock())


def context_dir(cache_dir: str, vc_id: object) -> str:
    return os.path.join(cache_dir, "context-files", str(vc_id))


def read_draft(directory: str) -> Optional[dict]:
    """The stored draft, or None. A corrupt file is removed rather than served."""
    path = os.path.join(directory, DRAFT_NAME)
    try:
        with open(path, encoding="utf-8") as handle:
            draft = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        draft = None
    if isinstance(draft, dict) and isinstance(draft.get("values"), dict) and isinstance(draft.get("base_values"), dict):
        return draft
    with contextlib.suppress(OSError):
        os.remove(path)
    return None


def write_draft(directory: str, draft: dict) -> None:
    """Replace the draft atomically: readers see the old or the new file, never a partial one."""
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".draft-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(draft, handle, ensure_ascii=False)
        os.replace(tmp, os.path.join(directory, DRAFT_NAME))
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


def delete_draft(directory: str) -> None:
    """Remove the draft and the import source; missing files are fine."""
    with contextlib.suppress(FileNotFoundError):
        os.remove(os.path.join(directory, DRAFT_NAME))
    shutil.rmtree(os.path.join(directory, IMPORT_DIR), ignore_errors=True)


def import_source_path(directory: str) -> Optional[str]:
    folder = os.path.join(directory, IMPORT_DIR)
    try:
        names = [name for name in os.listdir(folder) if os.path.isfile(os.path.join(folder, name))]
    except OSError:
        return None
    return os.path.join(folder, names[0]) if len(names) == 1 else None


def saved_values(vc: "Optional[VariantContext]") -> Values:
    """The saved model in draft-values shape."""
    if vc is None:
        return {**{key: None for key in TEXT_KEYS}, "system": {key: None for key in SYSTEM_KEYS},
                "stride": empty_stride_model()}
    return {
        **{key: getattr(vc, key) for key in TEXT_KEYS},
        "system": {key: getattr(vc, f"system_{key}") for key in SYSTEM_KEYS},
        "stride": vc.stride_model if vc.stride_model is not None else empty_stride_model(),
    }


def normalize_values(values: object) -> Values:
    """Validate draft values exactly as an editor save does; text keeps "" apart from None."""
    from ..models.variant_context import _editor_values

    if not isinstance(values, dict):
        raise StrideValidationError({"values": "must be an object"})
    errors: dict[str, str] = {}
    texts: dict[str, Optional[str]] = {}
    for key in TEXT_KEYS:
        value = values.get(key)
        if value is not None and not isinstance(value, str):
            errors[key] = "must be a string"
        texts[key] = value if isinstance(value, str) else None
    editor: dict[str, Any] = {}
    try:
        editor = _editor_values({"codebase_source": "references", "system": values.get("system"),
                                 "stride": values.get("stride")})
    except StrideValidationError as exc:
        errors.update({path: message for path, message in exc.fields.items() if path not in errors})
    if errors:
        raise StrideValidationError(errors)
    return {**texts, "system": {key: editor[f"system_{key}"] for key in SYSTEM_KEYS},
            "stride": editor["stride_model"]}


def _blank(value: Optional[str]) -> Optional[str]:
    return value if value is not None and value.strip() else None


def _merge_text(base: Optional[str], saved: Optional[str], draft: Optional[str]) -> tuple[Optional[str], bool]:
    """Context text; None in the draft or the result means "keep the saved value"."""
    if draft is None or _blank(draft) in (_blank(base), _blank(saved)):
        return None, False
    if _blank(saved) == _blank(base):
        return draft, False
    return None, True


def _merge_system(base: Optional[str], saved: Optional[str], draft: Optional[str]) -> tuple[Optional[str], bool]:
    b, s, d = _blank(base), _blank(saved), _blank(draft)
    if d == b:
        return s, False
    if s in (b, d):
        return d, False
    return s, True


def _model(values: Values) -> tuple[dict, dict]:
    system = values.get("system") or {}
    stride = values.get("stride") or {}
    return ({key: system.get(key) for key in SYSTEM_KEYS},
            {section: [dict(row) for row in stride.get(section) or []] for section in SECTIONS})


def _number(row_id: object) -> int:
    match = _ROW_ID.match(row_id) if isinstance(row_id, str) else None
    return int(match.group(1)) if match else 0


def _renumbering(base: dict, saved: dict, draft: dict) -> dict[str, str]:
    """New draft IDs that rows saved since already use get the next free ID of their prefix."""
    mapping: dict[str, str] = {}
    for section in SECTIONS:
        base_ids = {row.get("id") for row in base[section]}
        saved_ids = {row.get("id") for row in saved[section]}
        taken = base_ids | saved_ids | {row.get("id") for row in draft[section]}
        top = max((_number(row_id) for row_id in taken), default=0)
        for row in draft[section]:
            if row.get("id") not in base_ids and row.get("id") in saved_ids:
                top += 1
                mapping[row["id"]] = f"{PREFIX[section]}{top}"
    return mapping


def _rewrite(stride: dict, mapping: dict[str, str]) -> dict:
    def ref(value: object) -> object:
        return mapping.get(value, value) if isinstance(value, str) else value

    out = {}
    for section in SECTIONS:
        rows = []
        for row in stride[section]:
            row = {**row, "id": ref(row.get("id"))}
            for key in _REFS.get(section, ()):
                value = row.get(key)
                row[key] = [ref(item) for item in value] if isinstance(value, list) else ref(value)
            rows.append(row)
        out[section] = rows
    return out


def _merge_rows(section: str, base: list, saved: list, draft: list, conflicts: list) -> list:
    """Whole-row three-way merge by ID: saved rows first, then the draft's new rows."""
    base_by_id = {row.get("id"): row for row in base}
    saved_ids = {row.get("id") for row in saved}
    draft_by_id = {row.get("id"): row for row in draft}
    merged = []
    for row in saved:
        row_id = row.get("id")
        if row_id not in base_by_id:
            merged.append(row)
            continue
        original, proposed = base_by_id[row_id], draft_by_id.get(row_id)
        if proposed is None:
            if row != original:
                conflicts.append({"path": f"{section}[{row_id}]", "reason": "deleted in draft, changed since"})
                merged.append(row)
        elif proposed in (original, row):
            merged.append(row)
        elif row == original:
            merged.append(proposed)
        else:
            conflicts.append({"path": f"{section}[{row_id}]", "reason": "changed in both"})
            merged.append(row)
    for row_id, original in base_by_id.items():
        if row_id not in saved_ids and row_id in draft_by_id and draft_by_id[row_id] != original:
            conflicts.append({"path": f"{section}[{row_id}]", "reason": "changed in draft, deleted since"})
    merged.extend(row for row in draft if row.get("id") not in base_by_id)
    return merged


def _row_path(path: str, stride: dict) -> str:
    """components[2].name -> components[C3].name, so conflicts name rows, not positions."""
    match = _ROW_PATH.match(path)
    if not match:
        return path
    section, index, rest = match.group(1), int(match.group(2)), match.group(3)
    rows = stride[section]
    row_id = rows[index].get("id") if index < len(rows) else index
    return f"{section}[{row_id}]{rest}"


def rebase(base: Values, saved: Values, draft: Values) -> tuple[Optional[Values], list[dict], dict[str, str]]:
    """Merge a draft built on ``base`` onto ``saved``: (values or None, conflicts, renumbered IDs)."""
    conflicts: list[dict] = []
    values: Values = {}
    for key in TEXT_KEYS:
        values[key], clash = _merge_text(base.get(key), saved.get(key), draft.get(key))
        if clash:
            conflicts.append({"path": key, "reason": "changed in both"})
    (base_system, base_stride), (saved_system, saved_stride), (draft_system, draft_stride) = (
        _model(base), _model(saved), _model(draft))
    system = {}
    for key in SYSTEM_KEYS:
        system[key], clash = _merge_system(base_system[key], saved_system[key], draft_system[key])
        if clash:
            conflicts.append({"path": f"system.{key}", "reason": "changed in both"})
    renumbered = _renumbering(base_stride, saved_stride, draft_stride)
    draft_stride = _rewrite(draft_stride, renumbered)
    stride = {section: _merge_rows(section, base_stride[section], saved_stride[section],
                                   draft_stride[section], conflicts) for section in SECTIONS}
    values.update(system=system, stride=stride)
    if not conflicts:
        try:
            values = normalize_values(values)
        except StrideValidationError as exc:
            conflicts.extend({"path": _row_path(path, stride), "reason": message}
                             for path, message in exc.fields.items())
    return (None if conflicts else values), conflicts, renumbered

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Project-level shared entries; variant text is a compatibility projection."""

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
import re
import uuid
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models.project_context import ProjectContext
from ..models.variant import Variant
from ..models.variant_context import VariantContext
from .stride_context import SYSTEM_FIELDS, export_fields, serialize_model, serialize_register, validate_stride

CONTEXT_FIELDS = ("variant_description", "codebase_path", "environment", "other_info")
ARCHITECTURE_FIELDS = tuple(key for key, _ in SYSTEM_FIELDS)
COLLECTIONS = (
    "components", "interactions", "threats", "risks",
    "threat_notes", "risk_notes", "free_threat_model", "free_risks",
)
PREFIXES = {"components": "C", "interactions": "I", "threats": "T", "risks": "R"}


class ContextConflict(ValueError):
    """The project changed after the editor loaded its baseline."""


def empty_document(mode: str = "stride") -> dict:
    return {"editor_mode": mode, "fields": {key: [] for key in (*CONTEXT_FIELDS, *ARCHITECTURE_FIELDS)},
            **{key: [] for key in COLLECTIONS}}


def _all_rows(document: dict) -> list[dict]:
    return [row for rows in [*document["fields"].values(), *(document[key] for key in COLLECTIONS)] for row in rows]


def _references(row: dict) -> list[str]:
    return row.get("targetIds", [row.get(key, "") for key in ("threatId", "sourceId", "destinationId")])


def _used_ids(document: dict) -> set[str]:
    used = {row["id"] for row in _all_rows(document)}
    used.update(identifier for key in ("interactions", "threats", "risks")
                for row in document[key] for identifier in _references(row))
    return used


def _allocate(document: dict, prefix: str, reserved: set[str] | None = None) -> str:
    used = _used_ids(document) | (reserved or set())
    number = 1
    while f"{prefix}{number}" in used:
        number += 1
    return f"{prefix}{number}"


def _append(document: dict, rows: list, value: dict, variant_id: str, prefix: str = "X",
            preferred_id: str | None = None, retained_ids: set[str] | None = None) -> str:
    last = max((index for index, row in enumerate(rows) if variant_id in row["variant_ids"]), default=-1)
    for index, row in enumerate(rows):
        if index > last and variant_id not in row["variant_ids"] and {
            key: item for key, item in row.items() if key not in ("id", "variant_ids")
        } == value:
            row["variant_ids"].append(variant_id)
            return row["id"]
    declared = {row["id"] for row in _all_rows(document)}
    used = declared | (_used_ids(document) - (retained_ids or set()))
    identifier = preferred_id if preferred_id and preferred_id not in used else _allocate(document, prefix)
    rows.append({"id": identifier, "variant_ids": [variant_id], **value})
    return identifier


def _remove_target(rows: list, variant_id: str) -> None:
    for row in rows:
        row["variant_ids"] = [target for target in row["variant_ids"] if target != variant_id]
    rows[:] = [row for row in rows if row["variant_ids"]]


def _text(rows: list, variant_id: str, separator: str = "\n\n") -> str | None:
    values = [row["value"] for row in rows if variant_id in row["variant_ids"]]
    return separator.join(values) if values else None


def project_variant(document: dict, variant_id: str) -> dict:
    values = {
        key: _text(document["fields"][key], variant_id, ";" if key == "codebase_path" else "\n\n")
        for key in CONTEXT_FIELDS
    }
    if document["editor_mode"] == "free":
        return values | {"editor_mode": "free",
                         "threat_model": _text(document["free_threat_model"], variant_id),
                         "risks": _text(document["free_risks"], variant_id)}
    system: dict[str, Any] = {key: _text(document["fields"][key], variant_id) or "" for key in ARCHITECTURE_FIELDS}
    for key in ("components", "interactions"):
        system[key] = [{name: value for name, value in row.items() if name != "variant_ids"}
                       for row in document[key] if variant_id in row["variant_ids"]]
    model = {
        "threats": [
            {key: value for key, value in row.items() if key != "variant_ids"}
            for row in document["threats"] if variant_id in row["variant_ids"]
        ],
        "notes": _text(document["threat_notes"], variant_id) or "",
    }
    register = {
        "risks": [
            {key: value for key, value in row.items() if key not in ("id", "variant_ids")}
            for row in document["risks"] if variant_id in row["variant_ids"]
        ],
        "notes": _text(document["risk_notes"], variant_id) or "",
    }
    return values | {"editor_mode": "stride",
                     "threat_model": serialize_model(system, model, register, preserve_records=True) or None,
                     "risks": serialize_register(register) or None}


def _set_text(document: dict, rows: list, value: str | None, variant_id: str, paths: bool = False) -> None:
    if _text(rows, variant_id, ";" if paths else "\n\n") == value:
        return
    _remove_target(rows, variant_id)
    if value is not None:
        for part in value.split(";") if paths else [value]:
            _append(document, rows, {"value": part}, variant_id)


def _replace_variant(document: dict, variant_id: str, values: dict) -> None:
    previous = project_variant(document, variant_id)
    for key in CONTEXT_FIELDS:
        _set_text(document, document["fields"][key], values.get(key), variant_id, key == "codebase_path")
    if document["editor_mode"] == "free":
        for key in ("threat_model", "risks"):
            _set_text(document, document[f"free_{key}"], values.get(key), variant_id)
        return
    parsed = export_fields(values.get("threat_model"), values.get("risks"), "stride")
    mapping: dict[str, str] = {}
    if values.get("threat_model") != previous["threat_model"]:
        system, model = parsed["system"], parsed["threat_model"]
        retained = {row["id"] for key in ("components", "interactions", "threats")
                    for row in document[key] if variant_id in row["variant_ids"]}
        local_ids = {row["id"] for key in ("components", "interactions") for row in system[key]}
        local_ids.update(row["id"] for row in model["threats"])
        missing = {identifier for row in [*system["interactions"], *model["threats"], *parsed["risks"]["risks"]]
                   for identifier in _references(row) if identifier and identifier not in local_ids}
        declared = {row["id"] for row in _all_rows(document)}
        for identifier in sorted(missing & declared):
            mapping[identifier] = _allocate(document, identifier[0], set(mapping.values()) | local_ids | missing)
        for key in ARCHITECTURE_FIELDS:
            _set_text(document, document["fields"][key], system[key] or None, variant_id)
        for key in ("components", "interactions", "threats"):
            _remove_target(document[key], variant_id)
        for component in system["components"]:
            identifier = component["id"]
            mapping[identifier] = _append(
                document, document["components"], {key: value for key, value in component.items() if key != "id"},
                variant_id, "C", identifier, retained,
            )
        for interaction in system["interactions"]:
            row = {key: value for key, value in interaction.items() if key != "id"}
            for key in ("sourceId", "destinationId"):
                row[key] = mapping.get(row[key], row[key])
            mapping[interaction["id"]] = _append(
                document, document["interactions"], row, variant_id, "I", interaction["id"], retained,
            )
        for threat in model["threats"]:
            row = {key: value for key, value in threat.items() if key != "id"}
            row["targetIds"] = [mapping.get(target, target) for target in row["targetIds"]]
            mapping[threat["id"]] = _append(document, document["threats"], row, variant_id, "T", threat["id"], retained)
        _set_text(document, document["threat_notes"], model["notes"] or None, variant_id)
    remapped_threats = any(key != value for key, value in mapping.items() if key.startswith("T"))
    if values.get("risks") != previous["risks"] or remapped_threats:
        _remove_target(document["risks"], variant_id)
        for risk in parsed["risks"]["risks"]:
            row = {**risk, "threatId": mapping.get(risk["threatId"], risk["threatId"])}
            _append(document, document["risks"], row, variant_id, "R")
        _set_text(document, document["risk_notes"], parsed["risks"]["notes"] or None, variant_id)


def convert_mode(document: dict, mode: str, variant_ids: list[str]) -> dict:
    if mode == document["editor_mode"]:
        return deepcopy(document)
    result = empty_document(mode)
    for key in CONTEXT_FIELDS:
        result["fields"][key] = deepcopy(document["fields"][key])
    for identifier in variant_ids:
        _replace_variant(result, identifier, project_variant(document, identifier))
    return result


def load_document(project_id: uuid.UUID) -> tuple[ProjectContext | None, dict, list[Variant]]:
    variants = Variant.get_by_project(project_id)
    pc = ProjectContext.get_by_project(project_id)
    identifiers = {str(variant.id) for variant in variants}
    if pc is not None and pc.shared_context is not None:
        document = deepcopy(pc.shared_context)
        for rows in [*document["fields"].values(), *(document[key] for key in COLLECTIONS)]:
            for row in rows:
                row["variant_ids"] = [identifier for identifier in row["variant_ids"] if identifier in identifiers]
            rows[:] = [row for row in rows if row["variant_ids"]]
        return pc, document, variants
    contexts = [(variant, VariantContext.get_by_variant(variant.id)) for variant in variants]
    mode = "free" if any(
        vc is not None and export_fields(vc.threat_model, vc.risks, vc.editor_mode)["editor_mode"] == "free"
        for _, vc in contexts
    ) else "stride"
    document = empty_document(mode)
    for variant, vc in contexts:
        if vc is not None:
            _replace_variant(document, str(variant.id), vc.to_dict())
    return pc, document, variants


def validate_document(document: Any, variant_ids: set[str]) -> None:
    if not isinstance(document, dict) or set(document) != {"editor_mode", "fields", *COLLECTIONS}:
        raise ValueError("Invalid shared context fields")
    if document["editor_mode"] not in ("stride", "free"):
        raise ValueError("editor_mode must be stride or free")
    if not isinstance(document["fields"], dict) or set(document["fields"]) != {*CONTEXT_FIELDS, *ARCHITECTURE_FIELDS}:
        raise ValueError("Invalid scoped context fields")
    seen: set[str] = set()
    for key, rows in [*document["fields"].items(), *((key, document[key]) for key in COLLECTIONS)]:
        if not isinstance(rows, list):
            raise ValueError(f"{key} must be an array")
        for row in rows:
            prefix = PREFIXES.get(key, "X")
            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not re.fullmatch(
                rf"{prefix}[1-9][0-9]*", row["id"],
            ):
                raise ValueError(f"Invalid {key} identifier")
            if row["id"] in seen:
                raise ValueError(f"Duplicate identifier: {row['id']}")
            seen.add(row["id"])
            targets = row.get("variant_ids")
            if (not isinstance(targets, list) or not targets or any(not isinstance(target, str) for target in targets)
                    or len(set(targets)) != len(targets) or not set(targets) <= variant_ids):
                raise ValueError(f"Select existing project variants for {row['id']}")
            if key not in PREFIXES:
                if set(row) != {"id", "variant_ids", "value"} or not isinstance(row["value"], str):
                    raise ValueError(f"{key} entries must contain text")
                if key == "codebase_path" and ";" in row["value"]:
                    raise ValueError("Codebase paths cannot contain semicolons")
    if document["editor_mode"] == "stride":
        system: dict[str, Any] = {key: "" for key in ARCHITECTURE_FIELDS}
        system.update({key: [{name: value for name, value in row.items() if name != "variant_ids"}
                             for row in document[key]] for key in ("components", "interactions")})
        model = {"threats": [{key: value for key, value in row.items() if key != "variant_ids"}
                             for row in document["threats"]], "notes": ""}
        risks = {"risks": [{key: value for key, value in row.items() if key not in ("id", "variant_ids")}
                           for row in document["risks"]], "notes": ""}
        validate_stride(system, model, risks)
    elif any(document[key] for key in (*PREFIXES, "threat_notes", "risk_notes")) or any(
        document["fields"][key] for key in ARCHITECTURE_FIELDS
    ):
        raise ValueError("Advanced free mode must use scoped text, not structured records")
    if document["editor_mode"] == "stride" and (document["free_threat_model"] or document["free_risks"]):
        raise ValueError("STRIDE mode must use structured records")
    components = {row["id"]: set(row["variant_ids"]) for row in document["components"]}
    elements = components | {row["id"]: set(row["variant_ids"]) for row in document["interactions"]}
    threats = {row["id"]: set(row["variant_ids"]) for row in document["threats"]}
    for rows, keys, available in (
        (document["interactions"], ("sourceId", "destinationId"), components),
        (document["threats"], ("targetIds",), elements),
        (document["risks"], ("threatId",), threats),
    ):
        for row in rows:
            for key in keys:
                references = row[key] if key == "targetIds" else [row[key]]
                for identifier in references:
                    if identifier in available and not set(row["variant_ids"]) <= available[identifier]:
                        raise ValueError(f"{row['id']} applies to variants where {identifier} is unavailable")


def response(project_id: uuid.UUID) -> dict:
    pc, document, variants = load_document(project_id)
    return {"project_id": str(project_id), "description": pc.description if pc else None,
            "revision": pc.context_revision if pc else 0, "context": document,
            "variants": [{"id": str(variant.id), "name": variant.name} for variant in variants]}


def _store(project_id: uuid.UUID, pc: ProjectContext | None, before: dict, after: dict,
           variants: list[Variant], expected_revision: int, description: str | None,
           commit: bool = True, expected_variant: tuple[uuid.UUID, dict] | None = None) -> dict:
    validate_document(after, {str(variant.id) for variant in variants})
    for row in _all_rows(after):
        row["variant_ids"] = [str(variant.id) for variant in variants if str(variant.id) in row["variant_ids"]]
    if pc is None:
        try:
            with db.session.begin_nested():
                pc = ProjectContext(project_id=project_id, context_revision=0, description=None)
                db.session.add(pc)
                db.session.flush()
        except IntegrityError as exc:
            raise ContextConflict("Project context was created by another writer. Reload before saving.") from exc
    old_description = pc.description
    values: dict[str, Any] = {"shared_context": after, "context_revision": expected_revision + 1,
                              "description": description}
    if old_description != description:
        values["updated_at"] = datetime.now(timezone.utc)
    statement = db.update(ProjectContext).where(
        ProjectContext.project_id == project_id, ProjectContext.context_revision == expected_revision,
    )
    if expected_variant is not None:
        variant_identifier, expected = expected_variant
        vc = VariantContext.get_by_variant(variant_identifier)
        if vc is None:
            if any(value is not None for value in expected.values()):
                raise ContextConflict("The saved variant context changed. Reload before saving.")
        else:
            statement = statement.where(db.select(VariantContext.id).where(
                VariantContext.variant_id == variant_identifier,
                *(getattr(VariantContext, key) == value for key, value in expected.items()),
            ).exists())
    statement = statement.values(**values).returning(ProjectContext.id)
    if db.session.execute(statement).scalar_one_or_none() is None:
        raise ContextConflict("The saved project context changed. Keep your drafts and reload before saving.")
    comparison = convert_mode(before, after["editor_mode"], [str(variant.id) for variant in variants])
    changed = []
    for variant in variants:
        identifier = str(variant.id)
        fields = project_variant(after, identifier)
        content_changed = any(project_variant(comparison, identifier)[key] != value
                              for key, value in fields.items() if key != "editor_mode")
        existing = VariantContext.get_by_variant(variant.id)
        timestamp = existing.updated_at if existing else None
        vc = VariantContext.upsert(variant.id, **fields, commit=False, _sync_shared=False)
        if not content_changed:
            vc.updated_at = timestamp
        else:
            changed.append(identifier)
    if commit:
        db.session.commit()
    else:
        db.session.flush()
    return response(project_id) | {
        "changed_variant_ids": changed, "description_changed": old_description != description,
    }


def write_variant(variant_id: uuid.UUID, values: dict, commit: bool = True, partial: bool = False,
                  expected: dict | None = None) -> VariantContext:
    variant = Variant.get_by_id(variant_id)
    assert variant is not None
    pc, before, variants = load_document(variant.project_id)
    assert pc is not None
    if partial:
        values = project_variant(before, str(variant_id)) | values
    after = convert_mode(before, values.get("editor_mode") or before["editor_mode"],
                         [str(variant.id) for variant in variants])
    _replace_variant(after, str(variant_id), values)
    _store(variant.project_id, pc, before, after, variants, pc.context_revision, pc.description, commit,
           (variant_id, expected) if expected is not None else None)
    vc = VariantContext.get_by_variant(variant_id)
    assert vc is not None
    return vc


def prepare_section(project_id: uuid.UUID, body: dict) -> tuple:
    if (body.keys() - {"section", "context", "expected_revision", "description", "dry_run"}
            or type(body.get("expected_revision")) is not int or body["expected_revision"] < 0
            or ("dry_run" in body and type(body["dry_run"]) is not bool)):
        raise ValueError("Supply an integer expected_revision and an optional boolean dry_run")
    pc, before, variants = load_document(project_id)
    if body.get("expected_revision") != (pc.context_revision if pc else 0):
        raise ContextConflict("The saved project context changed. Keep your drafts and reload before saving.")
    if not isinstance(body.get("context"), dict) or body.get("section") not in (
        "context", "system", "threat_model", "risks",
    ):
        raise ValueError("Supply a context section and its shared entries")
    draft, section = body["context"], body["section"]
    identifiers = [str(variant.id) for variant in variants]
    mode = draft.get("editor_mode")
    if mode not in ("stride", "free"):
        raise ValueError("editor_mode must be stride or free")
    if section != "context" and mode != before["editor_mode"]:
        raise ValueError("Save Editor mode in Context before saving other sections")
    source = deepcopy(before)
    if section == "context":
        if not isinstance(draft.get("fields"), dict):
            raise ValueError("Supply the scoped text fields")
        for key in CONTEXT_FIELDS:
            source["fields"][key] = deepcopy(draft["fields"].get(key))
        validate_document(source, set(identifiers))
    baseline = convert_mode(source, mode, identifiers)
    after = deepcopy(baseline)
    fields = CONTEXT_FIELDS if section == "context" else ARCHITECTURE_FIELDS if section == "system" else ()
    if fields:
        if not isinstance(draft.get("fields"), dict):
            raise ValueError("Supply the scoped text fields")
        for key in fields:
            after["fields"][key] = deepcopy(draft["fields"].get(key))
    collections = {
        "context": (),
        "system": ("components", "interactions") if mode == "stride" else (),
        "threat_model": ("threats", "threat_notes") if mode == "stride" else ("free_threat_model",),
        "risks": ("risks", "risk_notes") if mode == "stride" else ("free_risks",),
    }[section]
    if section == "system" and mode == "free":
        raise ValueError("Save combined system/threat text from Threat model in Advanced free mode")
    for key in collections:
        after[key] = deepcopy(draft.get(key))
    validate_document(after, set(identifiers))
    old_elements = {row["id"]: set(row["variant_ids"]) for key in ("components", "interactions", "threats")
                    for row in baseline[key]}
    new_elements = {row["id"]: set(row["variant_ids"]) for key in ("components", "interactions", "threats")
                    for row in after[key]}
    old_missing = {(row["id"], target, identifier)
                   for row in [*baseline["interactions"], *baseline["threats"], *baseline["risks"]]
                   for identifier in _references(row) if identifier and identifier not in old_elements
                   for target in row["variant_ids"]}
    if (set(new_elements) - set(old_elements)) & {identifier for _, _, identifier in old_missing}:
        raise ValueError("New identifiers must not reuse unavailable references")
    for row in [*after["interactions"], *after["threats"], *after["risks"]]:
        for identifier in _references(row):
            if not identifier:
                continue
            if identifier not in new_elements and identifier not in old_elements and any(
                (row["id"], target, identifier) not in old_missing for target in row["variant_ids"]
            ):
                raise ValueError(f"Save the referenced system element or threat {identifier} first")
            if identifier in old_elements and any(
                target in old_elements[identifier] and target not in new_elements.get(identifier, set())
                for target in row["variant_ids"]
            ):
                raise ValueError(f"Save referencing entries before removing {identifier} from their variants")
    description = body.get("description", pc.description if pc else None) if section == "context" else (
        pc.description if pc else None
    )
    if description is not None and not isinstance(description, str):
        raise ValueError("Project description must be text or null")
    return pc, before, after, variants, description


def save_section(project_id: uuid.UUID, body: dict) -> dict:
    pc, before, after, variants, description = prepare_section(project_id, body)
    if body.get("dry_run"):
        comparison = convert_mode(before, after["editor_mode"], [str(variant.id) for variant in variants])
        return {"changed_variant_ids": [str(variant.id) for variant in variants if (
            project_variant(comparison, str(variant.id)) != project_variant(after, str(variant.id))
        )], "description_changed": description != (pc.description if pc else None)}
    return _store(project_id, pc, before, after, variants, body["expected_revision"], description)


def export_shared(project_id: uuid.UUID, names: list[str]) -> dict:
    """Export one canonical document, using portable variant names."""
    _, document, variants = load_document(project_id)
    selected = {str(variant.id): variant.name for variant in variants if variant.name in names}
    for rows in [*document["fields"].values(), *(document[key] for key in COLLECTIONS)]:
        for row in rows:
            row["variant_names"] = [selected[target] for target in row.pop("variant_ids") if target in selected]
        rows[:] = [row for row in rows if row["variant_names"]]
    return document


def import_shared(project_id: uuid.UUID, document: dict, names: dict[str, str], description: str | None) -> None:
    """Replace selected recipients without replacing other variants' shared entries."""
    incoming = deepcopy(document)
    for rows in [*incoming["fields"].values(), *(incoming[key] for key in COLLECTIONS)]:
        for row in rows:
            row["variant_ids"] = [names[name] for name in row.pop("variant_names") if name in names]
        rows[:] = [row for row in rows if row["variant_ids"]]
    pc, before, variants = load_document(project_id)
    after = convert_mode(before, incoming["editor_mode"], [str(variant.id) for variant in variants])
    for rows in [*after["fields"].values(), *(after[key] for key in COLLECTIONS)]:
        for target in names.values():
            _remove_target(rows, target)
    declared = {row["id"] for row in _all_rows(after)}
    incoming_ids = {row["id"] for row in _all_rows(incoming)}
    missing = _used_ids(incoming) - incoming_ids - {""}
    mapping: dict[str, str] = {}
    for identifier in sorted(missing & declared):
        mapping[identifier] = _allocate(after, identifier[0], incoming_ids | missing | set(mapping.values()))
    for source, destination in [
        *((incoming["fields"][key], after["fields"][key]) for key in incoming["fields"]),
        *((incoming[key], after[key]) for key in COLLECTIONS),
    ]:
        for row in source:
            value = {key: item for key, item in row.items() if key not in ("id", "variant_ids")}
            for key in ("sourceId", "destinationId", "threatId"):
                if key in value:
                    value[key] = mapping.get(value[key], value[key])
            if "targetIds" in value:
                value["targetIds"] = [mapping.get(target, target) for target in value["targetIds"]]
            existing = next((item for item in destination if item["id"] == row["id"] and {
                key: item for key, item in item.items() if key not in ("id", "variant_ids")
            } == value), None)
            # Retain common identity unless merging would reorder an imported recipient's records.
            merge = existing is not None and all(
                not any(target in item["variant_ids"] for item in destination[destination.index(existing) + 1:])
                for target in row["variant_ids"]
            )
            if merge:
                assert existing is not None
                existing["variant_ids"].extend(row["variant_ids"])
                mapping[row["id"]] = existing["id"]
                continue
            preferred = row["id"]
            identifier = preferred if preferred not in _used_ids(after) else _allocate(
                after, preferred[0], incoming_ids | set(mapping.values()),
            )
            mapping[preferred] = identifier
            destination.append({"id": identifier, "variant_ids": row["variant_ids"], **value})
    _store(project_id, pc, before, after, variants, pc.context_revision if pc else 0, description, commit=False)

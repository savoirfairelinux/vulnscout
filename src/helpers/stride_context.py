# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Structured context interchange and the readable STRIDE text used by AI tools."""

import re
from typing import Any


CATEGORIES = (
    "Spoofing", "Tampering", "Repudiation", "Information disclosure",
    "Denial of service", "Elevation of privilege",
)
SYSTEM_FIELDS = (
    ("scope", "System scope and assets"), ("actors", "Actors and access"),
    ("entry_points", "Entry points and data flows"), ("trust_boundaries", "Trust boundaries"),
)
COMPONENT_FIELDS = (("name", "Name"), ("description", "Description / role"), ("trustZone", "Trust zone"))
INTERACTION_FIELDS = (
    ("name", "Name"), ("sourceId", "Source component ID"), ("destinationId", "Destination component ID"),
    ("protocol", "Interface / protocol"), ("description", "Data / commands"), ("trustBoundary", "Trust boundary"),
)
THREAT_FIELDS = (("category", "STRIDE category"), ("description", "Description"))
RISK_FIELDS = (
    ("threatId", "Threat ID"), ("likelihood", "Likelihood"), ("impact", "Impact"),
    ("mitigation", "Mitigation"), ("decision", "Residual risk / decision"),
)
MODEL_TITLE = "# STRIDE threat model"
RISKS_TITLE = "# STRIDE risk register"
MARKER = "<!-- VulnScout STRIDE v1 -->"
SYSTEM_MARKER = "<!-- VulnScout STRIDE v2 -->"


def _object(value: Any, keys: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or not keys <= value.keys() or value.keys() - keys - (optional or set()):
        raise ValueError(f"Expected an object with fields: {', '.join(sorted(keys))}")
    return value


def _strings(value: dict[str, Any], keys: list[str]) -> None:
    if any(not isinstance(value[key], str) for key in keys):
        raise ValueError(f"Fields must be text: {', '.join(keys)}")


def _id(value: str, prefix: str, blank: bool = False) -> None:
    if not (blank and value == "") and not re.fullmatch(rf"[{prefix}][1-9][0-9]*", value):
        raise ValueError(f"Invalid {prefix} identifier: {value!r}")


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError("Records must be an array of objects")
    return value


def validate_stride(system: Any, model: Any, register: Any) -> tuple[dict, dict, dict]:
    """Validate structure, enums and identifier namespaces; retain unavailable references."""
    system = _object(system, {key for key, _ in SYSTEM_FIELDS} | {"components", "interactions"})
    _strings(system, [key for key, _ in SYSTEM_FIELDS])
    ids: set[str] = set()
    for key, prefix, fields in (("components", "C", COMPONENT_FIELDS), ("interactions", "I", INTERACTION_FIELDS)):
        for row in _rows(system[key]):
            _object(row, {"id"} | {name for name, _ in fields})
            _strings(row, ["id"] + [name for name, _ in fields])
            _id(row["id"], prefix)
            if row["id"] in ids:
                raise ValueError(f"Duplicate identifier: {row['id']}")
            ids.add(row["id"])
            if key == "interactions":
                _id(row["sourceId"], "C", blank=True)
                _id(row["destinationId"], "C", blank=True)
    model = _object(model, {"threats", "notes"})
    _strings(model, ["notes"])
    for threat in _rows(model["threats"]):
        _object(threat, {"id", "category", "description", "targetIds"})
        _strings(threat, ["id", "category", "description"])
        _id(threat["id"], "T")
        if threat["id"] in ids:
            raise ValueError(f"Duplicate identifier: {threat['id']}")
        ids.add(threat["id"])
        if threat["category"] not in ("", *CATEGORIES):
            raise ValueError(f"Invalid STRIDE category: {threat['category']}")
        targets = threat["targetIds"]
        if not isinstance(targets, list) or any(not isinstance(target, str) for target in targets):
            raise ValueError("targetIds must be an array of system identifiers")
        if len(set(targets)) != len(targets):
            raise ValueError("Duplicate threat target")
        for target in targets:
            _id(target, "CI")
    register = _object(register, {"risks", "notes"})
    _strings(register, ["notes"])
    for risk in _rows(register["risks"]):
        _object(risk, {key for key, _ in RISK_FIELDS}, {"legacyThreat"})
        _strings(risk, [key for key, _ in RISK_FIELDS])
        _id(risk["threatId"], "T", blank=True)
        if any(risk[key] not in ("", "Low", "Medium", "High") for key in ("likelihood", "impact")):
            raise ValueError("Risk ratings must be blank, Low, Medium or High")
        if "legacyThreat" in risk:
            legacy = _object(risk["legacyThreat"], {"category", "description"})
            _strings(legacy, ["category", "description"])
            if legacy["category"] not in ("", *CATEGORIES) or risk["threatId"]:
                raise ValueError("A legacy scenario must be unlinked and have a valid STRIDE category")
    return system, model, register


def _sections(title: str, sections: list[tuple[str, str]], marker: str = MARKER) -> str:
    if not any(value.strip() for _, value in sections):
        return ""
    blocks = [
        f"## {label}\n" + "\n".join(f"> {line}" if line else ">" for line in value.split("\n"))
        for label, value in sections
    ]
    return "\n\n".join([title, *blocks, marker])


def serialize_model(system: dict, model: dict, register: dict, preserve_records: bool = False) -> str:
    has_content = any(system[key].strip() for key, _ in SYSTEM_FIELDS) or model["notes"].strip()
    has_content = has_content or any(threat["description"].strip() for threat in model["threats"])
    has_content = has_content or any(
        row[key].strip()
        for collection, fields in (("components", COMPONENT_FIELDS), ("interactions", INTERACTION_FIELDS))
        for row in system[collection] for key, _ in fields
    )
    if not has_content and not (preserve_records and model["threats"]):
        return ""
    targets = {target for threat in model["threats"] for target in threat["targetIds"]}
    endpoints = {row[key] for row in system["interactions"] for key in ("sourceId", "destinationId")}
    sections = [(label, system[key]) for key, label in SYSTEM_FIELDS]
    components = [
        row for row in system["components"]
        if row["id"] in targets | endpoints or any(row[key].strip() for key, _ in COMPONENT_FIELDS)
    ]
    interactions = [
        row for row in system["interactions"]
        if row["id"] in targets or any(row[key].strip() for key, _ in INTERACTION_FIELDS)
    ]
    has_system = bool(components or interactions or targets)
    for collection, title, fields in (
        (components, "Component", COMPONENT_FIELDS),
        (interactions, "Interaction", INTERACTION_FIELDS),
    ):
        for number, row in enumerate(collection, 1):
            sections.append((f"{title} {number} / ID", row["id"]))
            sections.extend((f"{title} {number} / {label}", row[key]) for key, label in fields)
    references = {risk["threatId"] for risk in register["risks"]}
    threats = [row for row in model["threats"] if row["category"] or row["description"].strip()
               or row["targetIds"] or row["id"] in references]
    for number, threat in enumerate(threats, 1):
        sections.append((f"Threat {number} / ID", threat["id"]))
        sections.extend((f"Threat {number} / {label}", threat[key]) for key, label in THREAT_FIELDS)
        if has_system:
            sections.append((f"Threat {number} / Affected system elements", "\n".join(threat["targetIds"])))
    sections.append(("Additional threat model notes", model["notes"]))
    return _sections(MODEL_TITLE, sections, SYSTEM_MARKER if has_system else MARKER)


def serialize_register(register: dict) -> str:
    sections: list[tuple[str, str]] = []
    records = [risk for risk in register["risks"] if any(risk[key].strip() for key, _ in RISK_FIELDS)
               or any(value.strip() for value in risk.get("legacyThreat", {}).values())]
    for number, risk in enumerate(records, 1):
        fields = [(label, risk[key]) for key, label in RISK_FIELDS]
        if "legacyThreat" in risk:
            legacy = risk["legacyThreat"]
            fields = [("STRIDE category", legacy["category"]), ("Threat scenario", legacy["description"]), *fields[1:]]
        sections.extend((f"Risk {number} / {label}", value) for label, value in fields)
    sections.append(("Additional risk notes", register["notes"]))
    return _sections(RISKS_TITLE, sections)


def _parse_sections(text: str, title: str) -> tuple[list[tuple[str, str]], str]:
    blocks = text.strip().split("\n\n")
    if blocks[0] != title or blocks[-1] not in (MARKER, SYSTEM_MARKER):
        raise ValueError("Not a STRIDE text template")
    sections = []
    for block in blocks[1:-1]:
        heading, *lines = block.split("\n")
        if (not heading.startswith("## ") or not lines
                or any(line != ">" and not line.startswith("> ") for line in lines)):
            raise ValueError("Malformed STRIDE text section")
        sections.append((heading[3:], "\n".join("" if line == ">" else line[2:] for line in lines)))
    if _sections(title, sections, blocks[-1]) != text.strip():
        raise ValueError("Noncanonical STRIDE text")
    return sections, blocks[-1]


def _read_row(sections: list, prefix: str, fields: tuple) -> dict:
    if len(sections) != len(fields) or any(
        label != f"{prefix} / {fields[index][1]}" for index, (label, _) in enumerate(sections)
    ):
        raise ValueError(f"Malformed {prefix} fields")
    return {key: sections[index][1] for index, (key, _) in enumerate(fields)}


def parse_model(text: str) -> tuple[dict, dict]:
    system: dict[str, Any] = {key: "" for key, _ in SYSTEM_FIELDS} | {"components": [], "interactions": []}
    model: dict[str, Any] = {"threats": [], "notes": ""}
    if not text.strip():
        return system, model
    sections, marker = _parse_sections(text, MODEL_TITLE)
    if len(sections) < len(SYSTEM_FIELDS) + 1 or sections[-1][0] != "Additional threat model notes":
        raise ValueError("Malformed STRIDE model")
    for index, (key, label) in enumerate(SYSTEM_FIELDS):
        if sections[index][0] != label:
            raise ValueError("Malformed system fields")
        system[key] = sections[index][1]
    model["notes"] = sections[-1][1]
    entries = sections[len(SYSTEM_FIELDS):-1]
    if marker == SYSTEM_MARKER:
        for collection, title, fields in (
            ("components", "Component", COMPONENT_FIELDS), ("interactions", "Interaction", INTERACTION_FIELDS),
        ):
            fields = (("id", "ID"), *fields)
            while entries and entries[0][0].startswith(f"{title} "):
                prefix = f"{title} {len(system[collection]) + 1}"
                system[collection].append(_read_row(entries[:len(fields)], prefix, fields))
                entries = entries[len(fields):]
    category_labels = [f"{letter} - {name}" for letter, name in zip("STRIDE", CATEGORIES)]
    if marker == MARKER and [label for label, _ in entries] == category_labels:
        model["threats"] = [
            {"id": f"T{index + 1}", "category": name, "description": value, "targetIds": []}
            for index, (name, value) in enumerate(
                (CATEGORIES[i], value) for i, (_, value) in enumerate(entries) if value
            )
        ]
    else:
        threat_fields: tuple[tuple[str, str], ...] = THREAT_FIELDS
        if marker == SYSTEM_MARKER or (entries and entries[0][0] == "Threat 1 / ID"):
            threat_fields = (("id", "ID"), *threat_fields)
        if marker == SYSTEM_MARKER:
            threat_fields = (*threat_fields, ("targetIds", "Affected system elements"))
        while entries:
            number = len(model["threats"]) + 1
            row = _read_row(entries[:len(threat_fields)], f"Threat {number}", threat_fields)
            row.setdefault("id", f"T{number}")
            row["targetIds"] = row.get("targetIds", "").split("\n") if row.get("targetIds") else []
            model["threats"].append(row)
            entries = entries[len(threat_fields):]
    validate_stride(system, model, {"risks": [], "notes": ""})
    return system, model


def parse_register(text: str) -> dict:
    if not text.strip():
        return {"risks": [], "notes": ""}
    sections, marker = _parse_sections(text, RISKS_TITLE)
    if marker != MARKER or not sections or sections[-1][0] != "Additional risk notes":
        raise ValueError("Malformed risk register")
    register: dict[str, Any] = {"risks": [], "notes": sections[-1][1]}
    entries = sections[:-1]
    while entries:
        prefix = f"Risk {len(register['risks']) + 1}"
        legacy = entries[0][0] == f"{prefix} / STRIDE category"
        fields = (
            (("category", "STRIDE category"), ("description", "Threat scenario"), *RISK_FIELDS[1:])
            if legacy else RISK_FIELDS
        )
        row = _read_row(entries[:len(fields)], prefix, fields)
        if legacy:
            row["legacyThreat"] = {key: row.pop(key) for key in ("category", "description")}
            row["threatId"] = ""
        register["risks"].append(row)
        entries = entries[len(fields):]
    validate_stride(*parse_model(""), register)
    if serialize_register(register) != text.strip():
        raise ValueError("Noncanonical risk register")
    return register


def export_fields(threat_text: str | None, risk_text: str | None, mode: str | None) -> dict[str, Any]:
    if mode != "free":
        try:
            system, model = parse_model(threat_text or "")
        except ValueError:
            if mode == "stride":
                system, model = parse_model("")
                model["notes"] = threat_text or ""
            else:
                mode = "free"
        try:
            register = parse_register(risk_text or "")
        except ValueError:
            if mode == "stride":
                register = {"risks": [], "notes": risk_text or ""}
            else:
                mode = "free"
        if mode != "free":
            return {"editor_mode": "stride", "system": system, "threat_model": model, "risks": register}
    return {"editor_mode": "free", "threat_model": threat_text, "risks": risk_text}


def import_fields(entry: dict) -> dict[str, Any]:
    _object(entry, {"variant_name", "editor_mode"}, {
        "variant_description", "codebase_paths", "environment", "other_info", "system", "threat_model", "risks",
    })
    for key in ("variant_description", "environment", "other_info"):
        if entry.get(key) is not None and not isinstance(entry[key], str):
            raise ValueError(f"{key} must be text or null")
    paths = entry.get("codebase_paths", [])
    if not isinstance(paths, list) or any(not isinstance(path, str) or ";" in path for path in paths):
        raise ValueError("codebase_paths must be an array of paths without semicolons")
    values = {key: entry.get(key) for key in ("variant_description", "environment", "other_info")}
    values.update(codebase_path=";".join(paths) if paths else None, editor_mode=entry["editor_mode"])
    if entry["editor_mode"] == "free":
        if "system" in entry or any(entry.get(key) is not None and not isinstance(entry[key], str)
                                    for key in ("threat_model", "risks")):
            raise ValueError("Advanced free mode requires text threat_model and risks, without a system object")
        return values | {key: entry.get(key) for key in ("threat_model", "risks")}
    if entry["editor_mode"] != "stride":
        raise ValueError("editor_mode must be stride or free")
    system, model, register = validate_stride(*(entry.get(key) for key in ("system", "threat_model", "risks")))
    threat_text, risk_text = serialize_model(system, model, register), serialize_register(register)
    if parse_model(threat_text) != (system, model) or parse_register(risk_text) != register:
        raise ValueError("Empty placeholder records cannot be imported; omit them or record meaningful context")
    return values | {"threat_model": threat_text or None, "risks": risk_text or None}

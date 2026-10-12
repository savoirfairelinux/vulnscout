# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Backend/frontend parity and lossless structured-context validation."""

import json
import re
from pathlib import Path

import pytest

from src.helpers.stride_context import (
    CATEGORIES, MARKER, MODEL_TITLE, SYSTEM_FIELDS, _sections,
    export_fields, import_fields, parse_model, parse_register, serialize_model, serialize_register,
)


@pytest.fixture()
def fixture():
    return json.loads((Path(__file__).parents[1] / "fixtures/stride_context_v2.json").read_text())


def test_shared_frontend_text_fixture_roundtrips_without_changing_ids_or_whitespace(fixture):
    variant, text = fixture["variant"], fixture["text"]
    values = import_fields(variant)
    assert values["threat_model"] == text["threatModel"]
    assert values["risks"] == text["risks"]
    assert values["codebase_path"] == "/workspace/firmware;/workspace/drivers"
    assert export_fields(values["threat_model"], values["risks"], None) == {
        key: variant[key] for key in ("editor_mode", "system", "threat_model", "risks")
    }


@pytest.mark.parametrize("mode", [None, "free"])
def test_free_text_export_and_import_preserve_exact_values(mode):
    text = "  Custom\n\n## user heading\n\r\n\tNotes  \n"
    fields = export_fields(text, "", mode)
    assert fields == {"editor_mode": "free", "threat_model": text, "risks": ""}
    values = import_fields({"variant_name": "default", **fields})
    assert values["threat_model"] == text
    assert values["risks"] == ""


def test_explicit_free_mode_wins_over_recognizable_stride_text(fixture):
    text = fixture["text"]
    assert export_fields(text["threatModel"], text["risks"], "free") == {
        "editor_mode": "free", "threat_model": text["threatModel"], "risks": text["risks"],
    }


def test_partial_and_empty_contexts_roundtrip():
    fields = export_fields(None, None, None)
    assert fields["editor_mode"] == "stride"
    assert fields["threat_model"] == {"threats": [], "notes": ""}
    values = import_fields({"variant_name": "default", **fields})
    assert values["threat_model"] is None
    assert values["risks"] is None
    fields["system"]["scope"] = "Known scope only"
    assert export_fields(**{
        "threat_text": import_fields({"variant_name": "default", **fields})["threat_model"],
        "risk_text": None, "mode": None,
    }) == fields


def test_explicit_guided_mode_preserves_unrecognized_sections_as_notes(fixture):
    text = fixture["text"]
    fields = export_fields(text["threatModel"], "Custom risk\n\n notes ", "stride")
    assert fields["system"] == fixture["variant"]["system"]
    assert fields["risks"] == {"risks": [], "notes": "Custom risk\n\n notes "}
    fields = export_fields("Custom system", text["risks"], "stride")
    assert fields["threat_model"] == {"threats": [], "notes": "Custom system"}
    assert fields["risks"] == fixture["variant"]["risks"]
    assert export_fields(text["threatModel"], "Custom risk", None)["editor_mode"] == "free"


@pytest.mark.parametrize("path, value", [
    (("editor_mode",), "unknown"),
    (("editor_mode",), []),
    (("environment",), 12),
    (("codebase_paths",), "/src"),
    (("codebase_paths",), [None]),
    (("codebase_paths",), ["/src;other"]),
    (("system",), None),
    (("system", "scope"), []),
    (("system", "components"), {}),
    (("system", "components"), [None]),
    (("system", "components", 0, "id"), "T2"),
    (("system", "components", 1, "id"), "C2"),
    (("system", "interactions", 0, "sourceId"), "I3"),
    (("system", "interactions", 0, "destinationId"), "C0"),
    (("system", "interactions", 0, "id"), "C3"),
    (("threat_model", "threats", 0, "id"), "T0"),
    (("threat_model", "threats", 1, "id"), "T4"),
    (("threat_model", "threats", 0, "category"), "Unknown"),
    (("threat_model", "threats", 0, "description"), None),
    (("threat_model", "threats", 0, "targetIds"), "C2"),
    (("threat_model", "threats", 0, "targetIds"), [None]),
    (("threat_model", "threats", 0, "targetIds"), ["C2", "C2"]),
    (("threat_model", "threats", 0, "targetIds"), ["T4"]),
    (("risks", "risks", 0, "threatId"), "C2"),
    (("risks", "risks", 0, "likelihood"), "Critical"),
    (("risks", "risks", 0, "impact"), None),
    (("risks", "risks", 2, "legacyThreat"), None),
    (("risks", "risks", 2, "legacyThreat", "category"), "Unknown"),
    (("risks", "risks", 2, "threatId"), "T4"),
    (("risks", "notes"), None),
    (("extra",), "Must not discard"),
    (("system", "extra"), "Must not discard"),
])
def test_invalid_structured_data_is_rejected(fixture, path, value):
    variant = fixture["variant"]
    target = variant
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        import_fields(variant)


@pytest.mark.parametrize("change", [
    {"system": {}}, {"threat_model": []}, {"risks": 4},
])
def test_free_mode_rejects_structured_or_invalid_text(change):
    with pytest.raises(ValueError):
        import_fields({"variant_name": "default", "editor_mode": "free", **change})


@pytest.mark.parametrize("collection, record", [
    ("components", {"id": "C9", "name": "", "description": "", "trustZone": ""}),
    ("interactions", {"id": "I9", "name": "", "sourceId": "", "destinationId": "",
                      "protocol": "", "description": "", "trustBoundary": ""}),
    ("threats", {"id": "T9", "category": "", "description": "", "targetIds": []}),
    ("risks", {"threatId": "", "likelihood": "", "impact": "", "mitigation": "", "decision": ""}),
])
def test_blank_editor_placeholders_are_not_silently_discarded(fixture, collection, record):
    variant = fixture["variant"]
    parent = variant["system"] if collection in ("components", "interactions") else (
        variant["threat_model"] if collection == "threats" else variant["risks"]
    )
    parent[collection].append(record)
    with pytest.raises(ValueError, match="placeholder"):
        import_fields(variant)


def test_missing_endpoints_and_referenced_blank_records_are_preserved(fixture):
    variant = fixture["variant"]
    variant["system"]["interactions"][0]["sourceId"] = "C99"
    variant["system"]["components"][0].update(name="", description="", trustZone="")
    variant["threat_model"]["threats"][0].update(category="", description="")
    values = import_fields(variant)
    assert export_fields(values["threat_model"], values["risks"], "stride")["system"] == variant["system"]


def test_path_arrays_preserve_existing_delimited_storage_including_empty_segments():
    values = import_fields({
        "variant_name": "default", "editor_mode": "free", "codebase_paths": ["", "/src ", ""],
    })
    assert values["codebase_path"] == ";/src ;"
    assert import_fields({"variant_name": "default", "editor_mode": "free", "codebase_paths": [""]})[
        "codebase_path"
    ] == ""


def test_older_id_and_category_templates_are_readable(fixture):
    variant = fixture["variant"]
    system, model = variant["system"], variant["threat_model"]
    system.update(components=[], interactions=[])
    for threat in model["threats"]:
        threat["targetIds"] = []
    text = serialize_model(system, model, variant["risks"])
    assert text.endswith(MARKER)
    assert parse_model(text) == (system, model)
    without_ids = re.sub(r"\n\n## Threat \d+ / ID\n> T\d+", "", text)
    parsed = parse_model(without_ids)[1]
    assert [threat["id"] for threat in parsed["threats"]] == ["T1", "T2"]
    sections = [(label, system[key]) for key, label in SYSTEM_FIELDS]
    sections += [(f"{letter} - {category}", "Scenario" if letter in "TD" else "")
                 for letter, category in zip("STRIDE", CATEGORIES)]
    sections.append(("Additional threat model notes", ""))
    parsed = parse_model(_sections(MODEL_TITLE, sections))[1]
    assert [(threat["id"], threat["category"]) for threat in parsed["threats"]] == [
        ("T1", "Tampering"), ("T2", "Denial of service"),
    ]


@pytest.mark.parametrize("source, old, new", [
    ("threatModel", "> C5", "> C2"),
    ("threatModel", "> I3", "> I0"),
    ("threatModel", "> Tampering", "> Unknown"),
    ("threatModel", "## Component 1 / Name", "## Component 2 / Name"),
    ("threatModel", "## Actors and access", "## Other section"),
    ("threatModel", "## Additional threat model notes", "## Unknown notes"),
    ("threatModel", "> Firmware", "Firmware"),
    ("threatModel", "<!-- VulnScout STRIDE v2 -->", "<!-- Unknown -->"),
    ("risks", "> Medium", "> Unknown"),
    ("risks", "> T4", "> C4"),
    ("risks", "## Risk 1 / Impact", "## Wrong heading"),
    ("risks", "## Additional risk notes", "## Wrong notes"),
    ("risks", "<!-- VulnScout STRIDE v1 -->", "<!-- VulnScout STRIDE v2 -->"),
])
def test_malformed_markdown_remains_lossless_free_text(fixture, source, old, new):
    text = fixture["text"]
    text[source] = text[source].replace(old, new)
    fields = export_fields(text["threatModel"], text["risks"], None)
    assert fields["editor_mode"] == "free"
    assert fields["threat_model"] == text["threatModel"]
    assert fields["risks"] == text["risks"]


def test_blank_sections_do_not_invent_saved_context():
    system, model = parse_model("")
    assert serialize_model(system, model, {"risks": [], "notes": ""}) == ""
    assert serialize_register({"risks": [], "notes": ""}) == ""
    assert _sections(MODEL_TITLE, [("Unknown", "")]) == ""


def test_noncanonical_empty_templates_are_retained_as_free_text():
    empty_risk = (
        "# STRIDE risk register\n\n## Risk 1 / Threat ID\n>\n\n## Risk 1 / Likelihood\n>\n\n"
        "## Risk 1 / Impact\n>\n\n## Risk 1 / Mitigation\n>\n\n## Risk 1 / Residual risk / decision\n>\n\n"
        "## Additional risk notes\n> A meaningful note\n\n<!-- VulnScout STRIDE v1 -->"
    )
    assert export_fields("", empty_risk, None)["risks"] == empty_risk
    empty_sections = "# STRIDE threat model\n\n## Additional threat model notes\n>\n\n" + MARKER
    assert export_fields(empty_sections, "", None)["editor_mode"] == "free"
    sections = [(label, "") for _, label in SYSTEM_FIELDS]
    sections += [(f"{letter} - {category}", " " if letter == "S" else "")
                 for letter, category in zip("STRIDE", CATEGORIES)]
    sections.append(("Additional threat model notes", ""))
    legacy = _sections(MODEL_TITLE, sections[:-1] + [("Additional threat model notes", "temporary")])
    legacy = legacy.replace("> temporary", ">")
    assert export_fields(legacy, "", None)["threat_model"] == legacy

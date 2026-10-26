# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Unit tests for the STRIDE threat-model validator."""

import copy

import pytest

from src.helpers.stride_model import (
    MAX_ROWS,
    MAX_TEXT,
    RISK_DESCRIPTION_MAX,
    SYSTEM_KEYS,
    StrideValidationError,
    empty_stride_model,
    normalize_stride_model,
    normalize_system,
    render_risks,
    render_threat_model,
)


def _model(**over):
    m = empty_stride_model()
    m["components"] = [
        {"id": "C1", "name": "OTA updater", "description": "", "trust_zone": "device"},
        {"id": "C2", "name": "Update server", "description": "", "trust_zone": "cloud"},
    ]
    m["interactions"] = [
        {"id": "I1", "name": "Download", "source_id": "C1", "destination_id": "C2",
         "interface": "HTTPS", "data": "image", "trust_boundary": "internet"},
    ]
    m["threats"] = [
        {"id": "T1", "category": "tampering", "description": "Swap image", "target_ids": ["C1", "I1"]},
    ]
    m["risks"] = [
        {"threat_id": "T1", "likelihood": "high", "impact": None, "mitigation": "", "residual": ""},
    ]
    m.update(over)
    return m


def _fields(model):
    with pytest.raises(StrideValidationError) as exc:
        normalize_stride_model(model)
    return exc.value.fields


def test_valid_model_round_trips():
    assert normalize_stride_model(_model()) == _model()


def test_missing_keys_are_filled():
    assert normalize_stride_model({}) == empty_stride_model()


def test_duplicate_component_id_rejected():
    m = _model()
    m["components"].append(dict(m["components"][0]))
    assert "components[2].id" in _fields(m)


@pytest.mark.parametrize("bad_id", ["X1", "C", "c1", "C01x", "C0"])
def test_id_pattern_enforced(bad_id):
    m = _model()
    m["components"][0]["id"] = bad_id
    assert "components[0].id" in _fields(m)


def test_component_name_required():
    m = _model()
    m["components"][0]["name"] = "  "
    assert "components[0].name" in _fields(m)


def test_interaction_name_optional():
    m = _model()
    m["interactions"][0]["name"] = ""
    assert normalize_stride_model(m)["interactions"][0]["name"] == ""


def test_interaction_endpoint_must_exist():
    m = _model()
    m["interactions"][0]["destination_id"] = "C9"
    assert _fields(m) == {"interactions[0].destination_id": "references an unknown id"}


@pytest.mark.parametrize("blank", ["", "  ", None])
def test_interaction_endpoints_required(blank):
    m = _model()
    m["interactions"][0]["source_id"] = blank
    m["interactions"][0]["destination_id"] = blank
    assert _fields(m) == {
        "interactions[0].source_id": "is required",
        "interactions[0].destination_id": "is required",
    }


def test_interaction_endpoints_must_differ():
    m = _model()
    m["interactions"][0]["destination_id"] = m["interactions"][0]["source_id"]
    assert _fields(m) == {"interactions[0].destination_id": "must differ from the source"}


def test_unknown_category_rejected():
    m = _model()
    m["threats"][0]["category"] = "phishing"
    assert _fields(m)["threats[0].category"].startswith("must be one of")


@pytest.mark.parametrize("blank", ["", None])
def test_threat_category_required(blank):
    m = _model()
    m["threats"][0]["category"] = blank
    assert _fields(m) == {"threats[0].category": "is required"}


@pytest.mark.parametrize("targets", [[], None, "missing"])
def test_threat_target_required(targets):
    m = _model()
    if targets == "missing":
        del m["threats"][0]["target_ids"]
    else:
        m["threats"][0]["target_ids"] = targets
    assert _fields(m) == {"threats[0].target_ids": "is required"}


def test_threat_target_must_exist():
    m = _model()
    m["threats"][0]["target_ids"] = ["C1", "I7"]
    assert "threats[0].target_ids" in _fields(m)


def test_risk_threat_must_exist():
    m = _model()
    m["risks"][0]["threat_id"] = "T4"
    assert _fields(m) == {"risks[0].threat_id": "references an unknown id"}


def test_risk_threat_required():
    m = _model()
    m["risks"][0]["threat_id"] = ""
    assert _fields(m) == {"risks[0].threat_id": "is required"}


def test_several_risks_may_share_a_threat():
    m = _model()
    m["risks"].append(dict(m["risks"][0]))
    assert len(normalize_stride_model(m)["risks"]) == 2


@pytest.mark.parametrize("rating", [None, "low", "medium", "high"])
def test_valid_ratings_accepted(rating):
    m = _model()
    m["risks"][0]["likelihood"] = rating
    assert normalize_stride_model(m)["risks"][0]["likelihood"] == rating


def test_invalid_rating_rejected():
    m = _model()
    m["risks"][0]["likelihood"] = "severe"
    assert "risks[0].likelihood" in _fields(m)


def test_row_cap():
    comps = [{"id": f"C{i}", "name": "n", "description": "", "trust_zone": ""}
             for i in range(1, MAX_ROWS + 2)]
    assert "components" in _fields(_model(components=comps, interactions=[], threats=[], risks=[]))


def test_text_cap():
    m = _model()
    m["components"][0]["description"] = "x" * (MAX_TEXT + 1)
    assert "components[0].description" in _fields(m)


def test_stale_notes_keys_dropped():
    model = normalize_stride_model(_model(notes="n", risk_notes="r"))
    assert set(model) == {"components", "interactions", "threats", "risks"}


def test_non_object_rejected():
    with pytest.raises(StrideValidationError):
        normalize_stride_model([])


def test_all_errors_reported_at_once():
    m = _model()
    m["components"][0]["name"] = ""
    m["threats"][0]["category"] = "nope"
    fields = _fields(m)
    assert "components[0].name" in fields
    assert "threats[0].category" in fields


def test_input_not_mutated():
    m = _model()
    m["components"][0]["name"] = "  padded  "
    snapshot = copy.deepcopy(m)
    normalize_stride_model(m)
    assert m == snapshot


def test_system_keeps_only_known_keys():
    assert normalize_system({"scope": "a", "extra": "x"}) == {
        "scope": "a", "actors": None, "entry_points": None, "trust_boundaries": None}


def test_system_rejects_non_string():
    with pytest.raises(StrideValidationError) as exc:
        normalize_system({"actors": 3})
    assert "system.actors" in exc.value.fields


def test_full_render_matches_shape():
    system = {"scope": "Gateway", "actors": None, "entry_points": "", "trust_boundaries": "LAN/WAN"}
    assert render_threat_model(system, _model()) == (
        "System scope and assets:\nGateway\n\n"
        "Trust boundaries:\nLAN/WAN\n\n"
        "Components:\n- C1 OTA updater (trust zone: device)\n- C2 Update server (trust zone: cloud)\n\n"
        "Interactions:\n- I1 Download: C1 OTA updater -> C2 Update server; interface: HTTPS; "
        "data: image; trust boundary: internet\n\n"
        "Threats:\nTampering\n- T1 [C1 OTA updater, I1 Download]: Swap image")


def test_all_empty_is_none():
    assert render_threat_model({k: None for k in SYSTEM_KEYS}, None) is None
    assert render_threat_model({}, empty_stride_model()) is None


def test_whitespace_only_sections_omitted():
    system = {"scope": "  \n", "actors": "Admin"}
    assert render_threat_model(system, None) == "Actors and access:\nAdmin"


def test_component_and_interaction_optional_parts_omitted():
    m = empty_stride_model()
    m["components"] = [
        {"id": "C1", "name": "A", "description": "desc", "trust_zone": ""},
        {"id": "C2", "name": "B", "description": "", "trust_zone": ""},
    ]
    m["interactions"] = [
        {"id": "I1", "name": "", "source_id": "C1", "destination_id": "C2",
         "interface": "", "data": "", "trust_boundary": ""},
    ]
    assert render_threat_model({}, m) == (
        "Components:\n- C1 A: desc\n- C2 B\n\n"
        "Interactions:\n- I1: C1 A -> C2 B")


def test_threats_grouped_in_stride_order():
    m = _model()
    m["threats"] = [
        {"id": "T1", "category": "tampering", "description": "Swap image", "target_ids": ["C1"]},
        {"id": "T2", "category": "spoofing", "description": "", "target_ids": []},
    ]
    out = render_threat_model({}, m)
    assert out is not None
    assert out.split("Threats:\n")[1] == (
        "Spoofing\n- T2\n"
        "Tampering\n- T1 [C1 OTA updater]: Swap image")


def _risk_model(**risk):
    m = _model()
    m["risks"] = [{"threat_id": "T1", "likelihood": None, "impact": None,
                   "mitigation": "", "residual": "", **risk}]
    return m


def test_risk_line_full():
    m = _risk_model(likelihood="high", impact="medium", mitigation="Sign images", residual="Accept")
    assert render_risks(m) == (
        "- T1 Tampering, Swap image \u2014 Likelihood: High, Impact: Medium. "
        "Mitigation: Sign images. Residual risk / decision: Accept")


def test_risk_line_partial():
    assert render_risks(_risk_model(likelihood="high")) == "- T1 Tampering, Swap image \u2014 Likelihood: High"


def test_risk_line_without_rating_starts_with_mitigation():
    assert render_risks(_risk_model(mitigation="Sign")) == "- T1 Tampering, Swap image \u2014 Mitigation: Sign"


def test_unrated_empty_risk_skipped_and_none():
    assert render_risks(_risk_model()) is None
    assert render_risks(None) is None


def test_long_threat_description_truncated():
    m = _risk_model(likelihood="low")
    m["threats"][0]["description"] = "x" * 200
    assert render_risks(m) == f"- T1 Tampering, {'x' * RISK_DESCRIPTION_MAX}\u2026 \u2014 Likelihood: Low"


def test_risk_with_unknown_threat_renders_id_only():
    m = _risk_model(likelihood="low")
    m["risks"][0]["threat_id"] = "T9"
    assert render_risks(m) == "- T9 \u2014 Likelihood: Low"


def test_threat_target_ids_must_not_repeat():
    m = _model()
    m["threats"][0]["target_ids"] = ["C1", "C1"]
    assert _fields(m) == {"threats[0].target_ids": "must not repeat an id"}


def test_rendered_target_text_is_bounded():
    big = "x" * 20000
    m = {
        "components": [{"id": f"C{i}", "name": big, "description": "", "trust_zone": ""} for i in range(1, 21)],
        "interactions": [],
        "threats": [{"id": "T1", "category": "spoofing", "description": "", "target_ids": [f"C{i}" for i in range(1, 21)]}],
        "risks": [],
    }
    with pytest.raises(StrideValidationError) as exc:
        normalize_stride_model(m)
    assert "threats" in exc.value.fields

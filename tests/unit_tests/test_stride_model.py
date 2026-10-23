# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Unit tests for the STRIDE threat-model validator."""

import copy

import pytest

from src.helpers.stride_model import (
    MAX_ROWS,
    MAX_TEXT,
    StrideValidationError,
    empty_stride_model,
    normalize_stride_model,
    normalize_system,
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
    assert "interactions[0].destination_id" in _fields(m)


def test_unknown_category_rejected():
    m = _model()
    m["threats"][0]["category"] = "phishing"
    assert "threats[0].category" in _fields(m)


def test_threat_target_must_exist():
    m = _model()
    m["threats"][0]["target_ids"] = ["C1", "I7"]
    assert "threats[0].target_ids" in _fields(m)


def test_risk_threat_must_exist():
    m = _model()
    m["risks"][0]["threat_id"] = "T4"
    assert "risks[0].threat_id" in _fields(m)


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
    assert "notes" in _fields(_model(notes="x" * (MAX_TEXT + 1)))


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

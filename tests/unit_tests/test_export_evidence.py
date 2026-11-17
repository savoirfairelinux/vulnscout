# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json

import pytest

from src.helpers import export_evidence as evidence


@pytest.mark.parametrize("data", [
    {}, {"annotations": None, "@graph": None, "metadata": None},
    {"metadata": "not metadata"}, {"metadata": {"properties": None}},
    {"annotations": [{"comment": evidence.EVIDENCE_PREFIX + "not json"}]},
    {"metadata": {"properties": [{"name": evidence.EVIDENCE_PROPERTY, "value": "[]"}]}},
    {"metadata": {"properties": [{"name": evidence.EVIDENCE_PROPERTY, "value": "{}"}]}},
])
def test_unrelated_or_malformed_evidence_is_ignored(data):
    assert evidence.read_evidence(data) is None


@pytest.mark.parametrize("kind,scope,spdx2,spdx3", [
    ("", "", ("app", "lib", "DEPENDS_ON", ""), ("app", "lib", "dependsOn", "")),
    ("DEPENDENCY_OF", "", ("lib", "app", "DEPENDENCY_OF", ""), ("app", "lib", "dependsOn", "")),
    ("BUILD_DEPENDENCY_OF", "build",
     ("lib", "app", "BUILD_DEPENDENCY_OF", ""), ("app", "lib", "dependsOn", "build")),
    ("RUNTIME_DEPENDENCY_OF", "runtime",
     ("lib", "app", "RUNTIME_DEPENDENCY_OF", ""), ("app", "lib", "dependsOn", "runtime")),
    ("DEV_DEPENDENCY_OF", "development",
     ("lib", "app", "DEV_DEPENDENCY_OF", ""), ("app", "lib", "dependsOn", "development")),
    ("TEST_DEPENDENCY_OF", "test",
     ("lib", "app", "TEST_DEPENDENCY_OF", ""), ("app", "lib", "dependsOn", "test")),
    ("OPTIONAL_DEPENDENCY_OF", "",
     ("lib", "app", "OPTIONAL_DEPENDENCY_OF", ""), ("app", "lib", "hasOptionalDependency", "")),
    ("PROVIDED_DEPENDENCY_OF", "",
     ("lib", "app", "PROVIDED_DEPENDENCY_OF", ""), ("app", "lib", "hasProvidedDependency", "")),
    ("hasOptionalDependency", "",
     ("lib", "app", "OPTIONAL_DEPENDENCY_OF", ""), ("app", "lib", "hasOptionalDependency", "")),
    ("hasProvidedDependency", "",
     ("lib", "app", "PROVIDED_DEPENDENCY_OF", ""), ("app", "lib", "hasProvidedDependency", "")),
    ("dependencyOf", "runtime",
     ("lib", "app", "RUNTIME_DEPENDENCY_OF", ""), ("app", "lib", "dependsOn", "runtime")),
    ("hasPrerequisite", "unknown-producer-scope",
     ("app", "lib", "DEPENDS_ON", ""), ("app", "lib", "hasPrerequisite", "")),
])
def test_dependency_direction_and_explicit_scope(monkeypatch, kind, scope, spdx2, spdx3):
    monkeypatch.setattr(evidence, "dependency_records", lambda _: [{
        "source": "app", "target": "lib",
        "declarations": [{"relationship_type": kind, "lifecycle_scope": scope}] if kind else [],
    }])
    assert evidence.dependency_relationships(None, spdx3=False) == [spdx2]
    assert evidence.dependency_relationships(None, spdx3=True) == [spdx3]


def test_invalid_targets_are_not_restorable():
    assert not evidence._valid_target({})
    assert not evidence._valid_target({"id": "build", "name": "build", "package_ids": [],
                                      "languages": [{"language": "C", "flags": [1], "defines": []}]})
    assert evidence._valid_target({"id": "build", "name": "build", "package_ids": [],
                                  "languages": [{"language": "C", "flags": [""], "defines": []}]})


def test_evidence_reader_keeps_original_values():
    payload = {"dependencies": [], "build_targets": [], "unknown": {"raw": ["", "a b", "a b"]}}
    data = {"annotations": [{"comment": evidence.EVIDENCE_PREFIX + json.dumps(payload)}]}
    assert evidence.read_evidence(data) == payload

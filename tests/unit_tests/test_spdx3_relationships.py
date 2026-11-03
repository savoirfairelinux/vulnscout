# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from unittest.mock import MagicMock

from src.views.fast_spdx3 import FastSPDX3


def test_dependency_parser_ignores_invalid_endpoints_and_preserves_valid_relationship_directions():
    controllers = MagicMock()
    parser = FastSPDX3(controllers)
    parser._document_refs = {"ns:app": "app@", "ns:lib": "lib@"}
    graph = [
        {"type": "SpdxDocument", "namespaceMap": [{"prefix": "ns", "namespace": "https://example.org/"}]},
        None,
        {"type": "Relationship", "relationshipType": "dependsOn", "from": None, "to": "ns:lib"},
        {"type": "Relationship", "relationshipType": "dependsOn", "from": "ns:app", "to": {}},
        {"type": "Relationship", "relationshipType": "dependsOn", "from": "ns:app", "to": ["ns:lib", 123]},
        {"type": "LifecycleScopedRelationship", "relationshipType": "hasPrerequisite",
         "from": "ns:app", "to": "ns:runtime"},
        {"type": "Relationship", "relationshipType": "dependencyOf", "from": "ns:lib", "to": "ns:app"},
        {"type": "Relationship", "relationshipType": "contains", "from": "ns:app", "to": "ns:file"},
    ]
    parser.merge_dependencies_into_controller({"@graph": graph})
    controllers.packages.add_spdx3_dependencies.assert_called_once_with(
        parser._document_refs, {"ns": "https://example.org/"},
        {("ns:app", "ns:lib", "dependsOn", ""), ("ns:app", "ns:lib", "dependencyOf", ""),
         ("ns:app", "ns:runtime", "hasPrerequisite", "")},
    )


def test_source_parser_requires_explicit_builds_and_string_input_output_references():
    controllers = MagicMock()
    parser = FastSPDX3(controllers)
    parser._document_refs = {"ns:app": "app@"}
    url = f"git+https://example.org/source@{'a' * 40}"
    graph = [
        {"type": "build_Build", "spdxId": "ns:build"},
        {"type": "software_Package", "spdxId": "ns:source", "software_primaryPurpose": "source",
         "software_downloadLocation": url},
        {"from": "ns:build", "relationshipType": "hasInput", "to": ["ns:source", None]},
        {"from": "ns:build", "relationshipType": "hasOutput", "to": "ns:app"},
        {"from": None, "relationshipType": "hasInput", "to": "ns:source"},
        {"from": "ns:build", "relationshipType": "hasOutput", "to": {}},
    ]
    parser.merge_sources_into_controller({"@graph": graph})
    controllers.packages.add_spdx3_sources.assert_called_once_with(
        parser._document_refs, {}, {"ns:source": url}, {("ns:app", "ns:build")},
        {("ns:build", "ns:source")}, {"ns:build"},
    )

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Synthetic provenance must be explicit and exclusively used by inventory packages."""

from unittest.mock import MagicMock

import pytest

from src.views.fast_spdx import (
    FastSPDX, SPDX2_SYNTHETIC_SOURCE_COMMENT, spdx2_dependency_edge, spdx2_provenance_only_sources,
)


def _source():
    return {
        "SPDXID": "SPDXRef-source", "name": "source", "primaryPackagePurpose": "SOURCE",
        "comment": SPDX2_SYNTHETIC_SOURCE_COMMENT,
        "downloadLocation": f"git+https://example.org/lib@{'a' * 40}",
    }


@pytest.mark.parametrize("source,target", [(None, "SPDXRef-lib"), ("SPDXRef-lib", None), (1, []), ({}, "source")])
def test_dependency_edge_ignores_non_string_endpoints(source, target):
    assert spdx2_dependency_edge(source, "DEPENDS_ON", target) is None


@pytest.mark.parametrize("version_field", ["version", "Version", "packageVersion", "PackageVersion", "versionInfo"])
def test_versioned_marked_source_is_inventory_for_all_supported_version_fields(version_field):
    source = _source()
    source[version_field] = "1.0"
    assert spdx2_provenance_only_sources({
        "packages": [{"SPDXID": "SPDXRef-lib"}, source],
        "relationships": [{
            "spdxElementId": "SPDXRef-lib", "relationshipType": "GENERATED_FROM",
            "relatedSpdxElement": source["SPDXID"],
        }],
    }) == set()


@pytest.mark.parametrize("parent", [None, "SPDXRef-unknown", "SPDXRef-source"])
def test_marked_source_requires_a_non_source_local_inventory_parent(parent):
    source = _source()
    assert spdx2_provenance_only_sources({
        "packages": [None, {"SPDXID": 123}, source],
        "relationships": [None, {
            "spdxElementId": parent, "relationshipType": "GENERATED_FROM",
            "relatedSpdxElement": source["SPDXID"],
        }],
    }) == set()


def test_synthetic_source_with_its_own_outgoing_relation_is_inventory():
    source = _source()
    relations = [
        {"spdxElementId": "SPDXRef-lib", "relationshipType": "GENERATED_FROM",
         "relatedSpdxElement": source["SPDXID"]},
        {"spdxElementId": source["SPDXID"], "relationshipType": "DEPENDS_ON",
         "relatedSpdxElement": "SPDXRef-lib"},
    ]
    assert spdx2_provenance_only_sources({
        "packages": [{"SPDXID": "SPDXRef-lib"}, source], "relationships": relations,
    }) == set()


def test_fast_parser_ignores_malformed_relationships_without_losing_inventory():
    controllers = MagicMock()
    parser = FastSPDX(controllers)
    source = _source()
    source["comment"] = "A real upstream source package"
    parser.parse_from_dict({
        "spdxVersion": "SPDX-2.3", "documentNamespace": "https://example.org/sbom",
        "packages": [{"SPDXID": "SPDXRef-lib", "name": "lib", "versionInfo": "1.0"}, source],
        "relationships": [None, 123, {"spdxElementId": "SPDXRef-lib", "relatedSpdxElement": None}],
    })
    assert {call.args[0].string_id for call in controllers.packages.add.call_args_list} == {"lib@1.0", "source@"}
    assert parser._document_refs == {"SPDXRef-lib": "lib@1.0", "SPDXRef-source": "source@"}
    controllers.packages.add_spdx_dependencies.assert_called_once_with(
        "https://example.org/sbom", parser._document_refs, {}, set(),
    )
    assert controllers.packages.add_spdx_sources.call_args.args[3] == {
        source["SPDXID"]: source["downloadLocation"],
    }

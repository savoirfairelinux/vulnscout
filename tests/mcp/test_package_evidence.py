from unittest.mock import patch

import httpx
import pytest
import respx

from vulnscout_mcp.client import ScopedVulnScoutClient, VulnScoutClient, VulnScoutError
from vulnscout_mcp.tools.dependencies import register_tools
from .test_dependencies import BASE_URL, Server, document, edge, invoke, package


def source_file(path="src/vulnerable.c", **fields):
    return {
        "spdx_id": f"file:{path}", "path": path, "document_id": "files",
        "document_name": "files.spdx", "scan_id": "scan1", "variant_id": "v1", "variant_name": "board",
        "properties": {"name": path},
        "builds": [{"spdx_id": "target", "document_name": "build.spdx",
                    "build_type": "urn:spdx.dev:zephyr-cmake", "compiled": True,
                    "parameters": [{"key": "compile:flags:C", "value": '-DHEADER="a b.h" -O2'}],
                    "outputs": ["obj.o"]}],
        **fields,
    }


def file_package(files, **fields):
    return {
        "id": "lib@1", "source_files": files, "source_file_count": None if files is None else len(files),
        "compiled_source_file_count": 0, "compiled_sources_complete": False, **fields,
    }


def test_recorded_files_paginate_without_losing_builds_or_provenance():
    files = [source_file(), source_file("src/contained.c", builds=[])]
    row = file_package(files, compiled_source_file_count=1, compiled_sources_complete=True)
    server = Server()
    register_tools(server, VulnScoutClient(BASE_URL))
    with respx.mock:
        route = respx.get(f"{BASE_URL}/api/packages", params={
            "variant_id": "v1", "package_id": "lib@1", "include_source_files": "true",
        }).mock(return_value=httpx.Response(200, json=[row]))
        first = invoke(server.tools, "get_package_source_files", package_id="lib@1", limit=1)
        second = invoke(server.tools, "get_package_source_files", package_id="lib@1",
                        limit=1, offset=first["next_offset"])
    assert route.call_count == 2
    assert first["items"] + second["items"] == files
    assert first["files_recorded"] is True
    assert first["source_file_count"] == 2
    assert first["compiled_source_file_count"] == 1
    assert first["compiled_sources_complete"] is True
    assert second["next_offset"] is None


@pytest.mark.parametrize("files,recorded,count", [(None, False, None), ([], True, 0)])
def test_unknown_inventory_differs_from_recorded_empty(files, recorded, count):
    server = Server()
    client = VulnScoutClient(BASE_URL)
    register_tools(server, client)
    with patch.object(client, "get_package_source_files", return_value=file_package(files)):
        result = invoke(server.tools, "get_package_source_files", package_id="lib@1")
    assert result["files_recorded"] is recorded
    assert result["source_file_count"] == count
    assert result["items"] == []
    assert result["compiled_sources_complete"] is False


@pytest.mark.parametrize("response", [
    httpx.Response(200, json={}),
    httpx.Response(200, text="invalid JSON"),
    httpx.Response(200, json=[file_package([], id="other@1")]),
    httpx.Response(200, json=[file_package([source_file(variant_id="other")])]),
    httpx.Response(200, json=[file_package([], compiled_sources_complete=None)]),
    httpx.Response(200, json=[file_package("not a list")]),
])
def test_malformed_or_wrong_scope_files_are_errors(response):
    with respx.mock:
        respx.get(f"{BASE_URL}/api/packages").mock(return_value=response)
        server = Server()
        register_tools(server, VulnScoutClient(BASE_URL))
        assert server.tools["get_package_source_files"]("v1", "lib@1").startswith(
            "Error: Invalid recorded file evidence",
        )


@pytest.mark.parametrize("response,message", [
    (httpx.Response(200, json=[]), "Package not found"),
    (httpx.Response(404, json={"error": "unavailable"}), "unavailable"),
    (httpx.Response(503, text="offline"), "offline"),
])
def test_file_errors_are_not_empty_success(response, message):
    with respx.mock:
        respx.get(f"{BASE_URL}/api/packages").mock(return_value=response)
        server = Server()
        register_tools(server, VulnScoutClient(BASE_URL))
        result = server.tools["get_package_source_files"]("v1", "lib@1")
        assert result.startswith("Error: ")
        assert message in result


def test_source_scope_is_enforced_before_http():
    client = ScopedVulnScoutClient(BASE_URL, {"project_ids": ["p1"], "variant_ids": ["v1"]})
    with patch.object(VulnScoutClient, "get_package_source_files", return_value=file_package([])) as read:
        for variant in ("other", ""):
            with pytest.raises(VulnScoutError, match="outside"):
                client.get_package_source_files(variant, "lib@1")
        read.assert_not_called()
        assert client.get_package_source_files("v1", "lib@1")["id"] == "lib@1"
        read.assert_called_once_with("v1", "lib@1")


def test_source_connection_and_input_errors():
    client = VulnScoutClient(BASE_URL)
    server = Server()
    register_tools(server, client)
    with patch("httpx.Client") as http:
        for kwargs in ({"offset": -1}, {"limit": 501}):
            assert server.tools["get_package_source_files"]("v1", "lib@1", **kwargs).startswith("Error: ")
        for variant, name in (("", "lib@1"), ("v1", "")):
            with pytest.raises(VulnScoutError, match="required"):
                client.get_package_source_files(variant, name)
        http.assert_not_called()
    with respx.mock:
        respx.get(f"{BASE_URL}/api/packages").mock(side_effect=httpx.ConnectError("offline"))
        assert server.tools["get_package_source_files"]("v1", "lib@1").startswith("Error: Could not connect")


def test_compiler_metadata_stays_with_owning_document_target_and_language():
    def target(name, owners, language, flags):
        return {"id": name, "name": name, "package_ids": owners,
                "languages": [{"language": language, "flags": [flags], "defines": ['-DHEADER="a b.h"']}]}

    first = document("d1", [package("lib"), package("isolated")], [])
    second = document("d2", [package("lib")], [])
    first["build_targets"] = [
        target("t1", ["lib@1"], "C", "-O2"),
        target("t2", ["lib@1"], "CXX", "-O0"),
        target("other", ["isolated@1"], "ASM", "-march=armv7"),
    ]
    second["build_targets"] = [target("t3", ["lib@1"], "C", "-O3")]
    server = Server()
    register_tools(server, VulnScoutClient(BASE_URL))
    with respx.mock:
        respx.get(f"{BASE_URL}/api/package-dependencies").mock(
            return_value=httpx.Response(200, json={"documents": [first, second]}),
        )
        result = invoke(server.tools, "list_dependency_packages", query="lib")
        expected = [
            {**target, "document_id": doc["id"], "source_name": doc["source_name"]}
            for doc in (first, second) for target in doc["build_targets"] if "lib@1" in target["package_ids"]
        ]
        assert [row["build_targets"] for row in result["items"][0]["occurrences"]] == [expected, expected]
        scoped = invoke(server.tools, "list_dependency_packages", query="lib", document_id="d2")
        assert len(scoped["items"][0]["occurrences"]) == 1
        isolated = invoke(server.tools, "list_dependency_packages", query="isolated")
        assert scoped["items"][0]["occurrences"][0]["build_targets"] == expected
        assert isolated["items"][0]["occurrences"][0]["build_targets"] == [
            {**first["build_targets"][2], "document_id": "d1", "source_name": "d1.spdx"},
        ]


def test_build_only_companion_document_reaches_inventory_and_traversal():
    target = {"id": "compiler", "name": "compiler", "package_ids": ["lib@1"],
              "languages": [{"language": "C", "flags": ["-O2"], "defines": []}]}
    build = document("build", [], [])
    build["build_targets"] = [target]
    packages = document("packages", [package("app"), package("lib")], [edge("app", "lib")])
    other = document("other", [package("unrelated")], [])
    server = Server()
    client = VulnScoutClient(BASE_URL)
    register_tools(server, client)
    with patch.object(client, "get_dependency_graph", return_value={"documents": [build, packages, other]}):
        inventory = invoke(server.tools, "list_dependency_packages", query="lib")
        scoped = invoke(server.tools, "list_dependency_packages", query="lib", document_id="packages")
        traversal = invoke(server.tools, "get_package_dependencies", package_id="app@1")
        root = invoke(server.tools, "get_package_dependencies", package_id="lib@1", direction="dependents")
        for row in (inventory["items"][0], scoped["items"][0], traversal["items"][0], root["root"]):
            occurrence = row["occurrences"][0]
            assert occurrence["document_id"] == "packages"
            assert occurrence["build_targets"] == [
                {**target, "document_id": "build", "source_name": "build.spdx"},
            ]
        unrelated = invoke(server.tools, "list_dependency_packages", query="unrelated")
        assert unrelated["items"][0]["occurrences"][0]["build_targets"] == []


def test_typed_edges_preserve_conflicts_provenance_and_reverse_orientation():
    build = {"relationship_type": "BUILD_DEPENDENCY_OF", "lifecycle_scope": "build",
             "source_document_id": "original", "source_name": "original.spdx"}
    runtime = {**build, "relationship_type": "RUNTIME_DEPENDENCY_OF", "lifecycle_scope": "runtime"}
    declared = {**edge("app", "lib"), "declarations": [build, runtime]}
    docs = [
        document("d1", [package("app"), package("lib"), package("leaf")],
                 [declared, edge("lib", "leaf")]),
        document("d2", [package("app"), package("lib")],
                 [{**edge("app", "lib"), "declarations": [{**build, "lifecycle_scope": ""}]}]),
    ]
    server = Server()
    client = VulnScoutClient(BASE_URL)
    register_tools(server, client)
    with patch.object(client, "get_dependency_graph", return_value={"documents": docs}):
        forward = invoke(server.tools, "get_package_dependencies", package_id="app@1", max_depth=0)
        reverse = invoke(server.tools, "get_package_dependencies", package_id="lib@1", direction="dependents")
        scoped = invoke(server.tools, "get_package_dependencies", package_id="app@1", document_id="d1")
    hop = forward["items"][0]["path_edges"][0]
    assert hop == reverse["items"][0]["path_edges"][0]
    assert hop[0]["package_id"] == "app@1" and hop[0]["dependency_id"] == "lib@1"
    assert hop[0]["declarations"] == [build, runtime]
    assert [row["document_id"] for row in hop] == ["d1", "d2"]
    assert forward["items"][1]["path_edges"][1][0]["declarations"] == []
    assert scoped["items"][0]["path_edges"][0] == hop[:1]
    assert reverse["items"][0]["path"] == ["lib@1", "app@1"]


@pytest.mark.parametrize("field,value", [
    ("build_targets", None),
    ("build_targets", [{"id": "bad"}]),
    ("edges", [{**edge("lib", "other"), "declarations": "bad"}]),
])
def test_malformed_new_graph_evidence_is_reported(field, value):
    doc = document("d1", [package("lib")], [])
    doc[field] = value
    with respx.mock:
        respx.get(f"{BASE_URL}/api/package-dependencies").mock(
            return_value=httpx.Response(200, json={"documents": [doc]}),
        )
        with pytest.raises(VulnScoutError, match="Invalid dependency graph"):
            VulnScoutClient(BASE_URL).get_dependency_graph("v1")

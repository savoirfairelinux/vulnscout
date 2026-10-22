import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import respx

from vulnscout_mcp.client import ScopedVulnScoutClient, VulnScoutClient, VulnScoutError
from vulnscout_mcp.tools.dependencies import register_tools

BASE_URL = "http://vulnscout.test"


class Server:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def register(function):
            self.tools[function.__name__] = function
            return function
        return register


def package(name, version="1", **metadata):
    return {"id": f"{name}@{version}", "name": name, "version": version,
            "release_version": version, "source_revision": None, "version_evidence": [],
            "version_conflict": False, "revision_conflict": False, **metadata}


def edge(source, target):
    return {"package_id": f"{source}@1", "dependency_id": f"{target}@1"}


def document(document_id, packages, edges, recorded=True):
    return {"id": document_id, "variant_id": "v1", "variant_name": "board",
            "source_name": f"{document_id}.spdx", "dependencies_recorded": recorded,
            "packages": packages, "edges": edges}


@pytest.fixture
def graph():
    return {"documents": [
        document("d1", [package("demo"), package("a"), package("isolated")],
                 [edge("demo", "a"), edge("demo", "a"), edge("demo", "b"),
                  edge("demo", "demo"), edge("a", "c")]),
        document("d2", [package("b"), package("c"), package(
            "a", release_version=None, version_conflict=True,
            source_revision="f" * 40, version_evidence=[{"version": "2", "source": "purl", "identifier": "pkg:a@2"}],
        )], [edge("b", "c"), edge("c", "demo")]),
        document("old", [package("legacy", "0")], [], recorded=False),
    ]}


@pytest.fixture
def tools(graph):
    client = VulnScoutClient(BASE_URL)
    server = Server()
    register_tools(server, client)
    with patch.object(client, "get_dependency_graph", return_value=graph):
        yield server.tools


def invoke(tools, tool, **kwargs):
    return json.loads(tools[tool]("v1", **kwargs))


def test_documents_pagination_and_coverage(tools):
    first = invoke(tools, "list_dependency_documents", limit=1)
    assert first["total"] == 3
    assert first["next_offset"] == 1
    assert first["items"][0] == {
        "id": "d1", "source_name": "d1.spdx", "variant_id": "v1", "variant_name": "board",
        "dependencies_recorded": True, "package_count": 3, "edge_count": 5,
    }
    last = invoke(tools, "list_dependency_documents", offset=2)
    assert last["items"][0]["dependencies_recorded"] is False
    assert last["unrecorded_document_ids"] == ["old"]
    assert last["next_offset"] is None


def test_inventory_includes_isolated_nodes_and_pages(tools):
    items = []
    offset = 0
    while offset is not None:
        result = invoke(tools, "list_dependency_packages", offset=offset, limit=2)
        items.extend(result["items"])
        offset = result["next_offset"]
    assert [row["id"] for row in items] == ["a@1", "b@1", "c@1", "demo@1", "isolated@1", "legacy@0"]
    assert result["total"] == 6
    a = items[0]
    assert [row["document_id"] for row in a["occurrences"]] == ["d1", "d2"]
    assert a["occurrences"][1]["version_conflict"] is True
    assert a["occurrences"][1]["source_revision"] == "f" * 40
    assert a["occurrences"][1]["version_evidence"][0]["version"] == "2"


def test_inventory_query_and_document_selection(tools):
    result = invoke(tools, "list_dependency_packages", query="DEMO")
    assert [row["id"] for row in result["items"]] == ["demo@1"]
    assert invoke(tools, "list_dependency_packages", query="unknown")["items"] == []
    selected = invoke(tools, "list_dependency_packages", query="a@", document_id="d2")
    assert len(selected["items"]) == 1
    assert [row["document_id"] for row in selected["items"][0]["occurrences"]] == ["d2"]


def test_direct_and_transitive_with_cycle_diamond_and_cross_document_edges(tools):
    direct = invoke(tools, "get_package_dependencies", package_id="demo@1")
    assert [(row["id"], row["distance"], row["direct"]) for row in direct["items"]] == [
        ("a@1", 1, True), ("b@1", 1, True),
    ]
    assert direct["depth_limited"] is True
    full = invoke(tools, "get_package_dependencies", package_id="demo@1", max_depth=0)
    assert [(row["id"], row["distance"]) for row in full["items"]] == [("a@1", 1), ("b@1", 1), ("c@1", 2)]
    assert full["depth_limited"] is False
    assert full["root"]["id"] == "demo@1"
    assert full["items"][2]["path"] == ["demo@1", "a@1", "c@1"]
    assert full["items"][2]["path_document_ids"] == [["d1"], ["d1"]]
    assert full["items"][2]["direct"] is False


def test_reverse_traversal_preserves_shortest_paths_and_provenance(tools):
    result = invoke(tools, "get_package_dependencies", package_id="demo@1", direction="dependents", max_depth=0)
    assert [(row["id"], row["distance"]) for row in result["items"]] == [("c@1", 1), ("a@1", 2), ("b@1", 2)]
    assert result["items"][1]["path"] == ["demo@1", "c@1", "a@1"]
    assert result["items"][1]["path_document_ids"] == [["d2"], ["d1"]]


def test_document_filter_restricts_edges_but_resolves_companion_metadata(tools):
    result = invoke(tools, "get_package_dependencies", package_id="demo@1", document_id="d1", max_depth=0)
    assert {row["id"] for row in result["items"]} == {"a@1", "b@1", "c@1"}
    b = next(row for row in result["items"] if row["id"] == "b@1")
    assert b["occurrences"][0]["document_id"] == "d2"
    reverse = invoke(tools, "get_package_dependencies", package_id="demo@1", document_id="d1",
                     direction="dependents", max_depth=0)
    assert reverse["items"] == []


def test_traversal_pages_are_complete_and_do_not_include_root(tools):
    result = invoke(tools, "get_package_dependencies", package_id="demo@1", max_depth=0, offset=2, limit=1)
    assert result["total"] == 3
    assert result["next_offset"] is None
    assert result["items"][0]["id"] == "c@1"
    assert result["items"][0]["path"] == ["demo@1", "a@1", "c@1"]
    assert invoke(tools, "get_package_dependencies", package_id="isolated@1")["items"] == []
    assert invoke(tools, "get_package_dependencies", package_id="legacy@0")["unrecorded_document_ids"] == ["old"]


def test_shortest_direct_path_wins_over_indirect_paths(tools, graph):
    graph["documents"][0]["edges"].append(edge("demo", "c"))
    result = invoke(tools, "get_package_dependencies", package_id="demo@1")
    assert all(row["distance"] == 1 and row["direct"] for row in result["items"])
    assert result["depth_limited"] is False


def test_long_chain_is_iterative_and_last_page_retains_complete_path(tools, graph):
    count = 1500
    graph["documents"] = [document(
        "chain", [package(str(i)) for i in range(count)],
        [edge(str(i), str(i + 1)) for i in range(count - 1)],
    )]
    result = invoke(tools, "get_package_dependencies", package_id="0@1", max_depth=0, offset=count - 2, limit=1)
    assert result["total"] == count - 1
    assert result["next_offset"] is None
    assert result["items"][0]["distance"] == count - 1
    assert result["items"][0]["path"] == [f"{i}@1" for i in range(count)]


@pytest.mark.parametrize("name,arguments,message", [
    ("list_dependency_packages", {"offset": -1}, "offset"),
    ("list_dependency_documents", {"limit": 501}, "limit"),
    ("get_package_dependencies", {"package_id": "demo@1", "limit": 0}, "limit"),
    ("get_package_dependencies", {"package_id": "demo@1", "max_depth": -1}, "max_depth"),
    ("get_package_dependencies", {"package_id": "demo@1", "direction": "invalid"}, "direction"),
    ("get_package_dependencies", {"package_id": "demo"}, "exact package ID"),
    ("list_dependency_packages", {"document_id": "missing"}, "No active SBOM"),
    ("get_package_dependencies", {"package_id": "demo@1", "document_id": "old"}, "Package not found"),
])
def test_meaningful_input_errors(tools, name, arguments, message):
    result = tools[name]("v1", **arguments)
    assert result.startswith("Error: ")
    assert message in result


def test_no_active_sbom_is_empty_success_not_missing_dependencies(tools, graph):
    graph["documents"].clear()
    assert invoke(tools, "list_dependency_documents")["document_count"] == 0
    assert invoke(tools, "list_dependency_packages")["items"] == []
    assert tools["get_package_dependencies"]("v1", "demo@1").startswith("Error: Package not found")


def test_http_client_uses_only_explicit_variant_scope(graph):
    with respx.mock:
        route = respx.get(f"{BASE_URL}/api/package-dependencies", params={"variant_id": "v1"}).mock(
            return_value=httpx.Response(200, json=graph),
        )
        assert VulnScoutClient(BASE_URL).get_dependency_graph("v1") == graph
        assert route.call_count == 1


@pytest.mark.parametrize("response,message", [
    (httpx.Response(400, json={"error": "Invalid variant_id"}), "Invalid variant_id"),
    (httpx.Response(503, text="Unavailable"), "Unavailable"),
    (httpx.Response(200, json={}), "Invalid dependency graph"),
    (httpx.Response(200, json={"documents": [{"variant_id": "v1"}]}), "Invalid dependency graph"),
    (httpx.Response(200, json={"documents": [{"variant_id": "other"}]}), "Invalid dependency graph"),
    (httpx.Response(200, text="not json"), "Invalid dependency graph"),
])
def test_http_errors_do_not_masquerade_as_empty_inventory(response, message):
    with respx.mock:
        respx.get(f"{BASE_URL}/api/package-dependencies").mock(return_value=response)
        server = Server()
        register_tools(server, VulnScoutClient(BASE_URL))
        for name in ("list_dependency_documents", "list_dependency_packages", "get_package_dependencies"):
            args = ("v1", "demo@1") if name == "get_package_dependencies" else ("v1",)
            result = server.tools[name](*args)
            assert result.startswith("Error: ")
            assert message in result


def test_connection_error_and_missing_scope():
    client = VulnScoutClient(BASE_URL)
    with respx.mock:
        respx.get(f"{BASE_URL}/api/package-dependencies").mock(side_effect=httpx.ConnectError("offline"))
        with pytest.raises(VulnScoutError, match="Could not connect"):
            client.get_dependency_graph("v1")
    with patch("httpx.Client") as http:
        with pytest.raises(VulnScoutError, match="scope"):
            client.get_dependency_graph("")
        http.assert_not_called()


def test_scoped_client_rejects_outside_variant_before_http_and_allows_selected(graph):
    client = ScopedVulnScoutClient(BASE_URL, {"project_ids": ["p1"], "variant_ids": ["v1"]})
    with patch.object(VulnScoutClient, "get_dependency_graph", return_value=graph) as read:
        for variant_id in ("v2", ""):
            with pytest.raises(VulnScoutError, match="outside"):
                client.get_dependency_graph(variant_id)
        read.assert_not_called()
        assert client.get_dependency_graph("v1") == graph
        read.assert_called_once_with("v1")


def test_real_server_registers_dependency_tools(monkeypatch):
    from vulnscout_mcp.server import create_server

    monkeypatch.delenv("VULNSCOUT_AGENT_SCOPE", raising=False)
    server = create_server(BASE_URL)
    tools = asyncio.run(server.list_tools())
    assert {"list_dependency_documents", "list_dependency_packages", "get_package_dependencies"} <= {
        tool.name for tool in tools
    }


def test_skill_is_discoverable_and_requires_evidence():
    root = Path(__file__).resolve().parents[2]
    skill = root / ".github/skills/sbom-dependencies/SKILL.md"
    frontmatter, body = skill.read_text().split("---", 2)[1:]
    assert "name: sbom-dependencies" in frontmatter
    assert "description:" in frontmatter
    assert all(term in frontmatter for term in ("SBOM", "LTS", "EOL", "board"))
    assert all(term in body for term in (
        "next_offset", "source_revision", "version_conflict", "path_document_ids",
        "backport", "authoritative", "unknown", "runtime", "YYYY-MM-DD",
    ))
    assert "sbom-dependencies/SKILL.md" in (root / ".github/skills/README.md").read_text()

import json
from unittest.mock import patch

import httpx
import pytest
import respx

from vulnscout_mcp.client import ScopedVulnScoutClient, VulnScoutClient, VulnScoutError
from vulnscout_mcp.tools.context import _codebase_source_impl, _fmt_merged_context, register_tools

BASE_URL = "http://vulnscout.test"


def test_reference_metadata_contains_ids():
    result = _fmt_merged_context({"files": [{"id": "f1", "original_name": "source.zip", "description": "full"}]})
    assert json.loads(result.split("files=", 1)[1]) == [
        {"id": "f1", "original_name": "source.zip", "description": "full"},
    ]


@pytest.mark.parametrize("operation", ["list", "read", "search"])
@pytest.mark.parametrize("file_id", ["f1", "directory"])
def test_client_source_operation(operation, file_id):
    params = {"operation": operation, "path": "repo/a.c", "query": "needle"}
    with respx.mock:
        route = respx.get(f"{BASE_URL}/api/variants/v1/context/files/{file_id}/source", params=params).mock(
            return_value=httpx.Response(200, json={"file_id": "f1", "content": "needle"}),
        )
        result = _codebase_source_impl(VulnScoutClient(BASE_URL), "v1", file_id, params)
        assert json.loads(result)["content"] == "needle"
        assert route.called


@pytest.mark.parametrize("response,expected", [
    (httpx.Response(404, json={"error": "File not found"}), "File not found"),
    (httpx.Response(500, text="Storage failure"), "Storage failure"),
])
def test_api_errors_are_reported(response, expected):
    with respx.mock:
        respx.get(f"{BASE_URL}/api/variants/v1/context/files/f1/source").mock(return_value=response)
        assert _codebase_source_impl(VulnScoutClient(BASE_URL), "v1", "f1", {}) == f"Error: {expected}"


def test_connection_error():
    with respx.mock:
        respx.get(f"{BASE_URL}/api/variants/v1/context/files/f1/source").mock(
            side_effect=httpx.ConnectError("offline"),
        )
        assert _codebase_source_impl(VulnScoutClient(BASE_URL), "v1", "f1", {}).startswith(
            "Error: Could not connect",
        )


@pytest.mark.parametrize("file_id", ["f1", "directory"])
def test_scope_rejected_before_request(file_id):
    client = ScopedVulnScoutClient(BASE_URL, {"project_ids": ["p1"], "variant_ids": ["v1"]})
    with patch.object(VulnScoutClient, "get_codebase_source") as source:
        with pytest.raises(VulnScoutError, match="outside"):
            client.get_codebase_source("v2", file_id, {})
        source.assert_not_called()
        client.get_codebase_source("v1", file_id, {"operation": "list"})
        source.assert_called_once_with("v1", file_id, {"operation": "list"})


def test_directory_metadata_exposes_the_bounded_tool_id():
    result = _fmt_merged_context({
        "codebase_directory": {"file_id": "directory", "path": "/cache/vulnscout/context-p-v-id"},
    })
    assert "codebase_source=" not in result and "codebase_path=" not in result
    metadata = json.loads(result.split("codebase_directory=", 1)[1].splitlines()[0])
    assert metadata == {"file_id": "directory", "path": "/cache/vulnscout/context-p-v-id"}


def test_registered_tools_forward_parameters():
    class Server:
        def __init__(self):
            self.tools = {}

        def tool(self):
            def register(function):
                self.tools[function.__name__] = function
                return function
            return register

    server = Server()
    client = VulnScoutClient(BASE_URL)
    register_tools(server, client)
    with patch.object(client, "get_codebase_source", return_value={"ok": True}) as source:
        assert json.loads(server.tools["list_codebase_files"]("v1", "f1", "*.c", 10, 20)) == {"ok": True}
        source.assert_called_with("v1", "f1", {"operation": "list", "pattern": "*.c", "offset": 10, "limit": 20})
        server.tools["read_codebase_file"]("v1", "f1", "a.c", 3, 5)
        source.assert_called_with("v1", "f1", {
            "operation": "read", "path": "a.c", "start_line": 3, "max_lines": 5,
        })
        server.tools["search_codebase"]("v1", "f1", "needle", "*.c", 3)
        source.assert_called_with("v1", "f1", {
            "operation": "search", "query": "needle", "pattern": "*.c", "max_results": 3,
        })


def test_merged_context_lists_mount_file_ids():
    result = _fmt_merged_context({"mounts": [
        {"alias": "src", "file_id": "mount:src", "host_path": "/work/app", "created_at": "2026-01-01T00:00:00Z"},
    ]})
    line = next(line for line in result.splitlines() if line.startswith("mounts="))
    assert json.loads(line.split("=", 1)[1]) == [{"alias": "src", "file_id": "mount:src", "host_path": "/work/app"}]
    assert "mounts=[]" in _fmt_merged_context({})


@pytest.mark.parametrize("operation", ["list", "read", "search"])
def test_client_targets_one_mount_alias(operation):
    with respx.mock:
        route = respx.get(f"{BASE_URL}/api/variants/v1/context/files/mount%3Asrc/source").mock(
            return_value=httpx.Response(200, json={"file_id": "mount:src", "matches": []}),
        )
        result = _codebase_source_impl(VulnScoutClient(BASE_URL), "v1", "mount:src", {"operation": operation})
        assert json.loads(result)["file_id"] == "mount:src"
        assert route.called


def test_helper_unavailability_is_reported():
    with respx.mock:
        respx.get(f"{BASE_URL}/api/variants/v1/context/files/mount%3Asrc/source").mock(
            return_value=httpx.Response(503, json={"error": "Host folder helper is not running."}),
        )
        result = _codebase_source_impl(VulnScoutClient(BASE_URL), "v1", "mount:src", {})
        assert result == "Error: Host folder helper is not running."


def test_mount_scope_rejected_before_request():
    client = ScopedVulnScoutClient(BASE_URL, {"project_ids": ["p1"], "variant_ids": ["v1"]})
    with patch.object(VulnScoutClient, "get_codebase_source") as source:
        with pytest.raises(VulnScoutError, match="outside"):
            client.get_codebase_source("v2", "mount:src", {})
        source.assert_not_called()

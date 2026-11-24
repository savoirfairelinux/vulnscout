import json
from unittest.mock import patch

import httpx
import pytest
import respx

from vulnscout_mcp.client import ScopedVulnScoutClient, VulnScoutClient, VulnScoutError
from vulnscout_mcp.tools import context as context_tools
from vulnscout_mcp.tools.context import (
    _codebase_source_impl, _fmt_merged_context, _read_codebase_files_impl, register_tools,
)

BASE_URL = "http://vulnscout.test"


def test_reference_metadata_contains_ids():
    result = _fmt_merged_context({"files": [{"id": "f1", "original_name": "source.zip", "description": "full"}]})
    assert json.loads(result.split("files=", 1)[1]) == [
        {"id": "f1", "original_name": "source.zip", "description": "full"},
    ]


@pytest.mark.parametrize("operation", ["list", "read"])
@pytest.mark.parametrize("file_id", ["f1", "directory"])
def test_client_source_operation(operation, file_id):
    params = {"operation": operation, "path": "repo/a.c"}
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


def test_read_codebase_files_reads_in_order_and_isolates_errors():
    client = VulnScoutClient(BASE_URL)

    def fake(variant_id, file_id, params):
        if params["path"] == "bad.c":
            raise VulnScoutError("Source file not found or excluded.")
        return {"path": params["path"], "content": "x\n", "start_line": params["start_line"]}

    with patch.object(client, "get_codebase_source", side_effect=fake) as source:
        result = json.loads(_read_codebase_files_impl(client, "v1", "mount:src", ["a.c", "bad.c", "b.c"], 2, 5))
    assert [entry["path"] for entry in result["files"]] == ["a.c", "bad.c", "b.c"]
    assert result["files"][1] == {"path": "bad.c", "error": "Source file not found or excluded."}
    assert result["files"][0]["start_line"] == 2 and source.call_count == 3
    source.assert_any_call("v1", "mount:src", {"operation": "read", "path": "a.c", "start_line": 2, "max_lines": 5})


def test_read_codebase_files_validates_paths_and_caps_the_response(monkeypatch):
    client = VulnScoutClient(BASE_URL)
    assert _read_codebase_files_impl(client, "v1", "f", [], 1, 10).startswith("Error:")
    assert "at most" in _read_codebase_files_impl(client, "v1", "f", [f"{i}.c" for i in range(9)], 1, 10)
    monkeypatch.setattr(context_tools, "MAX_BATCH_BYTES", 210)
    with patch.object(client, "get_codebase_source", return_value={"content": "y" * 80}):
        response = _read_codebase_files_impl(client, "v1", "f", ["a.c", "b.c"], 1, 10)
    assert len(response.encode()) <= 210
    files = json.loads(response)["files"]
    assert "content" in files[0] and "budget" in files[1]["error"]
    with patch.object(client, "get_codebase_source", return_value={"content": "\u00e9" * 40}):
        response = _read_codebase_files_impl(client, "v1", "f", ["a.c"], 1, 10)
    assert len(response.encode()) <= 210 and "budget" in json.loads(response)["files"][0]["error"]
    assert "budget" in _read_codebase_files_impl(client, "v1", "f", ["x" * 210], 1, 10)


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
    assert "search_codebase" not in server.tools
    with patch.object(client, "get_codebase_source", return_value={"ok": True}) as source:
        assert json.loads(server.tools["list_codebase_files"]("v1", "f1", "*.c", 10, 20)) == {"ok": True}
        source.assert_called_with("v1", "f1", {"operation": "list", "pattern": "*.c", "offset": 10, "limit": 20})
        server.tools["list_codebase_files"]("v1", "mount:src", "*.c", 0, 5, "build/tmp")
        source.assert_called_with("v1", "mount:src", {
            "operation": "list", "pattern": "*.c", "offset": 0, "limit": 5, "folder": "build/tmp",
        })
        server.tools["read_codebase_file"]("v1", "f1", "a.c", 3, 5)
        source.assert_called_with("v1", "f1", {
            "operation": "read", "path": "a.c", "start_line": 3, "max_lines": 5,
        })


def test_shell_tool_is_embedded_only_and_scope_checked(monkeypatch):
    class Server:
        def __init__(self):
            self.tools = {}

        def tool(self):
            def register(function):
                self.tools[function.__name__] = function
                return function
            return register

    client = ScopedVulnScoutClient(BASE_URL, {"project_ids": ["p1"], "variant_ids": ["v1"]})
    monkeypatch.delenv("VULNSCOUT_AGENT_SHELL", raising=False)
    external = Server()
    register_tools(external, client)
    assert "run_codebase_shell" not in external.tools
    monkeypatch.setenv("VULNSCOUT_AGENT_SHELL", "1")
    embedded = Server()
    register_tools(embedded, client)
    with patch.object(VulnScoutClient, "run_codebase_shell", return_value={"output": "found", "exit_code": 0}) as run:
        assert json.loads(embedded.tools["run_codebase_shell"]("v1", "directory", "grep x a", "src"))["output"] == (
            "found"
        )
        run.assert_called_once_with("v1", "directory", "grep x a", "src")
        assert "outside" in embedded.tools["run_codebase_shell"]("v2", "directory", "ls")
        assert run.call_count == 1


def test_merged_context_lists_mount_file_ids():
    result = _fmt_merged_context({"mounts": [
        {"alias": "src", "file_id": "mount:src", "host_path": "/work/app", "created_at": "2026-01-01T00:00:00Z"},
    ]})
    line = next(line for line in result.splitlines() if line.startswith("mounts="))
    assert json.loads(line.split("=", 1)[1]) == [{"alias": "src", "file_id": "mount:src"}]
    assert "mounts=[]" in _fmt_merged_context({})


@pytest.mark.parametrize("operation", ["list", "read"])
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

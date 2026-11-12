"""MCP access to the cached OpenSSF Scorecard maintenance signal."""

import json
from urllib.parse import parse_qs, urlsplit

import pytest

from vulnscout_mcp.client import ScopedVulnScoutClient, VulnScoutClient, VulnScoutError
from vulnscout_mcp.tools.package_health import register_tools
from tests.unit_tests.test_package_health_sources import service  # noqa: F401
from .test_dependencies import Server

HEALTH = {
    "repository": "github.com/curl/curl", "repository_source": "sbom",
    "repository_evidence": "https://github.com/curl/curl", "deprecated": None, "deprecated_reason": None,
    "resolved_at": "2026-11-09T00:00:00+00:00",
    "scorecard": {"status": "scored", "score": 9.1, "checks": [{"name": "Maintained", "score": 10}]},
}


def _tool(service):  # noqa: F811
    server = Server()
    register_tools(server, VulnScoutClient(f"http://127.0.0.1:{service.server_port}"))
    return server.tools["get_package_health"]


def test_health_is_read_for_the_exact_package_and_variant(service):  # noqa: F811
    service.routes["/api/packages/health"] = [(200, {"enabled": True, "packages": {"curl@8.0.0": HEALTH}})]
    result = json.loads(_tool(service)("v1", "curl@8.0.0"))
    assert result["resolved"] is True
    assert result["lookups_enabled"] is True
    assert result["health"] == HEALTH
    assert "not evidence" in result["evidence"]
    query = parse_qs(urlsplit(service.requests[0][0]).query)
    assert query == {"variant_id": ["v1"], "package_id": ["curl@8.0.0"]}


def test_unresolved_packages_are_not_reported_as_unmaintained(service):  # noqa: F811
    service.routes["/api/packages/health"] = [(200, {"enabled": False, "packages": {}})]
    result = json.loads(_tool(service)("v1", "lib@1"))
    assert result["resolved"] is False
    assert result["health"] is None
    assert result["lookups_enabled"] is False


@pytest.mark.parametrize("status,body,message", [
    (400, {"error": "A project or variant scope is required"}, "scope is required"),
    (503, b"offline", "offline"),
    (200, [], "Invalid package health response"),
    (200, b"not json", "Invalid package health response"),
    (200, {"packages": []}, "Invalid package health response"),
])
def test_errors_are_explicit(service, status, body, message):  # noqa: F811
    service.routes["/api/packages/health"] = [(status, body)]
    result = _tool(service)("v1", "lib@1")
    assert result.startswith("Error: ")
    assert message in result


def test_inputs_scope_and_connection_are_checked():
    client = VulnScoutClient("http://127.0.0.1:9")
    for variant, package in (("", "lib@1"), ("v1", "")):
        with pytest.raises(VulnScoutError, match="required"):
            client.get_package_health(variant, package)
    with pytest.raises(VulnScoutError, match="Could not connect"):
        client.get_package_health("v1", "lib@1")
    scoped = ScopedVulnScoutClient("http://127.0.0.1:9", {"project_ids": ["p1"], "variant_ids": ["v1"]})
    with pytest.raises(VulnScoutError, match="outside"):
        scoped.get_package_health("other", "lib@1")
    with pytest.raises(VulnScoutError, match="Could not connect"):
        scoped.get_package_health("v1", "lib@1")


def test_real_server_registers_the_tool(monkeypatch):
    import asyncio
    from vulnscout_mcp.server import create_server

    monkeypatch.delenv("VULNSCOUT_AGENT_SCOPE", raising=False)
    tools = asyncio.run(create_server("http://127.0.0.1:9").list_tools())
    assert "get_package_health" in {tool.name for tool in tools}

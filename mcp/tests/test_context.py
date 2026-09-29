import json
import pytest
import respx
import httpx

# conftest.py puts mcp/ in sys.path
from client import VulnScoutClient
from tools.context import (
    _find_project_id_impl,
    _find_variant_id_impl,
    _get_merged_context_impl,
    _get_project_context_impl,
    _list_variants_impl,
    _update_project_context_impl,
    _update_variant_context_impl,
)


BASE_URL = "http://vulnscout.test"


@pytest.fixture
def client():
    return VulnScoutClient(BASE_URL)


class TestListVariantsImpl:

    def test_formats_one_line_per_variant(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/variants").mock(
                return_value=httpx.Response(
                    200,
                    json=[
                        {"id": "v1", "name": "Release", "project_id": "p1"},
                        {"id": "v2", "name": "Debug", "project_id": "p2"},
                    ],
                )
            )
            result = _list_variants_impl(client)
        assert result == (
            "id=v1 name=Release project_id=p1\n"
            "id=v2 name=Debug project_id=p2"
        )

    def test_empty_returns_none_marker(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/variants").mock(
                return_value=httpx.Response(200, json=[])
            )
            assert _list_variants_impl(client) == "(none)"

    def test_returns_error_string_on_failure(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/variants").mock(
                return_value=httpx.Response(500, json={"error": "boom"})
            )
            assert _list_variants_impl(client) == "Error: boom"


class TestFindProjectIdImpl:

    def test_returns_id_for_exact_match(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects").mock(
                return_value=httpx.Response(
                    200, json=[{"id": "p1", "name": "Alpha"}, {"id": "p2", "name": "Beta"}]
                )
            )
            result = _find_project_id_impl(client, "Beta")
        assert result == "p2"

    def test_returns_error_when_no_match(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects").mock(
                return_value=httpx.Response(200, json=[{"id": "p1", "name": "Alpha"}])
            )
            result = _find_project_id_impl(client, "Nonexistent")
        assert result == "Error: No project found with name 'Nonexistent'."

    def test_returns_error_when_multiple_matches(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects").mock(
                return_value=httpx.Response(
                    200, json=[{"id": "p1", "name": "Dup"}, {"id": "p2", "name": "Dup"}]
                )
            )
            result = _find_project_id_impl(client, "Dup")
        assert result == "Error: Multiple projects found with name 'Dup'."

    def test_api_error_returns_error_string(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects").mock(
                return_value=httpx.Response(500, json={"error": "Internal server error"})
            )
            result = _find_project_id_impl(client, "Alpha")
        assert result == "Error: Internal server error"


class TestFindVariantIdImpl:

    def test_returns_id_for_exact_match(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects").mock(
                return_value=httpx.Response(200, json=[{"id": "p1", "name": "Alpha"}])
            )
            respx.get(f"{BASE_URL}/api/projects/p1/variants").mock(
                return_value=httpx.Response(
                    200,
                    json=[
                        {"id": "v1", "name": "Debug", "project_id": "p1"},
                        {"id": "v2", "name": "Release", "project_id": "p1"},
                    ],
                )
            )
            result = _find_variant_id_impl(client, "Alpha", "Release")
        assert result == "v2"

    def test_returns_error_when_project_not_found(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects").mock(
                return_value=httpx.Response(200, json=[])
            )
            result = _find_variant_id_impl(client, "Nonexistent", "Release")
        assert result == "Error: No project found with name 'Nonexistent'."

    def test_returns_error_when_variant_not_found(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects").mock(
                return_value=httpx.Response(200, json=[{"id": "p1", "name": "Alpha"}])
            )
            respx.get(f"{BASE_URL}/api/projects/p1/variants").mock(
                return_value=httpx.Response(200, json=[])
            )
            result = _find_variant_id_impl(client, "Alpha", "Nonexistent")
        assert result == "Error: No variant found with name 'Nonexistent' in project 'Alpha'."


class TestGetMergedContextImpl:

    def test_returns_formatted_merged_context(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "project_id": "p1",
                        "description": "proj desc",
                        "variant_id": "v1",
                        "variant_description": "var desc",
                        "codebase_path": "/src/app",
                        "environment": "linux",
                        "threat_model": "CVSS >= 7",
                        "risks": "none",
                        "other_info": "n/a",
                        "files": [{"id": "f1", "original_name": "report.pdf"}],
                    },
                )
            )
            result = _get_merged_context_impl(client, "p1", "v1")
        assert "proj desc" in result
        assert "var desc" in result
        assert "/src/app" in result
        assert "CVSS >= 7" in result
        assert "report.pdf" in result

    def test_returns_no_files_placeholder_when_empty(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(
                return_value=httpx.Response(
                    200, json={"project_id": "p1", "variant_id": "v1", "files": []}
                )
            )
            result = _get_merged_context_impl(client, "p1", "v1")
        assert "files=(none)" in result

    def test_api_error_returns_error_string(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(
                return_value=httpx.Response(404, json={"error": "Project not found"})
            )
            result = _get_merged_context_impl(client, "p1", "v1")
        assert result == "Error: Project not found"

    def test_connection_error_returns_error_string(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            result = _get_merged_context_impl(client, "p1", "v1")
        assert "Error: Could not connect to VulnScout" in result


class TestGetProjectContextImpl:

    def test_returns_formatted_project_context(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects/p1/context").mock(
                return_value=httpx.Response(200, json={"project_id": "p1", "description": "hello"})
            )
            result = _get_project_context_impl(client, "p1")
        assert "project_id=p1" in result
        assert "description=hello" in result

    def test_api_error_returns_error_string(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects/p1/context").mock(
                return_value=httpx.Response(404, json={"error": "Project not found"})
            )
            result = _get_project_context_impl(client, "p1")
        assert result == "Error: Project not found"


class TestUpdateProjectContextImpl:

    def test_sends_description_and_returns_formatted_result(self, client):
        with respx.mock:
            route = respx.put(f"{BASE_URL}/api/projects/p1/context").mock(
                return_value=httpx.Response(200, json={"project_id": "p1", "description": "My project"})
            )
            result = _update_project_context_impl(client, "p1", "My project")
        body = json.loads(route.calls[0].request.content)
        assert body == {"description": "My project"}
        assert "description=My project" in result

    def test_none_description_clears_field(self, client):
        with respx.mock:
            route = respx.put(f"{BASE_URL}/api/projects/p1/context").mock(
                return_value=httpx.Response(200, json={"project_id": "p1", "description": None})
            )
            _update_project_context_impl(client, "p1", None)
        body = json.loads(route.calls[0].request.content)
        assert body == {"description": None}

    def test_api_error_returns_error_string(self, client):
        with respx.mock:
            respx.put(f"{BASE_URL}/api/projects/p1/context").mock(
                return_value=httpx.Response(404, json={"error": "Project not found"})
            )
            result = _update_project_context_impl(client, "p1", "x")
        assert result == "Error: Project not found"


class TestUpdateVariantContextImpl:

    def test_sends_all_fields_as_full_replacement(self, client):
        with respx.mock:
            route = respx.put(f"{BASE_URL}/api/variants/v1/context").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "variant_id": "v1",
                        "variant_description": None,
                        "environment": None,
                        "threat_model": "CVSS >= 7",
                        "risks": None,
                        "other_info": None,
                        "files": [],
                    },
                )
            )
            result = _update_variant_context_impl(client, "v1", threat_model="CVSS >= 7")
        body = json.loads(route.calls[0].request.content)
        # All fields are always sent, even when None, per full-replacement semantics.
        assert body == {
            "variant_description": None,
            "environment": None,
            "threat_model": "CVSS >= 7",
            "risks": None,
            "other_info": None,
        }
        assert "threat_model=CVSS >= 7" in result

    def test_api_error_returns_error_string(self, client):
        with respx.mock:
            respx.put(f"{BASE_URL}/api/variants/v1/context").mock(
                return_value=httpx.Response(404, json={"error": "Variant not found"})
            )
            result = _update_variant_context_impl(client, "v1", threat_model="x")
        assert result == "Error: Variant not found"

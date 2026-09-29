import json
import pytest
import respx
import httpx

# conftest.py adds mcp/ to sys.path so this import works
from client import VulnScoutClient, VulnScoutError


BASE_URL = "http://vulnscout.test"


@pytest.fixture
def client():
    return VulnScoutClient(BASE_URL)


class TestWriteAssessment:

    def test_success_returns_response_dict(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": "success",
                        "assessment": {
                            "id": "abc-123",
                            "status": "affected",
                            "packages": ["openssl@1.0.0"],
                        },
                    },
                )
            )
            result = client.write_assessment(
                "CVE-2024-1234",
                {"packages": ["openssl@1.0.0"], "status": "affected"},
            )
        assert result["status"] == "success"
        assert result["assessment"]["id"] == "abc-123"

    def test_sends_payload_as_json(self, client):
        with respx.mock:
            route = respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={"status": "success", "assessment": {"id": "x", "status": "affected", "packages": []}},
                )
            )
            client.write_assessment(
                "CVE-2024-1234",
                {"packages": ["lib@2.0"], "status": "affected"},
            )
        assert route.called
        body = json.loads(route.calls[0].request.content)
        assert body["status"] == "affected"
        assert body["packages"] == ["lib@2.0"]

    def test_api_400_raises_vuln_scout_error_with_message(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(400, json={"error": "Justification required"})
            )
            with pytest.raises(VulnScoutError, match="Justification required"):
                client.write_assessment(
                    "CVE-2024-1234",
                    {"packages": ["lib@1.0"], "status": "not_affected"},
                )

    def test_api_500_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(500, json={"error": "Internal server error"})
            )
            with pytest.raises(VulnScoutError, match="Internal server error"):
                client.write_assessment("CVE-2024-1234", {"packages": ["lib@1.0"], "status": "affected"})

    def test_connection_error_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            with pytest.raises(VulnScoutError, match="Could not connect to VulnScout at http://vulnscout.test"):
                client.write_assessment("CVE-2024-1234", {"packages": ["lib@1.0"], "status": "affected"})


class TestListProjects:

    def test_success_returns_project_list(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects").mock(
                return_value=httpx.Response(200, json=[{"id": "p1", "name": "MyProject"}])
            )
            result = client.list_projects()
        assert result == [{"id": "p1", "name": "MyProject"}]

    def test_api_error_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects").mock(
                return_value=httpx.Response(500, json={"error": "Internal server error"})
            )
            with pytest.raises(VulnScoutError, match="Internal server error"):
                client.list_projects()

    def test_connection_error_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            with pytest.raises(VulnScoutError, match="Could not connect to VulnScout at http://vulnscout.test"):
                client.list_projects()


class TestListVariantsByProject:

    def test_success_returns_variant_list(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects/p1/variants").mock(
                return_value=httpx.Response(
                    200, json=[{"id": "v1", "name": "MyVariant", "project_id": "p1"}]
                )
            )
            result = client.list_variants_by_project("p1")
        assert result == [{"id": "v1", "name": "MyVariant", "project_id": "p1"}]

    def test_api_404_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects/p1/variants").mock(
                return_value=httpx.Response(404, json={"error": "Project not found"})
            )
            with pytest.raises(VulnScoutError, match="Project not found"):
                client.list_variants_by_project("p1")

    def test_connection_error_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects/p1/variants").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            with pytest.raises(VulnScoutError, match="Could not connect to VulnScout at http://vulnscout.test"):
                client.list_variants_by_project("p1")


class TestListVariants:

    def test_success_returns_variant_list(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/variants").mock(
                return_value=httpx.Response(
                    200, json=[{"id": "v1", "name": "MyVariant", "project_id": "p1"}]
                )
            )
            result = client.list_variants()
        assert result == [{"id": "v1", "name": "MyVariant", "project_id": "p1"}]

    def test_api_error_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/variants").mock(
                return_value=httpx.Response(500, json={"error": "Internal server error"})
            )
            with pytest.raises(VulnScoutError, match="Internal server error"):
                client.list_variants()

    def test_connection_error_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/variants").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            with pytest.raises(VulnScoutError, match="Could not connect to VulnScout at http://vulnscout.test"):
                client.list_variants()


class TestGetMergedContext:

    def test_success_returns_response_dict(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "project_id": "p1",
                        "description": "proj desc",
                        "variant_id": "v1",
                        "threat_model": "CVSS >= 7",
                        "files": [],
                    },
                )
            )
            result = client.get_merged_context("p1", "v1")
        assert result["description"] == "proj desc"
        assert result["threat_model"] == "CVSS >= 7"

    def test_sends_project_and_variant_id_as_params(self, client):
        with respx.mock:
            route = respx.get(f"{BASE_URL}/api/context").mock(
                return_value=httpx.Response(200, json={"project_id": "p1", "variant_id": "v1"})
            )
            client.get_merged_context("p1", "v1")
        assert route.called
        params = route.calls[0].request.url.params
        assert params["project_id"] == "p1"
        assert params["variant_id"] == "v1"

    def test_api_400_raises_vuln_scout_error_with_message(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(
                return_value=httpx.Response(400, json={"error": "project_id is required"})
            )
            with pytest.raises(VulnScoutError, match="project_id is required"):
                client.get_merged_context("p1", "v1")

    def test_api_404_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(
                return_value=httpx.Response(404, json={"error": "Project not found"})
            )
            with pytest.raises(VulnScoutError, match="Project not found"):
                client.get_merged_context("p1", "v1")

    def test_connection_error_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            with pytest.raises(VulnScoutError, match="Could not connect to VulnScout at http://vulnscout.test"):
                client.get_merged_context("p1", "v1")


class TestGetProjectContext:

    def test_success_returns_response_dict(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects/p1/context").mock(
                return_value=httpx.Response(200, json={"project_id": "p1", "description": "hello"})
            )
            result = client.get_project_context("p1")
        assert result["description"] == "hello"

    def test_api_404_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects/p1/context").mock(
                return_value=httpx.Response(404, json={"error": "Project not found"})
            )
            with pytest.raises(VulnScoutError, match="Project not found"):
                client.get_project_context("p1")

    def test_connection_error_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/projects/p1/context").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            with pytest.raises(VulnScoutError, match="Could not connect to VulnScout at http://vulnscout.test"):
                client.get_project_context("p1")


class TestUpdateProjectContext:

    def test_sends_description_as_json(self, client):
        with respx.mock:
            route = respx.put(f"{BASE_URL}/api/projects/p1/context").mock(
                return_value=httpx.Response(200, json={"project_id": "p1", "description": "My project"})
            )
            result = client.update_project_context("p1", "My project")
        assert route.called
        body = json.loads(route.calls[0].request.content)
        assert body == {"description": "My project"}
        assert result["description"] == "My project"

    def test_null_description_sent_as_null(self, client):
        with respx.mock:
            route = respx.put(f"{BASE_URL}/api/projects/p1/context").mock(
                return_value=httpx.Response(200, json={"project_id": "p1", "description": None})
            )
            client.update_project_context("p1", None)
        body = json.loads(route.calls[0].request.content)
        assert body == {"description": None}

    def test_api_404_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.put(f"{BASE_URL}/api/projects/p1/context").mock(
                return_value=httpx.Response(404, json={"error": "Project not found"})
            )
            with pytest.raises(VulnScoutError, match="Project not found"):
                client.update_project_context("p1", "x")

    def test_connection_error_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.put(f"{BASE_URL}/api/projects/p1/context").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            with pytest.raises(VulnScoutError, match="Could not connect to VulnScout at http://vulnscout.test"):
                client.update_project_context("p1", "x")


class TestUpdateVariantContext:

    def test_sends_fields_as_json(self, client):
        with respx.mock:
            route = respx.put(f"{BASE_URL}/api/variants/v1/context").mock(
                return_value=httpx.Response(
                    200,
                    json={"variant_id": "v1", "threat_model": "CVSS >= 7", "environment": None},
                )
            )
            result = client.update_variant_context("v1", {"threat_model": "CVSS >= 7"})
        assert route.called
        body = json.loads(route.calls[0].request.content)
        assert body == {"threat_model": "CVSS >= 7"}
        assert result["threat_model"] == "CVSS >= 7"

    def test_api_404_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.put(f"{BASE_URL}/api/variants/v1/context").mock(
                return_value=httpx.Response(404, json={"error": "Variant not found"})
            )
            with pytest.raises(VulnScoutError, match="Variant not found"):
                client.update_variant_context("v1", {"threat_model": "x"})

    def test_connection_error_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.put(f"{BASE_URL}/api/variants/v1/context").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            with pytest.raises(VulnScoutError, match="Could not connect to VulnScout at http://vulnscout.test"):
                client.update_variant_context("v1", {"threat_model": "x"})


class TestGetVulnerability:

    def test_success_returns_response_dict(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234").mock(
                return_value=httpx.Response(
                    200,
                    json={"id": "CVE-2024-1234", "description": "desc", "texts": []},
                )
            )
            result = client.get_vulnerability("CVE-2024-1234")
        assert result["id"] == "CVE-2024-1234"
        assert result["description"] == "desc"

    def test_no_variant_id_sends_no_params(self, client):
        with respx.mock:
            route = respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234").mock(
                return_value=httpx.Response(200, json={"id": "CVE-2024-1234"})
            )
            client.get_vulnerability("CVE-2024-1234")
        assert route.called
        assert "variant_id" not in route.calls[0].request.url.params

    def test_sends_variant_id_as_param_when_provided(self, client):
        with respx.mock:
            route = respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234").mock(
                return_value=httpx.Response(200, json={"id": "CVE-2024-1234"})
            )
            client.get_vulnerability("CVE-2024-1234", variant_id="v1")
        assert route.called
        assert route.calls[0].request.url.params["variant_id"] == "v1"

    def test_api_404_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234").mock(
                return_value=httpx.Response(404, text="Not found")
            )
            with pytest.raises(VulnScoutError, match="Not found"):
                client.get_vulnerability("CVE-2024-1234")

    def test_connection_error_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            with pytest.raises(VulnScoutError, match="Could not connect to VulnScout at http://vulnscout.test"):
                client.get_vulnerability("CVE-2024-1234")


class TestUpdateAssessment:

    def test_sends_payload_and_returns_json(self, client):
        with respx.mock:
            route = respx.patch(f"{BASE_URL}/api/assessments/a1").mock(
                return_value=httpx.Response(
                    200,
                    json={"status": "success", "assessment": {"id": "a1", "status": "not_affected"}},
                )
            )
            result = client.update_assessment("a1", {"status": "not_affected"})
        assert route.called
        body = json.loads(route.calls[0].request.content)
        assert body == {"status": "not_affected"}
        assert result["assessment"]["status"] == "not_affected"

    def test_api_400_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.patch(f"{BASE_URL}/api/assessments/a1").mock(
                return_value=httpx.Response(400, json={"error": "Invalid status"})
            )
            with pytest.raises(VulnScoutError, match="Invalid status"):
                client.update_assessment("a1", {"status": "bogus"})

    def test_connection_error_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.patch(f"{BASE_URL}/api/assessments/a1").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            with pytest.raises(VulnScoutError, match="Could not connect to VulnScout at http://vulnscout.test"):
                client.update_assessment("a1", {"status": "not_affected"})

import pytest
import respx
import httpx

# conftest.py puts mcp/ in sys.path
from client import VulnScoutClient
from tools.vulnerabilities import _get_vulnerability_impl


BASE_URL = "http://vulnscout.test"


@pytest.fixture
def client():
    return VulnScoutClient(BASE_URL)


class TestGetVulnerabilityImpl:

    def test_success_returns_str_of_response_dict(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234").mock(
                return_value=httpx.Response(
                    200,
                    json={"id": "CVE-2024-1234", "description": "desc", "texts": []},
                )
            )
            result = _get_vulnerability_impl(client, vuln_id="CVE-2024-1234", variant_id="v1")
        assert result == str({"id": "CVE-2024-1234", "description": "desc", "texts": []})

    def test_forwards_variant_id_as_param(self, client):
        with respx.mock:
            route = respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234").mock(
                return_value=httpx.Response(200, json={"id": "CVE-2024-1234"})
            )
            _get_vulnerability_impl(client, vuln_id="CVE-2024-1234", variant_id="v1")
        assert route.called
        assert route.calls[0].request.url.params["variant_id"] == "v1"

    def test_not_found_returns_error_string(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234").mock(
                return_value=httpx.Response(404, text="Not found")
            )
            result = _get_vulnerability_impl(client, vuln_id="CVE-2024-1234", variant_id="v1")
        assert result == "Error: Not found"

    def test_connection_error_returns_error_string(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234").mock(
                side_effect=httpx.ConnectError("refused")
            )
            result = _get_vulnerability_impl(client, vuln_id="CVE-2024-1234", variant_id="v1")
        assert "Error" in result
        assert "Could not connect" in result

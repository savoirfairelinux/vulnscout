import json
import pytest
import respx
import httpx

# conftest.py adds repository root to sys.path
from vulnscout_mcp.client import VulnScoutClient, VulnScoutError
from vulnscout_mcp.tools.assessments import (
    _write_assessment_impl, _has_ai_assessment_impl, _update_ai_assessment_impl, find_ai_assessment,
)


BASE_URL = "http://vulnscout.test"


@pytest.fixture
def client():
    return VulnScoutClient(BASE_URL)


class TestWriteAssessmentImpl:

    def test_affected_status_returns_success_summary(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": "success",
                        "assessment": {
                            "id": "uuid-abc",
                            "status": "affected",
                            "packages": ["openssl@1.0.0"],
                        },
                    },
                )
            )
            result = _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                packages=["openssl@1.0.0"],
                status="affected",
                variant_id="variant-uuid-111",
            )
        assert "uuid-abc" in result
        assert "affected" in result
        assert "openssl@1.0.0" in result

    def test_not_affected_with_justification_sends_justification(self, client):
        with respx.mock:
            route = respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-5678/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": "success",
                        "assessment": {
                            "id": "uuid-def",
                            "status": "not_affected",
                            "packages": ["curl@7.0"],
                        },
                    },
                )
            )
            result = _write_assessment_impl(
                client,
                vuln_id="CVE-2024-5678",
                packages=["curl@7.0"],
                status="not_affected",
                variant_id="variant-uuid-111",
                justification="vulnerable_code_not_present",
            )
        assert "uuid-def" in result
        body = json.loads(route.calls[0].request.content)
        assert body["justification"] == "vulnerable_code_not_present"
        assert body["variant_id"] == "variant-uuid-111"

    def test_optional_fields_omitted_when_none(self, client):
        with respx.mock:
            route = respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={"status": "success", "assessment": {"id": "x", "status": "affected", "packages": []}},
                )
            )
            _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                packages=["lib@1.0"],
                status="affected",
                variant_id="variant-uuid-111",
            )
        body = json.loads(route.calls[0].request.content)
        assert "justification" not in body
        assert "status_notes" not in body
        assert "impact_statement" not in body
        assert "workaround" not in body
        assert "responses" not in body
        assert "timestamp" not in body
        assert body["variant_id"] == "variant-uuid-111"
        assert body["ai_generated"] is True  # always present, default True

    def test_ai_generated_false_is_forwarded(self, client):
        with respx.mock:
            route = respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={"status": "success", "assessment": {"id": "x", "status": "affected", "packages": []}},
                )
            )
            _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                packages=["lib@1.0"],
                status="affected",
                variant_id="variant-uuid-111",
                ai_generated=False,
            )
        body = json.loads(route.calls[0].request.content)
        assert body["ai_generated"] is False

    def test_variant_ids_sent_when_provided(self, client):
        with respx.mock:
            route = respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={"status": "success", "assessment": {
                        "id": "x", "status": "affected", "packages": [],
                        "variant_ids": ["v1", "v2"], "targets": [{}, {}],
                    }},
                )
            )
            result = _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                packages=["lib@1.0"],
                status="affected",
                variant_ids=["v1", "v2"],
            )
        body = json.loads(route.calls[0].request.content)
        assert body["variant_ids"] == ["v1", "v2"]
        assert "variant_id" not in body
        assert "2 target(s)" in result

    def test_result_reports_replaced_assessments(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": "success",
                        "assessment": {"id": "new", "status": "affected", "packages": []},
                        "replaced": [
                            {"id": "old1", "action": "deleted", "variant_ids": ["v1"]},
                            {"id": "old2", "action": "trimmed", "variant_ids": ["v1", "v2"]},
                        ],
                    },
                )
            )
            result = _write_assessment_impl(
                client, vuln_id="CVE-2024-1234", packages=["lib@1.0"],
                status="affected", variant_id="v1",
            )
        assert result.endswith("; replaced: old1 (deleted, v1), old2 (trimmed, v1 v2)")

    def test_result_omits_replaced_when_empty(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={"status": "success", "replaced": [],
                          "assessment": {"id": "new", "status": "affected", "packages": []}},
                )
            )
            result = _write_assessment_impl(
                client, vuln_id="CVE-2024-1234", packages=["lib@1.0"],
                status="affected", variant_id="v1",
            )
        assert "replaced" not in result

    def test_variant_ids_takes_precedence_over_variant_id(self, client):
        with respx.mock:
            route = respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={"status": "success", "assessment": {"id": "x", "status": "affected", "packages": []}},
                )
            )
            _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                packages=["lib@1.0"],
                status="affected",
                variant_id="variant-uuid-111",
                variant_ids=["v1", "v2"],
            )
        body = json.loads(route.calls[0].request.content)
        assert body["variant_ids"] == ["v1", "v2"]
        assert "variant_id" not in body

    def test_missing_variant_returns_error_without_request(self, client):
        with respx.mock:
            result = _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                packages=["lib@1.0"],
                status="affected",
            )
        assert result == "Error: variant_id or variant_ids is required"

    def test_missing_packages_returns_error_without_request(self, client):
        with respx.mock:
            result = _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                status="affected",
                variant_id="variant-uuid-111",
            )
        assert result == "Error: packages is required when targets is not provided"

    def test_sparse_multi_variant_targets_are_forwarded_exactly(self, client):
        # A multi-variant group where each variant has a different affected
        # package version cannot be expressed as packages x variant_ids
        # (that would cross-join and assess pairs never observed) — only the
        # exact (package, variant_id) pairs via `targets`.
        targets = [
            {"package": "openssl@1.0.0", "variant_id": "variant-uuid-111"},
            {"package": "openssl@1.0.1", "variant_id": "variant-uuid-222"},
        ]
        with respx.mock:
            route = respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": "success",
                        "assessment": {
                            "id": "uuid-sparse",
                            "status": "affected",
                            "packages": ["openssl@1.0.0", "openssl@1.0.1"],
                            "variant_ids": ["variant-uuid-111", "variant-uuid-222"],
                            "targets": targets,
                        },
                    },
                )
            )
            result = _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                status="affected",
                targets=targets,
            )
        body = json.loads(route.calls[0].request.content)
        assert body["targets"] == targets
        assert "packages" not in body
        assert "variant_id" not in body
        assert "variant_ids" not in body
        assert "uuid-sparse" in result
        assert "2 target(s)" in result

    def test_targets_take_precedence_over_packages_and_variants(self, client):
        targets = [{"package": "openssl@1.0.0", "variant_id": "variant-uuid-111"}]
        with respx.mock:
            route = respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={"status": "success", "assessment": {"id": "x", "status": "affected", "packages": []}},
                )
            )
            _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                status="affected",
                packages=["curl@7.0"],
                variant_id="other-variant",
                targets=targets,
            )
        body = json.loads(route.calls[0].request.content)
        assert body["targets"] == targets
        assert "packages" not in body
        assert "variant_id" not in body

    def test_api_error_returns_error_string(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(400, json={"error": "Justification required"})
            )
            result = _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                packages=["lib@1.0"],
                status="not_affected",
                variant_id="variant-uuid-111",
            )
        assert "Error" in result
        assert "Justification required" in result

    def test_connection_error_returns_error_string(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                side_effect=httpx.ConnectError("refused")
            )
            result = _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                packages=["lib@1.0"],
                status="affected",
                variant_id="variant-uuid-111",
            )
        assert "Error" in result
        assert "Could not connect" in result


class TestFindAiAssessment:

    def test_returns_ai_assessment_listed_in_variant_ids(self):
        ai = {"id": "a1", "origin": "ai", "variant_ids": ["var-1", "var-2"], "variant_id": "var-2"}
        assert find_ai_assessment([ai], "var-1") is ai

    def test_falls_back_to_single_variant_id(self):
        ai = {"id": "a1", "origin": "ai", "variant_ids": [], "variant_id": "var-1"}
        assert find_ai_assessment([ai], "var-1") is ai

    def test_ignores_non_ai_origin(self):
        custom = {"id": "c1", "origin": "custom", "variant_ids": ["var-1"]}
        assert find_ai_assessment([custom], "var-1") is None

    def test_returns_none_when_variant_not_covered(self):
        ai = {"id": "a1", "origin": "ai", "variant_ids": ["var-2"]}
        assert find_ai_assessment([ai], "var-1") is None


class TestHasAiAssessment:

    VARIANT_ID = "variant-uuid-111"

    def _make_assessment(self, origin, variant_id, assessment_id="uuid-ai", status="affected", variant_ids=None):
        return {
            "id": assessment_id,
            "status": status,
            "packages": ["lib@1.0"],
            "origin": origin,
            "variant_id": variant_id,
            "variant_ids": variant_ids if variant_ids is not None else ([variant_id] if variant_id else []),
        }

    def test_match_found_returns_assessment_details(self, client):
        assessments = [self._make_assessment("ai", self.VARIANT_ID, "uuid-ai", "affected")]
        with respx.mock:
            respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(200, json=assessments)
            )
            result = _has_ai_assessment_impl(client, vuln_id="CVE-2024-1234", variant_id=self.VARIANT_ID)
        assert "uuid-ai" in result
        assert "affected" in result

    def test_match_found_for_cross_variant_assessment(self, client):
        # A cross-variant assessment has variant_id=None but lists every
        # variant it covers in variant_ids.
        assessments = [self._make_assessment(
            "ai", None, "uuid-ai", "affected", variant_ids=["other-variant", self.VARIANT_ID],
        )]
        assessments[0]["targets"] = [
            {"variant_id": self.VARIANT_ID, "package": "openssl@1.0.0"},
            {"variant_id": "other-variant", "package": "zlib@1.3.0"},
        ]
        with respx.mock:
            respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(200, json=assessments)
            )
            result = _has_ai_assessment_impl(client, vuln_id="CVE-2024-1234", variant_id=self.VARIANT_ID)
        assert "uuid-ai" in result
        assert "openssl@1.0.0" in result
        assert "zlib@1.3.0" not in result

    def test_no_match_wrong_variant_id(self, client):
        assessments = [self._make_assessment("ai", "other-variant", "uuid-ai")]
        with respx.mock:
            respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(200, json=assessments)
            )
            result = _has_ai_assessment_impl(client, vuln_id="CVE-2024-1234", variant_id=self.VARIANT_ID)
        assert "No AI assessment found" in result

    def test_no_match_ai_generated_false(self, client):
        assessments = [self._make_assessment("custom", self.VARIANT_ID, "uuid-human")]
        with respx.mock:
            respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(200, json=assessments)
            )
            result = _has_ai_assessment_impl(client, vuln_id="CVE-2024-1234", variant_id=self.VARIANT_ID)
        assert "No AI assessment found" in result

    def test_empty_list_returns_not_found(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(200, json=[])
            )
            result = _has_ai_assessment_impl(client, vuln_id="CVE-2024-1234", variant_id=self.VARIANT_ID)
        assert "No AI assessment found" in result

    def test_api_error_returns_error_string(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(500, json={"error": "Internal server error"})
            )
            result = _has_ai_assessment_impl(client, vuln_id="CVE-2024-1234", variant_id=self.VARIANT_ID)
        assert "Error" in result
        assert "Internal server error" in result


class TestUpdateAiAssessmentImpl:

    ASSESSMENT_ID = "uuid-ai"

    def _ai_assessment(self, origin="ai", status="affected"):
        return {
            "id": self.ASSESSMENT_ID,
            "status": status,
            "packages": ["lib@1.0"],
            "origin": origin,
            "variant_id": "variant-uuid-111",
        }

    def test_updates_ai_assessment_and_returns_summary(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/assessments/{self.ASSESSMENT_ID}").mock(
                return_value=httpx.Response(200, json=self._ai_assessment())
            )
            patch_route = respx.patch(f"{BASE_URL}/api/assessments/{self.ASSESSMENT_ID}").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": "success",
                        "assessment": {"id": self.ASSESSMENT_ID, "status": "not_affected", "packages": ["lib@1.0"]},
                    },
                )
            )
            result = _update_ai_assessment_impl(
                client,
                assessment_id=self.ASSESSMENT_ID,
                status="not_affected",
                justification="vulnerable_code_not_present",
            )
        assert patch_route.called
        body = json.loads(patch_route.calls[0].request.content)
        assert body == {"status": "not_affected", "justification": "vulnerable_code_not_present"}
        assert self.ASSESSMENT_ID in result
        assert "not_affected" in result

    def test_refuses_to_modify_non_ai_assessment(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/assessments/{self.ASSESSMENT_ID}").mock(
                return_value=httpx.Response(200, json=self._ai_assessment(origin="custom"))
            )
            patch_route = respx.patch(f"{BASE_URL}/api/assessments/{self.ASSESSMENT_ID}")
            result = _update_ai_assessment_impl(client, assessment_id=self.ASSESSMENT_ID, status="fixed")
        assert not patch_route.called
        assert "not an AI-generated assessment" in result

    def test_refuses_to_modify_when_ai_generated_missing(self, client):
        assessment = self._ai_assessment()
        del assessment["origin"]
        with respx.mock:
            respx.get(f"{BASE_URL}/api/assessments/{self.ASSESSMENT_ID}").mock(
                return_value=httpx.Response(200, json=assessment)
            )
            patch_route = respx.patch(f"{BASE_URL}/api/assessments/{self.ASSESSMENT_ID}")
            result = _update_ai_assessment_impl(client, assessment_id=self.ASSESSMENT_ID, status="fixed")
        assert not patch_route.called
        assert "not an AI-generated assessment" in result

    def test_get_assessment_error_returns_error_string(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/assessments/{self.ASSESSMENT_ID}").mock(
                return_value=httpx.Response(404, json={"error": "Not found"})
            )
            patch_route = respx.patch(f"{BASE_URL}/api/assessments/{self.ASSESSMENT_ID}")
            result = _update_ai_assessment_impl(client, assessment_id=self.ASSESSMENT_ID, status="fixed")
        assert not patch_route.called
        assert "Error" in result
        assert "Not found" in result

    def test_update_error_returns_error_string(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/assessments/{self.ASSESSMENT_ID}").mock(
                return_value=httpx.Response(200, json=self._ai_assessment())
            )
            respx.patch(f"{BASE_URL}/api/assessments/{self.ASSESSMENT_ID}").mock(
                return_value=httpx.Response(400, json={"error": "Invalid status"})
            )
            result = _update_ai_assessment_impl(client, assessment_id=self.ASSESSMENT_ID, status="bogus")
        assert "Error" in result
        assert "Invalid status" in result

    def test_no_fields_provided_returns_error_without_patch(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/assessments/{self.ASSESSMENT_ID}").mock(
                return_value=httpx.Response(200, json=self._ai_assessment())
            )
            patch_route = respx.patch(f"{BASE_URL}/api/assessments/{self.ASSESSMENT_ID}")
            result = _update_ai_assessment_impl(client, assessment_id=self.ASSESSMENT_ID)
        assert not patch_route.called
        assert "Error" in result
        assert "no fields" in result

import json
from pathlib import Path

import pytest
import respx
import httpx

# conftest.py adds repository root to sys.path
from vulnscout_mcp.client import VulnScoutClient
from vulnscout_mcp.tools.context import (
    _find_project_id_impl,
    _find_variant_id_impl,
    _get_merged_context_impl,
    _get_project_context_impl,
    _list_variants_impl,
    _update_project_context_impl,
    _update_variant_context_impl,
    _update_variant_threat_model_impl,
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
                        "editor": {"codebase_source": "references"},
                    },
                )
            )
            result = _get_merged_context_impl(client, "p1", "v1")
        assert "proj desc" in result
        assert "var desc" in result
        assert "/src/app" in result
        assert "CVSS >= 7" in result
        assert "report.pdf" in result
        assert "codebase_source=references" in result

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
                        "codebase_path": "/repo/src",
                        "environment": None,
                        "threat_model": "CVSS >= 7",
                        "risks": None,
                        "other_info": None,
                        "files": [],
                        "editor": {"codebase_source": "paths"},
                    },
                )
            )
            result = _update_variant_context_impl(
                client,
                "v1",
                codebase_path="/repo/src",
            )
        body = json.loads(route.calls[0].request.content)
        # All fields are always sent, even when None, per full-replacement semantics.
        assert body == {
            "variant_description": None,
            "codebase_path": "/repo/src",
            "environment": None,
            "other_info": None,
        }
        assert "threat_model=CVSS >= 7" in result
        assert "codebase_path=/repo/src" in result
        assert "codebase_source=paths" in result

    def test_api_error_returns_error_string(self, client):
        with respx.mock:
            respx.put(f"{BASE_URL}/api/variants/v1/context").mock(
                return_value=httpx.Response(404, json={"error": "Variant not found"})
            )
            result = _update_variant_context_impl(client, "v1", environment="x")
        assert result == "Error: Variant not found"


def _saved_context(stride, system=None, codebase_source="paths", codebase_path="/src"):
    return {
        "project_id": "p1", "variant_id": "v1", "variant_description": "Board A",
        "codebase_path": codebase_path, "environment": "LAN only", "other_info": None,
        "editor": {
            "codebase_source": codebase_source, "codebase_path": codebase_path,
            "system": system or {"scope": "Gateway", "actors": None, "entry_points": None,
                                 "trust_boundaries": None},
            "stride": stride, "updated_at": "2026-11-10T00:00:00Z",
        },
    }


SAVED_STRIDE = {
    "components": [
        {"id": "C1", "name": "Web UI", "description": "lighttpd", "trust_zone": "LAN"},
        {"id": "C2", "name": "Browser", "description": "", "trust_zone": "User"},
    ],
    "interactions": [{"id": "I1", "name": "Login", "source_id": "C2", "destination_id": "C1",
                      "interface": "HTTPS", "data": "", "trust_boundary": ""}],
    "threats": [{"id": "T1", "category": "spoofing", "description": "CSRF", "target_ids": ["C1"]}],
    "risks": [{"id": "R1", "description": "", "threat_ids": ["T1"], "likelihood": "low",
               "impact": None, "mitigation": "", "residual": ""}],
}


class TestVariantThreatModel:

    def test_merged_context_returns_the_editable_model_on_request(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(
                return_value=httpx.Response(200, json=_saved_context(SAVED_STRIDE)))
            plain = _get_merged_context_impl(client, "p1", "v1")
            result = _get_merged_context_impl(client, "p1", "v1", include_model=True)
        assert "\nmodel=" not in plain
        assert result.startswith(plain + "\nmodel=")
        model = json.loads(result.rsplit("\nmodel=", 1)[1])
        assert model["system"]["scope"] == "Gateway"
        assert model["stride"] == SAVED_STRIDE

    def test_update_merges_rows_and_keeps_the_rest_of_the_context(self, client):
        from src.models.variant_context import _editor_values

        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(
                return_value=httpx.Response(200, json=_saved_context(SAVED_STRIDE)))
            route = respx.put(f"{BASE_URL}/api/variants/v1/context").mock(
                side_effect=lambda request: httpx.Response(200, json={"editor": {
                    **json.loads(request.content), "updated_at": "2026-11-11T00:00:00Z"}}))
            result = _update_variant_threat_model_impl(
                client, "p1", "v1",
                system={"actors": "Operator", "scope": None},
                rows={
                    "components": [{"id": "C1", "trust_zone": "DMZ"},
                                   {"id": "C3", "name": "OTA updater"}],
                    "threats": [{"id": "T2", "category": "tampering", "target_ids": ["C3"]}],
                    "risks": [{"id": "R2", "threat_ids": ["T2"], "likelihood": "high", "impact": "high"}],
                },
                remove_ids=["R1"],
            )
        body = json.loads(route.calls[0].request.content)
        _editor_values(body)
        assert {key: body[key] for key in (
            "variant_description", "environment", "other_info", "codebase_source", "codebase_path",
        )} == {"variant_description": "Board A", "environment": "LAN only", "other_info": None,
               "codebase_source": "paths", "codebase_path": "/src"}
        assert body["system"] == {"scope": None, "actors": "Operator", "entry_points": None,
                                  "trust_boundaries": None}
        stride = body["stride"]
        assert stride["components"][0] == {**SAVED_STRIDE["components"][0], "trust_zone": "DMZ"}
        assert [row["id"] for row in stride["components"]] == ["C1", "C2", "C3"]
        assert stride["interactions"] == SAVED_STRIDE["interactions"]
        assert [row["id"] for row in stride["threats"]] == ["T1", "T2"]
        assert [row["id"] for row in stride["risks"]] == ["R2"]
        assert "components=3, interactions=1, threats=2, risks=1" in result
        assert "system fields filled: actors" in result

    def test_update_creates_the_context_of_a_new_variant(self, client):
        from src.models.variant_context import _editor_values

        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(return_value=httpx.Response(
                200, json={"project_id": "p1", "variant_id": "v1", "files": [], "editor": {
                    "codebase_source": "references", "codebase_path": None,
                    "system": {"scope": None, "actors": None, "entry_points": None, "trust_boundaries": None},
                    "stride": {"components": [], "interactions": [], "threats": [], "risks": []},
                }}))
            route = respx.put(f"{BASE_URL}/api/variants/v1/context").mock(
                return_value=httpx.Response(200, json={"editor": {}}))
            _update_variant_threat_model_impl(client, "p1", "v1", system={"scope": "Gateway"})
        body = json.loads(route.calls[0].request.content)
        _editor_values(body)
        assert body["codebase_source"] == "references" and body["system"]["scope"] == "Gateway"

    @pytest.mark.parametrize("kwargs, message", [
        ({"remove_ids": ["C9"]}, "Cannot remove unknown ids: C9."),
        ({"rows": {"risks": [{"description": "x"}]}}, "Every risks row needs an id."),
        ({"rows": {"risks": [{"id": "R1"}]}, "remove_ids": ["R1"]}, "R1 is both removed and updated."),
        ({"system": {"assets": "x"}}, "Unknown system keys: assets."),
    ])
    def test_update_rejects_bad_changes_without_saving(self, client, kwargs, message):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(
                return_value=httpx.Response(200, json=_saved_context(SAVED_STRIDE)))
            route = respx.put(f"{BASE_URL}/api/variants/v1/context")
            result = _update_variant_threat_model_impl(client, "p1", "v1", **kwargs)
        assert result.startswith(f"Error: {message}")
        assert not route.called

    @pytest.mark.parametrize("expected, saved", [
        ("2026-11-09T00:00:00Z", False), (None, True), ("2026-11-10T00:00:00+00:00", True),
    ])
    def test_update_checks_the_expected_revision(self, client, expected, saved):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(
                return_value=httpx.Response(200, json=_saved_context(SAVED_STRIDE)))
            route = respx.put(f"{BASE_URL}/api/variants/v1/context").mock(
                return_value=httpx.Response(200, json={"editor": {}}))
            result = _update_variant_threat_model_impl(
                client, "p1", "v1", system={"actors": "Operator"}, expected_updated_at=expected)
        assert route.called is saved
        if not saved:
            assert result.startswith("Error: The variant context changed since 2026-11-09T00:00:00Z")
        else:
            assert "expected_updated_at" not in json.loads(route.calls[0].request.content)

    def test_update_reports_validation_errors(self, client):
        with respx.mock:
            respx.get(f"{BASE_URL}/api/context").mock(
                return_value=httpx.Response(200, json=_saved_context(SAVED_STRIDE)))
            respx.put(f"{BASE_URL}/api/variants/v1/context").mock(return_value=httpx.Response(
                400, json={"error": "threats[0].target_ids: references an unknown id"}))
            result = _update_variant_threat_model_impl(client, "p1", "v1", remove_ids=["C1"])
        assert result == "Error: threats[0].target_ids: references an unknown id"


class TestAiContextFormGuide:
    LABELS = (
        "Project description", "Variant description", "Codebase source", "Codebase references",
        "Codebase paths", "Environment", "Other information", "System scope and assets",
        "Actors and access", "Entry points and data flows", "Trust boundaries", "Components",
        "Interactions", "Description / role", "Trust zone", "Interface / protocol", "Data / commands",
        "Trust boundary", "Threats", "STRIDE category", "Targets", "Risks", "Likelihood", "Impact",
        "Mitigation", "Residual risk / decision", "Not rated", "Add component", "Add interaction",
        "Add threat", "Add risk", "Save changes",
    )

    def test_guide_matches_the_shipped_form(self):
        from pathlib import Path
        from src.helpers.stride_model import CATEGORY_LABELS, MAX_ROWS, MAX_TEXT, RATING_LABELS
        from vulnscout_mcp.tools.context import _ai_context_form_guide_impl

        guide = _ai_context_form_guide_impl()
        root = Path(__file__).resolve().parents[2] / "frontend/src"
        form = "\n".join(path.read_text() for path in [
            *(root / "components/aiContext").glob("*.tsx"), root / "helpers/strideModel.ts",
        ])
        for label in self.LABELS:
            assert label in guide, label
            assert label in form, label
        assert all(label in guide for label in CATEGORY_LABELS.values())
        assert all(label in guide for label in RATING_LABELS.values())
        assert f"{MAX_TEXT:,}" in guide and str(MAX_ROWS) in guide

    def test_guide_defines_copy_ready_reply_without_saving(self):
        from vulnscout_mcp.tools.context import _ai_context_form_guide_impl

        guide = _ai_context_form_guide_impl()
        assert all(term in guide for term in (
            "```text", "[confirm:", "update_variant_context", "unsaved", "C1: ",
        ))

    def test_real_server_registers_guide_tool(self, monkeypatch):
        import asyncio
        from vulnscout_mcp.server import create_server

        monkeypatch.delenv("VULNSCOUT_AGENT_SCOPE", raising=False)
        tools = {tool.name: tool for tool in asyncio.run(create_server(BASE_URL).list_tools())}
        assert "AI Context" in tools["get_ai_context_form_guide"].description
        update = tools["update_variant_threat_model"].input_schema["properties"]
        assert {"system", "components", "interactions", "threats", "risks", "remove_ids"} <= set(update)
        assert "include_model" in tools["get_merged_context"].input_schema["properties"]


class TestAiContextImportSkill:
    ROOT = Path(__file__).resolve().parents[2]
    SKILL_DIR = ROOT / ".github/skills/ai-context-import"
    FORM_LABELS = tuple(label for label in TestAiContextFormGuide.LABELS
                        if label not in ("Codebase references", "Codebase paths")) + (
        "Description", "Source", "Destination", "Not rated",
    )

    def test_skill_uses_the_shipped_form_labels_and_limits(self):
        from src.helpers.stride_model import CATEGORY_LABELS, MAX_ROWS, MAX_TEXT, RATING_LABELS

        skill = (self.SKILL_DIR / "SKILL.md").read_text()
        threagile = (self.SKILL_DIR / "references/threagile.md").read_text()
        form = "\n".join(path.read_text() for path in [
            *(self.ROOT / "frontend/src/components/aiContext").glob("*.tsx"),
            self.ROOT / "frontend/src/helpers/strideModel.ts",
        ])
        for label in self.FORM_LABELS:
            assert label in skill, label
            assert label in form, label
        assert all(label in skill for label in CATEGORY_LABELS.values())
        assert all(label in skill for label in RATING_LABELS.values())
        assert all(label in threagile for label in CATEGORY_LABELS.values() if label != "Repudiation")
        assert f"{MAX_TEXT:,}" in skill and str(MAX_ROWS) in skill
        assert "DESCRIPTION_PREVIEW = 40;" in form and "first 40 characters" in skill

    def test_skill_saves_only_after_review_documented_and_linked(self):
        skill = (self.SKILL_DIR / "SKILL.md").read_text()
        readme = (self.ROOT / ".github/skills/README.md").read_text()
        assert skill.startswith("---\nname: ai-context-import\ndescription: ")
        assert all(term in skill for term in (
            "references/threagile.md", "untrusted data", "Never invent", "[confirm:",
            "```text", "update_variant_context", "update_project_context", "write_assessment",
            "Not imported", "include_model", "update_variant_threat_model",
            "explicitly confirmed", "expected_updated_at", "Never open, list or extract an archive",
        ))
        assert "ai-context-import/SKILL.md" in readme

    def test_skill_save_example_passes_backend_validation(self):
        import re
        from src.models.variant_context import _editor_values

        skill = (self.SKILL_DIR / "SKILL.md").read_text()
        example = json.loads(re.search(r"   ```json\n(.*?)\n   ```", skill, re.S).group(1))
        sections = ("components", "interactions", "threats", "risks")
        assert set(example) == {"project_id", "variant_id", *sections}
        _editor_values({
            "variant_description": None, "environment": None, "other_info": None,
            "codebase_source": "references", "codebase_path": None,
            "system": {key: None for key in ("scope", "actors", "entry_points", "trust_boundaries")},
            "stride": {section: example[section] for section in sections},
        })

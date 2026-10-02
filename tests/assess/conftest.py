import os
import sys

import pytest

# Add repository root to sys.path so tests can import vulnscout_assess.* and vulnscout_mcp.*.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))


class FakeClient:
    """In-memory stand-in for vulnscout_mcp.client.VulnScoutClient."""

    def __init__(self):
        self.projects = [{"id": "p-default", "name": "default"}, {"id": "p-proj", "name": "Proj"}]
        self.variants = {
            "p-default": [{"id": "v-def", "name": "default"}, {"id": "v-rel", "name": "release"}],
            "p-proj": [{"id": "v-x86", "name": "x86"}, {"id": "v-arm", "name": "arm"}],
        }
        self.assessments: dict[str, list[dict]] = {}
        self.errors: dict[str, Exception] = {}
        # vuln id -> variants where it is present; no entry means present in every known variant
        self.vuln_variants: dict[str, list[dict]] = {}
        self.variant_calls: list[str] = []
        self.assessment_calls: list[str] = []

    def list_projects(self):
        return self.projects

    def list_variants_by_project(self, project_id):
        return self.variants.get(project_id, [])

    def list_variants_by_vuln(self, vuln_id):
        self.variant_calls.append(vuln_id)
        if vuln_id in self.vuln_variants:
            return self.vuln_variants[vuln_id]
        return [v for group in self.variants.values() for v in group]

    def list_assessments_by_vuln(self, vuln_id):
        self.assessment_calls.append(vuln_id)
        if vuln_id in self.errors:
            raise self.errors[vuln_id]
        return self.assessments.get(vuln_id, [])


@pytest.fixture()
def client():
    return FakeClient()

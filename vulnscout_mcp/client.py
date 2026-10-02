from typing import Optional

import httpx


class VulnScoutError(Exception):
    """Raised when VulnScout API returns an error or is unreachable."""
    pass


class VulnScoutClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def write_assessment(self, vuln_id: str, payload: dict) -> dict:
        """POST /api/vulnerabilities/<vuln_id>/assessments.

        Returns the parsed JSON response on success.
        Raises VulnScoutError on non-2xx response or connection failure.
        """
        url = f"{self.base_url}/api/vulnerabilities/{vuln_id}/assessments"
        try:
            with httpx.Client() as http:
                response = http.post(url, json=payload)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def get_assessment(self, assessment_id: str) -> dict:
        """GET /api/assessments/<assessment_id>."""
        url = f"{self.base_url}/api/assessments/{assessment_id}"
        try:
            with httpx.Client() as http:
                response = http.get(url)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def list_projects(self) -> list:
        """GET /api/projects. Returns a list of {id, name} dicts."""
        url = f"{self.base_url}/api/projects"
        try:
            with httpx.Client() as http:
                response = http.get(url)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def list_variants_by_project(self, project_id: str) -> list:
        """GET /api/projects/<project_id>/variants. Returns a list of {id, name, project_id} dicts."""
        url = f"{self.base_url}/api/projects/{project_id}/variants"
        try:
            with httpx.Client() as http:
                response = http.get(url)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def list_variants_by_vuln(self, vuln_id: str) -> list:
        """GET /api/vulnerabilities/<vuln_id>/variants. Returns {id, name, project_id} dicts
        for variants where the vulnerability is present (empty list for an unknown ID)."""
        url = f"{self.base_url}/api/vulnerabilities/{vuln_id}/variants"
        try:
            with httpx.Client() as http:
                response = http.get(url)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def list_variants(self) -> list:
        """GET /api/variants. Returns a list of {id, name, project_id} dicts across all projects."""
        url = f"{self.base_url}/api/variants"
        try:
            with httpx.Client() as http:
                response = http.get(url)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def get_merged_context(self, project_id: str, variant_id: str) -> dict:
        """GET /api/context?project_id=<project_id>&variant_id=<variant_id>.

        Returns the merged project + variant context view.
        """
        url = f"{self.base_url}/api/context"
        params = {"project_id": project_id, "variant_id": variant_id}
        try:
            with httpx.Client() as http:
                response = http.get(url, params=params)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def get_project_context(self, project_id: str) -> dict:
        """GET /api/projects/<project_id>/context."""
        url = f"{self.base_url}/api/projects/{project_id}/context"
        try:
            with httpx.Client() as http:
                response = http.get(url)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def update_project_context(self, project_id: str, description: str | None) -> dict:
        """PUT /api/projects/<project_id>/context."""
        url = f"{self.base_url}/api/projects/{project_id}/context"
        try:
            with httpx.Client() as http:
                response = http.put(url, json={"description": description})
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def update_variant_context(self, variant_id: str, fields: dict) -> dict:
        """PUT /api/variants/<variant_id>/context."""
        url = f"{self.base_url}/api/variants/{variant_id}/context"
        try:
            with httpx.Client() as http:
                response = http.put(url, json=fields)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def update_assessment(self, assessment_id: str, payload: dict) -> dict:
        """PATCH /api/assessments/<assessment_id>.

        Returns the parsed JSON response on success.
        Raises VulnScoutError on non-2xx response or connection failure.
        """
        url = f"{self.base_url}/api/assessments/{assessment_id}"
        try:
            with httpx.Client() as http:
                response = http.patch(url, json=payload)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def get_vulnerability(self, vuln_id: str, variant_id: str | None = None) -> dict:
        """GET /api/vulnerabilities/<vuln_id>, optionally scoped by variant_id.

        When variant_id is provided, the response's severity/effort fields are
        overridden with variant-scoped values.
        Returns the parsed JSON response on success.
        Raises VulnScoutError on non-2xx response or connection failure.
        """
        url = f"{self.base_url}/api/vulnerabilities/{vuln_id}"
        params = {"variant_id": variant_id} if variant_id is not None else None
        try:
            with httpx.Client() as http:
                response = http.get(url, params=params)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def list_vulnerabilities(
        self,
        *,
        variant_id: str | None = None,
        project_id: str | None = None,
        response_format: str = "list",
    ) -> list | dict:
        """GET /api/vulnerabilities with optional variant/project scoping."""
        url = f"{self.base_url}/api/vulnerabilities"
        params: dict[str, str] = {"format": response_format}
        if variant_id is not None:
            params["variant_id"] = variant_id
        if project_id is not None:
            params["project_id"] = project_id
        try:
            with httpx.Client() as http:
                response = http.get(url, params=params)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def get_vulnerability_for_variant(self, vuln_id: str, variant_id: str,
                                      agent_scoped: bool = False) -> dict:
        """Return one vulnerability with variant-scoped fields applied."""
        url = f"{self.base_url}/api/vulnerabilities/{vuln_id}"
        params = {"variant_id": variant_id}
        if agent_scoped:
            params["agent_scoped"] = "1"
        try:
            with httpx.Client() as http:
                response = http.get(url, params=params)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        payload = response.json()
        if not isinstance(payload, dict):
            raise VulnScoutError("Unexpected vulnerability payload")
        return payload

    def list_assessments_by_vuln(self, vuln_id: str, project_id: str | None = None) -> list:
        """GET /api/vulnerabilities/<vuln_id>/assessments."""
        url = f"{self.base_url}/api/vulnerabilities/{vuln_id}/assessments"
        try:
            with httpx.Client() as http:
                response = http.get(url, params={"project_id": project_id} if project_id else None)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def list_custom_assessments(self, params: dict) -> list:
        """GET /api/custom-assessments with the given query parameters."""
        url = f"{self.base_url}/api/custom-assessments"
        try:
            with httpx.Client() as http:
                response = http.get(url, params=params)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def get_assessment_review(
        self,
        assessment_id: str,
        variant_id: str,
        finding_id: Optional[str] = None,
        package: Optional[str] = None,
    ) -> dict:
        """GET /api/assessments/<assessment_id>/review for one target.

        A review is scoped to one (variant_id, finding_id/package) target of
        the assessment, so variant_id plus finding_id or package is required.
        Returns an empty dict when no review exists for that target, so
        callers can treat "no review" as an ordinary outcome rather than an
        error.
        """
        url = f"{self.base_url}/api/assessments/{assessment_id}/review"
        params: dict = {"variant_id": variant_id}
        if finding_id:
            params["finding_id"] = finding_id
        if package:
            params["package"] = package
        try:
            with httpx.Client() as http:
                response = http.get(url, params=params)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if response.status_code == 404:
            return {}
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def list_assessment_reviews(self, assessment_id: str) -> list:
        """GET /api/assessments/<assessment_id>/reviews — every review across all targets."""
        url = f"{self.base_url}/api/assessments/{assessment_id}/reviews"
        try:
            with httpx.Client() as http:
                response = http.get(url)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json().get("reviews", [])

    def write_assessment_review(self, assessment_id: str, payload: dict) -> dict:
        """PUT /api/assessments/<assessment_id>/review. Upserts the review."""
        url = f"{self.base_url}/api/assessments/{assessment_id}/review"
        try:
            with httpx.Client() as http:
                response = http.put(url, json=payload)
        except httpx.RequestError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()


class ScopedVulnScoutClient(VulnScoutClient):
    """Enforce the server-validated agent turn scope for every exposed tool."""

    def __init__(self, base_url: str, scope: dict):
        super().__init__(base_url)
        self.project_ids = frozenset(scope["project_ids"])
        self.variant_ids = frozenset(scope["variant_ids"])

    def _project(self, project_id: str) -> None:
        if project_id not in self.project_ids:
            raise VulnScoutError("Project is outside the current agent scope.")

    def _variant(self, variant_id: str) -> None:
        if variant_id not in self.variant_ids:
            raise VulnScoutError("Variant is outside the current agent scope.")

    def _assessment(self, assessment: dict, *, for_update: bool = False) -> dict:
        targets = assessment.get("targets") or []
        scoped = [target for target in targets if target.get("variant_id") in self.variant_ids]
        if not scoped or (for_update and len(scoped) != len(targets)):
            raise VulnScoutError("Assessment is outside the current agent scope.")
        result = dict(assessment)
        result["targets"] = scoped
        result["variant_ids"] = sorted({target["variant_id"] for target in scoped})
        result["variant_id"] = result["variant_ids"][0] if len(result["variant_ids"]) == 1 else None
        result["packages"] = list(dict.fromkeys(target["package"] for target in scoped if target.get("package")))
        result["project_id"] = next(iter(self.project_ids)) if len(self.project_ids) == 1 else None
        result.pop("vuln_texts", None)
        for key in ("reviews", "target_reviews"):
            if key in result:
                result[key] = [row for row in result[key] if row.get("variant_id") in self.variant_ids]
        return result

    def list_projects(self) -> list:
        return [row for row in super().list_projects() if row.get("id") in self.project_ids]

    def list_variants(self) -> list:
        return [row for row in super().list_variants() if row.get("id") in self.variant_ids]

    def list_variants_by_project(self, project_id: str) -> list:
        self._project(project_id)
        return [row for row in super().list_variants_by_project(project_id)
                if row.get("id") in self.variant_ids]

    def get_project_context(self, project_id: str) -> dict:
        self._project(project_id)
        return super().get_project_context(project_id)

    def get_merged_context(self, project_id: str, variant_id: str) -> dict:
        self._project(project_id)
        self._variant(variant_id)
        return super().get_merged_context(project_id, variant_id)

    def update_project_context(self, project_id: str, description: str | None) -> dict:
        self._project(project_id)
        if not {row["id"] for row in super().list_variants_by_project(project_id)} <= self.variant_ids:
            raise VulnScoutError("Select the entire project before changing its shared context.")
        return super().update_project_context(project_id, description)

    def update_variant_context(self, variant_id: str, fields: dict) -> dict:
        self._variant(variant_id)
        return super().update_variant_context(variant_id, fields)

    def get_assessment(self, assessment_id: str) -> dict:
        return self._assessment(super().get_assessment(assessment_id))

    def update_assessment(self, assessment_id: str, payload: dict) -> dict:
        self._assessment(super().get_assessment(assessment_id), for_update=True)
        result = super().update_assessment(assessment_id, {
            **payload, "allowed_variant_ids": sorted(self.variant_ids),
        })
        if "assessment" in result:
            result["assessment"] = self._assessment(result["assessment"])
        return result

    def write_assessment(self, vuln_id: str, payload: dict) -> dict:
        targets = payload.get("targets") or []
        ids = [target.get("variant_id") for target in targets] if targets else (
            payload.get("variant_ids") or [payload.get("variant_id")]
        )
        if not ids:
            raise VulnScoutError("Assessment targets require a scoped variant.")
        for variant_id in ids:
            self._variant(variant_id)
        result = super().write_assessment(vuln_id, {**payload, "ai_generated": True})
        if "assessment" in result:
            result["assessment"] = self._assessment(result["assessment"])
        result["replaced"] = [
            {**row, "variant_ids": [variant_id for variant_id in row.get("variant_ids") or []
                                     if variant_id in self.variant_ids]}
            for row in result.get("replaced") or []
            if any(variant_id in self.variant_ids for variant_id in row.get("variant_ids") or [])
        ]
        return result

    def list_assessments_by_vuln(self, vuln_id: str, project_id: str | None = None) -> list:
        if project_id:
            self._project(project_id)
        scoped_project = next(iter(self.project_ids)) if len(self.project_ids) == 1 else None
        rows = super().list_assessments_by_vuln(vuln_id, project_id=scoped_project)
        results = []
        for row in rows:
            try:
                results.append(self._assessment(row))
            except VulnScoutError:
                continue
        return results

    def get_vulnerability(self, vuln_id: str, variant_id: str | None = None) -> dict:
        if variant_id is None:
            raise VulnScoutError("A scoped variant is required for vulnerability details.")
        return self.get_vulnerability_for_variant(vuln_id, variant_id)

    def list_vulnerabilities(self, *, variant_id: str | None = None,
                             project_id: str | None = None, response_format: str = "list") -> list | dict:
        if variant_id:
            self._variant(variant_id)
        elif project_id:
            self._project(project_id)
            if not {row["id"] for row in super().list_variants_by_project(project_id)} <= self.variant_ids:
                raise VulnScoutError("Specify an allowed variant for a partial project scope.")
        else:
            raise VulnScoutError("A scoped project or variant is required.")
        return super().list_vulnerabilities(variant_id=variant_id, project_id=project_id,
                                            response_format=response_format)

    def get_vulnerability_for_variant(self, vuln_id: str, variant_id: str) -> dict:
        self._variant(variant_id)
        return super().get_vulnerability_for_variant(vuln_id, variant_id, agent_scoped=True)

    def list_custom_assessments(self, params: dict) -> list:
        params = dict(params)
        if params.get("variant_id"):
            self._variant(params["variant_id"])
        elif not self.variant_ids:
            return []
        else:
            params["variant_id"] = sorted(self.variant_ids)
        if params.get("project_id"):
            self._project(params["project_id"])
        rows = super().list_custom_assessments(params)
        results = []
        for row in rows:
            try:
                results.append(self._assessment(row))
            except VulnScoutError:
                continue
        return results

    def get_assessment_review(self, assessment_id: str, variant_id: str,
                              finding_id: Optional[str] = None, package: Optional[str] = None) -> dict:
        self._variant(variant_id)
        self.get_assessment(assessment_id)
        return super().get_assessment_review(assessment_id, variant_id, finding_id, package)

    def list_assessment_reviews(self, assessment_id: str) -> list:
        self.get_assessment(assessment_id)
        return [row for row in super().list_assessment_reviews(assessment_id)
                if row.get("variant_id") in self.variant_ids]

    def write_assessment_review(self, assessment_id: str, payload: dict) -> dict:
        self._variant(payload.get("variant_id"))
        self.get_assessment(assessment_id)
        return super().write_assessment_review(assessment_id, payload)

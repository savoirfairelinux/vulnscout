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
        except httpx.ConnectError:
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
        except httpx.ConnectError:
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
        except httpx.ConnectError:
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
        except httpx.ConnectError:
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
        except httpx.ConnectError:
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
        except httpx.ConnectError:
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
        except httpx.ConnectError:
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
        except httpx.ConnectError:
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
        except httpx.ConnectError:
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
        except httpx.ConnectError:
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
        except httpx.ConnectError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

    def list_assessments_by_vuln(self, vuln_id: str) -> list:
        """GET /api/vulnerabilities/<vuln_id>/assessments."""
        url = f"{self.base_url}/api/vulnerabilities/{vuln_id}/assessments"
        try:
            with httpx.Client() as http:
                response = http.get(url)
        except httpx.ConnectError:
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
        except httpx.ConnectError:
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
        except httpx.ConnectError:
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
        except httpx.ConnectError:
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
        except httpx.ConnectError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()

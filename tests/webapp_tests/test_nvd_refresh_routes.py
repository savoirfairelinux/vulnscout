# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from unittest.mock import patch
from src.bin.webapp import create_app
from . import write_demo_files, setup_demo_db


@pytest.fixture()
def init_files(tmp_path):
    files = {
        "status": tmp_path / "status.txt",
        "packages": tmp_path / "packages-merged.json",
        "vulnerabilities": tmp_path / "vulnerabilities-merged.json",
        "assessments": tmp_path / "assessments-merged.json",
        "openvex": tmp_path / "openvex.json",
        "time_estimates": tmp_path / "time_estimates.json",
    }
    write_demo_files(files)
    return files


@pytest.fixture()
def app(init_files):
    import os
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": init_files["status"],
            "OPENVEX_FILE": init_files["openvex"],
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db"
        })
        setup_demo_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def existing_cve_id():
    return "CVE-2020-35492"


class TestSingleCveRefreshEndpoint:

    def test_single_refresh_returns_200_with_vuln_payload(self, client, existing_cve_id):
        """POST /api/vulnerabilities/<id>/nvd-refresh returns 200 + updated vuln dict."""
        mock_details = {
            "description": "updated description",
            "status": "high",
            "attack_vector": "NETWORK",
            "links": ["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
            "weaknesses": ["CWE-79"],
            "publish_date": None,
            "nvd_last_modified": "2025-01-01T00:00:00.000",
            "base_score": 8.1,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_exploitability": 3.9,
            "cvss_impact": 5.2,
        }
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (200, {
                "vulnerabilities": [{"cve": {"id": existing_cve_id}}]
            })
            MockNVD.extract_cve_details.return_value = mock_details
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                               json={"mode": "api"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "vulnerabilities" in data
        vuln = data["vulnerabilities"][0]
        assert vuln["id"] == existing_cve_id
        assert "data_fetched_at" in vuln  # timestamp always stamped
        # CVSS score should be reflected in the response
        cvss_scores = vuln["severity"]["cvss"]
        assert any(abs(c["base_score"] - 8.1) < 0.01 for c in cvss_scores)
        # Severity min/max should be populated
        assert vuln["severity"]["max_score"] is not None
        # Transient fields must reflect the updated DB values (not stale pre-commit state)
        assert vuln["severity"]["severity"] == "high"
        assert vuln["texts"] == [
            {
                "title": "description",
                "content": "updated description"
            },
            {  # left untouched
                "title": "yocto",
                "content": "Some Yocto description"
            }
        ]
        assert any("nvd.nist.gov" in url for url in vuln["urls"])

    def test_single_refresh_updates_existing_cvss_score(self, client, existing_cve_id):
        """When NVD returns a different score for an existing version, the metric is updated."""
        mock_details = {
            "base_score": 9.8,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (200, {
                "vulnerabilities": [{"cve": {"id": existing_cve_id}}]
            })
            MockNVD.extract_cve_details.return_value = mock_details
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                               json={"mode": "api"})
        assert resp.status_code == 200
        vuln = resp.get_json()["vulnerabilities"][0]
        cvss_scores = vuln["severity"]["cvss"]
        assert any(abs(c["base_score"] - 9.8) < 0.01 for c in cvss_scores)

    def test_single_refresh_404_unknown_cve(self, client):
        resp = client.post("/api/vulnerabilities/CVE-9999-FAKE/nvd-refresh")
        assert resp.status_code == 404

    def test_single_refresh_503_on_empty_nvd_response(self, client, existing_cve_id):
        """503 when NVD returns 200 but no vulnerability data."""
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (200, {"vulnerabilities": []})
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                               json={"mode": "api"})
        assert resp.status_code == 503

    def test_single_refresh_503_on_nvd_failure(self, client, existing_cve_id):
        """503 when api_get_cve exhausts retries and returns a non-200/429/401/403 status."""
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (0, {})
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                               json={"mode": "api"})
        assert resp.status_code == 503
        data = resp.get_json()
        assert data["error_code"] == "unavailable"
        assert "api_key_configured" in data

    def test_single_refresh_503_on_unexpected_exception(self, client, existing_cve_id):
        """503 when an unexpected exception (e.g. network error) escapes api_get_cve."""
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.side_effect = OSError("network unreachable")
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                               json={"mode": "api"})
        assert resp.status_code == 503
        data = resp.get_json()
        assert data["error_code"] == "unavailable"
        assert "api_key_configured" in data

    def test_single_refresh_429_on_rate_limit(self, client, existing_cve_id):
        """429 + rate_limited error_code when NVD throttles the request."""
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (429, {})
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                               json={"mode": "api"})
        assert resp.status_code == 429
        data = resp.get_json()
        assert data["error_code"] == "rate_limited"
        assert "api_key_configured" in data

    def test_api_key_configured_field_reflects_env(self, client, existing_cve_id):
        """api_key_configured is False when NVD_API_KEY is unset, True when set."""
        import os
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (429, {})
            os.environ.pop("NVD_API_KEY", None)
            try:
                resp_no_key = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                                          json={"mode": "api"})
                os.environ["NVD_API_KEY"] = "test-key-value"
                resp_with_key = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                                            json={"mode": "api"})
            finally:
                os.environ.pop("NVD_API_KEY", None)
        assert resp_no_key.get_json()["api_key_configured"] is False
        assert resp_with_key.get_json()["api_key_configured"] is True

    def test_single_refresh_case_insensitive_cve_id(self, client, existing_cve_id):
        """CVE ID lookup is case-insensitive."""
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (200, {
                "vulnerabilities": [{"cve": {"id": existing_cve_id}}]
            })
            MockNVD.extract_cve_details.return_value = {}
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id.lower()}/nvd-refresh",
                               json={"mode": "api"})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Single CVE refresh — mode parameter (local vs api)
# ---------------------------------------------------------------------------

class TestSingleCveRefreshMode:
    """Tests for the ``mode`` parameter added by the local-nvd-fkie feature."""

    def test_default_mode_is_local(self, client, existing_cve_id):
        """When no mode is supplied, the local NVD-FKIE database is used."""
        with patch("src.routes.vulnerabilities.get_cve_json") as mock_local:
            mock_local.return_value = None  # not found in local DB → 503
            resp = client.post(
                f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                json={},
            )
        mock_local.assert_called_once_with(existing_cve_id)
        assert resp.status_code == 503
        data = resp.get_json()
        assert data["error_code"] == "unavailable"

    def test_explicit_local_mode_uses_local_db(self, client, existing_cve_id):
        """mode='local' explicitly routes to the local NVD-FKIE database."""
        with patch("src.routes.vulnerabilities.get_cve_json") as mock_local:
            mock_local.return_value = None
            resp = client.post(
                f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                json={"mode": "local"},
            )
        mock_local.assert_called_once_with(existing_cve_id)
        assert resp.status_code == 503

    def test_local_mode_returns_200_when_cve_found(self, client, existing_cve_id):
        """mode='local' returns 200 when the CVE is found in the local database."""
        cve_obj = {"id": existing_cve_id}
        with patch("src.routes.vulnerabilities.get_cve_json", return_value=cve_obj):
            with patch("src.routes.vulnerabilities.extract_cve_details", return_value={}):
                resp = client.post(
                    f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                    json={"mode": "local"},
                )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "vulnerabilities" in data

    def test_api_mode_uses_nvd_rest_api(self, client, existing_cve_id):
        """mode='api' calls NVD_DB.api_get_cve and does NOT call get_cve_json."""
        with patch("src.routes.vulnerabilities.get_cve_json") as mock_local, \
             patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (200, {
                "vulnerabilities": [{"cve": {"id": existing_cve_id}}]
            })
            MockNVD.extract_cve_details.return_value = {}
            resp = client.post(
                f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                json={"mode": "api"},
            )
        mock_local.assert_not_called()
        assert resp.status_code == 200

    def test_api_mode_returns_429_on_rate_limit(self, client, existing_cve_id):
        """mode='api' propagates a 429 rate-limit response with error_code."""
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (429, {})
            resp = client.post(
                f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                json={"mode": "api"},
            )
        assert resp.status_code == 429
        data = resp.get_json()
        assert data["error_code"] == "rate_limited"
        assert "api_key_configured" in data

    def test_api_mode_returns_503_on_network_exception(self, client, existing_cve_id):
        """mode='api' catches network errors and returns 503 unavailable."""
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.side_effect = OSError("network down")
            resp = client.post(
                f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                json={"mode": "api"},
            )
        assert resp.status_code == 503
        data = resp.get_json()
        assert data["error_code"] == "unavailable"

    def test_api_mode_unauthorized_returns_4xx(self, client, existing_cve_id):
        """mode='api' returns 401 with error_code unauthorized when NVD rejects key."""
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (401, {})
            resp = client.post(
                f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                json={"mode": "api"},
            )
        assert resp.status_code == 401
        data = resp.get_json()
        assert data["error_code"] == "unauthorized"

    def test_api_mode_returns_503_on_empty_nvd_response(self, client, existing_cve_id):
        """mode='api' returns 503 when NVD returns 200 but no vulnerability data."""
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (200, {"vulnerabilities": []})
            resp = client.post(
                f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                json={"mode": "api"},
            )
        assert resp.status_code == 503

    def test_api_mode_api_key_configured_reflects_env(self, client, existing_cve_id, monkeypatch):
        """api_key_configured in error payload reflects NVD_API_KEY presence."""
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (429, {})
            resp_no_key = client.post(
                f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                json={"mode": "api"},
            )
        assert resp_no_key.get_json()["api_key_configured"] is False

        monkeypatch.setenv("NVD_API_KEY", "mykey")
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (429, {})
            resp_with_key = client.post(
                f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh",
                json={"mode": "api"},
            )
        assert resp_with_key.get_json()["api_key_configured"] is True

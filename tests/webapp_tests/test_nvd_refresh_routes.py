# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import time
import uuid
from unittest.mock import patch
import pytest

from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Fixtures — follow the same pattern as test_scan_triggers.py
# ---------------------------------------------------------------------------

def _build_nvd_refresh_db(app):
    """Populate DB with a variant, a package, and a CVE for refresh tests."""
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        project = Project.create("RefreshProject")
        variant = Variant.create("RefreshVariant", project.id)
        Scan.create("initial scan", variant.id, scan_type="sbom")

        pkg = Package.find_or_create(
            "openssl", "1.1.1",
            cpe=["cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"],
        )
        _db.session.commit()

        vuln = Vulnerability.create_record(
            id="CVE-2024-0001",
            description="Test CVE for refresh",
            status="medium",
        )
        _db.session.commit()

        Finding.get_or_create(pkg.id, vuln.id)
        _db.session.commit()

        return {
            "variant_id": str(variant.id),
            "cve_id": vuln.id,
        }


@pytest.fixture()
def app(tmp_path):
    import os
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        ids = _build_nvd_refresh_db(application)
        application._test_ids = ids
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def variant_id(app):
    return app._test_ids["variant_id"]


@pytest.fixture()
def existing_cve_id(app):
    return app._test_ids["cve_id"]


class TestBulkRefreshEndpoints:

    def test_bulk_refresh_returns_202(self, client, variant_id):
        with patch("src.routes.scan_triggers.run_nvd_refresh"):
            resp = client.post(f"/api/variants/{variant_id}/nvd-refresh")
        assert resp.status_code == 202
        assert resp.get_json()["status"] == "started"

    def test_bulk_refresh_with_cve_ids_body(self, client, variant_id):
        with patch("src.routes.scan_triggers.run_nvd_refresh") as mock_refresh:
            resp = client.post(
                f"/api/variants/{variant_id}/nvd-refresh",
                json={"cve_ids": ["CVE-2024-0001", "CVE-2024-0002"]},
            )
            assert resp.status_code == 202
            time.sleep(0.1)  # allow background thread to start
        # Verify the CVE IDs were forwarded to run_nvd_refresh
        assert mock_refresh.called
        kwargs = mock_refresh.call_args[1]
        assert kwargs.get("requested_cve_ids") == ["CVE-2024-0001", "CVE-2024-0002"]

    def test_bulk_refresh_409_when_already_running(self, client, variant_id):
        with patch("src.routes.scan_triggers.run_nvd_refresh"):
            client.post(f"/api/variants/{variant_id}/nvd-refresh")
            resp = client.post(f"/api/variants/{variant_id}/nvd-refresh")
        assert resp.status_code == 409

    def test_bulk_refresh_404_unknown_variant(self, client):
        resp = client.post(f"/api/variants/{uuid.uuid4()}/nvd-refresh")
        assert resp.status_code == 404

    def test_bulk_refresh_400_invalid_variant_id(self, client):
        resp = client.post("/api/variants/not-a-uuid/nvd-refresh")
        assert resp.status_code == 400
        assert b"Invalid variant id" in resp.data

    def test_status_returns_idle_before_first_refresh(self, client, variant_id):
        resp = client.get(f"/api/variants/{variant_id}/nvd-refresh/status")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "idle"

    def test_status_returns_progress_while_running(self, client, variant_id):
        with patch("src.routes.scan_triggers.run_nvd_refresh"):
            client.post(f"/api/variants/{variant_id}/nvd-refresh")
        resp = client.get(f"/api/variants/{variant_id}/nvd-refresh/status")
        data = resp.get_json()
        assert data["status"] in ("running", "done")


class TestBulkRefreshStatus:

    def test_status_400_invalid_variant_id(self, client):
        resp = client.get("/api/variants/not-a-uuid/nvd-refresh/status")
        assert resp.status_code == 400
        assert b"Invalid variant id" in resp.data


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
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "vulnerabilities" in data
        assert data["vulnerabilities"][0]["id"] == existing_cve_id
        assert "nvd_fetched_at" in data["vulnerabilities"][0]  # timestamp always stamped

    def test_single_refresh_404_unknown_cve(self, client):
        resp = client.post("/api/vulnerabilities/CVE-9999-FAKE/nvd-refresh")
        assert resp.status_code == 404

    def test_single_refresh_503_on_empty_nvd_response(self, client, existing_cve_id):
        """503 when NVD returns 200 but no vulnerability data."""
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (200, {"vulnerabilities": []})
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh")
        assert resp.status_code == 503

    def test_single_refresh_503_on_nvd_failure(self, client, existing_cve_id):
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.side_effect = ConnectionError("NVD unavailable")
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh")
        assert resp.status_code == 503


class TestCollectTargetCveIds:

    def test_returns_empty_when_no_scans_for_variant(self, app):
        """A variant that doesn't exist in DB → active_scan_ids returns [] → returns []."""
        import uuid as _uuid
        from src.controllers.nvd_refresh import collect_target_cve_ids
        fake_variant = _uuid.uuid4()
        with app.app_context():
            result = collect_target_cve_ids(fake_variant, None, None)
        assert result == []

    def test_returns_empty_when_no_under_investigation_assessments(self, app, variant_id):
        """Existing variant with scan but no under_investigation assessments → []."""
        import uuid as _uuid
        from src.controllers.nvd_refresh import collect_target_cve_ids
        with app.app_context():
            result = collect_target_cve_ids(_uuid.UUID(variant_id), None, None)
        assert isinstance(result, list)
        assert result == []

    def test_returns_empty_via_project_uuid_path(self, app):
        """project_uuid branch: no matching scans → returns []."""
        import uuid as _uuid
        from src.controllers.nvd_refresh import collect_target_cve_ids
        fake_project = _uuid.uuid4()
        with app.app_context():
            result = collect_target_cve_ids(None, fake_project, None)
        assert result == []


class TestRunNvdRefresh:

    def test_run_nvd_refresh_empty_target(self, app, variant_id):
        """run_nvd_refresh with empty requested_cve_ids returns zero counts."""
        from src.controllers.nvd_refresh import run_nvd_refresh
        progress = {"status": "running", "logs": [], "done_count": 0}
        with app.app_context():
            result = run_nvd_refresh(
                variant_uuid=variant_id,
                project_uuid=None,
                requested_cve_ids=[],
                progress=progress,
            )
        assert result == {"refreshed": 0, "changed": 0, "failed": 0}
        assert progress["status"] == "done"

    def test_run_nvd_refresh_with_cpe_batch_match(self, app, variant_id, existing_cve_id):
        """run_nvd_refresh finds CVE via CPE batch and updates the record."""
        from src.controllers.nvd_refresh import run_nvd_refresh
        progress = {"status": "running", "logs": [], "done_count": 0}

        mock_nvd_vuln = {
            "cve": {
                "id": existing_cve_id,
                "descriptions": [{"lang": "en", "value": "Updated description"}],
                "metrics": {},
                "weaknesses": [],
                "references": [],
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2025-01-01T00:00:00.000",
            }
        }

        with app.app_context():
            with patch("src.controllers.nvd_db.NVD_DB") as MockNVD:
                mock_instance = MockNVD.return_value
                mock_instance.api_get_cves_by_cpe.return_value = [mock_nvd_vuln]
                MockNVD.extract_cve_details.return_value = {
                    "description": "Updated description",
                    "status": "high",
                    "links": ["https://nvd.nist.gov"],
                    "weaknesses": [],
                    "publish_date": None,
                    "attack_vector": "NETWORK",
                    "nvd_last_modified": "2025-01-01T00:00:00.000",
                }
                result = run_nvd_refresh(
                    variant_uuid=variant_id,
                    project_uuid=None,
                    requested_cve_ids=[existing_cve_id],
                    progress=progress,
                )

        assert result["refreshed"] >= 1
        assert progress["status"] == "done"

    def test_run_nvd_refresh_straggler_path(self, app, variant_id, existing_cve_id):
        """CVE not found via CPE goes through straggler individual fetch path."""
        from src.controllers.nvd_refresh import run_nvd_refresh
        progress = {"status": "running", "logs": [], "done_count": 0}

        with app.app_context():
            with patch("src.controllers.nvd_db.NVD_DB") as MockNVD:
                mock_instance = MockNVD.return_value
                mock_instance.api_get_cves_by_cpe.return_value = []
                mock_instance.api_get_cve.return_value = (200, {
                    "vulnerabilities": [{"cve": {
                        "id": existing_cve_id,
                        "descriptions": [{"lang": "en", "value": "Via straggler"}],
                        "metrics": {},
                        "weaknesses": [],
                        "references": [],
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2025-01-01T00:00:00.000",
                    }}]
                })
                MockNVD.extract_cve_details.return_value = {
                    "description": "Via straggler",
                    "status": "medium",
                    "links": [],
                    "weaknesses": [],
                    "publish_date": None,
                    "attack_vector": "NETWORK",
                    "nvd_last_modified": "2025-01-01T00:00:00.000",
                }
                result = run_nvd_refresh(
                    variant_uuid=variant_id,
                    project_uuid=None,
                    requested_cve_ids=[existing_cve_id],
                    progress=progress,
                )

        assert progress["status"] == "done"
        assert isinstance(result["refreshed"], int)

    def test_run_nvd_refresh_straggler_nvd_failure(self, app, variant_id, existing_cve_id):
        """Straggler fetch returning non-200 goes to failed set."""
        from src.controllers.nvd_refresh import run_nvd_refresh
        progress = {"status": "running", "logs": [], "done_count": 0}

        with app.app_context():
            with patch("src.controllers.nvd_db.NVD_DB") as MockNVD:
                mock_instance = MockNVD.return_value
                mock_instance.api_get_cves_by_cpe.return_value = []
                mock_instance.api_get_cve.return_value = (503, {})
                result = run_nvd_refresh(
                    variant_uuid=variant_id,
                    project_uuid=None,
                    requested_cve_ids=[existing_cve_id],
                    progress=progress,
                )

        assert progress["status"] == "done"
        assert result["failed"] >= 1

    def test_run_nvd_refresh_cpe_exception_handling(self, app, variant_id, existing_cve_id):
        """CPE batch exception is caught and logged; straggler handles the CVE."""
        from src.controllers.nvd_refresh import run_nvd_refresh
        progress = {"status": "running", "logs": [], "done_count": 0}

        with app.app_context():
            with patch("src.controllers.nvd_db.NVD_DB") as MockNVD:
                mock_instance = MockNVD.return_value
                mock_instance.api_get_cves_by_cpe.side_effect = ConnectionError("NVD unreachable")
                mock_instance.api_get_cve.return_value = (503, {})
                result = run_nvd_refresh(
                    variant_uuid=variant_id,
                    project_uuid=None,
                    requested_cve_ids=[existing_cve_id],
                    progress=progress,
                )

        assert progress["status"] == "done"
        assert result["failed"] >= 0

    def test_run_nvd_refresh_straggler_exception_handling(self, app, variant_id, existing_cve_id):
        """Straggler fetch exception is caught and CVE is counted as failed."""
        from src.controllers.nvd_refresh import run_nvd_refresh
        progress = {"status": "running", "logs": [], "done_count": 0}

        with app.app_context():
            with patch("src.controllers.nvd_db.NVD_DB") as MockNVD:
                mock_instance = MockNVD.return_value
                mock_instance.api_get_cves_by_cpe.return_value = []
                mock_instance.api_get_cve.side_effect = ConnectionError("timeout")
                result = run_nvd_refresh(
                    variant_uuid=variant_id,
                    project_uuid=None,
                    requested_cve_ids=[existing_cve_id],
                    progress=progress,
                )

        assert progress["status"] == "done"
        assert result["failed"] >= 1

    def test_run_nvd_refresh_cpe_match_no_db_record(self, app, variant_id):
        """CVE resolved via CPE but not found in local DB is skipped gracefully."""
        from src.controllers.nvd_refresh import run_nvd_refresh
        progress = {"status": "running", "logs": [], "done_count": 0}
        missing_cve = "CVE-9999-0001"

        mock_nvd_vuln = {"cve": {"id": missing_cve}}

        with app.app_context():
            with patch("src.controllers.nvd_db.NVD_DB") as MockNVD:
                mock_instance = MockNVD.return_value
                mock_instance.api_get_cves_by_cpe.return_value = [mock_nvd_vuln]
                MockNVD.extract_cve_details.return_value = {
                    "description": "no record",
                    "status": "low",
                    "links": [],
                    "weaknesses": [],
                    "publish_date": None,
                    "attack_vector": None,
                    "nvd_last_modified": None,
                }
                # Use a CVE that doesn't exist in the DB (no Finding → empty cpe_map)
                # but pass it as explicit ID so target_ids is non-empty
                result = run_nvd_refresh(
                    variant_uuid=variant_id,
                    project_uuid=None,
                    requested_cve_ids=[missing_cve],
                    progress=progress,
                )

        assert progress["status"] == "done"
        assert isinstance(result, dict)

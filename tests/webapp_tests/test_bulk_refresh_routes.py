# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from unittest.mock import patch, MagicMock, ANY
from src.bin.webapp import create_app
from tests.webapp_tests import write_demo_files, setup_demo_db


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
        })
        setup_demo_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def reset_progress_trackers():
    """Reset NVD, EPSS, GHSA and EUVD progress tracker singletons between tests."""
    from src.controllers.nvd_progress import NVDProgressTracker
    from src.controllers.epss_progress import EPSSProgressTracker
    from src.controllers.ghsa_progress import GHSAProgressTracker
    from src.controllers.euvd_progress import EUVDProgressTracker
    NVDProgressTracker.complete()
    EPSSProgressTracker.complete()
    GHSAProgressTracker.complete()
    EUVDProgressTracker.complete()
    yield
    NVDProgressTracker.complete()
    EPSSProgressTracker.complete()
    GHSAProgressTracker.complete()
    EUVDProgressTracker.complete()


@pytest.fixture()
def existing_cve_id():
    return "CVE-2020-35492"


# ---------------------------------------------------------------------------
# Bulk NVD refresh — /api/vulnerabilities/bulk-nvd-refresh
# ---------------------------------------------------------------------------

class TestBulkNvdRefreshEndpoint:

    def test_returns_202_with_valid_cve_ids(self, client, existing_cve_id):
        """POST with a known CVE ID returns 202 and starts the job."""
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": [existing_cve_id]},
            )
        assert resp.status_code == 202
        data = resp.get_json()
        assert data["status"] == "started"
        assert data["total"] >= 1
        MockThread.return_value.start.assert_called_once()

    def test_returns_400_when_cve_ids_missing(self, client):
        """400 when request body has no cve_ids."""
        resp = client.post("/api/vulnerabilities/bulk-nvd-refresh", json={})
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_returns_400_when_cve_ids_empty_list(self, client):
        """400 when cve_ids is an empty list."""
        resp = client.post(
            "/api/vulnerabilities/bulk-nvd-refresh",
            json={"cve_ids": []},
        )
        assert resp.status_code == 400

    def test_always_refreshes_previously_fetched_cve(self, client, existing_cve_id):
        """Manual refresh always runs even if the CVE was recently fetched."""
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": [existing_cve_id]},
            )
        assert resp.status_code == 202
        assert resp.get_json()["total"] == 1

    def test_returns_409_when_already_in_progress(self, client, existing_cve_id):
        """409 when start_if_idle returns False (tracker already running)."""
        with patch(
            "src.routes.bulk_refresh.NVDProgressTracker.start_if_idle",
            return_value=False,
        ):
            resp = client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": [existing_cve_id]},
            )
        assert resp.status_code == 409
        assert "already in progress" in resp.get_json()["error"]

    def test_409_only_after_valid_input(self, client, existing_cve_id):
        """Invalid input returns 400, not 409, even when tracker is running."""
        with patch(
            "src.routes.bulk_refresh.NVDProgressTracker.start_if_idle",
            return_value=False,
        ):
            resp = client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": ["not-a-cve"]},
            )
        assert resp.status_code == 400

    def test_cve_ids_normalized_to_uppercase(self, client, existing_cve_id):
        """Lowercase CVE IDs are normalized before processing."""
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": [existing_cve_id.lower()]},
            )
        assert resp.status_code == 202

    def test_returns_400_when_all_ids_are_blank_or_non_string(self, client):
        """400 when every element of cve_ids is empty/whitespace or non-string."""
        resp = client.post(
            "/api/vulnerabilities/bulk-nvd-refresh",
            json={"cve_ids": ["", "   ", 42, None]},
        )
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_total_matches_input_count(self, client, existing_cve_id):
        """Response total equals the number of CVE IDs submitted."""
        second_id = "CVE-2024-99999"
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": [existing_cve_id, second_id]},
            )
        assert resp.status_code == 202
        assert resp.get_json()["total"] == 2

    def test_returns_400_when_all_ids_are_invalid_format(self, client):
        """400 when every CVE ID has an invalid format."""
        resp = client.post(
            "/api/vulnerabilities/bulk-nvd-refresh",
            json={"cve_ids": ["not-a-cve", "CVE-ABCD-1234", "CVE-2024-FRESH"]},
        )
        assert resp.status_code == 400
        assert "valid CVE" in resp.get_json()["error"]

    def test_returns_400_when_count_exceeds_max(self, client):
        """400 when more than _MAX_CVE_IDS valid IDs are submitted in API mode."""
        from src.routes.bulk_refresh import _MAX_CVE_IDS
        ids = [f"CVE-2024-{i:05d}" for i in range(_MAX_CVE_IDS + 1)]
        resp = client.post(
            "/api/vulnerabilities/bulk-nvd-refresh",
            json={"cve_ids": ids, "mode": "api"},
        )
        assert resp.status_code == 400
        assert "at most" in resp.get_json()["error"]


# ---------------------------------------------------------------------------
# Bulk EPSS refresh — /api/vulnerabilities/bulk-epss-refresh
# ---------------------------------------------------------------------------

class TestBulkEpssRefreshEndpoint:

    def test_returns_202_with_valid_cve_ids(self, client, existing_cve_id):
        """POST with a known CVE ID returns 202 and starts the job."""
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-epss-refresh",
                json={"cve_ids": [existing_cve_id]},
            )
        assert resp.status_code == 202
        data = resp.get_json()
        assert data["status"] == "started"
        assert data["total"] >= 1
        MockThread.return_value.start.assert_called_once()

    def test_returns_400_when_cve_ids_missing(self, client):
        resp = client.post("/api/vulnerabilities/bulk-epss-refresh", json={})
        assert resp.status_code == 400

    def test_returns_400_when_cve_ids_empty_list(self, client):
        resp = client.post(
            "/api/vulnerabilities/bulk-epss-refresh",
            json={"cve_ids": []},
        )
        assert resp.status_code == 400

    def test_always_refreshes_previously_fetched_cve(self, client, existing_cve_id):
        """Manual refresh always runs even if the CVE was recently fetched."""
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-epss-refresh",
                json={"cve_ids": [existing_cve_id]},
            )
        assert resp.status_code == 202
        assert resp.get_json()["total"] == 1

    def test_returns_409_when_already_in_progress(self, client, existing_cve_id):
        """409 when start_if_idle returns False (tracker already running)."""
        with patch(
            "src.routes.bulk_refresh.EPSSProgressTracker.start_if_idle",
            return_value=False,
        ):
            resp = client.post(
                "/api/vulnerabilities/bulk-epss-refresh",
                json={"cve_ids": [existing_cve_id]},
            )
        assert resp.status_code == 409
        assert "already in progress" in resp.get_json()["error"]

    def test_409_only_after_valid_input(self, client, existing_cve_id):
        """Invalid input returns 400, not 409, even when tracker is running."""
        with patch(
            "src.routes.bulk_refresh.EPSSProgressTracker.start_if_idle",
            return_value=False,
        ):
            resp = client.post(
                "/api/vulnerabilities/bulk-epss-refresh",
                json={"cve_ids": ["not-a-cve"]},
            )
        assert resp.status_code == 400

    def test_cve_ids_normalized_to_uppercase(self, client, existing_cve_id):
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-epss-refresh",
                json={"cve_ids": [existing_cve_id.lower()]},
            )
        assert resp.status_code == 202

    def test_returns_400_when_all_ids_are_blank_or_non_string(self, client):
        """400 when every element of cve_ids is empty/whitespace or non-string."""
        resp = client.post(
            "/api/vulnerabilities/bulk-epss-refresh",
            json={"cve_ids": ["", "   ", 42, None]},
        )
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_returns_400_when_all_ids_are_invalid_format(self, client):
        """400 when every CVE ID has an invalid format."""
        resp = client.post(
            "/api/vulnerabilities/bulk-epss-refresh",
            json={"cve_ids": ["not-a-cve", "CVE-ABCD-1234", "CVE-2024-FRESH"]},
        )
        assert resp.status_code == 400
        assert "valid CVE" in resp.get_json()["error"]

    def test_returns_400_when_count_exceeds_max(self, client):
        """400 when more than _MAX_CVE_IDS valid IDs are submitted."""
        from src.routes.bulk_refresh import _MAX_CVE_IDS
        ids = [f"CVE-2024-{i:05d}" for i in range(_MAX_CVE_IDS + 1)]
        resp = client.post(
            "/api/vulnerabilities/bulk-epss-refresh",
            json={"cve_ids": ids},
        )
        assert resp.status_code == 400
        assert "at most" in resp.get_json()["error"]


# ---------------------------------------------------------------------------
# NVD background _run() — lines executed inside the daemon thread
# ---------------------------------------------------------------------------

class TestBulkNvdRefreshBackground:
    """Tests for the _run() closure spawned by bulk_nvd_refresh."""

    def _capture_target(self, client, cve_ids):
        """POST to the endpoint with mode=api and return the captured _run target without starting it."""
        captured = {}

        def fake_thread(target=None, **kwargs):
            captured["target"] = target
            return MagicMock()

        with patch("src.routes.bulk_refresh.threading.Thread", side_effect=fake_thread):
            resp = client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": cve_ids, "mode": "api"},
            )
        assert resp.status_code == 202
        return captured["target"]

    def test_run_applies_update_on_200(self, client, existing_cve_id):
        """_run() calls apply_nvd_update and apply_cvss_update when API returns 200."""
        target = self._capture_target(client, [existing_cve_id])
        mock_rec = MagicMock()
        mock_details = {"base_score": 7.5, "cvss_version": "3.1", "cvss_vector": "CVSS:3.1/X"}

        with patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh.apply_nvd_update") as mock_apply, \
             patch("src.routes.bulk_refresh.apply_cvss_update") as mock_cvss, \
             patch("src.routes.bulk_refresh.db") as mock_db, \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (
                200, {"vulnerabilities": [{"cve": {}}]}
            )
            MockNVD.extract_cve_details.return_value = mock_details
            mock_db.session.get.return_value = mock_rec
            target()

        mock_apply.assert_called_once_with(mock_rec, mock_details, ANY)
        mock_cvss.assert_called_once_with(mock_rec, mock_details, mock_db)

    def test_run_skips_update_on_non_200(self, client, existing_cve_id):
        """_run() skips the update and logs when API returns a non-200 status."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh.apply_nvd_update") as mock_apply, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            target()

        mock_apply.assert_not_called()

    def test_run_skips_update_when_no_vulnerabilities_in_response(self, client, existing_cve_id):
        """_run() skips update when 200 but vulnerabilities list is empty."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh.apply_nvd_update") as mock_apply, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (200, {"vulnerabilities": []})
            target()

        mock_apply.assert_not_called()

    def test_run_skips_update_when_record_not_in_db(self, client, existing_cve_id):
        """_run() skips apply_nvd_update when the vulnerability is absent from the local DB."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh.apply_nvd_update") as mock_apply, \
             patch("src.routes.bulk_refresh.db") as mock_db, \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (
                200, {"vulnerabilities": [{"cve": {}}]}
            )
            MockNVD.extract_cve_details.return_value = {}
            mock_db.session.get.return_value = None
            target()

        mock_apply.assert_not_called()

    def test_run_continues_after_per_cve_exception(self, client):
        """_run() catches per-CVE exceptions and keeps processing remaining CVEs."""
        cve_ids = ["CVE-2024-00001", "CVE-2024-00002"]
        target = self._capture_target(client, cve_ids)
        apply_counts = []

        def fake_get_cve(cve_id, **kwargs):
            if cve_id == "CVE-2024-00001":
                raise RuntimeError("transient API error")
            return (404, {})

        with patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh.apply_nvd_update") as mock_apply, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.side_effect = fake_get_cve
            target()

        MockTracker.complete.assert_called()

    def test_run_commits_at_batch_boundary(self, client):
        """_run() calls _safe_commit after every _NVD_COMMIT_EVERY items (50)."""
        cve_ids = [f"CVE-2024-{i:05d}" for i in range(50)]
        target = self._capture_target(client, cve_ids)

        with patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh._safe_commit") as mock_commit, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            target()

        # Commit at item #50 (mod boundary) plus the final commit → at least 2 calls
        assert mock_commit.call_count >= 2

    def test_run_sleeps_between_cves_but_not_after_last(self, client):
        """_run() sleeps between CVEs but not after the final one."""
        cve_ids = ["CVE-2024-00001", "CVE-2024-00002"]
        target = self._capture_target(client, cve_ids)

        with patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep") as mock_sleep, \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            target()

        assert mock_sleep.call_count == 1

    def test_run_calls_complete_on_success(self, client, existing_cve_id):
        """_run() calls NVDProgressTracker.complete() after all CVEs are processed."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            target()

        MockTracker.complete.assert_called()

    def test_run_calls_error_on_outer_exception(self, client, existing_cve_id):
        """_run() calls NVDProgressTracker.error() when an unhandled exception occurs."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            # complete() is inside the outer try, so making it raise triggers the outer except
            MockTracker.complete.side_effect = RuntimeError("tracker failure")
            target()

        MockTracker.error.assert_called_once()


# ---------------------------------------------------------------------------
# EPSS background _run() — lines executed inside the daemon thread
# ---------------------------------------------------------------------------

class TestBulkEpssRefreshBackground:
    """Tests for the _run() closure spawned by bulk_epss_refresh."""

    def _capture_target(self, client, cve_ids):
        captured = {}

        def fake_thread(target=None, **kwargs):
            captured["target"] = target
            return MagicMock()

        with patch("src.routes.bulk_refresh.threading.Thread", side_effect=fake_thread):
            resp = client.post(
                "/api/vulnerabilities/bulk-epss-refresh",
                json={"cve_ids": cve_ids},
            )
        assert resp.status_code == 202
        return captured["target"]

    def test_run_updates_record_when_epss_data_returned(self, client, existing_cve_id):
        """_run() calls update_record when EPSS returns a score for the CVE."""
        target = self._capture_target(client, [existing_cve_id])
        mock_rec = MagicMock()

        with patch("src.routes.bulk_refresh.EPSS_DB") as MockEPSS, \
             patch("src.routes.bulk_refresh.db") as mock_db, \
             patch("src.routes.bulk_refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {
                existing_cve_id: {"score": 0.42}
            }
            mock_db.session.get.return_value = mock_rec
            target()

        mock_rec.update_record.assert_called_once()

    def test_run_skips_cve_with_no_epss_result(self, client, existing_cve_id):
        """_run() skips update_record when EPSS returns no data for the CVE."""
        target = self._capture_target(client, [existing_cve_id])
        mock_rec = MagicMock()

        with patch("src.routes.bulk_refresh.EPSS_DB") as MockEPSS, \
             patch("src.routes.bulk_refresh.db") as mock_db, \
             patch("src.routes.bulk_refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {}
            mock_db.session.get.return_value = mock_rec
            target()

        mock_rec.update_record.assert_not_called()

    def test_run_skips_update_when_record_not_in_db(self, client, existing_cve_id):
        """_run() skips update_record when the vulnerability is absent from the local DB."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.routes.bulk_refresh.EPSS_DB") as MockEPSS, \
             patch("src.routes.bulk_refresh.db") as mock_db, \
             patch("src.routes.bulk_refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {
                existing_cve_id: {"score": 0.5}
            }
            mock_db.session.get.return_value = None
            target()
        # No exception → None branch handled correctly

    def test_run_continues_after_batch_exception(self, client, existing_cve_id):
        """_run() continues processing after api_get_epss_batch raises."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.routes.bulk_refresh.EPSS_DB") as MockEPSS, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.side_effect = Exception("API timeout")
            target()

        MockTracker.complete.assert_called()

    def test_run_continues_after_record_update_exception(self, client, existing_cve_id):
        """_run() catches and logs exceptions raised by update_record."""
        target = self._capture_target(client, [existing_cve_id])
        mock_rec = MagicMock()
        mock_rec.update_record.side_effect = Exception("DB constraint")

        with patch("src.routes.bulk_refresh.EPSS_DB") as MockEPSS, \
             patch("src.routes.bulk_refresh.db") as mock_db, \
             patch("src.routes.bulk_refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {
                existing_cve_id: {"score": 0.3}
            }
            mock_db.session.get.return_value = mock_rec
            target()

        MockTracker.complete.assert_called()

    def test_run_processes_multiple_chunks(self, client):
        """_run() batches CVEs into chunks of _EPSS_BATCH_SIZE (100)."""
        cve_ids = [f"CVE-2024-{i:05d}" for i in range(150)]
        target = self._capture_target(client, cve_ids)

        with patch("src.routes.bulk_refresh.EPSS_DB") as MockEPSS, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {}
            target()

        assert MockEPSS.return_value.api_get_epss_batch.call_count == 2

    def test_run_calls_complete_on_success(self, client, existing_cve_id):
        """_run() calls EPSSProgressTracker.complete() after successful processing."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.routes.bulk_refresh.EPSS_DB") as MockEPSS, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {}
            target()

        MockTracker.complete.assert_called()

    def test_run_calls_error_on_outer_exception(self, client, existing_cve_id):
        """_run() calls EPSSProgressTracker.error() on an unhandled outer exception."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.routes.bulk_refresh.EPSS_DB") as MockEPSS, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {}
            # complete() is inside the outer try, so making it raise triggers the outer except
            MockTracker.complete.side_effect = RuntimeError("tracker failure")
            target()

        MockTracker.error.assert_called_once()

    def test_bulk_epss_run_sets_data_updated_at_when_score_changes(self, app, client, existing_cve_id):
        """_run() stamps epss_data_updated_at only when the score changes."""
        from decimal import Decimal
        from src.models.vulnerability import Vulnerability
        from src.extensions import db

        with app.app_context():
            rec = db.session.get(Vulnerability, existing_cve_id)
            rec.epss_score = Decimal("0.1")
            rec.epss_data_updated_at = None
            db.session.commit()

        target = self._capture_target(client, [existing_cve_id])

        with patch("src.routes.bulk_refresh.EPSS_DB") as MockEPSS, \
             patch("src.routes.bulk_refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {
                existing_cve_id: {"score": 0.9}
            }
            with app.app_context():
                target()

        with app.app_context():
            rec = db.session.get(Vulnerability, existing_cve_id)
            assert rec.epss_data_updated_at is not None

    def test_bulk_epss_run_no_data_updated_at_when_score_unchanged(self, app, client, existing_cve_id):
        """_run() does NOT stamp epss_data_updated_at when the score is the same."""
        from decimal import Decimal
        from src.models.vulnerability import Vulnerability
        from src.extensions import db

        with app.app_context():
            rec = db.session.get(Vulnerability, existing_cve_id)
            rec.epss_score = Decimal("0.5")
            rec.epss_data_updated_at = None
            db.session.commit()

        target = self._capture_target(client, [existing_cve_id])

        with patch("src.routes.bulk_refresh.EPSS_DB") as MockEPSS, \
             patch("src.routes.bulk_refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {
                existing_cve_id: {"score": 0.5}
            }
            with app.app_context():
                target()

        with app.app_context():
            rec = db.session.get(Vulnerability, existing_cve_id)
            assert rec.epss_data_updated_at is None


# ---------------------------------------------------------------------------
# Cancel NVD refresh — /api/vulnerabilities/cancel-nvd-refresh
# ---------------------------------------------------------------------------

class TestCancelNvdRefreshEndpoint:

    def test_returns_200_when_refresh_in_progress(self, client):
        """POST to cancel-nvd-refresh returns 200 when a refresh is running."""
        with patch(
            "src.routes.bulk_refresh.NVDProgressTracker.cancel",
            return_value=True,
        ):
            resp = client.post("/api/vulnerabilities/cancel-nvd-refresh")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "cancelling"

    def test_returns_409_when_no_refresh_in_progress(self, client):
        """POST to cancel-nvd-refresh returns 409 when nothing is running."""
        with patch(
            "src.routes.bulk_refresh.NVDProgressTracker.cancel",
            return_value=False,
        ):
            resp = client.post("/api/vulnerabilities/cancel-nvd-refresh")
        assert resp.status_code == 409
        assert "currently in progress" in resp.get_json()["error"]


class TestCancelEpssRefreshEndpoint:

    def test_returns_200_when_refresh_in_progress(self, client):
        """POST to cancel-epss-refresh returns 200 when a refresh is running."""
        with patch(
            "src.routes.bulk_refresh.EPSSProgressTracker.cancel",
            return_value=True,
        ):
            resp = client.post("/api/vulnerabilities/cancel-epss-refresh")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "cancelling"

    def test_returns_409_when_no_refresh_in_progress(self, client):
        """POST to cancel-epss-refresh returns 409 when nothing is running."""
        with patch(
            "src.routes.bulk_refresh.EPSSProgressTracker.cancel",
            return_value=False,
        ):
            resp = client.post("/api/vulnerabilities/cancel-epss-refresh")
        assert resp.status_code == 409
        assert "currently in progress" in resp.get_json()["error"]


# ---------------------------------------------------------------------------
# GHSA progress tracker — smoke test the singleton
# ---------------------------------------------------------------------------

class TestGhsaProgressTracker:

    def test_singleton_starts_idle(self):
        from src.controllers.ghsa_progress import GHSAProgressTracker
        GHSAProgressTracker.complete()  # reset
        progress = GHSAProgressTracker.get_progress()
        assert progress["in_progress"] is False

    def test_ghsa_progress_endpoint_returns_200(self, client):
        from src.controllers.ghsa_progress import GHSAProgressTracker
        GHSAProgressTracker.complete()
        resp = client.get("/api/ghsa/progress")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "in_progress" in data
        assert "phase" in data
        assert "current" in data
        assert "total" in data


# ---------------------------------------------------------------------------
# Cancellation checks inside _run() threads
# ---------------------------------------------------------------------------

def _capture_refresh_target(client, endpoint, cve_ids):
    """Capture the thread target function without starting the thread."""
    captured = {}

    def fake_thread(target=None, **kwargs):
        captured["target"] = target
        return MagicMock()

    with patch("src.routes.bulk_refresh.threading.Thread", side_effect=fake_thread):
        resp = client.post(endpoint, json={"cve_ids": cve_ids, "mode": "api"})
    assert resp.status_code == 202
    return captured["target"]


class TestBulkNvdRefreshCancellation:
    """Tests that _run() respects the cancellation flag."""

    def _capture_target(self, client, cve_ids):
        return _capture_refresh_target(client, "/api/vulnerabilities/bulk-nvd-refresh", cve_ids)

    def test_run_stops_and_commits_when_cancelled(self, client):
        """_run() commits pending work and calls mark_cancelled when flag is set."""
        cve_ids = ["CVE-2024-00001", "CVE-2024-00002"]
        target = self._capture_target(client, cve_ids)

        call_count = {"n": 0}

        def fake_is_cancelled():
            call_count["n"] += 1
            # Cancel after first iteration
            return call_count["n"] > 1

        with patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh._safe_commit") as mock_commit, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            MockTracker.is_cancelled.side_effect = fake_is_cancelled
            target()

        MockTracker.mark_cancelled.assert_called_once()
        MockTracker.complete.assert_not_called()
        # commit must be called for the pending work
        mock_commit.assert_called()

    def test_run_does_not_process_all_cves_when_cancelled_early(self, client):
        """_run() stops processing before all CVEs when cancelled."""
        cve_ids = [f"CVE-2024-{i:05d}" for i in range(5)]
        target = self._capture_target(client, cve_ids)

        api_call_count = {"n": 0}
        cancel_after = 2

        def fake_api_get(cve_id, **kwargs):
            api_call_count["n"] += 1
            return (404, {})

        def fake_is_cancelled():
            return api_call_count["n"] >= cancel_after

        with patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh._safe_commit"), \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockNVD.return_value.api_get_cve.side_effect = fake_api_get
            MockTracker.is_cancelled.side_effect = fake_is_cancelled
            target()

        assert api_call_count["n"] < len(cve_ids)
        MockTracker.mark_cancelled.assert_called_once()


class TestBulkEpssRefreshCancellation:
    """Tests that _run() in the EPSS thread respects the cancellation flag."""

    def _capture_target(self, client, cve_ids):
        return _capture_refresh_target(client, "/api/vulnerabilities/bulk-epss-refresh", cve_ids)

    def test_run_stops_and_commits_when_cancelled(self, client):
        """_run() commits pending work and calls mark_cancelled when flag is set."""
        cve_ids = [f"CVE-2024-{i:05d}" for i in range(150)]  # 2 chunks
        target = self._capture_target(client, cve_ids)

        chunk_count = {"n": 0}

        def fake_is_cancelled():
            chunk_count["n"] += 1
            return chunk_count["n"] > 1

        with patch("src.routes.bulk_refresh.EPSS_DB") as MockEPSS, \
             patch("src.routes.bulk_refresh._safe_commit") as mock_commit, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.EPSSProgressTracker") as MockTracker:
            MockEPSS.return_value.api_get_epss_batch.return_value = {}
            MockTracker.is_cancelled.side_effect = fake_is_cancelled
            target()

        MockTracker.mark_cancelled.assert_called_once()
        MockTracker.complete.assert_not_called()
        mock_commit.assert_called()


# ---------------------------------------------------------------------------
# Concurrent-request tests — verify the atomic start_if_idle guard
# ---------------------------------------------------------------------------

class TestConcurrentBulkNvdRefresh:
    """Verify that simultaneous POST requests yield exactly one 202 and one 409."""

    def test_only_one_request_starts_when_concurrent(self, app, existing_cve_id):
        """Two threads posting simultaneously must produce exactly one 202 and one 409."""
        import threading
        RealThread = threading.Thread
        barrier = threading.Barrier(2)
        results = []

        def post():
            barrier.wait()
            with app.test_client() as c:
                resp = c.post(
                    "/api/vulnerabilities/bulk-nvd-refresh",
                    json={"cve_ids": [existing_cve_id]},
                )
            results.append(resp.status_code)

        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            threads = [RealThread(target=post) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        results.sort()
        assert results == [202, 409], f"Expected [202, 409], got {results}"


class TestConcurrentBulkEpssRefresh:
    """Verify that simultaneous POST requests yield exactly one 202 and one 409."""

    def test_only_one_request_starts_when_concurrent(self, app, existing_cve_id):
        """Two threads posting simultaneously must produce exactly one 202 and one 409."""
        import threading
        RealThread = threading.Thread
        barrier = threading.Barrier(2)
        results = []

        def post():
            barrier.wait()
            with app.test_client() as c:
                resp = c.post(
                    "/api/vulnerabilities/bulk-epss-refresh",
                    json={"cve_ids": [existing_cve_id]},
                )
            results.append(resp.status_code)

        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            threads = [RealThread(target=post) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        results.sort()
        assert results == [202, 409], f"Expected [202, 409], got {results}"


# ---------------------------------------------------------------------------
# Bulk GHSA refresh — /api/vulnerabilities/bulk-ghsa-refresh
# ---------------------------------------------------------------------------

@pytest.fixture()
def existing_ghsa_id():
    return "GHSA-R7JW-VC2X-4GBH"


class TestBulkGhsaRefreshEndpoint:

    def test_returns_202_with_valid_ghsa_ids(self, client, existing_ghsa_id):
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-ghsa-refresh",
                json={"ghsa_ids": [existing_ghsa_id]},
            )
        assert resp.status_code == 202
        data = resp.get_json()
        assert data["status"] == "started"
        assert data["total"] >= 1
        MockThread.return_value.start.assert_called_once()

    def test_returns_400_when_ghsa_ids_missing(self, client):
        resp = client.post("/api/vulnerabilities/bulk-ghsa-refresh", json={})
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_returns_400_when_ghsa_ids_empty_list(self, client):
        resp = client.post(
            "/api/vulnerabilities/bulk-ghsa-refresh",
            json={"ghsa_ids": []},
        )
        assert resp.status_code == 400

    def test_returns_400_when_all_ids_are_invalid_format(self, client):
        resp = client.post(
            "/api/vulnerabilities/bulk-ghsa-refresh",
            json={"ghsa_ids": ["not-a-ghsa", "GHSA-short"]},
        )
        assert resp.status_code == 400
        assert "valid GHSA" in resp.get_json()["error"]

    def test_rejects_cve_ids(self, client):
        resp = client.post(
            "/api/vulnerabilities/bulk-ghsa-refresh",
            json={"ghsa_ids": ["CVE-2024-1234"]},
        )
        assert resp.status_code == 400

    def test_returns_409_when_already_in_progress(self, client, existing_ghsa_id):
        with patch(
            "src.routes.bulk_refresh.GHSAProgressTracker.start_if_idle",
            return_value=False,
        ):
            resp = client.post(
                "/api/vulnerabilities/bulk-ghsa-refresh",
                json={"ghsa_ids": [existing_ghsa_id]},
            )
        assert resp.status_code == 409
        assert "already in progress" in resp.get_json()["error"]

    def test_ghsa_ids_normalized_to_uppercase(self, client, existing_ghsa_id):
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-ghsa-refresh",
                json={"ghsa_ids": [existing_ghsa_id.lower()]},
            )
        assert resp.status_code == 202

    def test_total_matches_input_count(self, client, existing_ghsa_id):
        second_id = "GHSA-J8XG-FQG3-53R7"
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-ghsa-refresh",
                json={"ghsa_ids": [existing_ghsa_id, second_id]},
            )
        assert resp.status_code == 202
        assert resp.get_json()["total"] == 2

    def test_returns_400_when_count_exceeds_max(self, client):
        from src.routes.bulk_refresh import _MAX_GHSA_IDS
        ids = [f"GHSA-{i:04X}-{(i+1):04X}-{(i+2):04X}" for i in range(_MAX_GHSA_IDS + 1)]
        resp = client.post(
            "/api/vulnerabilities/bulk-ghsa-refresh",
            json={"ghsa_ids": ids},
        )
        assert resp.status_code == 400
        assert "at most" in resp.get_json()["error"]


class TestBulkGhsaRefreshBackground:
    """Tests for the _run() closure spawned by bulk_ghsa_refresh."""

    def _capture_target(self, client, ghsa_ids):
        captured = {}

        def fake_thread(target=None, **kwargs):
            captured["target"] = target
            return MagicMock()

        with patch("src.routes.bulk_refresh.threading.Thread", side_effect=fake_thread):
            resp = client.post(
                "/api/vulnerabilities/bulk-ghsa-refresh",
                json={"ghsa_ids": ghsa_ids},
            )
        assert resp.status_code == 202
        return captured["target"]

    def test_run_updates_record_when_published_at_returned(self, client):
        target = self._capture_target(client, ["GHSA-R7JW-VC2X-4GBH"])
        mock_rec = MagicMock()

        with patch("src.routes.bulk_refresh.VulnerabilitiesController._fetch_ghsa_published",
                   return_value="2023-05-01T00:00:00Z"), \
             patch("src.routes.bulk_refresh.db") as mock_db, \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.GHSAProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            mock_db.session.get.return_value = mock_rec
            target()

        mock_rec.update_record.assert_called_once()
        call_kwargs = mock_rec.update_record.call_args.kwargs
        assert call_kwargs.get("commit") is False
        assert call_kwargs.get("publish_date") is not None
        assert call_kwargs.get("ghsa_fetched_at") is not None

    def test_run_skips_update_when_published_at_is_none(self, client):
        target = self._capture_target(client, ["GHSA-R7JW-VC2X-4GBH"])
        mock_rec = MagicMock()

        with patch("src.routes.bulk_refresh.VulnerabilitiesController._fetch_ghsa_published",
                   return_value=None), \
             patch("src.routes.bulk_refresh.db") as mock_db, \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.GHSAProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            mock_db.session.get.return_value = mock_rec
            target()

        mock_rec.update_record.assert_not_called()

    def test_run_skips_update_when_record_not_in_db(self, client):
        target = self._capture_target(client, ["GHSA-R7JW-VC2X-4GBH"])

        with patch("src.routes.bulk_refresh.VulnerabilitiesController._fetch_ghsa_published",
                   return_value="2023-01-01T00:00:00Z"), \
             patch("src.routes.bulk_refresh.db") as mock_db, \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.GHSAProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            mock_db.session.get.return_value = None
            target()
        # No exception — None branch handled correctly

    def test_run_continues_after_per_ghsa_exception(self, client):
        target = self._capture_target(client, ["GHSA-AAAA-BBBB-CCCC", "GHSA-R7JW-VC2X-4GBH"])

        def fake_fetch(ghsa_id):
            if ghsa_id == "GHSA-AAAA-BBBB-CCCC":
                raise RuntimeError("API error")
            return None

        with patch("src.routes.bulk_refresh.VulnerabilitiesController._fetch_ghsa_published",
                   side_effect=fake_fetch), \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.GHSAProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            target()

        MockTracker.complete.assert_called()

    def test_run_calls_complete_on_success(self, client):
        target = self._capture_target(client, ["GHSA-R7JW-VC2X-4GBH"])

        with patch("src.routes.bulk_refresh.VulnerabilitiesController._fetch_ghsa_published",
                   return_value=None), \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.GHSAProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            target()

        MockTracker.complete.assert_called()

    def test_run_calls_error_on_outer_exception(self, client):
        target = self._capture_target(client, ["GHSA-R7JW-VC2X-4GBH"])

        with patch("src.routes.bulk_refresh.VulnerabilitiesController._fetch_ghsa_published",
                   return_value=None), \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.GHSAProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockTracker.complete.side_effect = RuntimeError("tracker failure")
            target()

        MockTracker.error.assert_called_once()

    def test_bulk_ghsa_run_sets_data_updated_at_when_date_changes(self, app, client, ghsa_vuln):
        """_run() stamps ghsa_data_updated_at when publish_date actually changes."""
        import datetime as dt
        from src.models.vulnerability import Vulnerability
        from src.extensions import db

        with app.app_context():
            rec = db.session.get(Vulnerability, ghsa_vuln)
            rec.publish_date = dt.date(2020, 1, 1)
            rec.ghsa_data_updated_at = None
            db.session.commit()

        target = self._capture_target(client, [ghsa_vuln])

        with patch("src.routes.bulk_refresh.VulnerabilitiesController._fetch_ghsa_published",
                   return_value="2023-06-15T00:00:00Z"), \
             patch("src.routes.bulk_refresh.GHSAProgressTracker") as MockTracker, \
             patch("src.routes.bulk_refresh.time.sleep"):
            MockTracker.is_cancelled.return_value = False
            with app.app_context():
                target()

        with app.app_context():
            rec = db.session.get(Vulnerability, ghsa_vuln)
            assert rec.ghsa_data_updated_at is not None

    def test_bulk_ghsa_run_no_data_updated_at_when_date_unchanged(self, app, client, ghsa_vuln):
        """_run() does NOT stamp ghsa_data_updated_at when publish_date is same."""
        import datetime as dt
        from src.models.vulnerability import Vulnerability
        from src.extensions import db

        with app.app_context():
            rec = db.session.get(Vulnerability, ghsa_vuln)
            rec.publish_date = dt.date(2023, 5, 1)
            rec.ghsa_data_updated_at = None
            db.session.commit()

        target = self._capture_target(client, [ghsa_vuln])

        with patch("src.routes.bulk_refresh.VulnerabilitiesController._fetch_ghsa_published",
                   return_value="2023-05-01T00:00:00Z"), \
             patch("src.routes.bulk_refresh.GHSAProgressTracker") as MockTracker, \
             patch("src.routes.bulk_refresh.time.sleep"):
            MockTracker.is_cancelled.return_value = False
            with app.app_context():
                target()

        with app.app_context():
            rec = db.session.get(Vulnerability, ghsa_vuln)
            assert rec.ghsa_data_updated_at is None


class TestCancelGhsaRefreshEndpoint:

    def test_returns_200_when_refresh_in_progress(self, client):
        with patch(
            "src.routes.bulk_refresh.GHSAProgressTracker.cancel",
            return_value=True,
        ):
            resp = client.post("/api/vulnerabilities/cancel-ghsa-refresh")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "cancelling"

    def test_returns_409_when_no_refresh_in_progress(self, client):
        with patch(
            "src.routes.bulk_refresh.GHSAProgressTracker.cancel",
            return_value=False,
        ):
            resp = client.post("/api/vulnerabilities/cancel-ghsa-refresh")
        assert resp.status_code == 409
        assert "currently in progress" in resp.get_json()["error"]


class TestBulkGhsaRefreshCancellation:

    def _capture_target(self, client, ghsa_ids):
        captured = {}

        def fake_thread(target=None, **kwargs):
            captured["target"] = target
            return MagicMock()

        with patch("src.routes.bulk_refresh.threading.Thread", side_effect=fake_thread):
            resp = client.post(
                "/api/vulnerabilities/bulk-ghsa-refresh",
                json={"ghsa_ids": ghsa_ids},
            )
        assert resp.status_code == 202
        return captured["target"]

    def test_run_stops_and_commits_when_cancelled(self, client):
        ghsa_ids = ["GHSA-AAAA-BBBB-CCCC", "GHSA-R7JW-VC2X-4GBH"]
        target = self._capture_target(client, ghsa_ids)

        call_count = {"n": 0}

        def fake_is_cancelled():
            call_count["n"] += 1
            return call_count["n"] > 1

        with patch("src.routes.bulk_refresh.VulnerabilitiesController._fetch_ghsa_published",
                   return_value=None), \
             patch("src.routes.bulk_refresh._safe_commit") as mock_commit, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.GHSAProgressTracker") as MockTracker:
            MockTracker.is_cancelled.side_effect = fake_is_cancelled
            target()

        MockTracker.mark_cancelled.assert_called_once()
        MockTracker.complete.assert_not_called()
        mock_commit.assert_called()


class TestConcurrentBulkGhsaRefresh:

    def test_only_one_request_starts_when_concurrent(self, app):
        import threading
        RealThread = threading.Thread
        barrier = threading.Barrier(2)
        results = []
        ghsa_id = "GHSA-R7JW-VC2X-4GBH"

        def post():
            barrier.wait()
            with app.test_client() as c:
                resp = c.post(
                    "/api/vulnerabilities/bulk-ghsa-refresh",
                    json={"ghsa_ids": [ghsa_id]},
                )
            results.append(resp.status_code)

        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            threads = [RealThread(target=post) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        results.sort()
        assert results == [202, 409], f"Expected [202, 409], got {results}"


# ---------------------------------------------------------------------------
# Single GHSA refresh — /api/vulnerabilities/<ghsa_id>/ghsa-refresh
# ---------------------------------------------------------------------------

@pytest.fixture()
def ghsa_vuln(app, existing_ghsa_id):
    """Seed a GHSA vulnerability into the test DB and return its ID."""
    from src.extensions import db
    from src.models.vulnerability import Vulnerability
    with app.app_context():
        Vulnerability.create_record(id=existing_ghsa_id, description="GHSA test advisory")
        db.session.commit()
    return existing_ghsa_id


class TestSingleGhsaRefreshEndpoint:

    def test_returns_200_and_stamps_ghsa_fetched_at(self, client, ghsa_vuln):
        with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published",
                   return_value="2023-05-01T00:00:00Z"):
            resp = client.post(f"/api/vulnerabilities/{ghsa_vuln}/ghsa-refresh")
        assert resp.status_code == 200
        vuln = resp.get_json()["vulnerabilities"][0]
        assert vuln["id"] == ghsa_vuln
        assert vuln["data_fetched_at"] is not None

    def test_publish_date_stored_as_date_not_datetime(self, client, ghsa_vuln, app):
        """publish_date must be a date (not datetime) — guards the type-mismatch fix."""
        import datetime
        with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published",
                   return_value="2023-05-01T12:34:56Z"):
            resp = client.post(f"/api/vulnerabilities/{ghsa_vuln}/ghsa-refresh")
        assert resp.status_code == 200
        from src.extensions import db
        from src.models.vulnerability import Vulnerability
        with app.app_context():
            rec = db.session.get(Vulnerability, ghsa_vuln)
            assert isinstance(rec.publish_date, datetime.date)
            assert not isinstance(rec.publish_date, datetime.datetime)
            assert rec.publish_date == datetime.date(2023, 5, 1)

    def test_returns_404_for_unknown_ghsa_id(self, client):
        with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published",
                   return_value="2023-05-01T00:00:00Z"):
            resp = client.post("/api/vulnerabilities/GHSA-0000-0000-0000/ghsa-refresh")
        assert resp.status_code == 404

    def test_returns_400_for_non_ghsa_id(self, client):
        resp = client.post("/api/vulnerabilities/CVE-2020-35492/ghsa-refresh")
        assert resp.status_code == 400

    def test_returns_503_when_api_returns_none(self, client, ghsa_vuln):
        with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published",
                   return_value=None):
            resp = client.post(f"/api/vulnerabilities/{ghsa_vuln}/ghsa-refresh")
        assert resp.status_code == 503

    def test_returns_404_when_github_api_returns_404(self, client, ghsa_vuln):
        import urllib.error
        http_404 = urllib.error.HTTPError(url=None, code=404, msg="Not Found", hdrs=None, fp=None)
        with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published",
                   side_effect=http_404):
            resp = client.post(f"/api/vulnerabilities/{ghsa_vuln}/ghsa-refresh")
        assert resp.status_code == 404
        assert "not found" in resp.get_json()["error"].lower()

    def test_returns_503_on_network_error(self, client, ghsa_vuln):
        import urllib.error
        with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published",
                   side_effect=urllib.error.URLError("connection refused")):
            resp = client.post(f"/api/vulnerabilities/{ghsa_vuln}/ghsa-refresh")
        assert resp.status_code == 503

    def test_returns_503_on_unparseable_date(self, client, ghsa_vuln):
        with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published",
                   return_value="not-a-date"):
            resp = client.post(f"/api/vulnerabilities/{ghsa_vuln}/ghsa-refresh")
        assert resp.status_code == 503

    def test_returns_400_for_malformed_ghsa_id(self, client):
        """Regex rejects IDs with wrong segment length even if GHSA-prefixed."""
        resp = client.post("/api/vulnerabilities/GHSA-tooshort/ghsa-refresh")
        assert resp.status_code == 400

    def test_returns_400_for_ghsa_id_with_invalid_chars(self, client):
        """Regex rejects GHSA IDs containing characters outside [A-Z0-9]."""
        resp = client.post("/api/vulnerabilities/GHSA-xx!!-xxxx-xxxx/ghsa-refresh")
        assert resp.status_code == 400

    def test_response_includes_texts_key(self, client, ghsa_vuln):
        """Regression: single GHSA refresh must return 'texts' so the frontend
        does not overwrite the existing description with an empty array."""
        with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published",
                   return_value="2023-05-01T00:00:00Z"):
            resp = client.post(f"/api/vulnerabilities/{ghsa_vuln}/ghsa-refresh")
        assert resp.status_code == 200
        vuln = resp.get_json()["vulnerabilities"][0]
        assert "texts" in vuln
        assert isinstance(vuln["texts"], list)

    def test_ghsa_refresh_sets_data_updated_at_when_date_changes(self, app, client, ghsa_vuln):
        """ghsa_data_updated_at is stamped when the publish_date changes."""
        import datetime as dt
        from src.models.vulnerability import Vulnerability
        from src.extensions import db
        with app.app_context():
            rec = db.session.get(Vulnerability, ghsa_vuln)
            rec.publish_date = dt.date(2020, 1, 1)
            rec.ghsa_data_updated_at = None
            db.session.commit()

        with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published",
                   return_value="2023-06-15T00:00:00Z"):
            resp = client.post(f"/api/vulnerabilities/{ghsa_vuln}/ghsa-refresh")
        assert resp.status_code == 200

        with app.app_context():
            rec = db.session.get(Vulnerability, ghsa_vuln)
            assert rec.ghsa_data_updated_at is not None

    def test_ghsa_refresh_no_data_updated_at_when_date_unchanged(self, app, client, ghsa_vuln):
        """ghsa_data_updated_at is NOT stamped when the publish_date stays the same."""
        import datetime as dt
        from src.models.vulnerability import Vulnerability
        from src.extensions import db
        with app.app_context():
            rec = db.session.get(Vulnerability, ghsa_vuln)
            rec.publish_date = dt.date(2023, 5, 1)
            rec.ghsa_data_updated_at = None
            db.session.commit()

        with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published",
                   return_value="2023-05-01T00:00:00Z"):
            resp = client.post(f"/api/vulnerabilities/{ghsa_vuln}/ghsa-refresh")
        assert resp.status_code == 200

        with app.app_context():
            rec = db.session.get(Vulnerability, ghsa_vuln)
            assert rec.ghsa_data_updated_at is None


class TestBulkGhsaRefreshFailedCounter:
    """Guards the failed-counter logic and 403/429 abort in _run()."""

    def _capture_target(self, client, ghsa_ids):
        captured = {}

        def fake_thread(target=None, **kwargs):
            captured["target"] = target
            return MagicMock()

        with patch("src.routes.bulk_refresh.threading.Thread", side_effect=fake_thread):
            resp = client.post(
                "/api/vulnerabilities/bulk-ghsa-refresh",
                json={"ghsa_ids": ghsa_ids},
            )
        assert resp.status_code == 202
        return captured["target"]

    def test_complete_includes_failed_count_when_errors_occur(self, client):
        """complete() receives a message mentioning 'failed' when per-ID errors happen."""
        target = self._capture_target(client, ["GHSA-AAAA-BBBB-CCCC", "GHSA-R7JW-VC2X-4GBH"])

        def fake_fetch(ghsa_id):
            if ghsa_id == "GHSA-AAAA-BBBB-CCCC":
                raise RuntimeError("network error")
            return None

        with patch("src.routes.bulk_refresh.VulnerabilitiesController._fetch_ghsa_published",
                   side_effect=fake_fetch), \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.GHSAProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            target()

        MockTracker.complete.assert_called_once()
        call_args = MockTracker.complete.call_args
        msg = call_args[0][0] if call_args[0] else call_args[1].get("message", "")
        assert "failed" in msg.lower()

    def test_complete_called_without_message_when_no_errors(self, client):
        """complete() called with no message when all IDs succeed."""
        target = self._capture_target(client, ["GHSA-R7JW-VC2X-4GBH"])

        with patch("src.routes.bulk_refresh.VulnerabilitiesController._fetch_ghsa_published",
                   return_value=None), \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.GHSAProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            target()

        MockTracker.complete.assert_called_once_with()

    def test_run_aborts_and_calls_error_on_403(self, client):
        """HTTP 403 from GitHub triggers GHSAProgressTracker.error() and stops the loop."""
        import urllib.error
        target = self._capture_target(client, ["GHSA-AAAA-BBBB-CCCC", "GHSA-R7JW-VC2X-4GBH"])
        http_403 = urllib.error.HTTPError(url=None, code=403, msg="Forbidden", hdrs=None, fp=None)

        with patch("src.routes.bulk_refresh.VulnerabilitiesController._fetch_ghsa_published",
                   side_effect=http_403), \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.GHSAProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            target()

        MockTracker.error.assert_called_once()
        assert "GITHUB_TOKEN" in MockTracker.error.call_args[0][0]
        MockTracker.complete.assert_not_called()

    def test_run_aborts_and_calls_error_on_429(self, client):
        """HTTP 429 from GitHub triggers GHSAProgressTracker.error() and stops the loop."""
        import urllib.error
        target = self._capture_target(client, ["GHSA-AAAA-BBBB-CCCC", "GHSA-R7JW-VC2X-4GBH"])
        http_429 = urllib.error.HTTPError(url=None, code=429, msg="Too Many Requests", hdrs=None, fp=None)

        with patch("src.routes.bulk_refresh.VulnerabilitiesController._fetch_ghsa_published",
                   side_effect=http_429), \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.GHSAProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            target()

        MockTracker.error.assert_called_once()
        MockTracker.complete.assert_not_called()


# ---------------------------------------------------------------------------
# Bulk NVD refresh — mode parameter (local vs api)
# ---------------------------------------------------------------------------

class TestBulkNvdRefreshMode:
    """Tests for the ``mode`` body parameter added by the local-nvd-fkie feature."""

    def test_default_mode_is_local(self, client, existing_cve_id):
        """When no mode is supplied the endpoint accepts the request (local default)."""
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": [existing_cve_id]},
            )
        assert resp.status_code == 202

    def test_explicit_local_mode_accepted(self, client, existing_cve_id):
        """mode='local' is accepted with 202."""
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": [existing_cve_id], "mode": "local"},
            )
        assert resp.status_code == 202

    def test_explicit_api_mode_accepted(self, client, existing_cve_id):
        """mode='api' is accepted with 202."""
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": [existing_cve_id], "mode": "api"},
            )
        assert resp.status_code == 202

    def test_local_mode_background_uses_get_cve_json(self, client, existing_cve_id):
        """_run() uses get_cve_json (local DB) when mode is 'local'."""
        captured = {}

        def fake_thread(target=None, **kwargs):
            captured["target"] = target
            return MagicMock()

        with patch("src.routes.bulk_refresh.threading.Thread", side_effect=fake_thread):
            client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": [existing_cve_id], "mode": "local"},
            )

        with patch("src.routes.bulk_refresh.get_cve_json") as mock_local, \
             patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh._get_scc_engine"), \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            mock_local.return_value = None
            captured["target"]()

        mock_local.assert_called_once_with(existing_cve_id)
        MockNVD.return_value.api_get_cve.assert_not_called()

    def test_api_mode_background_uses_nvd_db(self, client, existing_cve_id):
        """_run() uses NVD_DB (REST API) when mode is 'api'."""
        captured = {}

        def fake_thread(target=None, **kwargs):
            captured["target"] = target
            return MagicMock()

        with patch("src.routes.bulk_refresh.threading.Thread", side_effect=fake_thread):
            client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": [existing_cve_id], "mode": "api"},
            )

        with patch("src.routes.bulk_refresh.get_cve_json") as mock_local, \
             patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep"), \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            captured["target"]()

        MockNVD.return_value.api_get_cve.assert_called_once_with(existing_cve_id, max_retries=2)
        mock_local.assert_not_called()

    def test_local_mode_background_no_sleep(self, client):
        """_run() does NOT sleep between CVEs when mode is 'local'."""
        cve_ids = ["CVE-2024-00001", "CVE-2024-00002"]
        captured = {}

        def fake_thread(target=None, **kwargs):
            captured["target"] = target
            return MagicMock()

        with patch("src.routes.bulk_refresh.threading.Thread", side_effect=fake_thread):
            client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": cve_ids, "mode": "local"},
            )

        with patch("src.routes.bulk_refresh.get_cve_json", return_value=None), \
             patch("src.routes.bulk_refresh._get_scc_engine"), \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep") as mock_sleep, \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            captured["target"]()

        mock_sleep.assert_not_called()

    def test_api_mode_background_sleeps_between_cves(self, client, monkeypatch):
        """_run() sleeps between CVEs when mode is 'api'."""
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        cve_ids = ["CVE-2024-00001", "CVE-2024-00002"]
        captured = {}

        def fake_thread(target=None, **kwargs):
            captured["target"] = target
            return MagicMock()

        with patch("src.routes.bulk_refresh.threading.Thread", side_effect=fake_thread):
            client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": cve_ids, "mode": "api"},
            )

        with patch("src.routes.bulk_refresh.NVD_DB") as MockNVD, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.time.sleep") as mock_sleep, \
             patch("src.routes.bulk_refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            captured["target"]()

        # One sleep between two CVEs, none after the last
        mock_sleep.assert_called_once()


# ---------------------------------------------------------------------------
# EUVD progress tracker — smoke test the singleton + endpoint
# ---------------------------------------------------------------------------

class TestEuvdProgressTracker:

    def test_singleton_starts_idle(self):
        from src.controllers.euvd_progress import EUVDProgressTracker
        EUVDProgressTracker.complete()  # reset
        progress = EUVDProgressTracker.get_progress()
        assert progress["in_progress"] is False

    def test_euvd_progress_endpoint_returns_200(self, client):
        from src.controllers.euvd_progress import EUVDProgressTracker
        EUVDProgressTracker.complete()
        resp = client.get("/api/euvd/progress")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "in_progress" in data
        assert "phase" in data


# ---------------------------------------------------------------------------
# Bulk EUVD refresh — /api/vulnerabilities/bulk-euvd-refresh
# ---------------------------------------------------------------------------

class TestBulkEuvdRefreshEndpoint:

    def test_returns_202_with_valid_cve_ids(self, client, existing_cve_id):
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-euvd-refresh",
                json={"cve_ids": [existing_cve_id]},
            )
        assert resp.status_code == 202
        data = resp.get_json()
        assert data["status"] == "started"
        assert data["total"] >= 1
        MockThread.return_value.start.assert_called_once()

    def test_returns_400_when_cve_ids_missing(self, client):
        resp = client.post("/api/vulnerabilities/bulk-euvd-refresh", json={})
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_returns_400_when_cve_ids_empty_list(self, client):
        resp = client.post(
            "/api/vulnerabilities/bulk-euvd-refresh",
            json={"cve_ids": []},
        )
        assert resp.status_code == 400

    def test_returns_400_when_all_ids_are_invalid_format(self, client):
        resp = client.post(
            "/api/vulnerabilities/bulk-euvd-refresh",
            json={"cve_ids": ["not-a-cve", "GHSA-xxxx-xxxx-xxxx"]},
        )
        assert resp.status_code == 400
        assert "valid CVE" in resp.get_json()["error"]

    def test_returns_409_when_already_in_progress(self, client, existing_cve_id):
        with patch(
            "src.routes.bulk_refresh.EUVDProgressTracker.start_if_idle",
            return_value=False,
        ):
            resp = client.post(
                "/api/vulnerabilities/bulk-euvd-refresh",
                json={"cve_ids": [existing_cve_id]},
            )
        assert resp.status_code == 409
        assert "already in progress" in resp.get_json()["error"]

    def test_cve_ids_normalized_to_uppercase(self, client, existing_cve_id):
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-euvd-refresh",
                json={"cve_ids": [existing_cve_id.lower()]},
            )
        assert resp.status_code == 202

    def test_total_matches_input_count(self, client, existing_cve_id):
        with patch("src.routes.bulk_refresh.threading.Thread") as MockThread:
            MockThread.return_value = MagicMock()
            resp = client.post(
                "/api/vulnerabilities/bulk-euvd-refresh",
                json={"cve_ids": [existing_cve_id, "CVE-2021-44228"]},
            )
        assert resp.status_code == 202
        assert resp.get_json()["total"] == 2


class TestBulkEuvdRefreshBackground:
    """Tests for the _run() closure spawned by bulk_euvd_refresh."""

    def _capture_target(self, client, cve_ids):
        captured = {}

        def fake_thread(target=None, **kwargs):
            captured["target"] = target
            return MagicMock()

        with patch("src.routes.bulk_refresh.threading.Thread", side_effect=fake_thread):
            resp = client.post(
                "/api/vulnerabilities/bulk-euvd-refresh",
                json={"cve_ids": cve_ids},
            )
        assert resp.status_code == 202
        return captured["target"]

    def test_run_annotates_record_from_mapping(self, client):
        cve = "CVE-2021-44228"
        target = self._capture_target(client, [cve])
        mock_rec = MagicMock()

        with patch("src.routes.bulk_refresh.EUVD_DB") as MockEuvd, \
             patch("src.routes.bulk_refresh.db") as mock_db, \
             patch("src.routes.bulk_refresh.EUVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            instance = MockEuvd.return_value
            instance.get_full_mapping.return_value = {cve: "EUVD-2021-34768"}
            instance.get_mapping.return_value = {}
            mock_db.session.get.return_value = mock_rec
            target()

        mock_rec.update_record.assert_called_once()
        call_kwargs = mock_rec.update_record.call_args.kwargs
        assert call_kwargs.get("euvd_id") == "EUVD-2021-34768"
        assert call_kwargs.get("euvd_known_exploited") is False
        assert call_kwargs.get("commit") is False
        MockTracker.complete.assert_called_once()

    def test_run_sets_known_exploited_from_kev(self, client):
        cve = "CVE-2021-44228"
        target = self._capture_target(client, [cve])
        mock_rec = MagicMock()

        with patch("src.routes.bulk_refresh.EUVD_DB") as MockEuvd, \
             patch("src.routes.bulk_refresh.db") as mock_db, \
             patch("src.routes.bulk_refresh.EUVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            instance = MockEuvd.return_value
            instance.get_full_mapping.return_value = {cve: "EUVD-2021-34768"}
            instance.get_mapping.return_value = {
                cve: {"euvd_id": "EUVD-2021-34768", "sources": ["cisa_kev"],
                      "date_added": "2025-10-06"},
            }
            mock_db.session.get.return_value = mock_rec
            target()

        call_kwargs = mock_rec.update_record.call_args.kwargs
        assert call_kwargs.get("euvd_known_exploited") is True
        assert call_kwargs.get("euvd_kev_sources") == ["cisa_kev"]
        assert call_kwargs.get("euvd_date_added") == "2025-10-06"

    def test_run_errors_when_mapping_empty(self, client):
        target = self._capture_target(client, ["CVE-2021-44228"])

        with patch("src.routes.bulk_refresh.EUVD_DB") as MockEuvd, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.EUVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            instance = MockEuvd.return_value
            instance.get_full_mapping.return_value = {}
            target()

        MockTracker.error.assert_called_once()
        MockTracker.complete.assert_not_called()

    def test_run_skips_unmatched_cve(self, client):
        target = self._capture_target(client, ["CVE-2099-0001"])
        mock_rec = MagicMock()

        with patch("src.routes.bulk_refresh.EUVD_DB") as MockEuvd, \
             patch("src.routes.bulk_refresh.db") as mock_db, \
             patch("src.routes.bulk_refresh.EUVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            instance = MockEuvd.return_value
            instance.get_full_mapping.return_value = {"CVE-2021-44228": "EUVD-2021-34768"}
            instance.get_mapping.return_value = {}
            mock_db.session.get.return_value = mock_rec
            target()

        mock_rec.update_record.assert_not_called()
        MockTracker.complete.assert_called_once()

    def test_run_stops_and_commits_when_cancelled(self, client):
        target = self._capture_target(client, ["CVE-2021-44228", "CVE-2021-22555"])
        call_count = {"n": 0}

        def fake_is_cancelled():
            call_count["n"] += 1
            return call_count["n"] > 1

        with patch("src.routes.bulk_refresh.EUVD_DB") as MockEuvd, \
             patch("src.routes.bulk_refresh._safe_commit") as mock_commit, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.EUVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.side_effect = fake_is_cancelled
            instance = MockEuvd.return_value
            instance.get_full_mapping.return_value = {
                "CVE-2021-44228": "EUVD-2021-34768",
                "CVE-2021-22555": "EUVD-2021-9696",
            }
            instance.get_mapping.return_value = {}
            target()

        MockTracker.mark_cancelled.assert_called_once()
        MockTracker.complete.assert_not_called()
        mock_commit.assert_called()

    def test_run_calls_error_on_outer_exception(self, client):
        target = self._capture_target(client, ["CVE-2021-44228"])

        with patch("src.routes.bulk_refresh.EUVD_DB") as MockEuvd, \
             patch("src.routes.bulk_refresh.db"), \
             patch("src.routes.bulk_refresh.EUVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEuvd.return_value.get_full_mapping.side_effect = RuntimeError("boom")
            target()

        MockTracker.error.assert_called_once()


class TestCancelEuvdRefreshEndpoint:

    def test_returns_200_when_refresh_in_progress(self, client):
        with patch(
            "src.routes.bulk_refresh.EUVDProgressTracker.cancel",
            return_value=True,
        ):
            resp = client.post("/api/vulnerabilities/cancel-euvd-refresh")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "cancelling"

    def test_returns_409_when_no_refresh_in_progress(self, client):
        with patch(
            "src.routes.bulk_refresh.EUVDProgressTracker.cancel",
            return_value=False,
        ):
            resp = client.post("/api/vulnerabilities/cancel-euvd-refresh")
        assert resp.status_code == 409
        assert "currently in progress" in resp.get_json()["error"]

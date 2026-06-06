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
    """Reset NVD and EPSS progress tracker singletons between tests."""
    from src.controllers.nvd_progress import NVDProgressTracker
    from src.controllers.epss_progress import EPSSProgressTracker
    NVDProgressTracker.complete()
    EPSSProgressTracker.complete()
    yield
    NVDProgressTracker.complete()
    EPSSProgressTracker.complete()


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
        """400 when more than _MAX_CVE_IDS valid IDs are submitted."""
        from src.routes.bulk_refresh import _MAX_CVE_IDS
        ids = [f"CVE-2024-{i:05d}" for i in range(_MAX_CVE_IDS + 1)]
        resp = client.post(
            "/api/vulnerabilities/bulk-nvd-refresh",
            json={"cve_ids": ids},
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
        """POST to the endpoint and return the captured _run target without starting it."""
        captured = {}

        def fake_thread(target=None, **kwargs):
            captured["target"] = target
            return MagicMock()

        with patch("src.routes.bulk_refresh.threading.Thread", side_effect=fake_thread):
            resp = client.post(
                "/api/vulnerabilities/bulk-nvd-refresh",
                json={"cve_ids": cve_ids},
            )
        assert resp.status_code == 202
        return captured["target"]

    def test_run_applies_update_on_200(self, client, existing_cve_id):
        """_run() calls apply_nvd_update and apply_cvss_update when API returns 200."""
        target = self._capture_target(client, [existing_cve_id])
        mock_rec = MagicMock()
        mock_details = {"base_score": 7.5, "cvss_version": "3.1", "cvss_vector": "CVSS:3.1/X"}

        with patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh.apply_nvd_update") as mock_apply, \
             patch("src.controllers.refresh.apply_cvss_update") as mock_cvss, \
             patch("src.controllers.refresh.db") as mock_db, \
             patch("src.controllers.refresh.time.sleep"), \
             patch("src.controllers.refresh.NVDProgressTracker") as MockTracker:
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

        with patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh.apply_nvd_update") as mock_apply, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep"), \
             patch("src.controllers.refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            target()

        mock_apply.assert_not_called()

    def test_run_skips_update_when_no_vulnerabilities_in_response(self, client, existing_cve_id):
        """_run() skips update when 200 but vulnerabilities list is empty."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh.apply_nvd_update") as mock_apply, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep"), \
             patch("src.controllers.refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (200, {"vulnerabilities": []})
            target()

        mock_apply.assert_not_called()

    def test_run_skips_update_when_record_not_in_db(self, client, existing_cve_id):
        """_run() skips apply_nvd_update when the vulnerability is absent from the local DB."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh.apply_nvd_update") as mock_apply, \
             patch("src.controllers.refresh.db") as mock_db, \
             patch("src.controllers.refresh.time.sleep"), \
             patch("src.controllers.refresh.NVDProgressTracker") as MockTracker:
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

        with patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh.apply_nvd_update") as mock_apply, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep"), \
             patch("src.controllers.refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.side_effect = fake_get_cve
            target()

        MockTracker.complete.assert_called()

    def test_run_commits_at_batch_boundary(self, client):
        """_run() calls _safe_commit after every _NVD_COMMIT_EVERY items (50)."""
        cve_ids = [f"CVE-2024-{i:05d}" for i in range(50)]
        target = self._capture_target(client, cve_ids)

        with patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh._safe_commit") as mock_commit, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep"), \
             patch("src.controllers.refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            target()

        # Commit at item #50 (mod boundary) plus the final commit → at least 2 calls
        assert mock_commit.call_count >= 2

    def test_run_sleeps_between_cves_but_not_after_last(self, client):
        """_run() sleeps between CVEs but not after the final one."""
        cve_ids = ["CVE-2024-00001", "CVE-2024-00002"]
        target = self._capture_target(client, cve_ids)

        with patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep") as mock_sleep, \
             patch("src.controllers.refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            target()

        assert mock_sleep.call_count == 1

    def test_run_calls_complete_on_success(self, client, existing_cve_id):
        """_run() calls NVDProgressTracker.complete() after all CVEs are processed."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep"), \
             patch("src.controllers.refresh.NVDProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            target()

        MockTracker.complete.assert_called()

    def test_run_calls_error_on_outer_exception(self, client, existing_cve_id):
        """_run() calls NVDProgressTracker.error() when an unhandled exception occurs."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep"), \
             patch("src.controllers.refresh.NVDProgressTracker") as MockTracker:
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

        with patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh.db") as mock_db, \
             patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker:
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

        with patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh.db") as mock_db, \
             patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {}
            mock_db.session.get.return_value = mock_rec
            target()

        mock_rec.update_record.assert_not_called()

    def test_run_skips_update_when_record_not_in_db(self, client, existing_cve_id):
        """_run() skips update_record when the vulnerability is absent from the local DB."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh.db") as mock_db, \
             patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker:
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

        with patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.side_effect = Exception("API timeout")
            target()

        MockTracker.complete.assert_called()

    def test_run_continues_after_record_update_exception(self, client, existing_cve_id):
        """_run() catches and logs exceptions raised by update_record."""
        target = self._capture_target(client, [existing_cve_id])
        mock_rec = MagicMock()
        mock_rec.update_record.side_effect = Exception("DB constraint")

        with patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh.db") as mock_db, \
             patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker:
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

        with patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {}
            target()

        assert MockEPSS.return_value.api_get_epss_batch.call_count == 2

    def test_run_calls_complete_on_success(self, client, existing_cve_id):
        """_run() calls EPSSProgressTracker.complete() after successful processing."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {}
            target()

        MockTracker.complete.assert_called()

    def test_run_calls_error_on_outer_exception(self, client, existing_cve_id):
        """_run() calls EPSSProgressTracker.error() on an unhandled outer exception."""
        target = self._capture_target(client, [existing_cve_id])

        with patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {}
            # complete() is inside the outer try, so making it raise triggers the outer except
            MockTracker.complete.side_effect = RuntimeError("tracker failure")
            target()

        MockTracker.error.assert_called_once()


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
# Cancellation checks inside _run() threads
# ---------------------------------------------------------------------------

def _capture_refresh_target(client, endpoint, cve_ids):
    """Capture the thread target function without starting the thread."""
    captured = {}

    def fake_thread(target=None, **kwargs):
        captured["target"] = target
        return MagicMock()

    with patch("src.routes.bulk_refresh.threading.Thread", side_effect=fake_thread):
        resp = client.post(endpoint, json={"cve_ids": cve_ids})
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

        with patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh._safe_commit") as mock_commit, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep"), \
             patch("src.controllers.refresh.NVDProgressTracker") as MockTracker:
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

        with patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh._safe_commit"), \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep"), \
             patch("src.controllers.refresh.NVDProgressTracker") as MockTracker:
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

        with patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh._safe_commit") as mock_commit, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker:
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

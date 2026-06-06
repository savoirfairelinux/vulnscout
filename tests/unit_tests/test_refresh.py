# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def mock_app():
    """Minimal Flask app mock with a working app_context."""
    app = MagicMock()
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=None)
    ctx.__exit__ = MagicMock(return_value=False)
    app.app_context.return_value = ctx
    return app


class TestNvdSleepInterval:

    def test_returns_six_seconds_without_api_key(self, monkeypatch):
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        from src.controllers.refresh import _nvd_sleep_interval
        assert _nvd_sleep_interval() == pytest.approx(6.0)

    def test_returns_point_six_with_api_key(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "abc123")
        from src.controllers.refresh import _nvd_sleep_interval
        assert _nvd_sleep_interval() == pytest.approx(0.6)


class TestSafeCommit:

    def test_commits_successfully(self):
        with patch("src.controllers.refresh.db") as mock_db:
            from src.controllers.refresh import _safe_commit
            _safe_commit("test")
            mock_db.session.commit.assert_called_once()
            mock_db.session.rollback.assert_not_called()

    def test_expunges_session_after_successful_commit(self):
        with patch("src.controllers.refresh.db") as mock_db:
            from src.controllers.refresh import _safe_commit
            _safe_commit("test")
            mock_db.session.expunge_all.assert_called_once()

    def test_rolls_back_on_commit_error(self):
        with patch("src.controllers.refresh.db") as mock_db:
            mock_db.session.commit.side_effect = Exception("DB error")
            from src.controllers.refresh import _safe_commit
            _safe_commit("test")
            mock_db.session.rollback.assert_called_once()

    def test_expunges_session_after_rollback(self):
        with patch("src.controllers.refresh.db") as mock_db:
            mock_db.session.commit.side_effect = Exception("DB error")
            from src.controllers.refresh import _safe_commit
            _safe_commit("test")
            mock_db.session.expunge_all.assert_called_once()


class TestRunEpssRefresh:
    """Tests for run_epss_refresh worker."""

    def test_calls_complete_when_empty_list(self, mock_app):
        """complete() is called even when cve_ids is empty (no batches)."""
        with patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker, \
             patch("src.controllers.refresh.EPSS_DB"), \
             patch("src.controllers.refresh.db"):
            MockTracker.is_cancelled.return_value = False
            from src.controllers.refresh import run_epss_refresh
            run_epss_refresh(mock_app, [])
        MockTracker.complete.assert_called_once()

    def test_updates_record_when_epss_data_returned(self, mock_app):
        """update_record is called when EPSS API returns a score."""
        mock_rec = MagicMock()
        cve_id = "CVE-2024-00001"
        with patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker, \
             patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh.db") as mock_db:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {cve_id: {"score": 0.42}}
            mock_db.session.get.return_value = mock_rec
            from src.controllers.refresh import run_epss_refresh
            run_epss_refresh(mock_app, [cve_id])
        mock_rec.update_record.assert_called_once()

    def test_skips_update_when_no_epss_result(self, mock_app):
        """update_record is not called when EPSS returns no data."""
        mock_rec = MagicMock()
        cve_id = "CVE-2024-00001"
        with patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker, \
             patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh.db") as mock_db:
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {}
            mock_db.session.get.return_value = mock_rec
            from src.controllers.refresh import run_epss_refresh
            run_epss_refresh(mock_app, [cve_id])
        mock_rec.update_record.assert_not_called()

    def test_calls_mark_cancelled_when_cancelled(self, mock_app):
        """mark_cancelled() is called when the tracker signals cancellation."""
        cve_ids = [f"CVE-2024-{i:05d}" for i in range(150)]  # 2 chunks
        chunk_count = {"n": 0}

        def fake_is_cancelled():
            chunk_count["n"] += 1
            return chunk_count["n"] > 1

        with patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker, \
             patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh._safe_commit"), \
             patch("src.controllers.refresh.db"):
            MockTracker.is_cancelled.side_effect = fake_is_cancelled
            MockEPSS.return_value.api_get_epss_batch.return_value = {}
            from src.controllers.refresh import run_epss_refresh
            run_epss_refresh(mock_app, cve_ids)
        MockTracker.mark_cancelled.assert_called_once()
        MockTracker.complete.assert_not_called()

    def test_calls_error_on_outer_exception(self, mock_app):
        """error() is called when an unhandled exception occurs."""
        with patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker, \
             patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh.db"):
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {}
            MockTracker.complete.side_effect = RuntimeError("tracker failure")
            from src.controllers.refresh import run_epss_refresh
            run_epss_refresh(mock_app, ["CVE-2024-00001"])
        MockTracker.error.assert_called_once()

    def test_batches_into_chunks_of_batch_size(self, mock_app):
        """api_get_epss_batch is called twice for 150 CVEs (batch size 100)."""
        cve_ids = [f"CVE-2024-{i:05d}" for i in range(150)]
        with patch("src.controllers.refresh.EPSSProgressTracker") as MockTracker, \
             patch("src.controllers.refresh.EPSS_DB") as MockEPSS, \
             patch("src.controllers.refresh.db"):
            MockTracker.is_cancelled.return_value = False
            MockEPSS.return_value.api_get_epss_batch.return_value = {}
            from src.controllers.refresh import run_epss_refresh
            run_epss_refresh(mock_app, cve_ids)
        assert MockEPSS.return_value.api_get_epss_batch.call_count == 2


class TestRunNvdRefresh:
    """Tests for run_nvd_refresh worker."""

    def test_calls_complete_when_empty_list(self, mock_app):
        """complete() is called even when cve_ids is empty."""
        with patch("src.controllers.refresh.NVDProgressTracker") as MockTracker, \
             patch("src.controllers.refresh.NVD_DB"), \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep"):
            MockTracker.is_cancelled.return_value = False
            from src.controllers.refresh import run_nvd_refresh
            run_nvd_refresh(mock_app, [])
        MockTracker.complete.assert_called_once()

    def test_applies_update_on_200_response(self, mock_app):
        """apply_nvd_update and apply_cvss_update are called on a 200 response."""
        from unittest.mock import ANY
        cve_id = "CVE-2024-00001"
        mock_rec = MagicMock()
        mock_details = {"base_score": 7.5}
        with patch("src.controllers.refresh.NVDProgressTracker") as MockTracker, \
             patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh.apply_nvd_update") as mock_apply, \
             patch("src.controllers.refresh.apply_cvss_update") as mock_cvss, \
             patch("src.controllers.refresh.db") as mock_db, \
             patch("src.controllers.refresh.time.sleep"):
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (
                200, {"vulnerabilities": [{"cve": {}}]}
            )
            MockNVD.extract_cve_details.return_value = mock_details
            mock_db.session.get.return_value = mock_rec
            from src.controllers.refresh import run_nvd_refresh
            run_nvd_refresh(mock_app, [cve_id])
        mock_apply.assert_called_once_with(mock_rec, mock_details, ANY)
        mock_cvss.assert_called_once_with(mock_rec, mock_details, mock_db)

    def test_skips_update_on_non_200(self, mock_app):
        """apply_nvd_update is not called when API returns non-200."""
        with patch("src.controllers.refresh.NVDProgressTracker") as MockTracker, \
             patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh.apply_nvd_update") as mock_apply, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep"):
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            from src.controllers.refresh import run_nvd_refresh
            run_nvd_refresh(mock_app, ["CVE-2024-00001"])
        mock_apply.assert_not_called()

    def test_calls_mark_cancelled_when_cancelled(self, mock_app):
        """mark_cancelled() is called and loop exits when tracker signals cancellation."""
        cve_ids = ["CVE-2024-00001", "CVE-2024-00002"]
        call_count = {"n": 0}

        def fake_is_cancelled():
            call_count["n"] += 1
            return call_count["n"] > 1

        with patch("src.controllers.refresh.NVDProgressTracker") as MockTracker, \
             patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh._safe_commit"), \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep"):
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            MockTracker.is_cancelled.side_effect = fake_is_cancelled
            from src.controllers.refresh import run_nvd_refresh
            run_nvd_refresh(mock_app, cve_ids)
        MockTracker.mark_cancelled.assert_called_once()
        MockTracker.complete.assert_not_called()

    def test_continues_after_per_cve_exception(self, mock_app):
        """Loop continues and complete() is called even when one CVE raises."""
        def fake_api(cve_id, **kw):
            if cve_id == "CVE-2024-00001":
                raise RuntimeError("transient error")
            return (404, {})

        with patch("src.controllers.refresh.NVDProgressTracker") as MockTracker, \
             patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep"):
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.side_effect = fake_api
            from src.controllers.refresh import run_nvd_refresh
            run_nvd_refresh(mock_app, ["CVE-2024-00001", "CVE-2024-00002"])
        MockTracker.complete.assert_called_once()

    def test_sleeps_between_cves_but_not_after_last(self, mock_app):
        """time.sleep is called N-1 times for N CVEs."""
        with patch("src.controllers.refresh.NVDProgressTracker") as MockTracker, \
             patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep") as mock_sleep:
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            from src.controllers.refresh import run_nvd_refresh
            run_nvd_refresh(mock_app, ["CVE-2024-00001", "CVE-2024-00002"])
        assert mock_sleep.call_count == 1

    def test_calls_error_on_outer_exception(self, mock_app):
        """error() is called when an unhandled exception occurs."""
        with patch("src.controllers.refresh.NVDProgressTracker") as MockTracker, \
             patch("src.controllers.refresh.NVD_DB") as MockNVD, \
             patch("src.controllers.refresh.db"), \
             patch("src.controllers.refresh.time.sleep"):
            MockTracker.is_cancelled.return_value = False
            MockNVD.return_value.api_get_cve.return_value = (404, {})
            MockTracker.complete.side_effect = RuntimeError("tracker failure")
            from src.controllers.refresh import run_nvd_refresh
            run_nvd_refresh(mock_app, ["CVE-2024-00001"])
        MockTracker.error.assert_called_once()

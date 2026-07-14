# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Unit tests for bulk refresh helper functions."""

import datetime
import os
import pytest
from unittest.mock import MagicMock, patch

from src.routes.bulk_refresh import _nvd_sleep_interval, _safe_commit
from src.controllers.nvd_apply import apply_cvss_update
from src.controllers.progress_tracker import ProgressTracker


class TestNvdSleepInterval:

    def test_returns_six_seconds_without_api_key(self, monkeypatch):
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        assert _nvd_sleep_interval() == pytest.approx(6.0)

    def test_returns_point_six_with_api_key(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "abc123")
        assert _nvd_sleep_interval() == pytest.approx(0.6)


class TestApplyCvssUpdate:

    def _make_rec(self, vuln_id="CVE-2024-0001"):
        rec = MagicMock()
        rec.id = vuln_id
        return rec

    def _make_db(self):
        mock_db = MagicMock()
        mock_db.select = MagicMock(return_value=MagicMock())
        return mock_db

    def test_does_nothing_when_base_score_missing(self):
        """No DB interaction when details has no base_score."""
        rec = self._make_rec()
        mock_db = self._make_db()
        apply_cvss_update(rec, {}, mock_db)
        mock_db.session.execute.assert_not_called()
        mock_db.session.add.assert_not_called()

    def test_does_nothing_when_cvss_version_missing(self):
        rec = self._make_rec()
        mock_db = self._make_db()
        apply_cvss_update(rec, {"base_score": 7.5}, mock_db)
        mock_db.session.execute.assert_not_called()

    def test_updates_existing_metric_when_score_differs(self):
        """When a Metrics row exists with a different score, it is updated."""
        rec = self._make_rec()
        existing = MagicMock()
        existing.score = 5.0
        existing.vector = "old-vector"
        mock_db = self._make_db()
        mock_db.session.execute.return_value.scalars.return_value.first.return_value = existing

        with patch("src.controllers.nvd_apply.Metrics"):
            apply_cvss_update(rec, {
                "base_score": 8.1,
                "cvss_version": "3.1",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            }, mock_db)

        assert float(existing.score) == pytest.approx(8.1)
        assert existing.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

    def test_adds_new_metric_when_none_exists(self):
        """When no Metrics row exists, a new one is added to the session."""
        rec = self._make_rec()
        mock_db = self._make_db()
        mock_db.session.execute.return_value.scalars.return_value.first.return_value = None

        with patch("src.controllers.nvd_apply.Metrics") as MockMetrics:
            apply_cvss_update(rec, {
                "base_score": 9.8,
                "cvss_version": "3.1",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }, mock_db)

        mock_db.session.add.assert_called_once()
        call_args = MockMetrics.call_args
        assert call_args is not None
        kwargs = call_args.kwargs if call_args.kwargs else call_args[1]
        assert kwargs["score"] == pytest.approx(9.8)
        assert kwargs["author"] == "nvd"

    def test_does_not_update_metric_when_score_and_vector_unchanged(self):
        """When the existing Metrics row already has the same score and vector, no write occurs."""
        rec = self._make_rec()
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        existing = MagicMock()
        existing.score = 8.1
        existing.vector = vector
        mock_db = self._make_db()
        mock_db.session.execute.return_value.scalars.return_value.first.return_value = existing

        with patch("src.controllers.nvd_apply.Metrics"):
            apply_cvss_update(rec, {
                "base_score": 8.1,
                "cvss_version": "3.1",
                "cvss_vector": vector,
            }, mock_db)

        mock_db.session.add.assert_not_called()
        assert float(existing.score) == pytest.approx(8.1)


class TestSafeCommit:

    def test_commits_successfully(self):
        with patch("src.routes.bulk_refresh.db") as mock_db:
            _safe_commit("test")
            mock_db.session.commit.assert_called_once()
            mock_db.session.rollback.assert_not_called()

    def test_expunges_session_after_successful_commit(self):
        with patch("src.routes.bulk_refresh.db") as mock_db:
            _safe_commit("test")
            mock_db.session.expunge_all.assert_called_once()

    def test_rolls_back_on_commit_error(self):
        with patch("src.routes.bulk_refresh.db") as mock_db:
            mock_db.session.commit.side_effect = Exception("DB error")
            _safe_commit("test")
            mock_db.session.rollback.assert_called_once()

    def test_expunges_session_after_rollback(self):
        with patch("src.routes.bulk_refresh.db") as mock_db:
            mock_db.session.commit.side_effect = Exception("DB error")
            _safe_commit("test")
            mock_db.session.expunge_all.assert_called_once()


class TestProgressTrackerCancel:

    def _tracker(self):
        return ProgressTracker(default_phase="test", completed_message="done")

    def test_cancel_returns_false_when_idle(self):
        tracker = self._tracker()
        assert tracker.cancel() is False

    def test_cancel_returns_true_when_in_progress(self):
        tracker = self._tracker()
        tracker.start()
        assert tracker.cancel() is True

    def test_is_cancelled_false_before_cancel_called(self):
        tracker = self._tracker()
        tracker.start()
        assert tracker.is_cancelled() is False

    def test_is_cancelled_true_after_cancel(self):
        tracker = self._tracker()
        tracker.start()
        tracker.cancel()
        assert tracker.is_cancelled() is True

    def test_mark_cancelled_resets_in_progress_and_flag(self):
        tracker = self._tracker()
        tracker.start()
        tracker.cancel()
        tracker.mark_cancelled()
        progress = tracker.get_progress()
        assert progress["in_progress"] is False
        assert progress["phase"] == "cancelled"
        assert tracker.is_cancelled() is False

    def test_start_resets_cancelled_flag(self):
        tracker = self._tracker()
        tracker.start()
        tracker.cancel()
        assert tracker.is_cancelled() is True
        tracker.mark_cancelled()
        tracker.start()
        assert tracker.is_cancelled() is False

    def test_cancel_on_already_completed_returns_false(self):
        tracker = self._tracker()
        tracker.start()
        tracker.complete()
        assert tracker.cancel() is False

    def test_cancel_on_already_cancelled_returns_false(self):
        tracker = self._tracker()
        tracker.start()
        tracker.cancel()
        tracker.mark_cancelled()
        assert tracker.cancel() is False

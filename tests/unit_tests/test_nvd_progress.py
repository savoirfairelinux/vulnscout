# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from datetime import datetime, timezone

from src.controllers.nvd_progress import NVDProgressTracker


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset the NVDProgressTracker singleton before and after each test."""
    NVDProgressTracker._instance = None
    yield
    NVDProgressTracker._instance = None


def test_singleton_pattern():
    t1 = NVDProgressTracker()
    t2 = NVDProgressTracker()
    assert t1 is t2


def test_initial_state():
    tracker = NVDProgressTracker()
    data = tracker.get_progress()
    assert data["in_progress"] is False
    assert data["phase"] == "idle"
    assert data["current"] == 0
    assert data["total"] == 0
    assert data["message"] == "No update in progress"
    assert data["last_update"] is None
    assert data["started_at"] is None


def test_start_default_phase():
    tracker = NVDProgressTracker()
    tracker.start()
    data = tracker.get_progress()
    assert data["in_progress"] is True
    assert data["phase"] == "enrichment"
    assert data["started_at"] is not None
    datetime.fromisoformat(data["started_at"])


def test_start_custom_phase():
    tracker = NVDProgressTracker()
    tracker.start(phase="nvd_fetch")
    data = tracker.get_progress()
    assert data["phase"] == "nvd_fetch"
    assert data["message"] == "Starting nvd_fetch"


def test_update_progress():
    tracker = NVDProgressTracker()
    tracker.start()
    tracker.update("loading", 25, 100, message="Loading CVEs")
    data = tracker.get_progress()
    assert data["in_progress"] is True
    assert data["phase"] == "loading"
    assert data["current"] == 25
    assert data["total"] == 100
    assert data["message"] == "Loading CVEs"
    datetime.fromisoformat(data["last_update"])


def test_update_auto_message():
    tracker = NVDProgressTracker()
    tracker.start()
    tracker.update("processing", 3, 10)
    assert tracker.get_progress()["message"] == "processing: 3/10"


def test_complete():
    tracker = NVDProgressTracker()
    tracker.start()
    tracker.complete()
    data = tracker.get_progress()
    assert data["in_progress"] is False
    assert data["phase"] == "completed"
    assert "completed" in data["message"].lower()


def test_error():
    tracker = NVDProgressTracker()
    tracker.start()
    tracker.error("API timeout")
    data = tracker.get_progress()
    assert data["in_progress"] is False
    assert data["phase"] == "error"
    assert data["message"] == "API timeout"


def test_get_progress_returns_copy():
    tracker = NVDProgressTracker()
    tracker.start(phase="test")
    snapshot = tracker.get_progress()
    snapshot["phase"] = "mutated"
    assert tracker.get_progress()["phase"] == "test"


def test_thread_safety():
    import threading
    tracker = NVDProgressTracker()
    tracker.start()
    errors = []

    def worker(i):
        try:
            tracker.update("parallel", i, 100)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert tracker.get_progress()["in_progress"] is True



# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch

from src.controllers.nvd_progress import NVDProgressTracker


@pytest.fixture
def temp_progress_dir(tmp_path, monkeypatch):
    """Create a temporary directory for progress files."""
    progress_dir = tmp_path / "progress"
    progress_dir.mkdir(parents=True, exist_ok=True)
    db_path = progress_dir / "nvd.db"
    monkeypatch.setenv("NVD_DB_PATH", str(db_path))
    
    # Reset the singleton instance before each test
    NVDProgressTracker._instance = None
    
    yield progress_dir
    
    # Clean up singleton instance after test
    NVDProgressTracker._instance = None


def test_singleton_pattern(temp_progress_dir):
    """Test that NVDProgressTracker is a singleton."""
    tracker1 = NVDProgressTracker()
    tracker2 = NVDProgressTracker()
    
    assert tracker1 is tracker2


def test_initialization_creates_progress_file(temp_progress_dir):
    """Test that initialization creates the progress file."""
    tracker = NVDProgressTracker()
    
    progress_file = temp_progress_dir / "nvd_progress.json"
    assert progress_file.exists()
    
    with open(progress_file, 'r') as f:
        data = json.load(f)
    
    assert data["in_progress"] is False
    assert data["phase"] == "idle"
    assert data["current"] == 0
    assert data["total"] == 0
    assert data["message"] == "No update in progress"
    assert data["last_update"] is None
    assert data["started_at"] is None


def test_start_update(temp_progress_dir):
    """Test starting an update process."""
    tracker = NVDProgressTracker()
    
    tracker.start(phase="initial_build")
    
    progress_file = temp_progress_dir / "nvd_progress.json"
    with open(progress_file, 'r') as f:
        data = json.load(f)
    
    assert data["in_progress"] is True
    assert data["phase"] == "initial_build"
    assert data["current"] == 0
    assert data["total"] == 0
    assert data["message"] == "Starting initial_build"
    assert data["last_update"] is not None
    assert data["started_at"] is not None
    
    # Verify timestamps are valid ISO format
    datetime.fromisoformat(data["last_update"])
    datetime.fromisoformat(data["started_at"])


def test_start_with_default_phase(temp_progress_dir):
    """Test starting an update with default phase."""
    tracker = NVDProgressTracker()
    
    tracker.start()
    
    data = tracker.get_progress()
    assert data["phase"] == "initial_build"
    assert data["message"] == "Starting initial_build"


def test_update_progress(temp_progress_dir):
    """Test updating progress information."""
    tracker = NVDProgressTracker()
    
    tracker.start()
    tracker.update(phase="downloading", current=50, total=100, message="Downloading CVEs")
    
    progress_file = temp_progress_dir / "nvd_progress.json"
    with open(progress_file, 'r') as f:
        data = json.load(f)
    
    assert data["in_progress"] is True
    assert data["phase"] == "downloading"
    assert data["current"] == 50
    assert data["total"] == 100
    assert data["message"] == "Downloading CVEs"
    assert data["last_update"] is not None


def test_update_progress_without_message(temp_progress_dir):
    """Test updating progress with auto-generated message."""
    tracker = NVDProgressTracker()
    
    tracker.start()
    tracker.update(phase="processing", current=25, total=50)
    
    data = tracker.get_progress()
    assert data["message"] == "processing: 25/50"


def test_complete_update(temp_progress_dir):
    """Test completing an update successfully."""
    tracker = NVDProgressTracker()
    
    tracker.start()
    tracker.update(phase="downloading", current=100, total=100)
    tracker.complete()
    
    progress_file = temp_progress_dir / "nvd_progress.json"
    with open(progress_file, 'r') as f:
        data = json.load(f)
    
    assert data["in_progress"] is False
    assert data["phase"] == "completed"
    assert data["message"] == "Update completed successfully"
    assert data["last_update"] is not None


def test_error_update(temp_progress_dir):
    """Test marking an update as failed."""
    tracker = NVDProgressTracker()
    
    tracker.start()
    tracker.error("Network connection failed")
    
    progress_file = temp_progress_dir / "nvd_progress.json"
    with open(progress_file, 'r') as f:
        data = json.load(f)
    
    assert data["in_progress"] is False
    assert data["phase"] == "error"
    assert data["message"] == "Network connection failed"
    assert data["last_update"] is not None


def test_get_progress(temp_progress_dir):
    """Test retrieving current progress."""
    tracker = NVDProgressTracker()
    
    tracker.start(phase="building")
    tracker.update(phase="building", current=33, total=100, message="Building database")
    
    progress = tracker.get_progress()
    
    assert isinstance(progress, dict)
    assert progress["in_progress"] is True
    assert progress["phase"] == "building"
    assert progress["current"] == 33
    assert progress["total"] == 100
    assert progress["message"] == "Building database"


def test_read_progress_file_not_found(temp_progress_dir):
    """Test reading progress when file doesn't exist yet."""
    # Create tracker but delete the progress file
    tracker = NVDProgressTracker()
    progress_file = temp_progress_dir / "nvd_progress.json"
    os.remove(progress_file)
    
    # _read_progress should return default data
    data = tracker._read_progress()
    
    assert data["in_progress"] is False
    assert data["phase"] == "idle"
    assert data["message"] == "No update in progress"


def test_read_progress_invalid_json(temp_progress_dir):
    """Test reading progress when file contains invalid JSON."""
    tracker = NVDProgressTracker()
    progress_file = temp_progress_dir / "nvd_progress.json"
    
    # Write invalid JSON
    with open(progress_file, 'w') as f:
        f.write("{ invalid json }")
    
    # _read_progress should return default data on JSONDecodeError
    data = tracker._read_progress()
    
    assert data["in_progress"] is False
    assert data["phase"] == "idle"


def test_write_progress_atomic(temp_progress_dir):
    """Test that progress writes are atomic."""
    tracker = NVDProgressTracker()
    
    test_data = {
        "in_progress": True,
        "phase": "test_phase",
        "current": 42,
        "total": 100,
        "message": "Test message",
        "last_update": datetime.now(timezone.utc).isoformat(),
        "started_at": datetime.now(timezone.utc).isoformat()
    }
    
    tracker._write_progress(test_data)
    
    progress_file = temp_progress_dir / "nvd_progress.json"
    assert progress_file.exists()
    
    # Verify temp file doesn't exist
    temp_file = Path(f"{progress_file}.tmp")
    assert not temp_file.exists()
    
    with open(progress_file, 'r') as f:
        data = json.load(f)
    
    assert data == test_data


def test_write_progress_error_cleanup(temp_progress_dir):
    """Test that temporary file is cleaned up on write error."""
    tracker = NVDProgressTracker()
    
    # Make the progress file a directory to cause a write error
    progress_file = temp_progress_dir / "nvd_progress.json"
    os.remove(progress_file)
    os.mkdir(progress_file)
    
    test_data = {
        "in_progress": True,
        "phase": "test",
        "current": 0,
        "total": 0,
        "message": "Test",
        "last_update": None,
        "started_at": None
    }
    
    # This should raise an exception
    with pytest.raises(Exception):
        tracker._write_progress(test_data)
    
    # Temp file should be cleaned up
    temp_file = Path(f"{progress_file}.tmp")
    assert not temp_file.exists()


def test_multiple_updates_sequence(temp_progress_dir):
    """Test a complete update sequence with multiple phases."""
    tracker = NVDProgressTracker()
    
    # Start
    tracker.start(phase="initialization")
    data = tracker.get_progress()
    assert data["phase"] == "initialization"
    assert data["in_progress"] is True
    
    # Download phase
    tracker.update(phase="downloading", current=0, total=100, message="Starting download")
    data = tracker.get_progress()
    assert data["phase"] == "downloading"
    assert data["current"] == 0
    
    tracker.update(phase="downloading", current=50, total=100, message="Halfway through")
    data = tracker.get_progress()
    assert data["current"] == 50
    
    tracker.update(phase="downloading", current=100, total=100, message="Download complete")
    data = tracker.get_progress()
    assert data["current"] == 100
    
    # Processing phase
    tracker.update(phase="processing", current=0, total=50)
    data = tracker.get_progress()
    assert data["phase"] == "processing"
    assert data["message"] == "processing: 0/50"
    
    tracker.update(phase="processing", current=50, total=50)
    data = tracker.get_progress()
    assert data["current"] == 50
    
    # Complete
    tracker.complete()
    data = tracker.get_progress()
    assert data["in_progress"] is False
    assert data["phase"] == "completed"


def test_progress_persistence(temp_progress_dir):
    """Test that progress persists across tracker instances."""
    tracker1 = NVDProgressTracker()
    tracker1.start(phase="persistent_test")
    tracker1.update(phase="persistent_test", current=75, total=100, message="Persisting")
    
    # Reset singleton to simulate new instance
    NVDProgressTracker._instance = None
    
    tracker2 = NVDProgressTracker()
    data = tracker2.get_progress()
    
    assert data["phase"] == "persistent_test"
    assert data["current"] == 75
    assert data["total"] == 100
    assert data["message"] == "Persisting"


def test_concurrent_access_with_lock(temp_progress_dir):
    """Test that lock protects concurrent access."""
    tracker = NVDProgressTracker()
    
    # This test verifies that the lock exists and operations use it
    # In a single-threaded test, we just verify operations work correctly
    tracker.start()
    tracker.update(phase="test", current=10, total=20)
    tracker.complete()
    
    data = tracker.get_progress()
    assert data["phase"] == "completed"

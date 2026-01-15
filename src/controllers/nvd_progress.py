# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from typing import Optional
from datetime import datetime, timezone
from threading import Lock
import json
import os
from pathlib import Path


class NVDProgressTracker:
    """
    Singleton class to track NVD database update progress using file-based storage.
    """

    _instance = None
    _lock = Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(NVDProgressTracker, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        cache_dir = os.getenv("NVD_DB_PATH", "/cache/vulnscout/nvd.db")
        progress_file_path = Path(cache_dir).parent / "nvd_progress.json"
        self._progress_file = str(progress_file_path)

        # Ensure parent directory exists
        progress_file_path.parent.mkdir(parents=True, exist_ok=True)

        self._default_data = {
            "in_progress": False,
            "phase": "idle",
            "current": 0,
            "total": 0,
            "message": "No update in progress",
            "last_update": None,
            "started_at": None
        }

        # Initialize file if it doesn't exist
        if not progress_file_path.exists():
            self._write_progress(self._default_data)

        self._initialized = True

    def _read_progress(self) -> dict:
        """Read progress from file."""
        try:
            with open(self._progress_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return self._default_data.copy()

    def _write_progress(self, data: dict):
        """Write progress to file atomically."""
        temp_file = f"{self._progress_file}.tmp"
        try:
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
            os.replace(temp_file, self._progress_file)
        except Exception as e:
            # Clean up temp file if it exists
            if os.path.exists(temp_file):
                os.remove(temp_file)
            raise e

    def start(self, phase: str = "initial_build"):
        """Mark the start of an update process."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            data = {
                "in_progress": True,
                "phase": phase,
                "current": 0,
                "total": 0,
                "message": f"Starting {phase}",
                "last_update": now,
                "started_at": now
            }
            self._write_progress(data)

    def update(self, phase: str, current: int, total: int, message: Optional[str] = None):
        """Update progress information."""
        with self._lock:
            data = self._read_progress()
            data["in_progress"] = True
            data["phase"] = phase
            data["current"] = current
            data["total"] = total
            data["message"] = message or f"{phase}: {current}/{total}"
            data["last_update"] = datetime.now(timezone.utc).isoformat()
            self._write_progress(data)

    def complete(self):
        """Mark the update as complete."""
        with self._lock:
            data = self._read_progress()
            data["in_progress"] = False
            data["phase"] = "completed"
            data["message"] = "Update completed successfully"
            data["last_update"] = datetime.now(timezone.utc).isoformat()
            self._write_progress(data)

    def error(self, message: str):
        """Mark the update as failed."""
        with self._lock:
            data = self._read_progress()
            data["in_progress"] = False
            data["phase"] = "error"
            data["message"] = message
            data["last_update"] = datetime.now(timezone.utc).isoformat()
            self._write_progress(data)

    def get_progress(self) -> dict:
        """Get current progress information."""
        with self._lock:
            return self._read_progress()

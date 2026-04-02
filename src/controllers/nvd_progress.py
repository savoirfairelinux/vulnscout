# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from typing import Optional
from datetime import datetime, timezone
from threading import Lock


class NVDProgressTracker:
    """
    Singleton class to track NVD enrichment progress in-memory.
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

        self._data = {
            "in_progress": False,
            "phase": "idle",
            "current": 0,
            "total": 0,
            "message": "No update in progress",
            "last_update": None,
            "started_at": None
        }
        self._initialized = True

    def start(self, phase: str = "enrichment"):
        """Mark the start of an enrichment process."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._data = {
                "in_progress": True,
                "phase": phase,
                "current": 0,
                "total": 0,
                "message": f"Starting {phase}",
                "last_update": now,
                "started_at": now
            }

    def update(self, phase: str, current: int, total: int, message: Optional[str] = None):
        """Update progress information."""
        with self._lock:
            self._data["in_progress"] = True
            self._data["phase"] = phase
            self._data["current"] = current
            self._data["total"] = total
            self._data["message"] = message or f"{phase}: {current}/{total}"
            self._data["last_update"] = datetime.now(timezone.utc).isoformat()

    def complete(self):
        """Mark the enrichment as complete."""
        with self._lock:
            self._data["in_progress"] = False
            self._data["phase"] = "completed"
            self._data["message"] = "Enrichment completed successfully"
            self._data["last_update"] = datetime.now(timezone.utc).isoformat()

    def error(self, message: str):
        """Mark the enrichment as failed."""
        with self._lock:
            self._data["in_progress"] = False
            self._data["phase"] = "error"
            self._data["message"] = message
            self._data["last_update"] = datetime.now(timezone.utc).isoformat()

    def get_progress(self) -> dict:
        """Get current progress information."""
        with self._lock:
            return dict(self._data)

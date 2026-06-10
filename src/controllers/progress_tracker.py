# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from typing import Optional
from datetime import datetime, timezone
from threading import Lock


class ProgressTracker:
    """Thread-safe tracker for enrichment progress.

    Each instance tracks its own progress state independently.
    """

    def __init__(self, default_phase: str = "enrichment",
                 completed_message: str = "Enrichment completed successfully"):
        self._default_phase = default_phase
        self._completed_message = completed_message
        self._lock = Lock()
        self._cancelled = False
        self._data = {
            "in_progress": False,
            "phase": "idle",
            "current": 0,
            "total": 0,
            "message": "No update in progress",
            "last_update": None,
            "started_at": None,
        }

    def start(self, phase: Optional[str] = None) -> None:
        """Mark the start of an enrichment process."""
        phase = phase or self._default_phase
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._cancelled = False
            self._data = {
                "in_progress": True,
                "phase": phase,
                "current": 0,
                "total": 0,
                "message": f"Starting {phase}",
                "last_update": now,
                "started_at": now,
            }

    def start_if_idle(self, phase: Optional[str] = None) -> bool:
        """Atomically start only if no operation is currently in progress.

        Combines the in_progress check and the state transition into a single
        lock acquisition, eliminating the TOCTOU race that exists when callers
        do ``get_progress()["in_progress"]`` followed by a separate ``start()``.

        Returns True when the tracker was idle and has been started.
        Returns False when an operation was already in progress (caller should
        return HTTP 409).
        """
        phase = phase or self._default_phase
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if self._data["in_progress"]:
                return False
            self._cancelled = False
            self._data = {
                "in_progress": True,
                "phase": phase,
                "current": 0,
                "total": 0,
                "message": f"Starting {phase}",
                "last_update": now,
                "started_at": now,
            }
            return True

    def update(self, phase: str, current: int, total: int, message: Optional[str] = None) -> None:
        """Update progress information."""
        with self._lock:
            self._data["in_progress"] = True
            self._data["phase"] = phase
            self._data["current"] = current
            self._data["total"] = total
            self._data["message"] = message or f"{phase}: {current}/{total}"
            self._data["last_update"] = datetime.now(timezone.utc).isoformat()

    def complete(self) -> None:
        """Mark the enrichment as complete."""
        with self._lock:
            self._data["in_progress"] = False
            self._data["phase"] = "completed"
            self._data["message"] = self._completed_message
            self._data["last_update"] = datetime.now(timezone.utc).isoformat()

    def cancel(self) -> bool:
        """Request cancellation of the in-progress enrichment.

        Thread-safe: the background thread must poll ``is_cancelled()`` and
        call ``cancelled()`` itself once it has safely stopped.
        Returns True if a cancellation was requested (refresh was in progress),
        False if nothing was running.
        """
        with self._lock:
            if not self._data["in_progress"]:
                return False
            self._cancelled = True
            return True

    def is_cancelled(self) -> bool:
        """Return True if a cancellation has been requested."""
        with self._lock:
            return self._cancelled

    def mark_cancelled(self) -> None:
        """Called by the background thread once it has stopped gracefully."""
        with self._lock:
            self._cancelled = False
            self._data["in_progress"] = False
            self._data["phase"] = "cancelled"
            self._data["message"] = "Bulk refresh cancelled"
            self._data["last_update"] = datetime.now(timezone.utc).isoformat()

    def error(self, message: str) -> None:
        """Mark the enrichment as failed."""
        with self._lock:
            self._data["in_progress"] = False
            self._data["phase"] = "error"
            self._data["message"] = message
            self._data["last_update"] = datetime.now(timezone.utc).isoformat()

    def get_progress(self) -> dict:
        """Return a copy of the current progress data."""
        with self._lock:
            return dict(self._data)

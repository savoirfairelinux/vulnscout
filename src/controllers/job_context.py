# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Reporting handle passed to every queued job.

A job body never touches the registry or the event bus directly; it calls
``report`` / ``log`` / ``is_cancelled`` on its context.  The context
coalesces updates so a scan emitting thousands of log lines produces a
bounded number of SSE frames.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .operation_registry import registry

# Minimum spacing between published updates for a single operation.
FLUSH_INTERVAL_SECONDS = 0.25


class CancelledError(Exception):
    """Raised by :meth:`JobContext.check_cancelled` when a stop was requested."""


class JobContext:
    """Progress channel and cancellation signal for one operation."""

    def __init__(self, op_id: str, options: Optional[Dict[str, Any]] = None) -> None:
        self.op_id = op_id
        self.options: Dict[str, Any] = options or {}
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._pending_logs: List[str] = []
        self._pending_progress: Optional[Dict[str, Any]] = None
        self._current = 0
        self._total = 0
        self._last_flush = 0.0
        self._on_cancel: Optional[Callable[[], None]] = None

    # ------------------------------------------------------------------
    # Cancellation
    # ------------------------------------------------------------------

    def request_cancel(self) -> None:
        with self._lock:
            on_cancel = self._on_cancel
        self._cancel.set()
        if on_cancel is not None:
            on_cancel()

    def set_cancel_hook(self, hook: Optional[Callable[[], None]]) -> None:
        """Register a callback that aborts blocking work (e.g. kills a subprocess)."""
        with self._lock:
            self._on_cancel = hook

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    def check_cancelled(self) -> None:
        if self._cancel.is_set():
            raise CancelledError()

    # ------------------------------------------------------------------
    # Progress reporting
    # ------------------------------------------------------------------

    def report(self, current: int, total: int, message: str) -> None:
        with self._lock:
            self._current = current
            self._total = total
            self._pending_progress = {
                "current": current,
                "total": total,
                "message": message,
            }
        self._maybe_flush()

    def message(self, message: str) -> None:
        """Update the status line while keeping the current counters."""
        with self._lock:
            self._pending_progress = {
                "current": self._current,
                "total": self._total,
                "message": message,
            }
        self._maybe_flush()

    def log(self, line: str) -> None:
        with self._lock:
            self._pending_logs.append(line)
        self._maybe_flush()

    def set_result(self, result: Dict[str, Any]) -> None:
        self.flush()
        registry.update(self.op_id, result=result)

    def _maybe_flush(self) -> None:
        now = time.monotonic()
        with self._lock:
            if now - self._last_flush < FLUSH_INTERVAL_SECONDS:
                return
            self._last_flush = now
        self.flush()

    def flush(self) -> None:
        """Publish everything buffered so far."""
        with self._lock:
            logs = self._pending_logs
            progress = self._pending_progress
            self._pending_logs = []
            self._pending_progress = None
        if not logs and progress is None:
            return
        patch: Dict[str, Any] = {}
        if progress is not None:
            patch["progress"] = progress
        if logs:
            patch["append_logs"] = logs
        registry.update(self.op_id, **patch)

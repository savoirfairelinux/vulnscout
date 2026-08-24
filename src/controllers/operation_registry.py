# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Single in-memory store for every long-running operation.

Scans, vulnerability refreshes, SBOM uploads, document exports and boot
enrichment all normalise to one :class:`Operation` shape here.  Every
mutation publishes to :data:`~src.controllers.event_bus.operation_events`,
which is what the ``/api/events/stream`` SSE endpoint serves.

State is process-local, matching the shipped single-process deployment.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .event_bus import operation_events

# Terminal operations stay visible this long so a reconnecting client still
# sees the outcome of work that finished while it was away.
TERMINAL_TTL_SECONDS = 3600

# Per-operation log cap; scans can emit thousands of lines.
MAX_LOGS = 500

KIND_SCAN = "scan"
KIND_REFRESH = "refresh"
KIND_UPLOAD = "upload"
KIND_EXPORT = "export"
KIND_ENRICHMENT = "enrichment"

LANE_PIPELINE = "pipeline"
LANE_EXPORT = "export"
LANE_UPLOAD = "upload"

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_ERROR = "error"
STATUS_CANCELLED = "cancelled"

TERMINAL_STATUSES = frozenset({STATUS_DONE, STATUS_ERROR, STATUS_CANCELLED})
ACTIVE_STATUSES = frozenset({STATUS_QUEUED, STATUS_RUNNING})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class OperationRegistry:
    """Thread-safe operation table with change publication."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._operations: Dict[str, dict] = {}
        self._finished_at: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def create(
        self,
        op_id: str,
        kind: str,
        source: str,
        label: str,
        lane: str,
        scope: Optional[dict] = None,
        queue_id: Optional[str] = None,
        position: Optional[int] = None,
        options: Optional[dict] = None,
        cancellable: bool = False,
    ) -> dict:
        """Register a new operation in ``queued`` state and publish it."""
        operation: Dict[str, Any] = {
            "op_id": op_id,
            "kind": kind,
            "source": source,
            "label": label,
            "lane": lane,
            "scope": scope,
            "status": STATUS_QUEUED,
            "progress": {"current": 0, "total": 0, "message": "Queued"},
            "logs": [],
            "error": None,
            "queue_id": queue_id,
            "position": position,
            "options": options or {},
            "cancellable": cancellable,
            "created_at": _now(),
            "started_at": None,
            "finished_at": None,
            "result": None,
        }
        with self._lock:
            self._operations[op_id] = operation
            self._finished_at.pop(op_id, None)
            snapshot = dict(operation)
        operation_events.publish("operation", snapshot)
        return snapshot

    def update(self, op_id: str, **patch: Any) -> Optional[dict]:
        """Apply *patch* to an operation and publish the new state.

        ``append_logs`` is handled specially: the given lines are appended to
        the existing log list rather than replacing it.
        """
        append_logs = patch.pop("append_logs", None)
        with self._lock:
            operation = self._operations.get(op_id)
            if operation is None:
                return None
            operation.update(patch)
            if append_logs:
                logs = operation["logs"]
                logs.extend(append_logs)
                if len(logs) > MAX_LOGS:
                    del logs[: len(logs) - MAX_LOGS]
            status = operation["status"]
            if status == STATUS_RUNNING and operation["started_at"] is None:
                operation["started_at"] = _now()
            if status in TERMINAL_STATUSES:
                if operation["finished_at"] is None:
                    operation["finished_at"] = _now()
                self._finished_at[op_id] = time.monotonic()
            snapshot = dict(operation)
            snapshot["logs"] = list(operation["logs"])
        operation_events.publish("operation", snapshot)
        return snapshot

    def remove(self, op_id: str) -> bool:
        """Drop a terminal operation and tell clients to forget it."""
        with self._lock:
            operation = self._operations.get(op_id)
            if operation is None or operation["status"] not in TERMINAL_STATUSES:
                return False
            del self._operations[op_id]
            self._finished_at.pop(op_id, None)
        operation_events.publish("operation_removed", {"op_id": op_id})
        return True

    def prune(self) -> None:
        """Drop terminal operations older than :data:`TERMINAL_TTL_SECONDS`."""
        cutoff = time.monotonic() - TERMINAL_TTL_SECONDS
        with self._lock:
            expired = [op_id for op_id, at in self._finished_at.items() if at < cutoff]
            for op_id in expired:
                self._operations.pop(op_id, None)
                self._finished_at.pop(op_id, None)
        for op_id in expired:
            operation_events.publish("operation_removed", {"op_id": op_id})

    def clear(self) -> None:
        """Drop every operation. Used by tests to isolate cases."""
        with self._lock:
            self._operations.clear()
            self._finished_at.clear()

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get(self, op_id: str) -> Optional[dict]:
        with self._lock:
            operation = self._operations.get(op_id)
            if operation is None:
                return None
            snapshot = dict(operation)
            snapshot["logs"] = list(operation["logs"])
            return snapshot

    def snapshot(self) -> List[dict]:
        with self._lock:
            result = []
            for operation in self._operations.values():
                entry = dict(operation)
                entry["logs"] = list(operation["logs"])
                result.append(entry)
        result.sort(key=lambda item: (item["created_at"], item["op_id"]))
        return result

    def active(self) -> List[dict]:
        return [op for op in self.snapshot() if op["status"] in ACTIVE_STATUSES]

    def has_active(self, op_id: str) -> bool:
        with self._lock:
            operation = self._operations.get(op_id)
            return operation is not None and operation["status"] in ACTIVE_STATUSES


def new_queue_id() -> str:
    return f"q-{uuid.uuid4()}"


registry = OperationRegistry()

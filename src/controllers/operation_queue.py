# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Server-side execution queue for every long-running operation.

Three lanes reproduce the concurrency the frontend used to enforce by hand:

``pipeline``
    Scans and vulnerability refreshes, strictly serial.  Grype shells out to
    ``flask export`` and sbom-cve-check holds a file lock on the engine, so
    only one may run at a time; refreshes were likewise gated behind a
    "wait for active scans" barrier in the browser.

``export``
    Document exports, two at a time, matching the previous
    ``ThreadPoolExecutor(max_workers=2)``.

``upload``
    SBOM imports, one thread each, unbounded.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, List, Optional

from flask import Flask

from .job_context import CancelledError, JobContext
from .operation_registry import (
    LANE_EXPORT,
    LANE_PIPELINE,
    LANE_UPLOAD,
    STATUS_CANCELLED,
    STATUS_DONE,
    STATUS_ERROR,
    STATUS_RUNNING,
    registry,
)

JobRunner = Callable[[JobContext], None]


@dataclass
class _Job:
    op_id: str
    lane: str
    ctx: JobContext
    runner: JobRunner


class _Lane:
    """One execution lane with a fixed worker count, or a thread per job."""

    def __init__(self, name: str, workers: Optional[int]) -> None:
        self.name = name
        self.workers = workers
        self._lock = threading.Lock()
        self._wake = threading.Condition(self._lock)
        self._pending: Deque[_Job] = deque()
        self._running: Dict[str, _Job] = {}
        self._started = False

    def start(self, execute: Callable[[_Job], None]) -> None:
        if self.workers is None or self._started:
            return
        self._started = True
        for index in range(self.workers):
            thread = threading.Thread(
                target=self._worker_loop,
                args=(execute,),
                name=f"operations-{self.name}-{index}",
                daemon=True,
            )
            thread.start()

    def submit(self, job: _Job, execute: Callable[[_Job], None]) -> None:
        if self.workers is None:
            with self._lock:
                self._running[job.op_id] = job
            threading.Thread(
                target=execute,
                args=(job,),
                name=f"operations-{self.name}-{job.op_id}",
                daemon=True,
            ).start()
            return
        with self._wake:
            self._pending.append(job)
            self._wake.notify()

    def _worker_loop(self, execute: Callable[[_Job], None]) -> None:
        while True:
            with self._wake:
                while not self._pending:
                    self._wake.wait()
                job = self._pending.popleft()
                self._running[job.op_id] = job
            execute(job)

    def finish(self, op_id: str) -> None:
        with self._lock:
            self._running.pop(op_id, None)

    def take_pending(self, op_id: str) -> Optional[_Job]:
        """Remove a not-yet-started job so it can be cancelled without running."""
        with self._lock:
            for job in self._pending:
                if job.op_id == op_id:
                    self._pending.remove(job)
                    return job
        return None

    def running_job(self, op_id: str) -> Optional[_Job]:
        with self._lock:
            return self._running.get(op_id)

    def pending_ids(self) -> List[str]:
        with self._lock:
            return [job.op_id for job in self._pending]


class OperationQueue:
    """Dispatches queued operations onto their lane and records the outcome."""

    def __init__(self) -> None:
        self._app: Optional[Flask] = None
        self._lanes = {
            LANE_PIPELINE: _Lane(LANE_PIPELINE, 1),
            LANE_EXPORT: _Lane(LANE_EXPORT, 2),
            LANE_UPLOAD: _Lane(LANE_UPLOAD, None),
        }

    def init_app(self, app: Flask) -> None:
        self._app = app
        for lane in self._lanes.values():
            lane.start(self._execute)

    def submit(self, op_id: str, lane: str, runner: JobRunner, ctx: JobContext) -> None:
        """Queue an already-registered operation for execution."""
        target = self._lanes[lane]
        target.submit(_Job(op_id=op_id, lane=lane, ctx=ctx, runner=runner), self._execute)

    def cancel(self, op_id: str) -> bool:
        """Cancel a queued or running operation.

        Queued work is dropped without ever starting; running work gets a
        cooperative stop signal that the job body polls.
        """
        operation = registry.get(op_id)
        if operation is None or not operation.get("cancellable", False):
            return False

        for lane in self._lanes.values():
            pending = lane.take_pending(op_id)
            if pending is not None:
                pending.ctx.request_cancel()
                registry.update(
                    op_id,
                    status=STATUS_CANCELLED,
                    progress={"current": 0, "total": 0, "message": "Cancelled before start"},
                )
                return True
            running = lane.running_job(op_id)
            if running is not None:
                running.ctx.request_cancel()
                registry.update(op_id, append_logs=["Cancellation requested"])
                return True
        return False

    def cancel_queue(self, queue_id: str) -> int:
        """Cancel every still-active operation belonging to a batch."""
        targets = [
            operation["op_id"]
            for operation in registry.active()
            if operation.get("queue_id") == queue_id
        ]
        return sum(1 for op_id in targets if self.cancel(op_id))

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def _execute(self, job: _Job) -> None:
        try:
            if job.ctx.is_cancelled():
                registry.update(
                    job.op_id,
                    status=STATUS_CANCELLED,
                    progress={"current": 0, "total": 0, "message": "Cancelled before start"},
                )
                return
            registry.update(
                job.op_id,
                status=STATUS_RUNNING,
                progress={"current": 0, "total": 0, "message": "Starting"},
            )
            self._run_body(job)
        finally:
            self._lanes[job.lane].finish(job.op_id)

    def _run_body(self, job: _Job) -> None:
        assert self._app is not None, "OperationQueue.init_app() was never called"
        try:
            with self._app.app_context():
                job.runner(job.ctx)
        except CancelledError:
            job.ctx.flush()
            registry.update(
                job.op_id,
                status=STATUS_CANCELLED,
                progress={"current": 0, "total": 0, "message": "Cancelled"},
                append_logs=["Operation cancelled"],
            )
        except Exception as error:  # noqa: BLE001 - surfaced to the client verbatim
            job.ctx.flush()
            message = str(error)[:500] or error.__class__.__name__
            registry.update(
                job.op_id,
                status=STATUS_ERROR,
                error=message,
                append_logs=[f"ERROR: {message}"],
            )
        else:
            job.ctx.flush()
            if job.ctx.is_cancelled():
                registry.update(
                    job.op_id,
                    status=STATUS_CANCELLED,
                    progress={"current": 0, "total": 0, "message": "Cancelled"},
                )
            else:
                registry.update(job.op_id, status=STATUS_DONE)


queue = OperationQueue()

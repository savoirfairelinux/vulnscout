# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Edge-case coverage for operation registry and event transport primitives."""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from flask import Flask

from src.controllers.event_bus import EventBus
from src.controllers import job_context as context_mod
from src.controllers import operation_queue as queue_mod
from src.controllers.job_context import CancelledError, JobContext
from src.controllers.operation_queue import OperationQueue
from src.controllers.operation_registry import (
    LANE_PIPELINE,
    STATUS_CANCELLED,
    STATUS_DONE,
    STATUS_ERROR,
    OperationRegistry,
    new_queue_id,
)
from src.controllers.progress_reporter import NULL_REPORTER


def test_event_bus_replay_close_and_backlog_paths():
    bus = EventBus(replay_size=2, client_backlog=1)
    sub = bus.subscribe()
    bus.publish("operation", {"id": "one"})
    bus.publish("operation", {"id": "two"})
    assert sub.drain(timeout=0) == [{"seq": 1, "event": "operation", "data": {"id": "one"}}]

    assert list(bus.replay_since(1))[0]["seq"] == 2
    assert bus.replay_since(-1) is None
    assert bus.replay_since(3) is None

    bus.close_all()
    assert sub.drain(timeout=0) == []
    assert sub.closed

    empty = EventBus()
    assert list(empty.replay_since(0)) == []
    assert empty.replay_since(1) is None

    draining = EventBus(client_backlog=2).subscribe()
    draining._queue.put_nowait({"seq": 1})
    draining._queue.put_nowait(None)
    assert draining.drain(timeout=0) == [{"seq": 1}]
    assert draining.closed

    multiple = EventBus(client_backlog=2).subscribe()
    multiple._queue.put_nowait({"seq": 1})
    multiple._queue.put_nowait({"seq": 2})
    assert multiple.drain(timeout=0) == [{"seq": 1}, {"seq": 2}]

    full = EventBus(client_backlog=1).subscribe()
    full._queue.put_nowait({"seq": 1})
    full.close()
    assert full.overflowed is False

    with EventBus().subscribe() as scoped:
        assert scoped.closed is False


def test_registry_prunes_logs_and_expired_operations(monkeypatch):
    registry = OperationRegistry()
    published = []
    monkeypatch.setattr("src.controllers.operation_registry.operation_events.publish", lambda *args: published.append(args))
    assert registry.update("missing", status=STATUS_DONE) is None
    registry.create("scan:test", "scan", "nvd", "NVD", LANE_PIPELINE)
    registry.update("scan:test", append_logs=[str(index) for index in range(600)])
    assert len(registry.get("scan:test")["logs"]) == 500

    registry.update("scan:test", status=STATUS_DONE)
    monkeypatch.setattr(time, "monotonic", lambda: 10_000_000)
    registry.create("scan:new", "scan", "nvd", "NVD", LANE_PIPELINE)
    assert registry.get("scan:test") is None
    assert published[-2][0] == "operation_removed"


def test_upload_lane_pending_ids_and_pre_cancelled_execution(monkeypatch):
    executed = []

    class InlineThread:
        def __init__(self, target, args, **_kwargs):
            self._target = target
            self._args = args

        def start(self):
            self._target(*self._args)

    monkeypatch.setattr(queue_mod.threading, "Thread", InlineThread)
    lane = queue_mod._Lane("upload", None)
    upload = queue_mod._Job("upload:one", "upload", SimpleNamespace(), lambda _ctx: None)
    lane.submit(upload, lambda job: executed.append(job.op_id))
    assert executed == ["upload:one"]

    pending_lane = queue_mod._Lane("pending", 1)
    pending_lane.submit(upload, lambda _job: None)
    assert pending_lane.pending_ids() == ["upload:one"]

    registry = OperationRegistry()
    monkeypatch.setattr(queue_mod, "registry", registry)
    registry.create("scan:cancelled", "scan", "nvd", "NVD", LANE_PIPELINE)
    operation_queue = OperationQueue()
    operation_queue._execute(queue_mod._Job(
        "scan:cancelled",
        LANE_PIPELINE,
        SimpleNamespace(is_cancelled=lambda: True),
        lambda _ctx: None,
    ))
    assert registry.get("scan:cancelled")["status"] == "cancelled"


def test_operation_queue_records_runner_outcomes(monkeypatch):
    registry = OperationRegistry()
    monkeypatch.setattr(queue_mod, "registry", registry)
    monkeypatch.setattr(context_mod, "registry", registry)
    operation_queue = OperationQueue()
    operation_queue._app = Flask(__name__)

    def successful(ctx):
        ctx.report(1, 1, "Complete")
        ctx.log("finished")

    def cancelled(ctx):
        ctx.request_cancel()
        ctx.check_cancelled()

    def failed(_ctx):
        raise RuntimeError("failed operation")

    cases = (
        ("scan:done", successful, STATUS_DONE),
        ("scan:cancelled", cancelled, STATUS_CANCELLED),
        ("scan:error", failed, STATUS_ERROR),
    )
    for op_id, runner, expected_status in cases:
        registry.create(op_id, "scan", "nvd", "NVD", LANE_PIPELINE)
        operation_queue._execute(queue_mod._Job(
            op_id,
            LANE_PIPELINE,
            JobContext(op_id),
            runner,
        ))
        operation = registry.get(op_id)
        assert operation["status"] == expected_status

    assert registry.get("scan:done")["logs"] == ["finished"]
    assert registry.get("scan:cancelled")["logs"] == ["Operation cancelled"]
    assert registry.get("scan:error")["error"] == "failed operation"


def test_operation_queue_cancels_pending_and_running_jobs(monkeypatch):
    registry = OperationRegistry()
    monkeypatch.setattr(queue_mod, "registry", registry)
    monkeypatch.setattr(context_mod, "registry", registry)
    operation_queue = OperationQueue()

    pending_ctx = JobContext("scan:pending")
    running_ctx = JobContext("scan:running")
    for op_id in (pending_ctx.op_id, running_ctx.op_id):
        registry.create(
            op_id,
            "scan",
            "nvd",
            "NVD",
            LANE_PIPELINE,
            queue_id="queue:one",
            cancellable=True,
        )

    lane = operation_queue._lanes[LANE_PIPELINE]
    lane._pending.append(queue_mod._Job(
        pending_ctx.op_id,
        LANE_PIPELINE,
        pending_ctx,
        lambda _ctx: None,
    ))
    lane._running[running_ctx.op_id] = queue_mod._Job(
        running_ctx.op_id,
        LANE_PIPELINE,
        running_ctx,
        lambda _ctx: None,
    )

    assert operation_queue.cancel("missing") is False
    assert operation_queue.cancel_queue("queue:one") == 2
    assert pending_ctx.is_cancelled()
    assert running_ctx.is_cancelled()
    assert registry.get(pending_ctx.op_id)["status"] == STATUS_CANCELLED
    assert registry.get(running_ctx.op_id)["logs"] == ["Cancellation requested"]


def test_operation_queue_handles_cancel_after_runner_returns(monkeypatch):
    registry = OperationRegistry()
    monkeypatch.setattr(queue_mod, "registry", registry)
    monkeypatch.setattr(context_mod, "registry", registry)
    operation_queue = OperationQueue()
    operation_queue._app = Flask(__name__)
    op_id = "scan:late-cancel"
    ctx = JobContext(op_id)
    registry.create(op_id, "scan", "nvd", "NVD", LANE_PIPELINE)

    operation_queue._execute(queue_mod._Job(
        op_id,
        LANE_PIPELINE,
        ctx,
        lambda runner_ctx: runner_ctx.request_cancel(),
    ))

    assert registry.get(op_id)["status"] == STATUS_CANCELLED


def test_event_bus_counts_closes_and_overflows():
    bus = EventBus(client_backlog=1)
    assert bus.seq == 0
    subscription = bus.subscribe()
    assert bus.subscriber_count() == 1

    bus.publish("operation", {"id": "one"})
    bus.publish("operation", {"id": "two"})
    assert bus.seq == 2
    assert subscription.overflowed

    bus.close_all()
    assert bus.subscriber_count() == 0

    closed = bus.subscribe()
    closed.close()
    assert closed.drain(timeout=0) == []
    assert closed.closed
    assert EventBus().subscribe().drain(timeout=0) == []


def test_registry_remove_clear_snapshot_and_active_state():
    registry = OperationRegistry()
    assert registry.remove("missing") is False
    registry.create("scan:queued", "scan", "nvd", "NVD", LANE_PIPELINE)
    assert registry.remove("scan:queued") is False
    assert registry.has_active("scan:queued")
    assert registry.has_active("missing") is False
    registry.update("scan:queued", status=STATUS_DONE, append_logs=["done"])
    assert registry.has_active("scan:queued") is False
    assert registry.snapshot()[0]["logs"] == ["done"]
    assert registry.remove("scan:queued") is True

    registry.create("scan:clear", "scan", "nvd", "NVD", LANE_PIPELINE)
    registry.clear()
    assert registry.snapshot() == []
    assert new_queue_id().startswith("q-")


def test_lane_start_queue_submission_and_queue_initialisation(monkeypatch):
    started = []

    class InlineThread:
        def __init__(self, target, args, **kwargs):
            started.append((target, args, kwargs))

        def start(self):
            return None

    monkeypatch.setattr(queue_mod.threading, "Thread", InlineThread)
    lane = queue_mod._Lane("pipeline", 2)
    lane.start(lambda _job: None)
    lane.start(lambda _job: None)
    assert len(started) == 2

    job = queue_mod._Job(
        "scan:queued",
        LANE_PIPELINE,
        JobContext("scan:queued"),
        lambda _ctx: None,
    )
    lane.submit(job, lambda _job: None)
    assert lane.pending_ids() == ["scan:queued"]
    assert lane.take_pending("missing") is None
    assert lane.running_job("missing") is None

    worker_lane = queue_mod._Lane("worker", 1)
    monkeypatch.setattr(worker_lane._wake, "wait", lambda: worker_lane._pending.append(job))
    with pytest.raises(RuntimeError, match="stop worker"):
        worker_lane._worker_loop(lambda _job: (_ for _ in ()).throw(RuntimeError("stop worker")))
    assert worker_lane.running_job(job.op_id) is job

    starts = []
    monkeypatch.setattr(queue_mod._Lane, "start", lambda self, execute: starts.append((self.name, execute)))
    operation_queue = OperationQueue()
    operation_queue.init_app(Flask(__name__))
    assert [name for name, _execute in starts] == ["pipeline", "export", "upload"]

    submitted = []
    monkeypatch.setattr(
        operation_queue._lanes[LANE_PIPELINE],
        "submit",
        lambda submitted_job, execute: submitted.append((submitted_job, execute)),
    )
    operation_queue.submit(job.op_id, job.lane, job.runner, job.ctx)
    assert submitted[0][0].op_id == job.op_id

    registry = OperationRegistry()
    monkeypatch.setattr(queue_mod, "registry", registry)
    registry.create(
        "scan:detached",
        "scan",
        "nvd",
        "NVD",
        LANE_PIPELINE,
        cancellable=True,
    )
    assert operation_queue.cancel("scan:detached") is False


def test_context_cancel_hook_empty_flush_and_null_reporter(monkeypatch):
    registry = OperationRegistry()
    monkeypatch.setattr(context_mod, "registry", registry)
    ctx = JobContext("scan:context")
    registry.create(ctx.op_id, "scan", "nvd", "NVD", LANE_PIPELINE)
    cancelled = []
    ctx.set_cancel_hook(lambda: cancelled.append(True))
    ctx.request_cancel()
    assert cancelled == [True]
    ctx.flush()
    ctx.message("waiting")
    ctx.set_result({"scan_id": "scan:result"})
    assert registry.get(ctx.op_id)["result"] == {"scan_id": "scan:result"}

    assert NULL_REPORTER.report(1, 2, "working") is None
    assert NULL_REPORTER.log("entry") is None
    assert NULL_REPORTER.is_cancelled() is False

    late_ctx = JobContext("scan:late-hook")
    late_ctx.request_cancel()
    terminated = []
    late_ctx.set_cancel_hook(lambda: terminated.append(True))
    assert terminated == [True]
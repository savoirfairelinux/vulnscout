# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Edge-case coverage for operation registry and event transport primitives."""

from __future__ import annotations

import time
from types import SimpleNamespace

from src.controllers.event_bus import EventBus
from src.controllers import operation_queue as queue_mod
from src.controllers.operation_queue import OperationQueue
from src.controllers.operation_registry import LANE_PIPELINE, STATUS_DONE, OperationRegistry


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
    registry.prune()
    assert registry.get("scan:test") is None
    assert published[-1][0] == "operation_removed"


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
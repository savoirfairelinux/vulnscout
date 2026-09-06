# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Operation registry, queue lanes and cancellation semantics."""

import os
import threading
import time

import pytest

from src.bin.webapp import create_app
from src.controllers.event_bus import EventBus
from src.controllers.job_context import CancelledError, JobContext
from src.controllers.operation_queue import OperationQueue
from src.controllers.operation_registry import (
    LANE_EXPORT,
    LANE_PIPELINE,
    STATUS_CANCELLED,
    STATUS_DONE,
    STATUS_ERROR,
    STATUS_QUEUED,
    STATUS_RUNNING,
    registry,
)


@pytest.fixture()
def app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture(autouse=True)
def clean_registry():
    registry.clear()
    yield
    registry.clear()


@pytest.fixture
def op_queue(app):
    queue = OperationQueue()
    queue.init_app(app)
    return queue


def _create(op_id, lane=LANE_PIPELINE, queue_id=None, position=None):
    return registry.create(
        op_id=op_id, kind="scan", source="grype", label="Grype",
        lane=lane, queue_id=queue_id, position=position, cancellable=True,
    )


def _wait_for(op_id, status, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        operation = registry.get(op_id)
        if operation is not None and operation["status"] == status:
            return operation
        time.sleep(0.01)
    actual = registry.get(op_id)
    raise AssertionError(
        f"{op_id} never reached {status}; last state="
        f"{actual['status'] if actual else 'missing'}"
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_create_publishes_queued_operation():
    operation = _create("scan:grype:v1")
    assert operation["status"] == STATUS_QUEUED
    assert registry.has_active("scan:grype:v1")
    assert [op["op_id"] for op in registry.snapshot()] == ["scan:grype:v1"]


def test_update_appends_logs_without_replacing_them():
    _create("scan:grype:v1")
    registry.update("scan:grype:v1", append_logs=["first"])
    registry.update("scan:grype:v1", append_logs=["second", "third"])
    assert registry.get("scan:grype:v1")["logs"] == ["first", "second", "third"]


def test_terminal_status_stamps_finished_at_once():
    _create("scan:grype:v1")
    registry.update("scan:grype:v1", status=STATUS_DONE)
    first = registry.get("scan:grype:v1")["finished_at"]
    registry.update("scan:grype:v1", append_logs=["late"])
    assert registry.get("scan:grype:v1")["finished_at"] == first


def test_remove_only_drops_terminal_operations():
    _create("scan:grype:v1")
    assert registry.remove("scan:grype:v1") is False
    registry.update("scan:grype:v1", status=STATUS_DONE)
    assert registry.remove("scan:grype:v1") is True
    assert registry.get("scan:grype:v1") is None


# ---------------------------------------------------------------------------
# Queue lanes
# ---------------------------------------------------------------------------

def test_pipeline_lane_runs_operations_serially_in_submission_order(op_queue):
    order = []
    running = []
    overlap = threading.Event()

    def make_runner(name):
        def runner(ctx):
            running.append(name)
            if len(running) > 1:
                overlap.set()
            order.append(name)
            time.sleep(0.05)
            running.remove(name)
        return runner

    for name in ("a", "b", "c"):
        _create(f"scan:grype:{name}")
        op_queue.submit(
            f"scan:grype:{name}", LANE_PIPELINE, make_runner(name),
            JobContext(f"scan:grype:{name}"),
        )

    for name in ("a", "b", "c"):
        _wait_for(f"scan:grype:{name}", STATUS_DONE)

    assert order == ["a", "b", "c"]
    assert not overlap.is_set(), "pipeline lane ran two operations at once"


def test_export_lane_runs_two_operations_concurrently(op_queue):
    both_started = threading.Barrier(2, timeout=5)

    def runner(ctx):
        both_started.wait()

    for name in ("x", "y"):
        _create(f"export:{name}", lane=LANE_EXPORT)
        op_queue.submit(
            f"export:{name}", LANE_EXPORT, runner, JobContext(f"export:{name}")
        )

    # The barrier only releases if both operations are in flight together.
    for name in ("x", "y"):
        _wait_for(f"export:{name}", STATUS_DONE)


def test_failing_job_records_the_error(op_queue):
    def runner(ctx):
        raise RuntimeError("grype binary not found on this system")

    _create("scan:grype:v1")
    op_queue.submit("scan:grype:v1", LANE_PIPELINE, runner, JobContext("scan:grype:v1"))

    operation = _wait_for("scan:grype:v1", STATUS_ERROR)
    assert operation["error"] == "grype binary not found on this system"
    assert operation["logs"][-1].startswith("ERROR:")


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------

def test_cancelling_a_queued_operation_prevents_it_from_running(op_queue):
    release = threading.Event()
    ran = []

    def blocker(ctx):
        release.wait(timeout=5)

    def should_not_run(ctx):
        ran.append(True)

    _create("scan:grype:first")
    op_queue.submit("scan:grype:first", LANE_PIPELINE, blocker, JobContext("scan:grype:first"))
    _wait_for("scan:grype:first", STATUS_RUNNING)

    _create("scan:grype:second")
    op_queue.submit(
        "scan:grype:second", LANE_PIPELINE, should_not_run, JobContext("scan:grype:second")
    )

    assert op_queue.cancel("scan:grype:second") is True
    assert registry.get("scan:grype:second")["status"] == STATUS_CANCELLED

    release.set()
    _wait_for("scan:grype:first", STATUS_DONE)
    assert ran == [], "a cancelled queued operation still executed"


def test_cancelling_a_running_operation_reaches_cancelled(op_queue):
    started = threading.Event()

    def runner(ctx):
        started.set()
        for _ in range(500):
            ctx.check_cancelled()
            time.sleep(0.01)

    _create("scan:grype:v1")
    op_queue.submit("scan:grype:v1", LANE_PIPELINE, runner, JobContext("scan:grype:v1"))
    assert started.wait(timeout=5)

    assert op_queue.cancel("scan:grype:v1") is True
    _wait_for("scan:grype:v1", STATUS_CANCELLED)


def test_cancel_queue_stops_every_operation_in_the_batch(op_queue):
    release = threading.Event()

    def blocker(ctx):
        release.wait(timeout=5)

    _create("scan:grype:a", queue_id="q-1", position=1)
    op_queue.submit("scan:grype:a", LANE_PIPELINE, blocker, JobContext("scan:grype:a"))
    _wait_for("scan:grype:a", STATUS_RUNNING)

    for index, name in enumerate(("b", "c"), 2):
        _create(f"scan:grype:{name}", queue_id="q-1", position=index)
        op_queue.submit(
            f"scan:grype:{name}", LANE_PIPELINE, blocker, JobContext(f"scan:grype:{name}")
        )

    assert op_queue.cancel_queue("q-1") == 3
    release.set()
    for name in ("b", "c"):
        assert registry.get(f"scan:grype:{name}")["status"] == STATUS_CANCELLED


def test_cancel_returns_false_for_unknown_operation(op_queue):
    assert op_queue.cancel("scan:grype:missing") is False


# ---------------------------------------------------------------------------
# Job context
# ---------------------------------------------------------------------------

def test_check_cancelled_raises_after_request():
    ctx = JobContext("scan:grype:v1")
    ctx.check_cancelled()
    ctx.request_cancel()
    with pytest.raises(CancelledError):
        ctx.check_cancelled()


def test_cancel_hook_fires_so_blocking_work_can_abort():
    ctx = JobContext("scan:grype:v1")
    aborted = threading.Event()
    ctx.set_cancel_hook(aborted.set)
    ctx.request_cancel()
    assert aborted.is_set()


def test_flush_publishes_buffered_progress_and_logs():
    _create("scan:grype:v1")
    ctx = JobContext("scan:grype:v1")
    ctx.report(3, 10, "3/10 packages")
    ctx.log("scanning")
    ctx.flush()

    operation = registry.get("scan:grype:v1")
    assert operation["progress"] == {"current": 3, "total": 10, "message": "3/10 packages"}
    assert operation["logs"] == ["scanning"]


def test_message_keeps_the_last_reported_counters():
    _create("scan:grype:v1")
    ctx = JobContext("scan:grype:v1")
    ctx.report(4, 9, "4/9 packages")
    ctx.flush()
    ctx.message("Syncing advisory database")
    ctx.flush()

    progress = registry.get("scan:grype:v1")["progress"]
    assert progress == {
        "current": 4, "total": 9, "message": "Syncing advisory database",
    }


# ---------------------------------------------------------------------------
# Event bus
# ---------------------------------------------------------------------------

def test_publish_assigns_monotonic_sequence_numbers():
    bus = EventBus()
    first = bus.publish("operation", {"op_id": "a"})
    second = bus.publish("operation", {"op_id": "b"})
    assert (first["seq"], second["seq"]) == (1, 2)
    assert bus.seq == 2


def test_subscriber_receives_events_published_after_subscribing():
    bus = EventBus()
    subscription = bus.subscribe()
    bus.publish("operation", {"op_id": "a"})
    events = subscription.drain(timeout=1)
    assert [event["data"]["op_id"] for event in events] == ["a"]
    subscription.close()


def test_replay_returns_events_after_the_given_sequence():
    bus = EventBus()
    for name in ("a", "b", "c"):
        bus.publish("operation", {"op_id": name})
    replayed = list(bus.replay_since(1))
    assert [event["data"]["op_id"] for event in replayed] == ["b", "c"]


def test_replay_returns_none_when_the_gap_is_too_wide():
    bus = EventBus(replay_size=2)
    for name in ("a", "b", "c", "d"):
        bus.publish("operation", {"op_id": name})
    assert bus.replay_since(1) is None


def test_slow_subscriber_overflows_instead_of_blocking_the_publisher():
    bus = EventBus(client_backlog=2)
    subscription = bus.subscribe()
    for index in range(5):
        bus.publish("operation", {"op_id": str(index)})
    assert subscription.overflowed is True
    subscription.close()


def test_close_all_signals_every_subscriber():
    bus = EventBus()
    subscription = bus.subscribe()
    bus.close_all()
    subscription.drain(timeout=1)
    assert subscription.closed is True

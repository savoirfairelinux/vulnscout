# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""The single SSE stream that replaced every status and progress endpoint."""

import json
import os

import pytest

from src.bin.webapp import create_app
from src.controllers.event_bus import operation_events
from src.controllers.operation_registry import (
    LANE_PIPELINE,
    STATUS_DONE,
    registry,
)
from src.routes import events as events_module


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


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def clean_registry():
    registry.clear()
    yield
    registry.clear()


@pytest.fixture(autouse=True)
def fast_heartbeat(monkeypatch):
    """Keep the idle timeout short so tests never wait 15 seconds."""
    monkeypatch.setattr(events_module, "HEARTBEAT_SECONDS", 0.05)


@pytest.fixture()
def open_stream(client):
    """Open streams and guarantee they are closed, freeing their slot."""
    readers = []

    def _open(**kwargs):
        response = client.get("/api/events/stream", **kwargs)
        reader = _Reader(response)
        readers.append(reader)
        return reader

    yield _open
    for reader in readers:
        reader.close()


class _Reader:
    """Pulls SSE frames off a streaming response.

    Reading is synchronous: the shortened heartbeat guarantees the generator
    yields something within milliseconds, so no worker thread is needed.
    """

    def __init__(self, response):
        self.response = response
        self._iterator = iter(response.response)

    def next_frame(self):
        chunk = next(self._iterator)
        return parse_frame(chunk.decode() if isinstance(chunk, bytes) else chunk)

    def next_frame_of(self, event_type, max_skips=50):
        for _ in range(max_skips):
            frame = self.next_frame()
            if frame["event"] == event_type:
                return frame
        raise AssertionError(f"no {event_type!r} frame arrived")

    def close(self):
        self.response.close()


def parse_frame(raw):
    parsed = {"id": None, "event": None, "data": None}
    for line in raw.strip().splitlines():
        key, _, value = line.partition(": ")
        if key == "id":
            parsed["id"] = int(value)
        elif key == "event":
            parsed["event"] = value
        elif key == "data":
            parsed["data"] = json.loads(value)
    return parsed


def _create(op_id, status=None):
    operation = registry.create(
        op_id=op_id, kind="scan", source="grype", label="Grype", lane=LANE_PIPELINE
    )
    if status is not None:
        operation = registry.update(op_id, status=status)
    return operation


# ---------------------------------------------------------------------------
# Response shape
# ---------------------------------------------------------------------------

def test_stream_declares_the_sse_content_type_and_disables_buffering(client):
    response = client.get("/api/events/stream")
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("text/event-stream")
    assert response.headers["X-Accel-Buffering"] == "no"
    assert "no-cache" in response.headers["Cache-Control"]
    response.close()


def test_stream_is_reachable_before_the_boot_import_finishes(app, tmp_path):
    """The UI opens the stream while /api is still gated, like /api/scan/status."""
    unfinished = tmp_path / "unfinished.txt"
    unfinished.write_text("3 still importing")
    app.config["SCAN_FILE"] = str(unfinished)
    app._INT_SCAN_FINISHED = False

    client = app.test_client()
    assert client.get("/api/packages").status_code == 503

    response = client.get("/api/events/stream")
    assert response.status_code == 200
    response.close()


# ---------------------------------------------------------------------------
# Snapshot first
# ---------------------------------------------------------------------------

def test_first_frame_is_a_full_snapshot(open_stream):
    _create("scan:grype:v1")
    _create("refresh:epss")

    frame = open_stream().next_frame()

    assert frame["event"] == "snapshot"
    assert sorted(op["op_id"] for op in frame["data"]["operations"]) == [
        "refresh:epss", "scan:grype:v1",
    ]


def test_snapshot_carries_progress_and_logs_so_a_reload_restores_everything(open_stream):
    _create("scan:grype:v1")
    registry.update(
        "scan:grype:v1",
        status="running",
        progress={"current": 7, "total": 20, "message": "7/20 packages"},
        append_logs=["Resolving active packages…"],
    )

    operations = open_stream().next_frame_of("snapshot")["data"]["operations"]

    assert operations[0]["progress"] == {
        "current": 7, "total": 20, "message": "7/20 packages",
    }
    assert operations[0]["logs"] == ["Resolving active packages…"]


def test_queued_operations_survive_a_reload(open_stream):
    """The old per-variant status endpoints could only restore running scans."""
    _create("scan:grype:v1")

    operations = open_stream().next_frame_of("snapshot")["data"]["operations"]

    assert [op["status"] for op in operations] == ["queued"]


# ---------------------------------------------------------------------------
# Deltas
# ---------------------------------------------------------------------------

def test_updates_arrive_as_operation_deltas(open_stream):
    reader = open_stream()
    reader.next_frame_of("snapshot")

    _create("scan:grype:v1")
    frame = reader.next_frame_of("operation")

    assert frame["data"]["op_id"] == "scan:grype:v1"
    assert frame["id"] is not None


def test_dismissal_is_broadcast_so_every_client_forgets_the_operation(open_stream):
    _create("scan:grype:v1", status=STATUS_DONE)

    reader = open_stream()
    reader.next_frame_of("snapshot")

    registry.remove("scan:grype:v1")
    frame = reader.next_frame_of("operation_removed")

    assert frame["data"] == {"op_id": "scan:grype:v1"}


def test_idle_stream_emits_heartbeats(open_stream):
    reader = open_stream()
    reader.next_frame_of("snapshot")

    assert reader.next_frame_of("heartbeat")["event"] == "heartbeat"


# ---------------------------------------------------------------------------
# Reconnection
# ---------------------------------------------------------------------------

def test_reconnect_with_last_event_id_replays_instead_of_resnapshotting(open_stream):
    _create("scan:grype:v1")
    baseline = operation_events.seq
    registry.update("scan:grype:v1", status=STATUS_DONE)

    frame = open_stream(headers={"Last-Event-ID": str(baseline)}).next_frame()

    assert frame["event"] == "operation"
    assert frame["data"]["status"] == STATUS_DONE


def test_reconnect_resnapshots_when_the_gap_is_too_wide(open_stream):
    _create("scan:grype:v1")

    # A sequence far beyond anything published cannot be bridged from the buffer.
    frame = open_stream(headers={"Last-Event-ID": "999999999"}).next_frame()

    assert frame["event"] == "snapshot"


def test_unparsable_last_event_id_falls_back_to_a_snapshot(open_stream):
    frame = open_stream(headers={"Last-Event-ID": "garbage"}).next_frame()

    assert frame["event"] == "snapshot"


# ---------------------------------------------------------------------------
# Capacity
# ---------------------------------------------------------------------------

def test_stream_count_is_capped_because_each_one_holds_a_thread(client, open_stream, monkeypatch):
    monkeypatch.setenv("VULNSCOUT_SSE_MAX_STREAMS", "1")

    assert open_stream().response.status_code == 200

    refused = client.get("/api/events/stream")
    assert refused.status_code == 503
    assert "Too many concurrent event streams" in refused.get_json()["error"]


def test_client_disconnect_releases_the_subscription_and_the_stream_slot(open_stream):
    subscribers_before = operation_events.subscriber_count()
    streams_before = events_module._active_streams

    reader = open_stream()
    reader.next_frame_of("snapshot")
    assert operation_events.subscriber_count() == subscribers_before + 1
    assert events_module._active_streams == streams_before + 1

    # Closing the response finalizes the generator, as a client abort does.
    reader.close()

    assert operation_events.subscriber_count() == subscribers_before
    assert events_module._active_streams == streams_before

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Server-sent event stream carrying every operation update.

One connection replaces the per-scan, per-refresh, upload and export polling
loops the frontend used to run. A new connection starts with a full snapshot;
a reconnecting client that sends a usable ``Last-Event-ID`` receives the
buffered deltas it missed instead, and falls back to a fresh snapshot when the
gap is too wide to replay.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Iterator, Optional

from flask import Flask, Response, jsonify, request, stream_with_context
from flask.typing import ResponseReturnValue

from ..controllers.event_bus import operation_events
from ..controllers.operation_registry import registry

STREAM_PATH = "/api/events/stream"

# Long enough to stay cheap, short enough that proxies and load balancers do
# not treat an idle stream as dead.
HEARTBEAT_SECONDS = 15.0

DEFAULT_MAX_STREAMS = 32

_active_streams = 0
_streams_lock = threading.Lock()


def _max_streams() -> int:
    """Cap concurrent streams; each one occupies a server thread."""
    try:
        return max(1, int(os.environ.get("VULNSCOUT_SSE_MAX_STREAMS", DEFAULT_MAX_STREAMS)))
    except ValueError:
        return DEFAULT_MAX_STREAMS


def _acquire_slot() -> bool:
    global _active_streams
    with _streams_lock:
        if _active_streams >= _max_streams():
            return False
        _active_streams += 1
        return True


def _release_slot() -> None:
    global _active_streams
    with _streams_lock:
        _active_streams = max(0, _active_streams - 1)


def _frame(event_type: str, data: dict, seq: Optional[int] = None) -> str:
    lines = []
    if seq is not None:
        lines.append(f"id: {seq}")
    lines.append(f"event: {event_type}")
    lines.append(f"data: {json.dumps(data, default=str)}")
    return "\n".join(lines) + "\n\n"


def _snapshot_frame() -> tuple[str, int]:
    seq = operation_events.seq
    return _frame("snapshot", {"seq": seq, "operations": registry.snapshot()}), seq


def _parse_last_event_id() -> Optional[int]:
    raw = request.headers.get("Last-Event-ID") or request.args.get("last_event_id")
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _stream(last_event_id: Optional[int]) -> Iterator[str]:
    # Subscribe before snapshotting so nothing published in between is lost;
    # overlapping events are filtered by sequence below.
    subscription = operation_events.subscribe()
    try:
        highest_sent = 0
        replay = (
            operation_events.replay_since(last_event_id)
            if last_event_id is not None else None
        )
        if replay is not None:
            highest_sent = last_event_id or 0
            for event in replay:
                yield _frame(event["event"], event["data"], event["seq"])
                highest_sent = max(highest_sent, event["seq"])
        else:
            # No usable history: the client rebuilds from a full snapshot.
            frame, highest_sent = _snapshot_frame()
            yield frame

        while True:
            events = subscription.drain(HEARTBEAT_SECONDS)
            if subscription.closed:
                yield _frame("bye", {"reason": "server shutdown"})
                return
            if subscription.overflowed:
                subscription.overflowed = False
                frame, highest_sent = _snapshot_frame()
                yield frame
                continue
            if not events:
                yield _frame("heartbeat", {"seq": highest_sent})
                continue
            for event in events:
                if event["seq"] <= highest_sent:
                    continue
                yield _frame(event["event"], event["data"], event["seq"])
                highest_sent = event["seq"]
    finally:
        subscription.close()
        _release_slot()


def init_app(app: Flask) -> None:

    @app.route(STREAM_PATH)
    def operation_event_stream() -> ResponseReturnValue:
        """Stream every operation update over a single connection.

        Frames are ``snapshot`` (full state, sent first), ``operation`` and
        ``operation_removed`` deltas, ``heartbeat`` every 15 seconds, and
        ``bye`` on shutdown. Reconnecting clients that send ``Last-Event-ID``
        are replayed from the buffer, or resnapshotted when the gap is too wide.

        OpenAPI:
        header Last-Event-ID string optional Resume from this sequence number.
        response 200 string Server-sent event stream.
        response 503 Error Too many concurrent streams.
        """
        if not _acquire_slot():
            return jsonify({"error": "Too many concurrent event streams"}), 503

        response = Response(
            stream_with_context(_stream(_parse_last_event_id())),
            mimetype="text/event-stream",
        )
        response.headers["Cache-Control"] = "no-cache, no-transform"
        response.headers["Connection"] = "keep-alive"
        # Tells nginx and friends to forward frames instead of buffering them.
        response.headers["X-Accel-Buffering"] = "no"
        return response

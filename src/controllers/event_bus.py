# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""In-process publish/subscribe bus backing the SSE event stream.

Publishers (scan threads, refresh trackers, the operation watcher) call
:meth:`EventBus.publish`.  Every connected SSE client owns one
:class:`Subscription` and drains its queue.

State is process-local: a multi-worker deployment would need a shared
transport (Redis, database polling) before a single stream could serve
events produced by another worker.
"""

from __future__ import annotations

import queue
import threading
from collections import deque
from typing import Any, Deque, Iterator, List, Optional, Set

# Events kept for reconnecting clients that send ``Last-Event-ID``.
DEFAULT_REPLAY_BUFFER = 512

# Per-client backlog. A client slower than this is dropped and must resync
# from a fresh snapshot rather than stalling the publisher.
DEFAULT_CLIENT_BACKLOG = 256


class Subscription:
    """A single client's view of the bus."""

    def __init__(self, bus: "EventBus", backlog: int) -> None:
        self._bus = bus
        self._queue: queue.Queue[Optional[dict]] = queue.Queue(maxsize=backlog)
        self.overflowed = False
        self.closed = False

    def _offer(self, event: dict) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.overflowed = True

    def close(self) -> None:
        self._bus.unsubscribe(self)
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass

    def drain(self, timeout: float) -> List[dict]:
        """Block up to *timeout* seconds for events, then take what is queued.

        Returns an empty list when the timeout expires with nothing pending,
        which is the caller's cue to emit a heartbeat.
        """
        events: List[dict] = []
        try:
            first = self._queue.get(timeout=timeout)
        except queue.Empty:
            return events
        if first is None:
            self.closed = True
            return events
        events.append(first)
        while True:
            try:
                nxt = self._queue.get_nowait()
            except queue.Empty:
                break
            if nxt is None:
                self.closed = True
                break
            events.append(nxt)
        return events

    def __enter__(self) -> "Subscription":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


class EventBus:
    """Thread-safe fan-out with a bounded replay buffer."""

    def __init__(
        self,
        replay_size: int = DEFAULT_REPLAY_BUFFER,
        client_backlog: int = DEFAULT_CLIENT_BACKLOG,
    ) -> None:
        self._lock = threading.Lock()
        self._subscribers: Set[Subscription] = set()
        self._replay: Deque[dict] = deque(maxlen=replay_size)
        self._client_backlog = client_backlog
        self._seq = 0

    @property
    def seq(self) -> int:
        with self._lock:
            return self._seq

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def publish(self, event_type: str, data: dict) -> dict:
        """Stamp *data* with a monotonic sequence id and fan it out."""
        with self._lock:
            self._seq += 1
            event = {"seq": self._seq, "event": event_type, "data": data}
            self._replay.append(event)
            targets = list(self._subscribers)
        for sub in targets:
            sub._offer(event)
        return event

    def subscribe(self) -> Subscription:
        sub = Subscription(self, self._client_backlog)
        with self._lock:
            self._subscribers.add(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            self._subscribers.discard(sub)

    def close_all(self) -> None:
        """Signal every stream to terminate so clients reconnect."""
        with self._lock:
            targets = list(self._subscribers)
            self._subscribers.clear()
        for sub in targets:
            try:
                sub._queue.put_nowait(None)
            except queue.Full:
                pass

    def replay_since(self, last_seq: int) -> Optional[Iterator[dict]]:
        """Return buffered events after *last_seq*.

        ``None`` means the gap is too large to bridge and the client must
        restart from a snapshot.
        """
        with self._lock:
            if not self._replay:
                return iter(()) if last_seq == self._seq else None
            oldest = self._replay[0]["seq"]
            if last_seq < oldest - 1 or last_seq > self._seq:
                return None
            return iter([e for e in self._replay if e["seq"] > last_seq])


# Single bus shared by every stream in this process.
operation_events = EventBus()

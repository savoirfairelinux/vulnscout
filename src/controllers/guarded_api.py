# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Serve the app on a private loopback port whose writes go through a per-turn guard.

The agent's MCP server talks to the API through a ``GuardedApi``.  Its requests carry the
``GuardedApi``'s guard holder in the WSGI environ, so the hooks installed once by :func:`init_app`
guard them and leave every other request (the web UI, ``app.test_client()``) untouched.
"""

from __future__ import annotations

import threading
from typing import Any, Iterable, Protocol

from flask import Flask, Response, make_response, request
from werkzeug.serving import BaseWSGIServer, WSGIRequestHandler, make_server

ENVIRON_KEY = "vulnscout.turn_guard"
# The guard that saw a request in before_request, so the same one records its response.
_ARMED_KEY = "vulnscout.turn_guard.armed"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
NO_TURN = "No AI turn is running."


class TurnGuard(Protocol):
    def allow(self) -> Response | None:
        """Called in the request context of every mutating request; return a Response to reject it."""

    def record(self, response: Response) -> None:
        """Called with every finished response, including rejections."""


class _Holder:
    """The guard armed on one GuardedApi; read by the hooks through the WSGI environ."""

    def __init__(self) -> None:
        self.guard: TurnGuard | None = None


def init_app(app: Flask) -> None:
    """Install the guard hooks; they do nothing for requests that did not come through a GuardedApi."""

    @app.before_request
    def _guarded_before() -> Response | None:
        holder = request.environ.get(ENVIRON_KEY)
        if holder is None:
            return None
        guard = holder.guard
        request.environ[_ARMED_KEY] = guard
        if request.method in SAFE_METHODS:
            return None
        if guard is None:
            return make_response({"error": NO_TURN}, 403)
        return guard.allow()

    @app.after_request
    def _guarded_after(response: Response) -> Response:
        holder = request.environ.get(ENVIRON_KEY)
        if holder is None:
            return response
        guard = request.environ.get(_ARMED_KEY, holder.guard)
        if guard is not None:
            guard.record(response)
        return response


class _QuietHandler(WSGIRequestHandler):
    """Do not log each agent request (the dev server's INFO access log) from this port."""

    def log_request(self, *args: Any, **kwargs: Any) -> None:
        pass


class GuardedApi:
    """The app served on 127.0.0.1:<free port>, where mutating requests need the armed guard's consent."""

    def __init__(self, app: Flask) -> None:
        self._app = app
        self._holder = _Holder()
        self._server: BaseWSGIServer | None = None
        self._thread: threading.Thread | None = None
        self.url: str | None = None

    def _wsgi(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        return self._app.wsgi_app({**environ, ENVIRON_KEY: self._holder}, start_response)

    def start(self) -> str:
        """Start serving (once) and return the base URL."""
        if self.url is not None:
            return self.url
        server = make_server("127.0.0.1", 0, self._wsgi, threaded=True, request_handler=_QuietHandler)
        thread = threading.Thread(target=server.serve_forever, name="guarded-api", daemon=True)
        thread.start()
        self._server, self._thread = server, thread
        self.url = f"http://127.0.0.1:{server.server_port}"
        return self.url

    def arm(self, guard: TurnGuard | None) -> None:
        """Set the guard of the next requests; ``None`` rejects every mutating request."""
        self._holder.guard = guard

    def stop(self) -> None:
        """Stop serving and free the port; safe to call more than once."""
        server, thread = self._server, self._thread
        self._server = self._thread = None
        self.url = None
        if server is None:
            return
        server.shutdown()
        if thread is not None:
            thread.join(timeout=5)
        server.server_close()

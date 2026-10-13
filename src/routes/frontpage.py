# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os

from flask import Flask, abort, send_from_directory
from flask.typing import ResponseReturnValue

# Everything the backend owns lives under /api; those paths must never fall
# back to the SPA shell, or an unknown endpoint would answer HTML with 200.
API_PREFIX = "api/"


def init_app(app: Flask) -> None:

    @app.route('/')
    def index_front() -> ResponseReturnValue:
        if app.static_folder is None:
            return {"error": "Static folder not configured"}, 500
        return send_from_directory(app.static_folder, "index.html")

    # A path matching a file under /static/... is served as-is (JS bundles,
    # images, ...). A path with no matching file is a client-side route owned
    # by the frontend router (e.g. /sbom, /vulnerabilities), so it falls back
    # to index.html and lets the SPA's router take over from there.
    #
    # Two kinds of path are never client routes and keep returning 404:
    # /api/... (backend-owned, so API clients get an error instead of HTML)
    # and anything carrying a file extension (a missing asset).
    @app.route('/<path:path>')
    def static_file(path: str) -> ResponseReturnValue:
        if app.static_folder is None:
            return {"error": "Static folder not configured"}, 500
        if os.path.isfile(os.path.join(app.static_folder, path)):
            return send_from_directory(app.static_folder, path)
        if path == API_PREFIX.rstrip('/') or path.startswith(API_PREFIX):
            abort(404)
        if os.path.splitext(path)[1]:
            abort(404)
        return send_from_directory(app.static_folder, "index.html")

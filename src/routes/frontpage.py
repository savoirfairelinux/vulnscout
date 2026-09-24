# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os

from flask import Flask, send_from_directory
from flask.typing import ResponseReturnValue


def init_app(app: Flask) -> None:

    @app.route('/')
    def index_front() -> ResponseReturnValue:
        if app.static_folder is None:
            return {"error": "Static folder not configured"}, 500
        return send_from_directory(app.static_folder, "index.html")

    # All paths not starting with /api serve the matching file under
    # /static/... when it exists (JS bundles, images, ...). A path with no
    # matching file is a client-side route owned by the frontend router
    # (e.g. /sbom, /vulnerabilities) rather than a real asset, so it falls
    # back to index.html and lets the SPA's router take over from there.
    @app.route('/<path:path>')
    def static_file(path: str) -> ResponseReturnValue:
        if app.static_folder is None:
            return {"error": "Static folder not configured"}, 500
        if os.path.isfile(os.path.join(app.static_folder, path)):
            return send_from_directory(app.static_folder, path)
        return send_from_directory(app.static_folder, "index.html")

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import Flask, send_from_directory
from flask.typing import ResponseReturnValue


def init_app(app: Flask) -> None:

    @app.route('/')
    def index_front() -> ResponseReturnValue:
        if app.static_folder is None:
            return {"error": "Static folder not configured"}, 500
        return send_from_directory(app.static_folder, "index.html")

    # all path not starting wit /api should serve the file in /static/... path
    @app.route('/<path:path>')
    def static_file(path: str) -> ResponseReturnValue:
        if app.static_folder is None:
            return {"error": "Static folder not configured"}, 500
        return send_from_directory(app.static_folder, path)

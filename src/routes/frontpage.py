# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from typing import Any
from flask import send_from_directory


def init_app(app: Any) -> None:

    @app.route('/')
    def index_front() -> Any:
        return send_from_directory(app.static_folder, "index.html")

    # all path not starting wit /api should serve the file in /static/... path
    @app.route('/<path:path>')
    def static_file(path: str) -> Any:
        return send_from_directory(app.static_folder, path)

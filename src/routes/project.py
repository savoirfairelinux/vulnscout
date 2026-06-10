# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from typing import Any
from flask import jsonify

from ..controllers.projects import ProjectController


def init_app(app: Any) -> None:

    @app.route('/api/projects')
    def list_projects() -> Any:
        projects = ProjectController.get_all()
        return jsonify(ProjectController.serialize_list(projects))

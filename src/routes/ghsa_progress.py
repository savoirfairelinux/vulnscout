# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import jsonify
from ..controllers.ghsa_progress import GHSAProgressTracker


def init_app(app):
    """Initialize GHSA progress routes."""

    @app.route('/api/ghsa/progress', methods=['GET'])
    def get_ghsa_progress():
        """
        Get the current progress of GHSA bulk refresh.

        Returns:
            JSON object with progress information:
            {
                "in_progress": bool,
                "phase": str,
                "current": int,
                "total": int,
                "message": str,
                "last_update": str,
                "started_at": str
            }

        OpenAPI:
        response 200 JsonObject GHSA refresh progress payload.
        """
        progress = GHSAProgressTracker.get_progress()
        return jsonify(progress), 200

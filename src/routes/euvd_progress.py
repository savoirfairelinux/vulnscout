# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import jsonify
from ..controllers.euvd_progress import EUVDProgressTracker


def init_app(app):
    """Initialize EUVD progress routes."""

    @app.route('/api/euvd/progress', methods=['GET'])
    def get_euvd_progress():
        """
        Get the current progress of an EUVD bulk refresh.

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
        """
        progress = EUVDProgressTracker.get_progress()
        return jsonify(progress), 200

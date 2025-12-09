# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import jsonify
from ..controllers.nvd_progress import NVDProgressTracker


def init_app(app):
    """
    Initialize NVD progress routes.
    """

    @app.route('/api/nvd/progress', methods=['GET'])
    def get_nvd_progress():
        """
        Get the current progress of NVD database updates.

        Returns:
            JSON object with progress information:
            {
                "in_progress": bool,     # Whether an update is currently running
                "phase": str,            # Current phase of update
                "current": int,          # Current progress count
                "total": int,            # Total items to process
                "message": str,          # Human-readable status message
                "last_update": str,      # ISO timestamp of last update
                "started_at": str        # ISO timestamp when update started
            }
        """
        tracker = NVDProgressTracker()
        progress = tracker.get_progress()
        return jsonify(progress), 200

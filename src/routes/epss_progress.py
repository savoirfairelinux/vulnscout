# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import jsonify
from ..controllers.epss_progress import EPSSProgressTracker


def init_app(app):
    """
    Initialize EPSS progress routes.
    """

    @app.route('/api/epss/progress', methods=['GET'])
    def get_epss_progress():
        """
        Get the current progress of EPSS score enrichment.

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
        tracker = EPSSProgressTracker()
        progress = tracker.get_progress()
        return jsonify(progress), 200

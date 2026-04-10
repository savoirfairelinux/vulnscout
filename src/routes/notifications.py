#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import os
from flask import jsonify

NOTIFICATION_FILE = "/scan/legacy_notification.json"


def init_app(app):

    @app.route('/api/notifications')
    def get_notifications():
        """Return any pending system notification (e.g. legacy-setup warning).

        Returns an empty list when no notification is pending, or a list with
        one notification object::

            [{"level": "warning", "title": "...", "message": "...", "action": "..."}]
        """
        if not os.path.isfile(NOTIFICATION_FILE):
            return jsonify([])
        try:
            with open(NOTIFICATION_FILE) as fh:
                data = json.load(fh)
            # Normalise: always return a list
            if isinstance(data, dict):
                data = [data]
            return jsonify(data)
        except (OSError, json.JSONDecodeError):
            return jsonify([])

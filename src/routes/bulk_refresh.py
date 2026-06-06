# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Bulk NVD and EPSS refresh endpoints.

Each endpoint accepts a list of CVE IDs and spawns a background daemon thread
to perform the actual API calls for all of them.
Progress is reported via the shared NVDProgressTracker / EPSSProgressTracker
singletons, which are already polled by /api/nvd/progress and /api/epss/progress.
"""

import threading

from flask import jsonify, request

from ..controllers.refresh import (
    run_epss_refresh,
    run_nvd_refresh,
    _MAX_CVE_IDS,
    _CVE_RE,
    _safe_commit,
    _nvd_sleep_interval,
)
from ..controllers.nvd_progress import NVDProgressTracker
from ..controllers.epss_progress import EPSSProgressTracker


def init_app(app):

    @app.route('/api/vulnerabilities/bulk-nvd-refresh', methods=['POST'])
    def bulk_nvd_refresh():
        """Trigger a bulk NVD refresh for a list of CVE IDs.

        Body: ``{"cve_ids": ["CVE-A", "CVE-B", ...]}``

        Returns 202 immediately and runs the refresh in a background thread.
        Returns 409 if a refresh is already in progress.
        Returns 400 if cve_ids is empty or contains no valid CVE identifiers.
        """
        body = request.get_json(force=True, silent=True) or {}
        raw_ids = body.get("cve_ids", [])
        if not raw_ids or not isinstance(raw_ids, list):
            return jsonify({"error": "cve_ids must be a non-empty list"}), 400

        cve_ids = [c.strip().upper() for c in raw_ids if isinstance(c, str) and c.strip()]
        cve_ids = [c for c in cve_ids if _CVE_RE.match(c)]
        if not cve_ids:
            return jsonify({"error": "cve_ids must contain valid CVE identifiers (e.g. CVE-2024-1234)"}), 400
        if len(cve_ids) > _MAX_CVE_IDS:
            return jsonify({"error": f"cve_ids must contain at most {_MAX_CVE_IDS} entries"}), 400

        total = len(cve_ids)
        if not NVDProgressTracker.start_if_idle("bulk_nvd_refresh"):
            return jsonify({"error": "A bulk NVD refresh is already in progress"}), 409
        NVDProgressTracker.update("bulk_nvd_refresh", 0, total, f"Starting bulk NVD refresh: 0/{total}")

        def _run():
            run_nvd_refresh(app, cve_ids)

        threading.Thread(target=_run, name="bulk-nvd-refresh", daemon=True).start()
        return jsonify({"status": "started", "total": total}), 202

    @app.route('/api/vulnerabilities/cancel-nvd-refresh', methods=['POST'])
    def cancel_nvd_refresh():
        """Request cancellation of an in-progress bulk NVD refresh."""
        if NVDProgressTracker.cancel():
            return jsonify({"status": "cancelling"}), 200
        return jsonify({"error": "No bulk NVD refresh is currently in progress"}), 409

    @app.route('/api/vulnerabilities/bulk-epss-refresh', methods=['POST'])
    def bulk_epss_refresh():
        """Trigger a bulk EPSS refresh for a list of CVE IDs.

        Body: ``{"cve_ids": ["CVE-A", "CVE-B", ...]}``

        Returns 202 immediately and runs the refresh in a background thread.
        Returns 409 if a refresh is already in progress.
        Returns 400 if cve_ids is empty or contains no valid CVE identifiers.
        """
        body = request.get_json(force=True, silent=True) or {}
        raw_ids = body.get("cve_ids", [])
        if not raw_ids or not isinstance(raw_ids, list):
            return jsonify({"error": "cve_ids must be a non-empty list"}), 400

        cve_ids = [c.strip().upper() for c in raw_ids if isinstance(c, str) and c.strip()]
        cve_ids = [c for c in cve_ids if _CVE_RE.match(c)]
        if not cve_ids:
            return jsonify({"error": "cve_ids must contain valid CVE identifiers (e.g. CVE-2024-1234)"}), 400
        if len(cve_ids) > _MAX_CVE_IDS:
            return jsonify({"error": f"cve_ids must contain at most {_MAX_CVE_IDS} entries"}), 400

        total = len(cve_ids)
        if not EPSSProgressTracker.start_if_idle("bulk_epss_refresh"):
            return jsonify({"error": "A bulk EPSS refresh is already in progress"}), 409
        EPSSProgressTracker.update("bulk_epss_refresh", 0, total, f"Starting bulk EPSS refresh: 0/{total}")

        def _run():
            run_epss_refresh(app, cve_ids)

        threading.Thread(target=_run, name="bulk-epss-refresh", daemon=True).start()
        return jsonify({"status": "started", "total": total}), 202

    @app.route('/api/vulnerabilities/cancel-epss-refresh', methods=['POST'])
    def cancel_epss_refresh():
        """Request cancellation of an in-progress bulk EPSS refresh."""
        if EPSSProgressTracker.cancel():
            return jsonify({"status": "cancelling"}), 200
        return jsonify({"error": "No bulk EPSS refresh is currently in progress"}), 409

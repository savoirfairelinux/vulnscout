# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Bulk NVD and EPSS refresh endpoints.

Each endpoint accepts a list of CVE IDs and spawns a background daemon thread
to perform the actual API calls for all of them.
Progress is reported via the shared NVDProgressTracker / EPSSProgressTracker
singletons, which are already polled by /api/nvd/progress and /api/epss/progress.
"""

import datetime
import os
import re
import threading
import time

from flask import jsonify, request

from ..models import Vulnerability
from ..extensions import db
from ..controllers.nvd_db import NVD_DB
from ..controllers.nvd_apply import apply_nvd_update, apply_cvss_update
from ..controllers.epss_db import EPSS_DB
from ..controllers.nvd_progress import NVDProgressTracker
from ..controllers.epss_progress import EPSSProgressTracker

from typing import Any

_EPSS_BATCH_SIZE = 100
_NVD_COMMIT_EVERY = 50
# HIGH: cap prevents unbounded background threads (no API key = 6 s/CVE × N seconds of work)
_MAX_CVE_IDS = 1000
# HIGH: only accept well-formed CVE identifiers to avoid wasting rate-limit quota
_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$')


def _nvd_sleep_interval() -> float:
    """Return seconds to sleep between NVD API calls based on key presence.

    Without an API key: 5 req / 30 s → 6 s per call.
    With an API key:   50 req / 30 s → 0.6 s per call.

    Reference: https://nvd.nist.gov/developers/start-here, section "Rate Limits"
    """
    return 0.6 if os.getenv("NVD_API_KEY") else 6.0


def _safe_commit(label: str) -> None:
    """Commit the current session; rollback and log on failure.

    Always expunges all objects from the session after commit or rollback so
    that the SQLAlchemy identity map does not accumulate loaded records across
    many loop iterations (fix for unbounded session-cache growth).
    """
    try:
        db.session.commit()
    except Exception as exc:
        print(f"[{label}] commit error: {exc}", flush=True)
        db.session.rollback()
    finally:
        db.session.expunge_all()


def init_app(app: Any) -> None:

    @app.route('/api/vulnerabilities/bulk-nvd-refresh', methods=['POST'])
    def bulk_nvd_refresh() -> Any:
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

        def _run() -> None:
            with app.app_context():
                sleep_between = _nvd_sleep_interval()
                nvd_api_key = os.getenv("NVD_API_KEY")
                nvd = NVD_DB(nvd_api_key=nvd_api_key)
                done = 0
                try:
                    for cve_id in cve_ids:
                        if NVDProgressTracker.is_cancelled():
                            _safe_commit("bulk NVD refresh cancel")
                            NVDProgressTracker.mark_cancelled()
                            return

                        try:
                            now = datetime.datetime.now(datetime.timezone.utc)
                            status_code, data = nvd.api_get_cve(cve_id, max_retries=2)
                            if status_code == 200 and data.get("vulnerabilities"):
                                cve = data["vulnerabilities"][0]["cve"]
                                details = NVD_DB.extract_cve_details(cve)
                                rec = db.session.get(Vulnerability, cve_id)
                                if rec is not None:
                                    apply_nvd_update(rec, details, now)
                                    apply_cvss_update(rec, details, db)
                            else:
                                print(
                                    f"[bulk NVD refresh] {cve_id}: status={status_code}, "
                                    "skipping",
                                    flush=True,
                                )
                        except Exception as exc:
                            print(f"[bulk NVD refresh] error for {cve_id}: {exc}", flush=True)

                        done += 1
                        NVDProgressTracker.update(
                            "bulk_nvd_refresh", done, total,
                            f"NVD refresh: {done}/{total} ({cve_id})",
                        )
                        if done % _NVD_COMMIT_EVERY == 0:
                            _safe_commit("bulk NVD refresh")
                        if done < total:
                            time.sleep(sleep_between)

                    _safe_commit("bulk NVD refresh final")
                    NVDProgressTracker.complete()
                except Exception as exc:
                    print(f"[bulk NVD refresh] unhandled error: {exc}", flush=True)
                    NVDProgressTracker.error(str(exc)[:200])

        threading.Thread(target=_run, name="bulk-nvd-refresh", daemon=True).start()
        return jsonify({"status": "started", "total": total}), 202

    @app.route('/api/vulnerabilities/cancel-nvd-refresh', methods=['POST'])
    def cancel_nvd_refresh() -> Any:
        """Request cancellation of an in-progress bulk NVD refresh.

        Returns 200 when the cancellation was accepted (refresh was running).
        Returns 409 when no bulk NVD refresh is currently in progress.
        """
        if NVDProgressTracker.cancel():
            return jsonify({"status": "cancelling"}), 200
        return jsonify({"error": "No bulk NVD refresh is currently in progress"}), 409

    @app.route('/api/vulnerabilities/bulk-epss-refresh', methods=['POST'])
    def bulk_epss_refresh() -> Any:
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

        def _run() -> None:
            with app.app_context():
                epss = EPSS_DB()
                now = datetime.datetime.now(datetime.timezone.utc)
                processed = 0
                try:
                    chunks = [
                        cve_ids[i:i + _EPSS_BATCH_SIZE]
                        for i in range(0, total, _EPSS_BATCH_SIZE)
                    ]
                    for chunk in chunks:
                        if EPSSProgressTracker.is_cancelled():
                            _safe_commit("bulk EPSS refresh cancel")
                            EPSSProgressTracker.mark_cancelled()
                            return

                        try:
                            results = epss.api_get_epss_batch(chunk)
                        except Exception as exc:
                            print(f"[bulk EPSS refresh] batch error: {exc}", flush=True)
                            processed += len(chunk)
                            EPSSProgressTracker.update(
                                "bulk_epss_refresh", processed, total,
                                f"EPSS refresh: {processed}/{total}",
                            )
                            continue

                        for cve_id in chunk:
                            result = results.get(cve_id)
                            if result:
                                try:
                                    rec = db.session.get(Vulnerability, cve_id)
                                    if rec is not None:
                                        rec.update_record(
                                            epss_score=result["score"],
                                            epss_fetched_at=now,
                                            commit=False,
                                        )
                                except Exception as exc:
                                    print(
                                        f"[bulk EPSS refresh] error updating {cve_id}: {exc}",
                                        flush=True,
                                    )
                            processed += 1

                        _safe_commit("bulk EPSS refresh")
                        EPSSProgressTracker.update(
                            "bulk_epss_refresh", processed, total,
                            f"EPSS refresh: {processed}/{total}",
                        )

                    EPSSProgressTracker.complete()
                except Exception as exc:
                    print(f"[bulk EPSS refresh] unhandled error: {exc}", flush=True)
                    EPSSProgressTracker.error(str(exc)[:200])

        threading.Thread(target=_run, name="bulk-epss-refresh", daemon=True).start()
        return jsonify({"status": "started", "total": total}), 202

    @app.route('/api/vulnerabilities/cancel-epss-refresh', methods=['POST'])
    def cancel_epss_refresh() -> Any:
        """Request cancellation of an in-progress bulk EPSS refresh.

        Returns 200 when the cancellation was accepted (refresh was running).
        Returns 409 when no bulk EPSS refresh is currently in progress.
        """
        if EPSSProgressTracker.cancel():
            return jsonify({"status": "cancelling"}), 200
        return jsonify({"error": "No bulk EPSS refresh is currently in progress"}), 409

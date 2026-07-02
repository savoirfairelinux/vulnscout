# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Bulk NVD and EPSS refresh endpoints.

Each endpoint accepts a list of CVE IDs and spawns a background daemon thread
to perform the actual API calls for all of them.
Progress is reported via the shared NVDProgressTracker / EPSSProgressTracker
singletons, which are already polled by /api/nvd/progress and /api/epss/progress.
"""

import datetime
import decimal
import os
import re
import threading
import time
import urllib.error

from flask import jsonify, request, Flask
from flask.typing import ResponseReturnValue

from ..models import Vulnerability
from ..extensions import db
from ..controllers.nvd_db import NVD_DB
from ..controllers.nvd_apply import apply_nvd_update, apply_cvss_update
from ..controllers.epss_db import EPSS_DB
from ..controllers.nvd_progress import NVDProgressTracker
from ..controllers.epss_progress import EPSSProgressTracker
from ..controllers.ghsa_progress import GHSAProgressTracker
from ..controllers.euvd_progress import EUVDProgressTracker
from ..controllers.euvd_db import EUVD_DB
from ..controllers.vulnerabilities import VulnerabilitiesController

_EPSS_BATCH_SIZE = 100
_NVD_COMMIT_EVERY = 50
# HIGH: cap prevents unbounded background threads (no API key = 6 s/CVE × N seconds of work)
_MAX_CVE_IDS = 1000
# HIGH: only accept well-formed CVE identifiers to avoid wasting rate-limit quota
_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$')
_MAX_GHSA_IDS = 500
_GHSA_RE = re.compile(r'^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$')
_GHSA_COMMIT_EVERY = 20
_GHSA_SLEEP_INTERVAL = 1.0
# EUVD enrichment annotates from already-cached ENISA dumps (no per-CVE network
# call), so it is fast; commit in larger batches than the network-bound refreshes.
_EUVD_COMMIT_EVERY = 200


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


def init_app(app: Flask) -> None:

    @app.route('/api/vulnerabilities/bulk-nvd-refresh', methods=['POST'])
    def bulk_nvd_refresh() -> ResponseReturnValue:
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
    def cancel_nvd_refresh() -> ResponseReturnValue:
        """Request cancellation of an in-progress bulk NVD refresh.

        Returns 200 when the cancellation was accepted (refresh was running).
        Returns 409 when no bulk NVD refresh is currently in progress.
        """
        if NVDProgressTracker.cancel():
            return jsonify({"status": "cancelling"}), 200
        return jsonify({"error": "No bulk NVD refresh is currently in progress"}), 409

    @app.route('/api/vulnerabilities/bulk-epss-refresh', methods=['POST'])
    def bulk_epss_refresh() -> ResponseReturnValue:
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
                                        new_score = decimal.Decimal(str(result["score"]))
                                        ek: dict = {
                                            "epss_score": new_score,
                                            "epss_fetched_at": now,
                                            "commit": False,
                                        }
                                        if rec.epss_score is None or rec.epss_score != new_score:
                                            ek["epss_data_updated_at"] = now
                                        rec.update_record(**ek)
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
    def cancel_epss_refresh() -> ResponseReturnValue:
        """Request cancellation of an in-progress bulk EPSS refresh.

        Returns 200 when the cancellation was accepted (refresh was running).
        Returns 409 when no bulk EPSS refresh is currently in progress.
        """
        if EPSSProgressTracker.cancel():
            return jsonify({"status": "cancelling"}), 200
        return jsonify({"error": "No bulk EPSS refresh is currently in progress"}), 409

    @app.route('/api/vulnerabilities/bulk-ghsa-refresh', methods=['POST'])
    def bulk_ghsa_refresh() -> ResponseReturnValue:
        """Trigger a bulk GHSA refresh for a list of GHSA IDs.

        Body: ``{"ghsa_ids": ["GHSA-xxxx-xxxx-xxxx", ...]}``

        Only GHSA-prefixed identifiers are accepted; CVE IDs are rejected.
        Returns 202 immediately and runs the refresh in a background thread.
        Returns 409 if a refresh is already in progress.
        Returns 400 if ghsa_ids is empty or contains no valid GHSA identifiers.
        """
        body = request.get_json(force=True, silent=True) or {}
        raw_ids = body.get("ghsa_ids", [])
        if not raw_ids or not isinstance(raw_ids, list):
            return jsonify({"error": "ghsa_ids must be a non-empty list"}), 400

        ghsa_ids = [c.strip().upper() for c in raw_ids if isinstance(c, str) and c.strip()]
        ghsa_ids = [c for c in ghsa_ids if _GHSA_RE.match(c)]
        if not ghsa_ids:
            return jsonify({"error": "ghsa_ids must contain valid GHSA identifiers (e.g. GHSA-xxxx-xxxx-xxxx)"}), 400
        if len(ghsa_ids) > _MAX_GHSA_IDS:
            return jsonify({"error": f"ghsa_ids must contain at most {_MAX_GHSA_IDS} entries"}), 400

        total = len(ghsa_ids)
        if not GHSAProgressTracker.start_if_idle("bulk_ghsa_refresh"):
            return jsonify({"error": "A bulk GHSA refresh is already in progress"}), 409
        GHSAProgressTracker.update("bulk_ghsa_refresh", 0, total, f"Starting bulk GHSA refresh: 0/{total}")

        def _run() -> None:
            with app.app_context():
                now = datetime.datetime.now(datetime.timezone.utc)
                done = 0
                failed = 0
                try:
                    for ghsa_id in ghsa_ids:
                        if GHSAProgressTracker.is_cancelled():
                            _safe_commit("bulk GHSA refresh cancel")
                            GHSAProgressTracker.mark_cancelled()
                            return

                        try:
                            published_at = VulnerabilitiesController._fetch_ghsa_published(ghsa_id)
                            if published_at:
                                rec = db.session.get(Vulnerability, ghsa_id)
                                if rec is not None:
                                    try:
                                        publish_date = datetime.date.fromisoformat(
                                            str(published_at)[:10]
                                        )
                                    except ValueError:
                                        publish_date = None
                                    gk: dict = {
                                        "ghsa_fetched_at": now,
                                        "commit": False,
                                    }
                                    if publish_date is not None:
                                        gk["publish_date"] = publish_date
                                        if rec.publish_date != publish_date:
                                            gk["ghsa_data_updated_at"] = now
                                    rec.update_record(**gk)
                        except urllib.error.HTTPError as exc:
                            if exc.code in (403, 429):
                                _safe_commit("bulk GHSA refresh rate-limited")
                                GHSAProgressTracker.error(
                                    f"GitHub rate limit reached after {done} IDs (HTTP {exc.code})."
                                    " Set GITHUB_TOKEN env var to increase quota."
                                )
                                return
                            print(f"[bulk GHSA refresh] error for {ghsa_id}: {exc}", flush=True)
                            failed += 1
                        except Exception as exc:
                            print(f"[bulk GHSA refresh] error for {ghsa_id}: {exc}", flush=True)
                            failed += 1

                        done += 1
                        GHSAProgressTracker.update(
                            "bulk_ghsa_refresh", done, total,
                            f"GHSA refresh: {done}/{total} ({ghsa_id})",
                        )
                        if done % _GHSA_COMMIT_EVERY == 0:
                            _safe_commit("bulk GHSA refresh")
                        if done < total:
                            time.sleep(_GHSA_SLEEP_INTERVAL)

                    _safe_commit("bulk GHSA refresh final")
                    if failed:
                        GHSAProgressTracker.complete(
                            f"GHSA refresh complete ({total} IDs, {failed} failed)"
                        )
                    else:
                        GHSAProgressTracker.complete()
                except Exception as exc:
                    print(f"[bulk GHSA refresh] unhandled error: {exc}", flush=True)
                    GHSAProgressTracker.error(str(exc)[:200])

        threading.Thread(target=_run, name="bulk-ghsa-refresh", daemon=True).start()
        return jsonify({"status": "started", "total": total}), 202

    @app.route('/api/vulnerabilities/cancel-ghsa-refresh', methods=['POST'])
    def cancel_ghsa_refresh() -> ResponseReturnValue:
        """Request cancellation of an in-progress bulk GHSA refresh.

        Returns 200 when the cancellation was accepted (refresh was running).
        Returns 409 when no bulk GHSA refresh is currently in progress.
        """
        if GHSAProgressTracker.cancel():
            return jsonify({"status": "cancelling"}), 200
        return jsonify({"error": "No bulk GHSA refresh is currently in progress"}), 409

    @app.route('/api/vulnerabilities/bulk-euvd-refresh', methods=['POST'])
    def bulk_euvd_refresh() -> ResponseReturnValue:
        """Trigger a bulk ENISA EUVD enrichment for a list of CVE IDs.

        Body: ``{"cve_ids": ["CVE-A", "CVE-B", ...]}``

        Unlike NVD/EPSS/GHSA this performs no per-CVE network call: it loads two
        already-cached ENISA dumps once — the full CVE -> EUVD id mapping (the
        *alias*, present for every published CVE ENISA tracks) and the EU KEV
        dump (the *known-exploited* flag) — and annotates each selected CVE.

        Returns 202 immediately and runs the enrichment in a background thread.
        Returns 409 if an enrichment is already in progress.
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

        total = len(cve_ids)
        if not EUVDProgressTracker.start_if_idle("bulk_euvd_refresh"):
            return jsonify({"error": "A bulk EUVD refresh is already in progress"}), 409
        EUVDProgressTracker.update("bulk_euvd_refresh", 0, total, f"Starting bulk EUVD refresh: 0/{total}")

        def _run() -> None:
            with app.app_context():
                try:
                    EUVDProgressTracker.update(
                        "bulk_euvd_refresh", 0, total, "Loading ENISA EUVD CVE mapping…")
                    euvd = EUVD_DB()
                    full_map = euvd.get_full_mapping()
                    if not full_map:
                        EUVDProgressTracker.error("ENISA EUVD CVE mapping unavailable or empty")
                        return
                    kev_map = euvd.get_mapping()

                    now = datetime.datetime.now(datetime.timezone.utc)
                    done = 0
                    matched = 0
                    kev_matched = 0
                    for cve_id in cve_ids:
                        if EUVDProgressTracker.is_cancelled():
                            _safe_commit("bulk EUVD refresh cancel")
                            EUVDProgressTracker.mark_cancelled()
                            return

                        kev = kev_map.get(cve_id)
                        euvd_id = full_map.get(cve_id) or (kev["euvd_id"] if kev else None)
                        if euvd_id:
                            rec = db.session.get(Vulnerability, cve_id)
                            if rec is not None:
                                known_exploited = kev is not None
                                rec.update_record(
                                    euvd_id=euvd_id,
                                    euvd_known_exploited=known_exploited,
                                    euvd_kev_sources=(kev.get("sources") or []) if kev else [],
                                    euvd_date_added=kev.get("date_added") if kev else None,
                                    euvd_fetched_at=now,
                                    euvd_data_updated_at=now,
                                    commit=False,
                                )
                                matched += 1
                                if known_exploited:
                                    kev_matched += 1

                        done += 1
                        EUVDProgressTracker.update(
                            "bulk_euvd_refresh", done, total,
                            f"EUVD refresh: {done}/{total}",
                        )
                        if done % _EUVD_COMMIT_EVERY == 0:
                            _safe_commit("bulk EUVD refresh")

                    _safe_commit("bulk EUVD refresh final")
                    EUVDProgressTracker.complete(
                        f"EUVD enrichment complete "
                        f"({matched}/{total} matched, {kev_matched} known exploitable)"
                    )
                except Exception as exc:
                    print(f"[bulk EUVD refresh] unhandled error: {exc}", flush=True)
                    EUVDProgressTracker.error(str(exc)[:200])

        threading.Thread(target=_run, name="bulk-euvd-refresh", daemon=True).start()
        return jsonify({"status": "started", "total": total}), 202

    @app.route('/api/vulnerabilities/cancel-euvd-refresh', methods=['POST'])
    def cancel_euvd_refresh() -> ResponseReturnValue:
        """Request cancellation of an in-progress bulk EUVD refresh.

        Returns 200 when the cancellation was accepted (refresh was running).
        Returns 409 when no bulk EUVD refresh is currently in progress.
        """
        if EUVDProgressTracker.cancel():
            return jsonify({"status": "cancelling"}), 200
        return jsonify({"error": "No bulk EUVD refresh is currently in progress"}), 409

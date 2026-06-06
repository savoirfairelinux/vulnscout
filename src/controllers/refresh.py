# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Core EPSS and NVD refresh workers shared by startup enrichment and bulk refresh routes.

Callers are responsible for calling the appropriate ProgressTracker.start_if_idle()
before invoking a worker. Workers call complete() or error() when done.
"""

import datetime
import os
import re
import time

from ..extensions import db
from ..models import Vulnerability
from ..controllers.nvd_db import NVD_DB
from ..controllers.nvd_apply import apply_nvd_update, apply_cvss_update
from ..controllers.epss_db import EPSS_DB
from ..controllers.nvd_progress import NVDProgressTracker
from ..controllers.epss_progress import EPSSProgressTracker

_EPSS_BATCH_SIZE = 100
_NVD_COMMIT_EVERY = 50
_MAX_CVE_IDS = 1000
_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$')


def _nvd_sleep_interval() -> float:
    """Return seconds to sleep between NVD API calls based on key presence.

    Without an API key: 5 req / 30 s → 6 s per call.
    With an API key:   50 req / 30 s → 0.6 s per call.
    """
    return 0.6 if os.getenv("NVD_API_KEY") else 6.0


def _safe_commit(label: str) -> None:
    """Commit the current session; rollback and log on failure.

    Always expunges all objects from the session after commit or rollback so
    that the SQLAlchemy identity map does not accumulate loaded records across
    many loop iterations.
    """
    try:
        db.session.commit()
    except Exception as exc:
        print(f"[{label}] commit error: {exc}", flush=True)
        db.session.rollback()
    finally:
        db.session.expunge_all()


def run_epss_refresh(app, cve_ids: list) -> None:
    """EPSS refresh worker. Caller must have called EPSSProgressTracker.start_if_idle()."""
    total = len(cve_ids)
    with app.app_context():
        epss = EPSS_DB()
        processed = 0
        try:
            chunks = [cve_ids[i:i + _EPSS_BATCH_SIZE] for i in range(0, total, _EPSS_BATCH_SIZE)]
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
                                    epss_fetched_at=datetime.datetime.now(datetime.timezone.utc),
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


def run_nvd_refresh(app, cve_ids: list) -> None:
    """NVD refresh worker. Caller must have called NVDProgressTracker.start_if_idle()."""
    total = len(cve_ids)
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

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Vulnerability refresh job bodies executed by the operation queue.

NVD, EPSS, GHSA and ENISA EUVD each run on the ``pipeline`` lane so they never
overlap a scan, reproducing the barrier the frontend used to enforce.
"""

from __future__ import annotations

import datetime
import decimal
import os
import re
import time
import urllib.error
import uuid
from typing import Dict, List, Optional, Set, Tuple

from ..extensions import db
from ..helpers.active_scans import active_package_ids_for_scans, active_scan_ids_for_variant
from ..models import Finding, Observation, Scan, Vulnerability
from .epss_db import EPSS_DB
from .euvd_db import EUVD_DB
from .job_context import JobContext
from .nvd_apply import apply_cvss_update, apply_nvd_update
from .nvd_db import NVD_DB
from .nvd_extract import extract_cve_details
from .operation_registry import STATUS_CANCELLED, STATUS_ERROR, registry
from .scc_engine import get_cve_json, get_engine as _get_scc_engine
from .vulnerabilities import VulnerabilitiesController

EPSS_BATCH_SIZE = 100
NVD_COMMIT_EVERY = 50
# Cap prevents burning NVD API rate-limit quota (6 s/CVE without a key).
MAX_CVE_IDS = 1000
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$')
MAX_GHSA_IDS = 500
GHSA_RE = re.compile(r'^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$')
GHSA_COMMIT_EVERY = 20
GHSA_SLEEP_INTERVAL = 1.0
# EUVD annotates from cached ENISA dumps with no per-CVE network call, so it
# commits in larger batches than the network-bound refreshes.
EUVD_COMMIT_EVERY = 200
# Kept under SQLite's 999 bound-parameter limit so the "which of these exist?"
# intersection stays an indexed ``WHERE id IN (...)`` bounded by request size.
DB_LOOKUP_CHUNK = 500


def _nvd_sleep_interval() -> float:
    """Seconds between NVD REST calls: 6 s without an API key, 0.6 s with one."""
    return 0.6 if os.getenv("NVD_API_KEY") else 6.0


def _safe_commit(label: str) -> None:
    """Commit, rolling back on failure, then expunge so the identity map stays bounded."""
    try:
        db.session.commit()
    except Exception as exc:
        print(f"[{label}] commit error: {exc}", flush=True)
        db.session.rollback()
    finally:
        db.session.expunge_all()


def normalise_cve_ids(raw_ids: object) -> List[str]:
    if not isinstance(raw_ids, list):
        return []
    candidates = [c.strip().upper() for c in raw_ids if isinstance(c, str) and c.strip()]
    return [c for c in dict.fromkeys(candidates) if CVE_RE.match(c)]


def normalise_ghsa_ids(raw_ids: object) -> List[str]:
    if not isinstance(raw_ids, list):
        return []
    candidates = [c.strip().upper() for c in raw_ids if isinstance(c, str) and c.strip()]
    return [c for c in dict.fromkeys(candidates) if GHSA_RE.match(c)]


def known_cve_ids(cve_ids: List[str]) -> List[str]:
    """Intersect *cve_ids* with the database in request-bounded chunks."""
    known: Set[str] = set()
    for start in range(0, len(cve_ids), DB_LOOKUP_CHUNK):
        chunk = cve_ids[start:start + DB_LOOKUP_CHUNK]
        rows = db.session.query(Vulnerability.id).filter(Vulnerability.id.in_(chunk)).all()
        known.update(row[0] for row in rows)
    return [cve_id for cve_id in cve_ids if cve_id in known]


def _scoped_vulnerability_ids(variant_ids: List[str]) -> Set[str]:
    """Return vulnerability IDs visible in the active scans for the variants."""
    scan_ids = [
        scan_id
        for variant_id in variant_ids
        for scan_id in active_scan_ids_for_variant(uuid.UUID(variant_id))
    ]
    if not scan_ids:
        return set()

    package_ids = active_package_ids_for_scans(scan_ids)
    query = (
        db.select(Vulnerability.id)
        .join(Finding, Vulnerability.id == Finding.vulnerability_id)
        .join(Observation, Finding.id == Observation.finding_id)
        .join(Scan, Observation.scan_id == Scan.id)
        .where(Observation.scan_id.in_(scan_ids))
    )
    if package_ids:
        query = query.where(db.or_(
            Scan.scan_type.is_(None),
            Scan.scan_type == "sbom",
            Finding.package_id.in_(package_ids),
        ))
    return set(db.session.execute(query.distinct()).scalars().all())


def run_deferred_refresh(ctx: JobContext) -> None:
    """Resolve a wizard refresh target after its preceding scans have finished."""
    ctx.check_cancelled()
    operation = registry.get(ctx.op_id)
    if operation is not None and operation.get("queue_id") is not None:
        preceding_scans = [
            candidate for candidate in registry.snapshot()
            if candidate.get("queue_id") == operation["queue_id"]
            and candidate.get("kind") == "scan"
            and candidate.get("position", 0) < operation.get("position", 0)
        ]
        if any(scan.get("status") in {STATUS_ERROR, STATUS_CANCELLED} for scan in preceding_scans):
            ctx.report(0, 0, "Skipped because an earlier scan did not complete")
            return

    source = str(ctx.options["source"])
    existing_ids = set(ctx.options.get("exclude_ids", []))
    scoped_ids = _scoped_vulnerability_ids(list(ctx.options["variant_ids"]))
    if source == "ghsa":
        ids = normalise_ghsa_ids(sorted(scoped_ids - existing_ids))
    else:
        ids = normalise_cve_ids(sorted(scoped_ids - existing_ids))
        if source == "epss":
            ids = known_cve_ids(ids)
        if source == "nvd" and ctx.options.get("mode") == "api" and len(ids) > MAX_CVE_IDS:
            raise RuntimeError(
                f"nvd refresh accepts at most {MAX_CVE_IDS} identifiers in api mode"
            )

    if not ids:
        ctx.report(0, 0, "No newly discovered vulnerabilities to refresh")
        return

    ctx.options["ids"] = ids
    REFRESH_JOBS[source](ctx)


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

def _refresh_nvd_record(cve_id: str, mode: str, nvd: Optional[NVD_DB]) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    if mode == "api" and nvd is not None:
        status_code, payload = nvd.api_get_cve(cve_id, max_retries=2)
        if status_code != 200 or not payload.get("vulnerabilities"):
            print(f"[bulk NVD refresh] {cve_id}: status={status_code}, skipping", flush=True)
            return
        details = NVD_DB.extract_cve_details(payload["vulnerabilities"][0]["cve"])
    else:
        cve_obj = get_cve_json(cve_id)
        if cve_obj is None:
            print(
                f"[bulk NVD refresh] {cve_id}: not found in local NVD database, skipping",
                flush=True,
            )
            return
        details = extract_cve_details(cve_obj)

    record = db.session.get(Vulnerability, cve_id)
    if record is not None:
        apply_nvd_update(record, details, now)
        apply_cvss_update(record, details, db)


def run_nvd_refresh(ctx: JobContext) -> None:
    """Refresh NVD/CVSS metadata from the local FKIE database or the REST API."""
    cve_ids: List[str] = list(ctx.options["ids"])
    mode = ctx.options.get("mode", "local")
    total = len(cve_ids)
    ctx.report(0, total, f"Starting bulk NVD refresh: 0/{total}")

    nvd: Optional[NVD_DB] = None
    sleep_between = 0.0
    if mode == "api":
        sleep_between = _nvd_sleep_interval()
        nvd = NVD_DB(nvd_api_key=os.getenv("NVD_API_KEY"))
    else:
        # Pre-warm the shared engine once so per-CVE lookups reuse the cache.
        try:
            _get_scc_engine(progress=lambda message: ctx.report(0, total, message))
        except Exception as exc:
            raise RuntimeError(f"Failed to load local NVD database: {exc}")

    done = 0
    for cve_id in cve_ids:
        if ctx.is_cancelled():
            _safe_commit("bulk NVD refresh cancel")
            ctx.check_cancelled()
        try:
            _refresh_nvd_record(cve_id, mode, nvd)
        except Exception as exc:
            print(f"[bulk NVD refresh] error for {cve_id}: {exc}", flush=True)

        done += 1
        ctx.report(done, total, f"NVD refresh: {done}/{total} ({cve_id})")
        if done % NVD_COMMIT_EVERY == 0:
            _safe_commit("bulk NVD refresh")
        if mode == "api" and done < total:
            time.sleep(sleep_between)

    _safe_commit("bulk NVD refresh final")
    ctx.report(total, total, "NVD refresh complete")


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------

def _apply_epss_score(cve_id: str, score: object, now: datetime.datetime) -> None:
    record = db.session.get(Vulnerability, cve_id)
    if record is None:
        return
    new_score = decimal.Decimal(str(score))
    updates: dict = {
        "epss_score": new_score,
        "epss_fetched_at": now,
        "commit": False,
    }
    if record.epss_score is None or record.epss_score != new_score:
        updates["epss_data_updated_at"] = now
    record.update_record(**updates)


def run_epss_refresh(ctx: JobContext) -> None:
    """Refresh EPSS scores in batches of :data:`EPSS_BATCH_SIZE`."""
    cve_ids: List[str] = list(ctx.options["ids"])
    total = len(cve_ids)
    ctx.report(0, total, f"Starting bulk EPSS refresh: 0/{total}")

    epss = EPSS_DB()
    now = datetime.datetime.now(datetime.timezone.utc)
    processed = 0

    for start in range(0, total, EPSS_BATCH_SIZE):
        chunk = cve_ids[start:start + EPSS_BATCH_SIZE]
        if ctx.is_cancelled():
            _safe_commit("bulk EPSS refresh cancel")
            ctx.check_cancelled()

        try:
            results = epss.api_get_epss_batch(chunk)
        except Exception as exc:
            print(f"[bulk EPSS refresh] batch error: {exc}", flush=True)
            processed += len(chunk)
            ctx.report(processed, total, f"EPSS refresh: {processed}/{total}")
            continue

        for cve_id in chunk:
            result = results.get(cve_id)
            if result:
                try:
                    _apply_epss_score(cve_id, result["score"], now)
                except Exception as exc:
                    print(f"[bulk EPSS refresh] error updating {cve_id}: {exc}", flush=True)
            processed += 1

        _safe_commit("bulk EPSS refresh")
        ctx.report(processed, total, f"EPSS refresh: {processed}/{total}")

    ctx.report(total, total, "EPSS refresh complete")


# ---------------------------------------------------------------------------
# GHSA
# ---------------------------------------------------------------------------

def _apply_ghsa_published(ghsa_id: str, now: datetime.datetime) -> None:
    published_at = VulnerabilitiesController._fetch_ghsa_published(ghsa_id)
    if not published_at:
        return
    record = db.session.get(Vulnerability, ghsa_id)
    if record is None:
        return
    try:
        publish_date = datetime.date.fromisoformat(str(published_at)[:10])
    except ValueError:
        publish_date = None

    updates: dict = {"ghsa_fetched_at": now, "commit": False}
    if publish_date is not None:
        updates["publish_date"] = publish_date
        if record.publish_date != publish_date:
            updates["ghsa_data_updated_at"] = now
    record.update_record(**updates)


def run_ghsa_refresh(ctx: JobContext) -> None:
    """Fetch GHSA publication dates, honouring GitHub's rate limit."""
    ghsa_ids: List[str] = list(ctx.options["ids"])
    total = len(ghsa_ids)
    ctx.report(0, total, f"Starting bulk GHSA refresh: 0/{total}")

    now = datetime.datetime.now(datetime.timezone.utc)
    done = 0
    failed = 0

    for ghsa_id in ghsa_ids:
        if ctx.is_cancelled():
            _safe_commit("bulk GHSA refresh cancel")
            ctx.check_cancelled()

        try:
            _apply_ghsa_published(ghsa_id, now)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429):
                _safe_commit("bulk GHSA refresh rate-limited")
                raise RuntimeError(
                    f"GitHub rate limit reached after {done} IDs (HTTP {exc.code})."
                    " Set GITHUB_TOKEN env var to increase quota."
                )
            print(f"[bulk GHSA refresh] error for {ghsa_id}: {exc}", flush=True)
            failed += 1
        except Exception as exc:
            print(f"[bulk GHSA refresh] error for {ghsa_id}: {exc}", flush=True)
            failed += 1

        done += 1
        ctx.report(done, total, f"GHSA refresh: {done}/{total} ({ghsa_id})")
        if done % GHSA_COMMIT_EVERY == 0:
            _safe_commit("bulk GHSA refresh")
        if done < total:
            time.sleep(GHSA_SLEEP_INTERVAL)

    _safe_commit("bulk GHSA refresh final")
    summary = (
        f"GHSA refresh complete ({total} IDs, {failed} failed)"
        if failed else "GHSA refresh complete"
    )
    ctx.report(total, total, summary)


# ---------------------------------------------------------------------------
# ENISA EUVD
# ---------------------------------------------------------------------------

def _apply_euvd(
    cve_id: str,
    full_map: Dict[str, str],
    kev_map: Dict[str, dict],
    now: datetime.datetime,
) -> Tuple[bool, bool]:
    """Annotate one CVE. Returns ``(matched_an_euvd_id, known_exploited)``."""
    record = db.session.get(Vulnerability, cve_id)
    if record is None:
        return False, False

    kev = kev_map.get(cve_id)
    euvd_id = full_map.get(cve_id) or (kev["euvd_id"] if kev else None)

    if euvd_id:
        known_exploited = kev is not None
        record.update_record(
            euvd_id=euvd_id,
            euvd_known_exploited=known_exploited,
            euvd_kev_sources=(kev.get("sources") or []) if kev else [],
            euvd_date_added=kev.get("date_added") if kev else None,
            euvd_fetched_at=now,
            euvd_data_updated_at=now,
            commit=False,
        )
        return True, known_exploited

    had_euvd_data = (
        record.euvd_id is not None
        or record.euvd_known_exploited
        or record.euvd_kev_sources
        or record.euvd_date_added is not None
    )
    if had_euvd_data:
        record.euvd_id = None
        record.euvd_known_exploited = False
        record.euvd_kev_sources = []
        record.euvd_date_added = None
        record.update_record(euvd_fetched_at=now, euvd_data_updated_at=now, commit=False)
    else:
        record.update_record(euvd_fetched_at=now, commit=False)
    return False, False


def run_euvd_refresh(ctx: JobContext) -> None:
    """Annotate CVEs from the cached ENISA EUVD mapping and EU KEV dump."""
    cve_ids: List[str] = list(ctx.options["ids"])
    total = len(cve_ids)
    ctx.report(0, total, "Loading ENISA EUVD CVE mapping…")

    euvd = EUVD_DB()
    full_map = euvd.get_full_mapping()
    if not full_map:
        raise RuntimeError("ENISA EUVD CVE mapping unavailable or empty")
    kev_map = euvd.get_mapping()

    now = datetime.datetime.now(datetime.timezone.utc)
    done = 0
    matched = 0
    kev_matched = 0

    for cve_id in cve_ids:
        if ctx.is_cancelled():
            _safe_commit("bulk EUVD refresh cancel")
            ctx.check_cancelled()

        matched_euvd, known_exploited = _apply_euvd(cve_id, full_map, kev_map, now)
        if matched_euvd:
            matched += 1
        if known_exploited:
            kev_matched += 1

        done += 1
        ctx.report(done, total, f"EUVD refresh: {done}/{total}")
        if done % EUVD_COMMIT_EVERY == 0:
            _safe_commit("bulk EUVD refresh")

    _safe_commit("bulk EUVD refresh final")
    ctx.report(
        total, total,
        f"EUVD enrichment complete ({matched}/{total} matched, "
        f"{kev_matched} known exploitable)",
    )


REFRESH_JOBS = {
    "nvd": run_nvd_refresh,
    "epss": run_epss_refresh,
    "ghsa": run_ghsa_refresh,
    "euvd": run_euvd_refresh,
}

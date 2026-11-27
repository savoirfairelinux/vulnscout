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
from collections.abc import Callable
from typing import Dict, List, Set, Tuple

from ..extensions import db
from ..helpers.refresh_runs import (
    NO_PROVIDER_RECORD, UNSUPPORTED_CVE_IDENTIFIER, add_targets, target_result, target_results, tracked_refresh,
)
from ..helpers.active_scans import active_package_ids_for_scans, active_scan_ids_for_variant
from ..models import Finding, Observation, Scan, Vulnerability
from .epss_db import EPSS_DB
from .euvd_db import EUVD_DB
from .job_context import CancelledError, JobContext, OperationError
from .nvd_apply import apply_cvss_update, apply_nvd_update
from .nvd_db import NVD_DB, parse_nvd_lookup
from .nvd_extract import extract_cve_details
from .operation_registry import STATUS_CANCELLED, STATUS_ERROR, registry
from .scc_engine import get_engine as _get_scc_engine
from .vulnerabilities import VulnerabilitiesController

EPSS_BATCH_SIZE = 100
NVD_COMMIT_EVERY = 50
# Cap prevents burning NVD API rate-limit quota (6 s/CVE without a key).
MAX_CVE_IDS = 1000
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.ASCII)
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
SKIP_BATCH_SIZE = 500


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
        raise
    finally:
        db.session.expunge_all()


def normalise_vulnerability_ids(raw_ids: object) -> List[str]:
    if not isinstance(raw_ids, list):
        return []
    candidates = (c.strip().upper() for c in raw_ids if isinstance(c, str))
    return list(dict.fromkeys(c for c in candidates if c and "\x00" not in c))


def is_cve_id(identifier: str) -> bool:
    return CVE_RE.fullmatch(identifier.strip().upper()) is not None


def normalise_cve_ids(raw_ids: object) -> List[str]:
    return [c for c in normalise_vulnerability_ids(raw_ids) if is_cve_id(c)]


def normalise_ghsa_ids(raw_ids: object) -> List[str]:
    if not isinstance(raw_ids, list):
        return []
    candidates = [c.strip().upper() for c in raw_ids if isinstance(c, str) and c.strip()]
    return [c for c in dict.fromkeys(candidates) if GHSA_RE.match(c)]


def known_vulnerability_ids(ids: List[str]) -> Set[str]:
    """Intersect the supplied IDs with the database in bounded chunks."""
    known: Set[str] = set()
    for start in range(0, len(ids), DB_LOOKUP_CHUNK):
        chunk = ids[start:start + DB_LOOKUP_CHUNK]
        rows = db.session.query(Vulnerability.id).filter(Vulnerability.id.in_(chunk)).all()
        known.update(row[0] for row in rows)
    return known


def _applicable_cve_targets(ctx: JobContext, source: str) -> tuple[list[str], int]:
    ctx.check_cancelled()
    ids: list[str] = ctx.options["ids"]
    applicable: list[str] = []
    skipped = 0
    for start in range(0, len(ids), SKIP_BATCH_SIZE):
        unsupported: list[str] = []
        for identifier in ids[start:start + SKIP_BATCH_SIZE]:
            (applicable if is_cve_id(identifier) else unsupported).append(identifier)
        if unsupported:
            target_results(source, unsupported, "skipped", UNSUPPORTED_CVE_IDENTIFIER)
            _safe_commit(f"bulk {source} refresh unsupported targets")
            skipped += len(unsupported)
        ctx.check_cancelled()
    return applicable, skipped


def _scoped_vulnerability_ids(variant_ids: List[str]) -> Set[str]:
    """Return vulnerability IDs visible in the active scans for the variants."""
    scoped_ids: Set[str] = set()
    for variant_id in variant_ids:
        scan_ids = active_scan_ids_for_variant(uuid.UUID(variant_id))
        if not scan_ids:
            continue
        package_ids = active_package_ids_for_scans(scan_ids)
        query = (
            db.select(Vulnerability.id)
            .join(Finding, Vulnerability.id == Finding.vulnerability_id)
            .join(Observation, Finding.id == Observation.finding_id)
            .join(Scan, Observation.scan_id == Scan.id)
            .where(Observation.scan_id.in_(scan_ids))
            .where(db.or_(
                Scan.scan_type.is_(None),
                Scan.scan_type == "sbom",
                Finding.package_id.in_(package_ids),
            ))
        )
        scoped_ids.update(db.session.execute(query.distinct()).scalars().all())
    return scoped_ids


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
            from ..helpers.refresh_runs import finish_source
            if ctx.queue_id:
                finish_source(ctx.queue_id, str(ctx.options["source"]), "skipped",
                              "Earlier scan failed or was cancelled")
            ctx.report(0, 0, "Skipped because an earlier scan did not complete")
            return

    source = str(ctx.options["source"])
    existing_ids = set(ctx.options.get("exclude_ids", []))
    discovered = sorted(_scoped_vulnerability_ids(list(ctx.options["variant_ids"])) - existing_ids)
    if source == "ghsa":
        ids = normalise_ghsa_ids(discovered)
    elif source == "euvd":
        ids = normalise_cve_ids(discovered)
    else:
        ids = discovered
        if source == "nvd" and ctx.options.get("mode") == "api" and sum(map(is_cve_id, ids)) > MAX_CVE_IDS:
            raise OperationError(
                f"nvd refresh accepts at most {MAX_CVE_IDS} CVE identifiers in api mode"
            )

    if not ids:
        ctx.report(0, 0, "No newly discovered vulnerabilities to refresh")
        return

    ctx.options["ids"] = ids
    if ctx.queue_id:
        add_targets(ctx.queue_id, source, ids)
    REFRESH_JOBS[source](ctx)


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

def _refresh_nvd_record(cve_id: str, lookup: Callable[[str], dict | None]) -> bool:
    cve = lookup(cve_id)
    if cve is None:
        return False
    record = db.session.get(Vulnerability, cve_id)
    if record is None:
        raise ValueError("Vulnerability no longer exists in VulnScout")
    details = extract_cve_details(cve)
    apply_nvd_update(record, details, datetime.datetime.now(datetime.timezone.utc))
    apply_cvss_update(record, details, db)
    return True


def _api_nvd_lookup(nvd: NVD_DB) -> Callable[[str], dict | None]:
    def lookup(cve_id: str) -> dict | None:
        status_code, payload = nvd.api_get_cve(cve_id, max_retries=2)
        if status_code != 200:
            raise ValueError(f"NVD lookup failed (HTTP {status_code})")
        return parse_nvd_lookup(payload, cve_id)
    return lookup


@tracked_refresh("nvd")
def run_nvd_refresh(ctx: JobContext) -> None:
    """Refresh NVD/CVSS metadata from the local FKIE database or the REST API."""
    cve_ids, skipped = _applicable_cve_targets(ctx, "nvd")
    mode = ctx.options.get("mode", "local")
    total = len(cve_ids) + skipped
    ctx.report(skipped, total, f"Starting bulk NVD refresh: {skipped}/{total}")
    if not cve_ids:
        ctx.check_cancelled()
        return

    sleep_between = 0.0
    if mode == "api":
        sleep_between = _nvd_sleep_interval()
        lookup = _api_nvd_lookup(NVD_DB(nvd_api_key=os.getenv("NVD_API_KEY")))
    else:
        # Verify the local snapshot once before looking up the targets.
        try:
            engine = _get_scc_engine(progress=lambda message: ctx.report(skipped, total, message))
            lookup = engine.nvd_snapshot_lookup()
        except Exception as exc:
            raise OperationError("Failed to load local NVD database") from exc

    for done, cve_id in enumerate(cve_ids, start=1):
        if ctx.is_cancelled():
            _safe_commit("bulk NVD refresh cancel")
            ctx.check_cancelled()
        try:
            checked = _refresh_nvd_record(cve_id, lookup)
            target_result("nvd", cve_id, "complete" if checked else NO_PROVIDER_RECORD)
        except Exception as exc:
            target_result("nvd", cve_id, "failed", str(exc)[:500])
            print(f"[bulk NVD refresh] error for {cve_id}: {exc}", flush=True)

        ctx.report(done + skipped, total, f"NVD refresh: {done + skipped}/{total} ({cve_id})")
        if done % NVD_COMMIT_EVERY == 0:
            _safe_commit("bulk NVD refresh")
        if mode == "api" and done < len(cve_ids):
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


@tracked_refresh("epss")
def run_epss_refresh(ctx: JobContext) -> None:
    """Refresh EPSS scores in batches of :data:`EPSS_BATCH_SIZE`."""
    cve_ids, skipped = _applicable_cve_targets(ctx, "epss")
    total = len(cve_ids) + skipped
    ctx.report(skipped, total, f"Starting bulk EPSS refresh: {skipped}/{total}")
    if not cve_ids:
        ctx.check_cancelled()
        return

    epss = EPSS_DB()
    now = datetime.datetime.now(datetime.timezone.utc)
    processed = skipped

    for start in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        chunk = cve_ids[start:start + EPSS_BATCH_SIZE]
        if ctx.is_cancelled():
            _safe_commit("bulk EPSS refresh cancel")
            ctx.check_cancelled()

        try:
            results = epss.api_get_epss_batch(chunk, check_cancelled=ctx.check_cancelled)
        except CancelledError:
            raise
        except Exception as exc:
            ctx.check_cancelled()
            for cve_id in chunk:
                target_result("epss", cve_id, "failed", str(exc)[:500])
            print(f"[bulk EPSS refresh] batch error: {exc}", flush=True)
            _safe_commit("bulk EPSS refresh failed batch")
            processed += len(chunk)
            ctx.report(processed, total, f"EPSS refresh: {processed}/{total}")
            continue

        ctx.check_cancelled()
        for cve_id in chunk:
            if cve_id in results:
                try:
                    _apply_epss_score(cve_id, results[cve_id]["score"], now)
                    target_result("epss", cve_id)
                except Exception as exc:
                    target_result("epss", cve_id, "failed", str(exc)[:500])
                    print(f"[bulk EPSS refresh] error updating {cve_id}: {exc}", flush=True)
            else:
                target_result("epss", cve_id, NO_PROVIDER_RECORD)
            processed += 1

        _safe_commit("bulk EPSS refresh")
        ctx.report(processed, total, f"EPSS refresh: {processed}/{total}")

    ctx.report(total, total, "EPSS refresh complete")


# ---------------------------------------------------------------------------
# GHSA
# ---------------------------------------------------------------------------

def _apply_ghsa_published(ghsa_id: str, now: datetime.datetime) -> bool:
    published_at = VulnerabilitiesController._fetch_ghsa_published(ghsa_id)
    if not published_at:
        return False
    record = db.session.get(Vulnerability, ghsa_id)
    if record is None:
        return False
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
    return publish_date is not None


@tracked_refresh("ghsa")
def run_ghsa_refresh(ctx: JobContext) -> None:
    """Fetch GHSA publication dates, honouring GitHub's rate limit."""
    ghsa_ids: List[str] = list(ctx.options["ids"])
    total = len(ghsa_ids)
    ctx.report(0, total, f"Starting bulk GHSA refresh: 0/{total}")
    if not total:
        return

    now = datetime.datetime.now(datetime.timezone.utc)
    done = 0
    failed = 0

    for ghsa_id in ghsa_ids:
        if ctx.is_cancelled():
            _safe_commit("bulk GHSA refresh cancel")
            ctx.check_cancelled()

        try:
            checked = _apply_ghsa_published(ghsa_id, now)
            target_result("ghsa", ghsa_id, "complete" if checked else "skipped",
                          None if checked else "Provider record unavailable")
        except urllib.error.HTTPError as exc:
            target_result("ghsa", ghsa_id, "failed", str(exc)[:500])
            if exc.code in (403, 429):
                _safe_commit("bulk GHSA refresh rate-limited")
                raise OperationError(
                    f"GitHub rate limit reached after {done} IDs (HTTP {exc.code})."
                    " Set GITHUB_TOKEN env var to increase quota."
                )
            print(f"[bulk GHSA refresh] error for {ghsa_id}: {exc}", flush=True)
            failed += 1
        except Exception as exc:
            target_result("ghsa", ghsa_id, "failed", str(exc)[:500])
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


@tracked_refresh("euvd")
def run_euvd_refresh(ctx: JobContext) -> None:
    """Annotate CVEs from the cached ENISA EUVD mapping and EU KEV dump."""
    cve_ids: List[str] = list(ctx.options["ids"])
    total = len(cve_ids)
    ctx.report(0, total, "Loading ENISA EUVD CVE mapping…")
    if not total:
        return

    euvd = EUVD_DB()
    full_map = euvd.get_full_mapping()
    if not full_map:
        raise OperationError("ENISA EUVD CVE mapping unavailable or empty")
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
        target_result("euvd", cve_id)
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

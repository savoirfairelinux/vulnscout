# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Scan-history diff cache: read, write, recompute, and invalidate.

Stores pre-computed list-view diff badges in the ``scan_diff_cache``
table so that subsequent list requests skip the expensive computation.
"""

import json
import uuid as uuid_module

from sqlalchemy.exc import OperationalError

from ..controllers.scans import ScanController
from ..models.scan import Scan
from ..models.scan_diff_cache import ScanDiffCache
from ..extensions import db

from ._scan_queries import _variant_info
from ._scan_diff import _serialize_list_with_diff


# Fields stored in ScanDiffCache (must match the model columns).
_CACHE_FIELDS = (
    "finding_count", "package_count", "vuln_count", "is_first",
    "findings_added", "findings_removed", "findings_upgraded", "findings_unchanged",
    "packages_added", "packages_removed", "packages_upgraded", "packages_unchanged",
    "vulns_added", "vulns_removed", "vulns_unchanged",
    "newly_detected_findings", "newly_detected_vulns",
    "branch_finding_count", "branch_vuln_count", "branch_package_count",
    "global_finding_count", "global_vuln_count", "global_package_count",
)


def _ensure_cache_table() -> None:
    """Create the scan_diff_cache table if it doesn't exist.

    This handles the case where the table was manually dropped or
    the database was migrated without the cache table.
    """
    ScanDiffCache.__table__.create(db.engine, checkfirst=True)  # type: ignore[attr-defined]


def _store_cache(results: list[dict]) -> None:
    """Upsert computed diff data into scan_diff_cache for each result dict."""
    if not results:
        return
    scan_ids = [uuid_module.UUID(r["id"]) for r in results]
    try:
        # Delete existing cache rows for these scans
        db.session.execute(
            db.delete(ScanDiffCache).where(ScanDiffCache.scan_id.in_(scan_ids))
        )
    except OperationalError:
        db.session.rollback()
        _ensure_cache_table()
    for r in results:
        row = ScanDiffCache(scan_id=uuid_module.UUID(r["id"]))
        for field in _CACHE_FIELDS:
            setattr(row, field, r.get(field))
        formats = r.get("formats")
        row.formats_json = json.dumps(formats) if formats is not None else None
        db.session.add(row)
    db.session.commit()


def _read_cache(scans: list[Scan]) -> list[dict] | None:
    """Try to build the list-view response entirely from cache.

    Returns the list of result dicts (same shape as _serialize_list_with_diff)
    if every scan has a cache entry.  Returns ``None`` on any cache miss so
    the caller can fall back to full computation.
    """
    if not scans:
        return []
    scan_ids = [s.id for s in scans]
    try:
        rows = db.session.execute(
            db.select(ScanDiffCache).where(ScanDiffCache.scan_id.in_(scan_ids))
        ).scalars().all()
    except OperationalError:
        # Table is missing — recreate it and signal a cache miss so the
        # caller recomputes from source data and populates the new table.
        db.session.rollback()
        _ensure_cache_table()
        return None
    cache_map = {r.scan_id: r for r in rows}
    if len(cache_map) != len(scan_ids):
        return None  # cache miss
    # Build variant info for display names
    variant_map = _variant_info(list({s.variant_id for s in scans}))
    result = []
    for scan in scans:
        c = cache_map[scan.id]
        base = ScanController.serialize(scan)
        variant_name, project_name = variant_map.get(scan.variant_id, (None, None))
        base["variant_name"] = variant_name
        base["project_name"] = project_name
        for field in _CACHE_FIELDS:
            base[field] = getattr(c, field)
        base["formats"] = json.loads(c.formats_json) if c.formats_json else []
        result.append(base)
    return result


def recompute_variant_cache(variant_id) -> None:
    """Re-compute and store the scan-history diff cache for *variant_id*.

    Call this after any mutation that affects scan history (SBOM upload,
    tool scan completion, scan deletion).
    """
    scans = Scan.get_by_variant_id(variant_id)
    if not scans:
        # No scans left — clear any stale cache rows
        try:
            db.session.execute(
                db.delete(ScanDiffCache).where(
                    ScanDiffCache.scan_id.in_(
                        db.select(Scan.id).where(Scan.variant_id == variant_id)
                    )
                )
            )
            db.session.commit()
        except OperationalError:
            db.session.rollback()
            _ensure_cache_table()
        return
    results = _serialize_list_with_diff(scans)
    _store_cache(results)


def invalidate_variant_cache(variant_id) -> None:
    """Delete cached scan-history data for *variant_id*.

    The cache will be lazily rebuilt the next time a list endpoint is hit.
    Use this when the calling context cannot easily recompute (e.g. a
    background thread that spawns sub-processes without direct DB access).
    """
    try:
        scan_ids = [
            row[0] for row in db.session.execute(
                db.select(Scan.id).where(Scan.variant_id == variant_id)
            ).all()
        ]
        if scan_ids:
            db.session.execute(
                db.delete(ScanDiffCache).where(ScanDiffCache.scan_id.in_(scan_ids))
            )
            db.session.commit()
    except OperationalError:
        db.session.rollback()
        _ensure_cache_table()

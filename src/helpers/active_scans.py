#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Centralised helpers for determining which scans are "active".

Every route that needs to scope its data to the current view (vulns,
packages, findings, …) should use these functions instead of rolling
their own logic.  This avoids subtle count differences between tabs.

Active-scan strategy
--------------------
For a given variant the *active set* is:

* The **latest SBOM scan**, plus
* The **latest tool scan per source** (nvd, osv, …).

This ensures that:
  • Running an OSV enrichment doesn't hide NVD results.
  • The count of vulnerabilities / packages is consistent across all
    pages (Metrics, Vulnerabilities, Packages, Scan History).

When querying by project the same logic is applied to *every* variant
in the project.

Active-package filtering
------------------------
Tool scans can reference packages that are no longer present in the
latest SBOM.  ``active_package_ids_for_scans()`` returns the set of
package IDs from the SBOM scans in the active set so that callers can
optionally restrict tool-scan results to those packages.
"""

from __future__ import annotations

import uuid

from ..extensions import db
from ..models.scan import Scan
from ..models.variant import Variant
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage


# ------------------------------------------------------------------
# Active scan IDs
# ------------------------------------------------------------------

def active_scan_ids_for_variant(variant_uuid: uuid.UUID) -> list:
    """Return the active Scan IDs for *variant_uuid*.

    ``[latest_sbom, latest_tool:nvd, latest_tool:osv, …]``
    """
    rows = db.session.execute(
        db.select(Scan.id, Scan.scan_type, Scan.scan_source)
        .where(Scan.variant_id == variant_uuid)
        .order_by(Scan.timestamp.desc())
    ).all()
    ids: list = []
    seen_keys: set = set()  # "sbom" or "tool:<source>"
    for scan_id, scan_type, scan_source in rows:
        st = scan_type or "sbom"
        key = f"tool:{scan_source}" if st == "tool" else "sbom"
        if key not in seen_keys:
            seen_keys.add(key)
            ids.append(scan_id)
    return ids


def active_scan_ids_for_project(project_uuid: uuid.UUID) -> list:
    """Return the active Scan IDs for every variant in *project_uuid*."""
    rows = db.session.execute(
        db.select(Scan.id, Scan.variant_id, Scan.scan_type, Scan.scan_source, Scan.timestamp)
        .join(Variant, Scan.variant_id == Variant.id)
        .where(Variant.project_id == project_uuid)
        .order_by(Scan.variant_id, Scan.timestamp.desc())
    ).all()
    ids: list = []
    seen: dict = {}  # variant_id -> set of keys already picked
    for scan_id, vid, scan_type, scan_source, _ts in rows:
        st = scan_type or "sbom"
        key = f"tool:{scan_source}" if st == "tool" else "sbom"
        variant_seen = seen.setdefault(vid, set())
        if key not in variant_seen:
            variant_seen.add(key)
            ids.append(scan_id)
    return ids


# ------------------------------------------------------------------
# SBOM-only scan IDs (for package queries)
# ------------------------------------------------------------------

def active_sbom_scan_ids_for_variant(variant_uuid: uuid.UUID) -> list:
    """Return only the SBOM-type scan ID(s) from the active set for *variant_uuid*.

    Packages come exclusively from SBOM scans (tool scans don't create
    SBOMDocuments), so the packages route should use this instead of
    ``active_scan_ids_for_variant``.
    """
    rows = db.session.execute(
        db.select(Scan.id)
        .where(Scan.variant_id == variant_uuid)
        .where(db.or_(Scan.scan_type == "sbom", Scan.scan_type.is_(None)))
        .order_by(Scan.timestamp.desc())
        .limit(1)
    ).all()
    return [r[0] for r in rows]


def active_sbom_scan_ids_for_project(project_uuid: uuid.UUID) -> list:
    """Return only the SBOM-type scan ID(s) from the active set for *project_uuid*.

    One latest SBOM scan per variant.
    """
    rows = db.session.execute(
        db.select(Scan.id, Scan.variant_id, Scan.timestamp)
        .join(Variant, Scan.variant_id == Variant.id)
        .where(Variant.project_id == project_uuid)
        .where(db.or_(Scan.scan_type == "sbom", Scan.scan_type.is_(None)))
        .order_by(Scan.variant_id, Scan.timestamp.desc())
    ).all()
    ids: list = []
    seen_variants: set = set()
    for scan_id, vid, _ts in rows:
        if vid not in seen_variants:
            seen_variants.add(vid)
            ids.append(scan_id)
    return ids


# ------------------------------------------------------------------
# Active package IDs (from SBOM scans only)
# ------------------------------------------------------------------

def active_package_ids_for_scans(scan_ids: list) -> set:
    """Return the set of package IDs present in the SBOM documents of *scan_ids*.

    Packages listed by SBOM scans form the "active" package set.
    Tool-scan findings for packages outside this set are stale
    (the package was upgraded or removed) and should be excluded.
    """
    if not scan_ids:
        return set()
    # Filter to SBOM-type scans only
    sbom_scan_ids = [
        sid for (sid,) in db.session.execute(
            db.select(Scan.id)
            .where(Scan.id.in_(scan_ids))
            .where(
                db.or_(Scan.scan_type == "sbom", Scan.scan_type.is_(None))
            )
        ).all()
    ]
    if not sbom_scan_ids:
        return set()
    rows = db.session.execute(
        db.select(SBOMPackage.package_id)
        .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
        .where(SBOMDocument.scan_id.in_(sbom_scan_ids))
        .distinct()
    ).all()
    return {r[0] for r in rows}

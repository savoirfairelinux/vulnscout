#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Low-level DB query helpers and serialisation primitives for scan routes.

All functions are *stateless* — they run batch queries and return plain
dicts/sets without any diff or comparison logic.
"""

import uuid as uuid_module

from sqlalchemy.orm import selectinload

from ..models.scan import Scan
from ..models.observation import Observation
from ..models.finding import Finding
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
from ..models.package import Package
from ..models.variant import Variant
from ..models.project import Project
from ..extensions import db


# ---------------------------------------------------------------------------
# Batch query — findings
# ---------------------------------------------------------------------------

def _findings_by_scan_ids(scan_ids: list) -> dict:
    """Return {scan_id: set(finding_id)} using a single DB query."""
    if not scan_ids:
        return {}
    rows = db.session.execute(
        db.select(Observation.scan_id, Observation.finding_id)
        .where(Observation.scan_id.in_(scan_ids))
    ).all()
    result: dict = {}
    for sid, fid in rows:
        result.setdefault(sid, set()).add(fid)
    return result


# ---------------------------------------------------------------------------
# Batch query — vulnerabilities
# ---------------------------------------------------------------------------

def _vulns_by_scan_ids(scan_ids: list) -> dict:
    """Return {scan_id: set(vulnerability_id)} via Observation -> Finding join."""
    if not scan_ids:
        return {}
    rows = db.session.execute(
        db.select(Observation.scan_id, Finding.vulnerability_id)
        .join(Finding, Finding.id == Observation.finding_id)
        .where(Observation.scan_id.in_(scan_ids))
    ).all()
    result: dict = {}
    for sid, vid in rows:
        result.setdefault(sid, set()).add(vid)
    return result


# ---------------------------------------------------------------------------
# Batch query — packages
# ---------------------------------------------------------------------------

def _packages_by_scan_ids(scan_ids: list) -> dict:
    """Return {scan_id: set(package_id)} via sbom_documents -> sbom_packages, in one query."""
    if not scan_ids:
        return {}
    rows = db.session.execute(
        db.select(SBOMDocument.scan_id, SBOMPackage.package_id)
        .join(SBOMPackage, SBOMPackage.sbom_document_id == SBOMDocument.id)
        .where(SBOMDocument.scan_id.in_(scan_ids))
    ).all()
    result: dict = {}
    for sid, pid in rows:
        result.setdefault(sid, set()).add(pid)
    return result


def _package_rows(package_ids: set) -> dict:
    """Return {package_id: Package} for the given id set, in one query."""
    if not package_ids:
        return {}
    pkgs = db.session.execute(
        db.select(Package).where(Package.id.in_(package_ids))
    ).scalars().all()
    return {p.id: p for p in pkgs}


def _pkg_to_dict(pkg: Package) -> dict:
    return {
        "package_id": str(pkg.id),
        "package_name": pkg.name or "unknown",
        "package_version": pkg.version or "",
    }


# ---------------------------------------------------------------------------
# Batch query — variant / project names
# ---------------------------------------------------------------------------

def _variant_info(variant_ids: list) -> dict:
    """Return {variant_id: (variant_name, project_name)} in two queries."""
    if not variant_ids:
        return {}
    variants = db.session.execute(
        db.select(Variant).where(Variant.id.in_(variant_ids))
    ).scalars().all()
    project_ids = list({v.project_id for v in variants})
    projects = db.session.execute(
        db.select(Project).where(Project.id.in_(project_ids))
    ).scalars().all()
    project_map = {p.id: p.name for p in projects}
    return {
        v.id: (v.name, project_map.get(v.project_id))
        for v in variants
    }


# ---------------------------------------------------------------------------
# Eager-loading helpers
# ---------------------------------------------------------------------------

def _load_scan_with_findings(scan_id: uuid_module.UUID) -> Scan | None:
    """Load a scan with all observations -> finding -> package eagerly."""
    return db.session.execute(
        db.select(Scan)
        .options(
            selectinload(Scan.observations)  # type: ignore[arg-type]
            .selectinload(Observation.finding)  # type: ignore[arg-type]
            .selectinload(Finding.package)
        )
        .where(Scan.id == scan_id)
    ).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Observation / finding serialisation
# ---------------------------------------------------------------------------

def _obs_to_dict(obs: Observation, origin: str = "Imported SBOM") -> dict:
    f = obs.finding
    pkg = f.package
    return {
        "finding_id": str(f.id),
        "package_name": pkg.name if pkg else "unknown",
        "package_version": pkg.version if pkg else "",
        "package_id": str(f.package_id),
        "vulnerability_id": f.vulnerability_id,
        "origin": origin,
    }


_TOOL_SOURCE_LABELS: dict = {
    "grype": "Grype Scan",
    "nvd": "NVD CPE Scan",
    "osv": "OSV Scan",
}


def _origin_for_scan(scan) -> str:
    """Return a human-readable origin label for a scan."""
    if (scan.scan_type or "sbom") == "tool":
        return _TOOL_SOURCE_LABELS.get(scan.scan_source or "", "Vulnerability Scan")
    return "Imported SBOM"


# ---------------------------------------------------------------------------
# Batch query — assessments per scan
# ---------------------------------------------------------------------------


def _assessment_rows_for_scans(scan_ids: list):
    """Shared query returning assessment rows linked to the given scan IDs.

    Returns a list of tuples:
        (scan_id, assessment_id, assessment_timestamp,
         status, simplified_status, justification, impact_statement,
         status_notes, vulnerability_id, origin)

    The query logic:
      - Start FROM observation
      - JOIN finding ON finding.id = observation.finding_id
      - JOIN assessment ON assessment.finding_id = finding.id
      - JOIN scan ON scan.id = observation.scan_id
      - WHERE observation.scan_id IN (scan_ids)
            AND assessment.variant_id = scan.variant_id
    """
    from ..models.assessment import Assessment

    if not scan_ids:
        return []

    return db.session.execute(
        db.select(
            Observation.scan_id,
            Assessment.id,
            Assessment.timestamp,
            Assessment.status,
            Assessment.simplified_status,
            Assessment.justification,
            Assessment.impact_statement,
            Assessment.status_notes,
            Finding.vulnerability_id,
            Assessment.origin,
        )
        .select_from(Observation)
        .join(Finding, Finding.id == Observation.finding_id)
        .join(Assessment, Assessment.finding_id == Finding.id)
        .join(Scan, Scan.id == Observation.scan_id)
        .where(
            Observation.scan_id.in_(scan_ids),
            Assessment.variant_id == Scan.variant_id,
        )
    ).all()


def _assessments_by_scan(scans: list[Scan]) -> dict:
    """Return {scan_id: {"total": N, "added": N, "unchanged": N}} for each scan.

    An assessment is counted for a scan if:
      - Its finding_id matches an observation in that scan
      - Its variant_id matches the scan's variant_id

    An assessment is "added" (new) if it was imported from the SBOM
    (origin == "sbom") and its timestamp >= the scan's timestamp AND
    < the next scan's timestamp (same variant).

    Total counts assessments that existed up to (but not including) the
    next scan's timestamp. This ensures that:
    - Assessments imported during this scan (ats slightly > scan_ts) are included
    - Assessments imported by a later scan are excluded
    """
    if not scans:
        return {}

    scan_ids = [s.id for s in scans]
    scan_map = {s.id: s for s in scans}

    # Determine next_scan_ts for each scan (next scan of same variant by timestamp)
    by_variant: dict = {}  # variant_id -> [scans sorted by timestamp]
    for s in scans:
        by_variant.setdefault(s.variant_id, []).append(s)
    for v_scans in by_variant.values():
        v_scans.sort(key=lambda s: s.timestamp)

    next_ts_map: dict = {}  # scan_id -> next_scan_timestamp or None
    for v_scans in by_variant.values():
        for i, s in enumerate(v_scans):
            if i + 1 < len(v_scans):
                next_ts_map[s.id] = v_scans[i + 1].timestamp
            else:
                next_ts_map[s.id] = None  # last scan — no upper bound

    rows = _assessment_rows_for_scans(scan_ids)

    # Deduplicate: same assessment may appear multiple times if a finding
    # belongs to multiple observations (shouldn't happen, but be safe).
    # Group by scan_id, then deduplicate assessment_id.
    # Exclude custom (manually-created) assessments — only automated
    # sources (sbom, grype, osv, nvd, etc.) are shown in scan history.
    per_scan: dict = {}  # scan_id -> {assess_id: timestamp}
    for row in rows:
        sid, aid, ats, origin = row[0], row[1], row[2], row[9]
        if origin == "custom":
            continue  # skip manually-created assessments
        per_scan.setdefault(sid, {})[aid] = ats

    result: dict = {}
    for sid, assessments in per_scan.items():
        scan_ts = scan_map[sid].timestamp
        next_scan_ts = next_ts_map.get(sid)

        # Total = assessments created before the next scan started.
        # NULL-timestamp assessments are always included (they exist but
        # lack a recorded creation time).
        if next_scan_ts is not None:
            total = sum(
                1 for ats in assessments.values()
                if ats is None or ats < next_scan_ts
            )
        else:
            total = len(assessments)

        # Added = imported by THIS scan (ats in [scan_ts, next_scan_ts))
        # NULL timestamp → can't classify as "added", so excluded here.
        if next_scan_ts is not None:
            added = sum(
                1 for ats in assessments.values()
                if ats is not None and ats >= scan_ts and ats < next_scan_ts
            )
        else:
            added = sum(
                1 for ats in assessments.values()
                if ats is not None and ats >= scan_ts
            )

        result[sid] = {
            "total": total,
            "added": added,
            "unchanged": total - added,
            "removed": 0,  # computed below after all scans are processed
        }

    # Compute "removed" — assessments present in previous scan but absent
    # in this scan (e.g. because the associated finding/vulnerability was
    # removed). Compare assessment ID sets between consecutive scans.
    # Build prev_scan_map per (variant, scan_type, scan_source)
    by_key: dict = {}
    for s in scans:
        stype = s.scan_type or "sbom"
        source = s.scan_source if stype == "tool" else None
        key = (s.variant_id, stype, source)
        by_key.setdefault(key, []).append(s)

    for group_scans in by_key.values():
        group_scans.sort(key=lambda s: s.timestamp)
        for i, s in enumerate(group_scans):
            if i == 0:
                continue  # first scan — no previous to compare
            prev_s = group_scans[i - 1]
            curr_ids = set(per_scan.get(s.id, {}).keys())
            prev_ids = set(per_scan.get(prev_s.id, {}).keys())
            removed = len(prev_ids - curr_ids)
            if s.id in result:
                result[s.id]["removed"] = removed

    # Fill in scans with no assessments
    for s in scans:
        if s.id not in result:
            result[s.id] = {"total": 0, "added": 0, "unchanged": 0, "removed": 0}

    return result


def _assessments_detail_for_scan(scan: Scan, next_scan_ts=None, prev_scan=None) -> dict:
    """Return assessment details AND counts for a single scan.

    Uses the SAME shared query (_assessment_rows_for_scans) as
    _assessments_by_scan to guarantee identical results.

    *next_scan_ts* is the timestamp of the next scan for the same variant.
    If None, no upper bound is applied (last scan — current state).

    *prev_scan* is the previous scan (same type/source). Used to compute
    removed and unchanged assessment detail arrays.

    Returns:
        {
            "added": [<AssessmentDiffEntry>, ...],
            "removed": [<AssessmentDiffEntry>, ...],
            "unchanged": [<AssessmentDiffEntry>, ...],
            "total": int,
            "added_count": int,
            "removed_count": int,
            "unchanged_count": int,
        }
    """
    rows = _assessment_rows_for_scans([scan.id])

    # Deduplicate by assessment id (row[1])
    # Exclude custom (manually-created) assessments — only automated
    # sources (sbom, grype, osv, nvd, etc.) are shown in scan diff.
    seen: dict = {}
    for row in rows:
        aid = row[1]
        origin = row[9]
        if origin == "custom":
            continue
        if aid not in seen:
            seen[aid] = row

    scan_ts = scan.timestamp
    added = []
    unchanged_list = []

    for row in seen.values():
        ats = row[2]  # assessment timestamp
        entry = {
            "vulnerability_id": row[8],
            "status": row[3] or "under_investigation",
            "simplified_status": row[4] or "Pending Assessment",
            "justification": row[5] or "",
            "impact_statement": row[6] or "",
            "status_notes": row[7] or "",
        }
        # "Added" = created during this scan's window [scan_ts, next_scan_ts)
        is_added = False
        if ats is not None and ats >= scan_ts:
            if next_scan_ts is None or ats < next_scan_ts:
                is_added = True
                added.append(entry)

        # "In total" = existed before next scan (NULL timestamps always count)
        in_total = False
        if next_scan_ts is not None:
            in_total = (ats is None or ats < next_scan_ts)
        else:
            in_total = True

        if in_total and not is_added:
            unchanged_list.append(entry)

    # Sort by vulnerability_id for stable output
    added.sort(key=lambda e: e["vulnerability_id"])
    unchanged_list.sort(key=lambda e: e["vulnerability_id"])

    # Total
    if next_scan_ts is not None:
        total = sum(1 for row in seen.values() if row[2] is None or row[2] < next_scan_ts)
    else:
        total = len(seen)

    # Removed = assessments in previous scan but not in this scan
    removed_list = []
    if prev_scan is not None:
        prev_rows = _assessment_rows_for_scans([prev_scan.id])
        prev_seen: dict = {}
        for row in prev_rows:
            aid = row[1]
            origin = row[9]
            if origin == "custom":
                continue
            if aid not in prev_seen:
                prev_seen[aid] = row

        curr_ids = set(seen.keys())
        for aid, row in prev_seen.items():
            if aid not in curr_ids:
                removed_list.append({
                    "vulnerability_id": row[8],
                    "status": row[3] or "under_investigation",
                    "simplified_status": row[4] or "Pending Assessment",
                    "justification": row[5] or "",
                    "impact_statement": row[6] or "",
                    "status_notes": row[7] or "",
                })
        removed_list.sort(key=lambda e: e["vulnerability_id"])

    added_count = len(added)
    removed_count = len(removed_list)
    unchanged_count = len(unchanged_list)
    return {
        "added": added,
        "removed": removed_list,
        "unchanged_list": unchanged_list,
        "total": total,
        "added_count": added_count,
        "removed_count": removed_count,
        "unchanged_count": unchanged_count,
    }

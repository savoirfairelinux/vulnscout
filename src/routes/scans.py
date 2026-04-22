#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import uuid as uuid_module

from flask import jsonify
from sqlalchemy.orm import selectinload

from ..controllers.scans import ScanController
from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController
from ..models.scan import Scan
from ..models.scan_diff_cache import ScanDiffCache
from ..models.observation import Observation
from ..models.finding import Finding
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
from ..models.package import Package
from ..models.variant import Variant
from ..models.project import Project
from ..extensions import db


# ---------------------------------------------------------------------------
# Helpers — findings
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
# Helpers — vulnerabilities
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
# Helpers — packages
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


def _classify_package_changes(added_pkg_ids: set, removed_pkg_ids: set, pkg_lookup: dict) -> tuple:
    """Classify package changes into truly-added, truly-removed, and upgraded.

    A package is "upgraded" when the same package name appears in both the
    added and removed sets with different versions.

    Returns (truly_added_ids, truly_removed_ids, upgraded_pairs) where
    upgraded_pairs is a list of (old_pkg, new_pkg) Package dicts.
    """
    added_by_name: dict = {}
    for pid in added_pkg_ids:
        pkg = pkg_lookup.get(pid)
        if pkg:
            added_by_name.setdefault(pkg.name or "unknown", []).append(pkg)

    removed_by_name: dict = {}
    for pid in removed_pkg_ids:
        pkg = pkg_lookup.get(pid)
        if pkg:
            removed_by_name.setdefault(pkg.name or "unknown", []).append(pkg)

    upgraded_pairs = []
    matched_added_ids: set = set()
    matched_removed_ids: set = set()

    for name in set(added_by_name) & set(removed_by_name):
        new_pkgs = list(added_by_name[name])
        old_pkgs = list(removed_by_name[name])
        # Pair highest versions first so the closest predecessor matches
        new_pkgs.sort(key=lambda p: p.version or "", reverse=True)
        old_pkgs.sort(key=lambda p: p.version or "", reverse=True)
        for i in range(min(len(new_pkgs), len(old_pkgs))):
            upgraded_pairs.append((old_pkgs[i], new_pkgs[i]))
            matched_added_ids.add(new_pkgs[i].id)
            matched_removed_ids.add(old_pkgs[i].id)

    truly_added_ids = added_pkg_ids - matched_added_ids
    truly_removed_ids = removed_pkg_ids - matched_removed_ids
    return truly_added_ids, truly_removed_ids, upgraded_pairs


# ---------------------------------------------------------------------------
# Helpers — variant / project names
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
# Helpers — scan ordering
# ---------------------------------------------------------------------------

def _prev_scan_map(scans: list[Scan]) -> dict:
    """Return {scan.id: previous_scan_or_None} grouped by (variant, scan_type, scan_source), ordered by timestamp.

    Tool scans are further grouped by scan_source so that Grype scans only
    compare against previous Grype scans, NVD against NVD, etc.
    SBOM scans are only compared against previous SBOM scans.
    """
    by_key: dict = {}
    for s in scans:
        stype = s.scan_type or "sbom"
        source = s.scan_source if stype == "tool" else None
        key = (s.variant_id, stype, source)
        by_key.setdefault(key, []).append(s)
    mapping: dict = {}
    for group_scans in by_key.values():
        for i, s in enumerate(group_scans):
            mapping[s.id] = group_scans[i - 1] if i > 0 else None
    return mapping


# ---------------------------------------------------------------------------
# Helpers — serialisation for list view
# ---------------------------------------------------------------------------

def _latest_sbom_scan_per_variant(scans: list[Scan]) -> dict:
    """Return {variant_id: latest_sbom_Scan} from the given scan list.

    Only considers scans with scan_type == 'sbom' (or NULL which defaults to
    'sbom').  For each variant, keeps the scan with the latest timestamp.
    """
    latest: dict = {}
    for s in scans:
        if (s.scan_type or "sbom") != "sbom":
            continue
        prev = latest.get(s.variant_id)
        if prev is None or s.timestamp > prev.timestamp:
            latest[s.variant_id] = s
    return latest


def _sbom_scans_by_variant(scans: list[Scan]) -> dict:
    """Return {variant_id: [sbom_scan, …]} ordered by timestamp ascending.

    Used to look up which SBOM scan was active at any point in time.
    """
    by_variant: dict = {}
    for s in scans:
        if (s.scan_type or "sbom") != "sbom":
            continue
        by_variant.setdefault(s.variant_id, []).append(s)
    # scans are already chronological but be safe
    for v in by_variant.values():
        v.sort(key=lambda s: s.timestamp)
    return by_variant


def _sbom_active_at(sbom_list: list, timestamp) -> "Scan | None":
    """Return the most recent SBOM scan whose timestamp <= *timestamp*.

    *sbom_list* must be sorted ascending by timestamp.
    """
    result = None
    for s in sbom_list:
        if s.timestamp <= timestamp:
            result = s
        else:
            break
    return result


def _serialize_list_with_diff(scans: list[Scan]) -> list[dict]:
    if not scans:
        return []

    scan_ids = [s.id for s in scans]
    findings_map = _findings_by_scan_ids(scan_ids)
    packages_map = _packages_by_scan_ids(scan_ids)
    vulns_map = _vulns_by_scan_ids(scan_ids)
    prev_map = _prev_scan_map(scans)
    variant_map = _variant_info(list({s.variant_id for s in scans}))

    # For tool scans: determine the SBOM baseline that was active at the
    # time of each tool scan.  This ensures that historical tool scan
    # entries show the "newly detected" counts as they were at scan time,
    # not re-calculated against a later SBOM import.
    sbom_lists = _sbom_scans_by_variant(scans)
    # We may need findings/vulns for SBOM scans that aren't already in our maps
    # (they already are because all scans in the list are fetched).

    # First pass: compute package diffs and collect all finding IDs that need
    # package-level info for upgrade classification.
    scan_data = []
    all_fids_needing_lookup: set = set()
    all_pkg_ids_needing_lookup: set = set()

    for scan in scans:
        curr_f = findings_map.get(scan.id, set())
        curr_p = packages_map.get(scan.id, set())
        curr_v = vulns_map.get(scan.id, set())
        prev = prev_map.get(scan.id)
        is_tool_scan = (scan.scan_type or "sbom") == "tool"

        entry = {
            "scan": scan,
            "curr_f": curr_f, "curr_p": curr_p, "curr_v": curr_v,
            "prev": prev,
            "upgraded_pairs": [],
            "raw_added_f": set(), "raw_removed_f": set(),
        }

        # Skip package-level diff for tool scans (e.g. Grype) since they only
        # report the subset of packages that have vulnerabilities.
        if prev is not None and not is_tool_scan:
            prev_p = packages_map.get(prev.id, set())
            raw_added_p = curr_p - prev_p
            raw_removed_p = prev_p - curr_p
            if raw_added_p or raw_removed_p:
                entry["_raw_added_p"] = raw_added_p
                entry["_raw_removed_p"] = raw_removed_p
                all_pkg_ids_needing_lookup |= raw_added_p | raw_removed_p

        scan_data.append(entry)

    # Single batch query: package_id -> Package for all changed packages
    all_pkg_lookup = _package_rows(all_pkg_ids_needing_lookup)

    # Second mini-pass: classify packages and collect finding IDs
    for entry in scan_data:
        raw_added_p = entry.pop("_raw_added_p", None)
        if raw_added_p is None:
            continue
        raw_removed_p = entry.pop("_raw_removed_p", set())
        truly_added, truly_removed, upgraded = _classify_package_changes(
            raw_added_p, raw_removed_p, all_pkg_lookup
        )
        entry["truly_added_p"] = len(truly_added)
        entry["truly_removed_p"] = len(truly_removed)
        entry["truly_removed_ids"] = truly_removed
        entry["upgraded_pairs"] = upgraded

        if upgraded:
            scan = entry["scan"]
            prev = entry["prev"]
            curr_f = entry["curr_f"]
            prev_f = findings_map.get(prev.id, set())
            raw_added_f = curr_f - prev_f
            raw_removed_f = prev_f - curr_f
            entry["raw_added_f"] = raw_added_f
            entry["raw_removed_f"] = raw_removed_f
            all_fids_needing_lookup |= raw_added_f | raw_removed_f

    # Single batch query: finding_id -> (package_id, vulnerability_id)
    # Include all tool-scan finding IDs so we can check which ones belong
    # to removed packages when computing SBOM diff counts.
    tool_scan_fids: set = set()
    for scan in scans:
        if (scan.scan_type or "sbom") == "tool":
            tool_scan_fids |= findings_map.get(scan.id, set())
    all_fids_needing_lookup |= tool_scan_fids

    fid_to_info: dict = {}
    if all_fids_needing_lookup:
        rows = db.session.execute(
            db.select(Finding.id, Finding.package_id, Finding.vulnerability_id)
            .where(Finding.id.in_(all_fids_needing_lookup))
        ).all()
        fid_to_info = {r[0]: (r[1], r[2]) for r in rows}

    # Pre-build reverse index: tool-scan finding → package_id
    # so scan-result computation can filter by package set in O(1).
    tool_fid_to_pkg: dict = {}  # finding_id → package_id (tool scans only)
    for fid in tool_scan_fids:
        info = fid_to_info.get(fid)
        if info:
            tool_fid_to_pkg[fid] = info[0]
    # Second pass: build result dicts
    # Track latest tool-scan findings/vulns per (variant, source) as we
    # iterate in chronological order so we can compute the "global" result
    # (SBOM ∪ all latest sources) at each point in time.
    # Also track the SBOM baseline that was active at each tool scan's
    # timestamp so historical counts stay stable.
    running_src_findings: dict = {}  # (variant_id, source) -> set
    running_src_vulns: dict = {}     # (variant_id, source) -> set
    # Cache: sbom_scan.id -> (findings_set, vulns_set)
    _sbom_cache: dict = {}
    result = []
    for entry in scan_data:
        scan = entry["scan"]
        base = ScanController.serialize(scan)
        variant_name, project_name = variant_map.get(scan.variant_id, (None, None))
        base["variant_name"] = variant_name
        base["project_name"] = project_name
        curr_f = entry["curr_f"]
        curr_v = entry["curr_v"]
        prev = entry["prev"]

        base["finding_count"] = len(curr_f)
        base["package_count"] = len(entry["curr_p"])
        base["vuln_count"] = len(curr_v)

        is_tool_scan = (scan.scan_type or "sbom") == "tool"

        if is_tool_scan:
            # ---- Tool scan: diff against the GLOBAL state ----
            # Use the SBOM baseline that was active at THIS scan's timestamp
            # so that a later SBOM import doesn't retroactively change the
            # "newly detected" counts of earlier tool scans.
            sbom_at_time = _sbom_active_at(
                sbom_lists.get(scan.variant_id, []),
                scan.timestamp,
            )
            if sbom_at_time and sbom_at_time.id not in _sbom_cache:
                _sbom_cache[sbom_at_time.id] = (
                    findings_map.get(sbom_at_time.id, set()),
                    vulns_map.get(sbom_at_time.id, set()),
                )
            if sbom_at_time:
                baseline_f, baseline_v = _sbom_cache[sbom_at_time.id]
            else:
                baseline_f, baseline_v = set(), set()

            src_key = (scan.variant_id, scan.scan_source)

            # SBOM active package set — used to filter tool findings.
            sbom_pkg = packages_map.get(
                sbom_at_time.id, set()
            ) if sbom_at_time else set()

            def _filtered_tool_f(f_ids: set) -> set:
                """Return only findings whose package is in the active SBOM."""
                return {fid for fid in f_ids
                        if tool_fid_to_pkg.get(fid) in sbom_pkg}

            # Global state BEFORE this scan (filtered to SBOM packages)
            global_before_f = set(baseline_f)
            global_before_v = set(baseline_v)
            for (vid, _src), f_ids in running_src_findings.items():
                if vid == scan.variant_id:
                    global_before_f |= _filtered_tool_f(f_ids)
            for fid in global_before_f - baseline_f:
                info = fid_to_info.get(fid)
                if info:
                    global_before_v.add(info[1])

            # Update running tracker for this source
            running_src_findings[src_key] = curr_f
            running_src_vulns[src_key] = curr_v

            # Global state AFTER this scan (filtered to SBOM packages)
            global_f = set(baseline_f)
            global_v = set(baseline_v)
            for (vid, _src), f_ids in running_src_findings.items():
                if vid == scan.variant_id:
                    global_f |= _filtered_tool_f(f_ids)
            for fid in global_f - baseline_f:
                info = fid_to_info.get(fid)
                if info:
                    global_v.add(info[1])

            base["is_first"] = (prev is None)
            base["packages_added"] = 0
            base["packages_removed"] = 0
            base["packages_upgraded"] = 0
            base["packages_unchanged"] = 0
            base["findings_upgraded"] = 0
            base["findings_unchanged"] = 0
            base["findings_added"] = len(global_f - global_before_f)
            base["findings_removed"] = len(global_before_f - global_f)
            base["vulns_added"] = len(global_v - global_before_v)
            base["vulns_removed"] = len(global_before_v - global_v)
            base["vulns_unchanged"] = 0

            # "Newly detected" = findings/vulns added to the global result.
            base["newly_detected_findings"] = base["findings_added"]
            base["newly_detected_vulns"] = base["vulns_added"]

            # Branch result = SBOM baseline ∪ this tool scan (already filtered)
            branch_f = baseline_f | _filtered_tool_f(curr_f)
            branch_v = set(baseline_v)
            for fid in branch_f - baseline_f:
                info = fid_to_info.get(fid)
                if info:
                    branch_v.add(info[1])
            base["branch_finding_count"] = len(branch_f)
            base["branch_vuln_count"] = len(branch_v)
            base["branch_package_count"] = len(sbom_pkg)

            # Global result = already-filtered global_f / global_v
            base["global_finding_count"] = len(global_f)
            base["global_vuln_count"] = len(global_v)
            base["global_package_count"] = len(sbom_pkg)

            base["formats"] = []
        elif prev is None:
            base["is_first"] = True
            base["findings_added"] = None
            base["findings_removed"] = None
            base["findings_upgraded"] = None
            base["findings_unchanged"] = None
            base["packages_added"] = None
            base["packages_removed"] = None
            base["packages_upgraded"] = None
            base["packages_unchanged"] = None
            base["vulns_added"] = None
            base["vulns_removed"] = None
            base["vulns_unchanged"] = None
        else:
            prev_f = findings_map.get(prev.id, set())
            prev_v = vulns_map.get(prev.id, set())
            base["is_first"] = False

            upgraded_pairs = entry["upgraded_pairs"]
            prev_pkgs = packages_map.get(prev.id, set())
            base["packages_added"] = entry.get("truly_added_p", len(entry["curr_p"] - prev_pkgs))
            base["packages_removed"] = entry.get("truly_removed_p", len(prev_pkgs - entry["curr_p"]))
            base["packages_upgraded"] = len(upgraded_pairs)

            # --- Compute current scan result (SBOM ∪ tool-scan on active pkgs) ---
            curr_pkg_id_set = entry["curr_p"]
            curr_scan_result_f = set(curr_f)
            for (vid, _src), f_ids in running_src_findings.items():
                if vid == scan.variant_id:
                    for fid in f_ids:
                        if tool_fid_to_pkg.get(fid) in curr_pkg_id_set:
                            curr_scan_result_f.add(fid)
            curr_scan_result_v: set = set(curr_v)  # start with complete SBOM vulns
            for fid in curr_scan_result_f - curr_f:  # add vulns from tool findings only
                info = fid_to_info.get(fid)
                if info:
                    curr_scan_result_v.add(info[1])

            # --- Compute previous scan result (prev SBOM ∪ tool-scan on prev pkgs) ---
            # This uses the CURRENT running_src_findings (which includes all
            # tool scans that ran between the two SBOMs), reflecting what the
            # user would have seen on the previous card right before this SBOM.
            prev_v = vulns_map.get(prev.id, set())
            prev_sr_f = set(prev_f)
            for (vid, _src), f_ids in running_src_findings.items():
                if vid == scan.variant_id:
                    for fid in f_ids:
                        if tool_fid_to_pkg.get(fid) in prev_pkgs:
                            prev_sr_f.add(fid)
            prev_sr_v: set = set(prev_v)  # start with complete prev SBOM vulns
            for fid in prev_sr_f - prev_f:  # add vulns from tool findings only
                info = fid_to_info.get(fid)
                if info:
                    prev_sr_v.add(info[1])

            # --- Classify findings using scan result diffs ---
            # new + upgraded + unchanged = current scan result
            # removed + upgraded + unchanged = previous scan result
            sr_new_f = curr_scan_result_f - prev_sr_f
            sr_gone_f = prev_sr_f - curr_scan_result_f
            sr_unchanged_f = prev_sr_f & curr_scan_result_f

            upgraded_old_ids_set: set = {old_pkg.id for old_pkg, _ in upgraded_pairs}
            upgraded_new_ids_set: set = {new_pkg.id for _, new_pkg in upgraded_pairs}

            # Group gone findings on upgraded-old packages by vuln
            _rem_by_vuln: dict = {}
            for fid in sr_gone_f:
                info = fid_to_info.get(fid)
                if info and info[0] in upgraded_old_ids_set:
                    _rem_by_vuln.setdefault(info[1], []).append(fid)
            # Match new findings on upgraded-new packages 1:1
            sr_upgraded_count = 0
            for fid in sr_new_f:
                info = fid_to_info.get(fid)
                if info and info[0] in upgraded_new_ids_set:
                    candidates = _rem_by_vuln.get(info[1], [])
                    if candidates:
                        candidates.pop(0)
                        sr_upgraded_count += 1

            base["findings_added"] = len(sr_new_f) - sr_upgraded_count
            base["findings_removed"] = len(sr_gone_f) - sr_upgraded_count
            base["findings_upgraded"] = sr_upgraded_count
            base["findings_unchanged"] = len(sr_unchanged_f)

            # --- vulns: all from scan result ---
            base["vulns_added"] = len(curr_scan_result_v - prev_sr_v)
            base["vulns_removed"] = len(prev_sr_v - curr_scan_result_v)
            base["vulns_unchanged"] = len(prev_sr_v & curr_scan_result_v)

            # Unchanged packages = intersection minus upgraded (old+new) IDs
            unchanged_pkg_ids = entry["curr_p"] & prev_pkgs
            for old_pkg, new_pkg in upgraded_pairs:
                unchanged_pkg_ids.discard(old_pkg.id)
                unchanged_pkg_ids.discard(new_pkg.id)
            base["packages_unchanged"] = len(unchanged_pkg_ids)

        # ---- Non-tool (SBOM) scans: set tool-only fields to None ----
        if not is_tool_scan:
            base["newly_detected_findings"] = None
            base["newly_detected_vulns"] = None
            base["branch_finding_count"] = None
            base["branch_vuln_count"] = None
            base["branch_package_count"] = None

            # Scan Result for SBOM scans = SBOM ∪ tool-scan findings
            # BUT only tool-scan findings whose package is still in the
            # current SBOM (removed/upgraded-away packages are dropped).
            has_tool_scans = any(
                vid == scan.variant_id for (vid, _src) in running_src_findings
            )
            if has_tool_scans:
                # Reuse curr_scan_result_f/v if already computed in the diff
                # section above (i.e. prev is not None); otherwise compute now.
                if prev is None:
                    curr_pkg_id_set = entry["curr_p"]
                    curr_scan_result_f = set(curr_f)
                    for (vid, _src), f_ids in running_src_findings.items():
                        if vid == scan.variant_id:
                            for fid in f_ids:
                                if tool_fid_to_pkg.get(fid) in curr_pkg_id_set:
                                    curr_scan_result_f.add(fid)
                    curr_scan_result_v = set(curr_v)  # complete SBOM vulns
                    for fid in curr_scan_result_f - curr_f:  # add tool vulns
                        info = fid_to_info.get(fid)
                        if info:
                            curr_scan_result_v.add(info[1])
                base["global_finding_count"] = len(curr_scan_result_f)
                base["global_vuln_count"] = len(curr_scan_result_v)
                base["global_package_count"] = len(entry["curr_p"])
            else:
                base["global_finding_count"] = None
                base["global_vuln_count"] = None
                base["global_package_count"] = None

            doc_formats = set()
            for doc in (scan.sbom_documents or []):
                if doc.format:
                    doc_formats.add(doc.format)
            base["formats"] = sorted(doc_formats)

        result.append(base)
    return result


# ---------------------------------------------------------------------------
# Cache — computed diff fields
# ---------------------------------------------------------------------------

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


def _store_cache(results: list[dict]) -> None:
    """Upsert computed diff data into scan_diff_cache for each result dict."""
    if not results:
        return
    scan_ids = [uuid_module.UUID(r["id"]) for r in results]
    # Delete existing cache rows for these scans
    db.session.execute(
        db.delete(ScanDiffCache).where(ScanDiffCache.scan_id.in_(scan_ids))
    )
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
    rows = db.session.execute(
        db.select(ScanDiffCache).where(ScanDiffCache.scan_id.in_(scan_ids))
    ).scalars().all()
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
        db.session.execute(
            db.delete(ScanDiffCache).where(
                ScanDiffCache.scan_id.in_(
                    db.select(Scan.id).where(Scan.variant_id == variant_id)
                )
            )
        )
        db.session.commit()
        return
    results = _serialize_list_with_diff(scans)
    _store_cache(results)


def invalidate_variant_cache(variant_id) -> None:
    """Delete cached scan-history data for *variant_id*.

    The cache will be lazily rebuilt the next time a list endpoint is hit.
    Use this when the calling context cannot easily recompute (e.g. a
    background thread that spawns sub-processes without direct DB access).
    """
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


# ---------------------------------------------------------------------------
# Helpers — detailed diff (for the diff endpoint)
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


def _classify_finding_changes(findings_added, findings_removed, upgraded_pairs):
    """Separate findings into truly-added, truly-removed, and upgraded.

    A finding is "upgraded" when the same vulnerability_id appears in both
    added and removed sets, and the package_id changed between an upgraded
    package pair.

    Args:
        findings_added: list of obs dicts (from _obs_to_dict) that were added
        findings_removed: list of obs dicts that were removed
        upgraded_pairs: list of (old_pkg, new_pkg) Package objects

    Returns (truly_added, truly_removed, upgraded_findings, upgraded_keys) where
    upgraded_findings is a list of dicts with vuln_id, pkg_name, old_version, new_version,
    and upgraded_keys is a set of (vuln_id, old_pkg_id_str) pairs that were matched.
    """
    # Build set of (old_pkg_id, new_pkg_id) from upgraded pairs
    upgraded_pkg_map = {}  # old_pkg_id -> new_pkg Package
    new_to_old_pkg = {}    # new_pkg_id -> old_pkg Package
    for old_pkg, new_pkg in upgraded_pairs:
        upgraded_pkg_map[str(old_pkg.id)] = new_pkg
        new_to_old_pkg[str(new_pkg.id)] = old_pkg

    # Index removed findings by (vuln_id, old_pkg_id) for matching
    removed_by_key = {}
    for f in findings_removed:
        key = (f["vulnerability_id"], f["package_id"])
        removed_by_key.setdefault(key, []).append(f)

    upgraded_findings = []
    matched_added_ids = set()
    matched_removed_ids = set()
    matched_upgraded_keys: set = set()  # (vuln_id, old_pkg_id_str)

    for f_added in findings_added:
        pkg_id = f_added["package_id"]
        vuln_id = f_added["vulnerability_id"]
        if pkg_id not in new_to_old_pkg:
            continue
        old_pkg = new_to_old_pkg[pkg_id]
        old_pkg_id_str = str(old_pkg.id)
        key = (vuln_id, old_pkg_id_str)
        candidates = removed_by_key.get(key, [])
        for f_removed in candidates:
            if f_removed["finding_id"] in matched_removed_ids:
                continue
            # Match found
            upgraded_findings.append({
                "vulnerability_id": vuln_id,
                "package_name": f_added["package_name"],
                "old_version": old_pkg.version or "",
                "new_version": f_added["package_version"],
            })
            matched_added_ids.add(f_added["finding_id"])
            matched_removed_ids.add(f_removed["finding_id"])
            matched_upgraded_keys.add(key)
            break

    truly_added = [f for f in findings_added if f["finding_id"] not in matched_added_ids]
    truly_removed = [f for f in findings_removed if f["finding_id"] not in matched_removed_ids]
    return truly_added, truly_removed, upgraded_findings, matched_upgraded_keys


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def init_app(app):

    # Track running Grype scans so we can report status / prevent duplicates
    _grype_scans_in_progress: dict = {}  # variant_id -> {status, error, progress, logs, total, done_count}

    @app.route('/api/scans')
    def list_all_scans():
        scans = ScanController.get_all()
        cached = _read_cache(scans)
        if cached is not None:
            return jsonify(cached)
        result = _serialize_list_with_diff(scans)
        _store_cache(result)
        return jsonify(result)

    @app.route('/api/projects/<project_id>/scans')
    def list_scans_by_project(project_id):
        project = ProjectController.get(project_id)
        if project is None:
            return jsonify({"error": "Project not found"}), 404
        scans = ScanController.get_by_project(project_id)
        cached = _read_cache(scans)
        if cached is not None:
            return jsonify(cached)
        result = _serialize_list_with_diff(scans)
        _store_cache(result)
        return jsonify(result)

    @app.route('/api/variants/<variant_id>/scans')
    def list_scans_by_variant(variant_id):
        variant = VariantController.get(variant_id)
        if variant is None:
            return jsonify({"error": "Variant not found"}), 404
        scans = ScanController.get_by_variant(variant_id)
        cached = _read_cache(scans)
        if cached is not None:
            return jsonify(cached)
        result = _serialize_list_with_diff(scans)
        _store_cache(result)
        return jsonify(result)

    @app.route('/api/scans/<scan_id>', methods=['PATCH'])
    def update_scan(scan_id):
        from flask import request as req
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400
        payload = req.get_json(silent=True)
        if not payload or "description" not in payload:
            return jsonify({"error": "Missing 'description' field"}), 400
        description = payload["description"]
        if not isinstance(description, str):
            return jsonify({"error": "'description' must be a string"}), 400
        scan = ScanController.get(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404
        updated = ScanController.update(scan, description)
        return jsonify(ScanController.serialize(updated))

    @app.route('/api/scans/<scan_id>', methods=['DELETE'])
    def delete_scan(scan_id):
        """Delete a scan and its observations.

        Findings that are no longer referenced by any observation are
        also removed (cascade cleaned).  The response includes the
        number of orphaned findings that were deleted.
        """
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400
        scan = ScanController.get(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404

        # Remember variant so we can recompute cache after deletion.
        variant_id = scan.variant_id

        # Collect finding IDs referenced by this scan's observations
        # *before* the cascade delete removes them.
        finding_ids = {obs.finding_id for obs in (scan.observations or [])}

        # Delete the scan (cascades to observations + sbom_documents)
        ScanController.delete(scan)

        # Clean up orphaned findings — those that no longer have any
        # observation linking them to a remaining scan.
        orphaned_count = 0
        if finding_ids:
            from sqlalchemy import exists as sa_exists
            for fid in finding_ids:
                has_obs = db.session.query(
                    sa_exists().where(Observation.finding_id == fid)
                ).scalar()
                if not has_obs:
                    finding = db.session.get(Finding, fid)
                    if finding:
                        db.session.delete(finding)
                        orphaned_count += 1
            if orphaned_count:
                db.session.commit()

        # Recompute scan-history cache for the affected variant.
        recompute_variant_cache(variant_id)

        return jsonify({
            "deleted": True,
            "scan_id": scan_id,
            "orphaned_findings_removed": orphaned_count,
        })

    @app.route('/api/scans/<scan_id>/diff')
    def get_scan_diff(scan_id):
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400

        scan = _load_scan_with_findings(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404

        # Locate the previous scan of the same type (and source) for the same variant
        all_variant_scans = ScanController.get_by_variant(scan.variant_id)
        scan_type = scan.scan_type or "sbom"
        scan_source = scan.scan_source
        prev_scan_id = None
        same_type_scans = [
            s for s in all_variant_scans
            if (s.scan_type or "sbom") == scan_type
            and (s.scan_source == scan_source if scan_type == "tool" else True)
        ]
        for i, s in enumerate(same_type_scans):
            if s.id == scan.id and i > 0:
                prev_scan_id = same_type_scans[i - 1].id
                break

        is_tool_scan = scan_type == "tool"
        scan_origin = _origin_for_scan(scan)

        # --- Findings diff ---
        current_finding_ids = {obs.finding_id for obs in scan.observations}
        curr_vulns = {obs.finding.vulnerability_id for obs in scan.observations}

        if prev_scan_id is None:
            findings_added = [_obs_to_dict(obs, scan_origin) for obs in scan.observations]
            findings_removed: list = []
            vulns_added = sorted(curr_vulns)
            vulns_removed: list = []
        else:
            prev_scan = _load_scan_with_findings(prev_scan_id)
            prev_finding_ids = {obs.finding_id for obs in prev_scan.observations} if prev_scan else set()
            prev_vulns = {obs.finding.vulnerability_id for obs in prev_scan.observations} if prev_scan else set()
            added_fids = current_finding_ids - prev_finding_ids
            removed_fids = prev_finding_ids - current_finding_ids
            findings_added = [_obs_to_dict(obs, scan_origin) for obs in scan.observations if obs.finding_id in added_fids]
            findings_removed = (
                [_obs_to_dict(obs, scan_origin) for obs in prev_scan.observations if obs.finding_id in removed_fids]
                if prev_scan else []
            )
            vulns_added = sorted(curr_vulns - prev_vulns)
            vulns_removed = sorted(prev_vulns - curr_vulns)

        # --- Packages diff (skipped for tool scans) ---
        if is_tool_scan:
            curr_pkg_ids: set = set()
            packages_added: list = []
            packages_removed: list = []
            packages_upgraded: list = []
            upgraded_pairs: list = []
        else:
            scans_to_query = [scan.id] if prev_scan_id is None else [scan.id, prev_scan_id]
            pkg_sets = _packages_by_scan_ids(scans_to_query)
            curr_pkg_ids = pkg_sets.get(scan.id, set())
            prev_pkg_ids = pkg_sets.get(prev_scan_id, set()) if prev_scan_id else set()

            raw_added_pkg_ids = curr_pkg_ids - prev_pkg_ids
            raw_removed_pkg_ids = prev_pkg_ids - curr_pkg_ids

            all_relevant_pkg_ids = raw_added_pkg_ids | raw_removed_pkg_ids
            pkg_lookup = _package_rows(all_relevant_pkg_ids)

            truly_added_ids, truly_removed_ids, upgraded_pairs = _classify_package_changes(
                raw_added_pkg_ids, raw_removed_pkg_ids, pkg_lookup
            )

            packages_added = [_pkg_to_dict(pkg_lookup[pid]) for pid in truly_added_ids if pid in pkg_lookup]
            packages_removed = [_pkg_to_dict(pkg_lookup[pid]) for pid in truly_removed_ids if pid in pkg_lookup]
            packages_upgraded = [
                {
                    "package_name": (old_pkg.name or "unknown"),
                    "old_version": (old_pkg.version or ""),
                    "new_version": (new_pkg.version or ""),
                    "old_package_id": str(old_pkg.id),
                    "new_package_id": str(new_pkg.id),
                }
                for old_pkg, new_pkg in upgraded_pairs
            ]

        # --- Classify findings using scan-result diffs ---
        # For SBOM scans: scan result = SBOM ∪ tool-scan findings on
        # that SBOM's active packages.  The diff is between the current
        # and previous scan results so all categories are consistent:
        #   new + upgraded + unchanged  = current scan result
        #   removed + upgraded + unchanged = previous scan result
        if not is_tool_scan and prev_scan_id is not None:
            # Collect latest tool scans for this variant that were active
            # at this SBOM's timestamp (mirrors the list view's chronological
            # running_src_findings snapshot).
            tool_scans = [
                s for s in all_variant_scans
                if (s.scan_type or "sbom") == "tool"
                and s.timestamp <= scan.timestamp
            ]
            latest_tool_by_source: dict = {}
            for ts in tool_scans:
                src = ts.scan_source or ""
                prev_ts = latest_tool_by_source.get(src)
                if prev_ts is None or ts.timestamp > prev_ts.timestamp:
                    latest_tool_by_source[src] = ts

            # Build finding_id → (obs_dict, origin) lookup for all sources
            fid_obs_map: dict = {}  # finding_id → obs dict
            fid_info: dict = {}     # finding_id → (pkg_id, vuln_id)
            # Current SBOM observations
            for obs in scan.observations:
                fid = obs.finding_id
                fid_obs_map[fid] = _obs_to_dict(obs, scan_origin)
                fid_info[fid] = (obs.finding.package_id, obs.finding.vulnerability_id)
            # Previous SBOM observations
            for obs in prev_scan.observations:  # type: ignore[possibly-undefined]
                fid = obs.finding_id
                if fid not in fid_obs_map:
                    fid_obs_map[fid] = _obs_to_dict(obs, scan_origin)
                if fid not in fid_info:
                    fid_info[fid] = (obs.finding.package_id, obs.finding.vulnerability_id)
            # Tool-scan observations
            for tool_scan_obj in latest_tool_by_source.values():
                tool_loaded = _load_scan_with_findings(tool_scan_obj.id)
                if not tool_loaded:
                    continue
                tool_origin = _origin_for_scan(tool_loaded)
                for obs in tool_loaded.observations:
                    fid = obs.finding_id
                    if fid not in fid_obs_map:
                        fid_obs_map[fid] = _obs_to_dict(obs, tool_origin)
                    if fid not in fid_info:
                        fid_info[fid] = (obs.finding.package_id, obs.finding.vulnerability_id)

            # Build current scan result = curr SBOM ∪ tool findings on curr pkgs
            curr_sr_fids: set = set(current_finding_ids)
            for tool_scan_obj in latest_tool_by_source.values():
                tool_loaded = _load_scan_with_findings(tool_scan_obj.id)
                if not tool_loaded:
                    continue
                for obs in tool_loaded.observations:
                    if obs.finding.package_id in curr_pkg_ids:
                        curr_sr_fids.add(obs.finding_id)

            # Build previous scan result = prev SBOM ∪ tool findings on prev pkgs
            prev_sr_fids: set = set(prev_finding_ids)  # type: ignore[possibly-undefined]
            for tool_scan_obj in latest_tool_by_source.values():
                tool_loaded = _load_scan_with_findings(tool_scan_obj.id)
                if not tool_loaded:
                    continue
                for obs in tool_loaded.observations:
                    if obs.finding.package_id in prev_pkg_ids:  # type: ignore[possibly-undefined]
                        prev_sr_fids.add(obs.finding_id)

            # Derive vuln sets from scan results — start from complete SBOM
            # vuln sets and add only tool-scan vulns on top.
            curr_sr_vids: set = set(curr_vulns)
            for fid in curr_sr_fids - current_finding_ids:
                info = fid_info.get(fid)
                if info:
                    curr_sr_vids.add(info[1])
            prev_sr_vids: set = set(prev_vulns)  # type: ignore[possibly-undefined]
            for fid in prev_sr_fids - prev_finding_ids:  # type: ignore[possibly-undefined]
                info = fid_info.get(fid)
                if info:
                    prev_sr_vids.add(info[1])

            # Diff scan results
            sr_new_fids = curr_sr_fids - prev_sr_fids
            sr_gone_fids = prev_sr_fids - curr_sr_fids
            sr_unchanged_fids = prev_sr_fids & curr_sr_fids

            # 1:1 upgrade matching
            upgraded_old_ids_set: set = {old_pkg.id for old_pkg, _ in upgraded_pairs}
            upgraded_new_ids_set: set = {new_pkg.id for _, new_pkg in upgraded_pairs}
            upgraded_old_to_new: dict = {}
            for old_pkg, new_pkg in upgraded_pairs:
                upgraded_old_to_new[old_pkg.id] = (old_pkg, new_pkg)

            # Group gone findings on upgraded-old packages by vuln
            _rem_by_vuln: dict = {}  # vuln_id → [(fid, pkg_id)]
            for fid in sr_gone_fids:
                info = fid_info.get(fid)
                if info and info[0] in upgraded_old_ids_set:
                    _rem_by_vuln.setdefault(info[1], []).append((fid, info[0]))

            # Match new findings on upgraded-new packages 1:1
            sr_upgraded_fids_new: set = set()   # fids from new (on new pkg)
            sr_upgraded_fids_gone: set = set()   # fids from gone (on old pkg)
            findings_upgraded_list: list = []
            for fid in sr_new_fids:
                info = fid_info.get(fid)
                if info and info[0] in upgraded_new_ids_set:
                    candidates = _rem_by_vuln.get(info[1], [])
                    if candidates:
                        old_fid, old_pkg_id = candidates.pop(0)
                        sr_upgraded_fids_new.add(fid)
                        sr_upgraded_fids_gone.add(old_fid)
                        old_pkg, new_pkg = upgraded_old_to_new[old_pkg_id]
                        obs_dict = fid_obs_map.get(fid, {})
                        findings_upgraded_list.append({
                            "vulnerability_id": info[1],
                            "package_name": old_pkg.name or "unknown",
                            "old_version": old_pkg.version or "",
                            "new_version": new_pkg.version or "",
                            "origin": obs_dict.get("origin", scan_origin),
                        })

            findings_added = [
                fid_obs_map[fid] for fid in sr_new_fids - sr_upgraded_fids_new
                if fid in fid_obs_map
            ]
            findings_removed = [
                fid_obs_map[fid] for fid in sr_gone_fids - sr_upgraded_fids_gone
                if fid in fid_obs_map
            ]
            findings_upgraded = findings_upgraded_list
            findings_unchanged = [
                fid_obs_map[fid] for fid in sr_unchanged_fids
                if fid in fid_obs_map
            ]

            vulns_added = sorted(curr_sr_vids - prev_sr_vids)
            vulns_removed = sorted(prev_sr_vids - curr_sr_vids)
            vulns_unchanged = sorted(prev_sr_vids & curr_sr_vids)

            # Unchanged packages
            unchanged_pkg_ids = curr_pkg_ids & prev_pkg_ids  # type: ignore[possibly-undefined]
            for old_pkg, new_pkg in upgraded_pairs:
                unchanged_pkg_ids.discard(old_pkg.id)
                unchanged_pkg_ids.discard(new_pkg.id)
            if unchanged_pkg_ids:
                unchanged_pkg_lookup = _package_rows(unchanged_pkg_ids)
                packages_unchanged = [
                    _pkg_to_dict(unchanged_pkg_lookup[pid])
                    for pid in unchanged_pkg_ids if pid in unchanged_pkg_lookup
                ]
            else:
                packages_unchanged = []
        elif not is_tool_scan:
            # First SBOM scan — no previous scan result
            findings_upgraded = []
            findings_unchanged = []
            vulns_unchanged = []
            packages_unchanged = []
        else:
            findings_upgraded = []
            findings_unchanged = []
            vulns_unchanged = []
            packages_unchanged = []

        # Sort for stable output
        packages_added.sort(key=lambda p: (p["package_name"], p["package_version"]))
        packages_removed.sort(key=lambda p: (p["package_name"], p["package_version"]))
        packages_upgraded.sort(key=lambda p: (p["package_name"], p["old_version"]))
        findings_upgraded.sort(key=lambda f: (f["package_name"], f["vulnerability_id"]))

        # --- Newly detected (tool scans only) ---
        newly_detected_findings_count = None
        newly_detected_vulns_count = None
        newly_detected_findings_list = None
        newly_detected_vulns_list = None

        if is_tool_scan:
            sbom_scans = [s for s in all_variant_scans if (s.scan_type or "sbom") == "sbom"]
            sbom_fids: set = set()
            sbom_vids: set = set()
            if sbom_scans:
                sbom_at_time = _sbom_active_at(sbom_scans, scan.timestamp)
                if sbom_at_time:
                    sbom_scan_loaded = _load_scan_with_findings(sbom_at_time.id)
                else:
                    sbom_scan_loaded = None
                if sbom_scan_loaded:
                    sbom_fids = {obs.finding_id for obs in sbom_scan_loaded.observations}
                    sbom_vids = {obs.finding.vulnerability_id for obs in sbom_scan_loaded.observations}

            # Start from findings/vulns not in SBOM
            new_fids = current_finding_ids - sbom_fids
            new_vids = curr_vulns - sbom_vids

            # Subtract what was already present in the previous tool scan
            if prev_scan_id is not None:
                prev_scan_loaded = _load_scan_with_findings(prev_scan_id)
                if prev_scan_loaded:
                    prev_tool_fids = {obs.finding_id for obs in prev_scan_loaded.observations}
                    new_fids = new_fids - prev_tool_fids
                    prev_tool_vids = {obs.finding.vulnerability_id for obs in prev_scan_loaded.observations}
                    new_vids = new_vids - prev_tool_vids

            newly_detected_findings_count = len(new_fids)
            newly_detected_vulns_count = len(new_vids)
            newly_detected_findings_list = [
                _obs_to_dict(obs, scan_origin) for obs in scan.observations
                if obs.finding_id in new_fids
            ]
            newly_detected_vulns_list = sorted(new_vids)

        return jsonify({
            "scan_id": str(scan.id),
            "scan_type": scan_type,
            "previous_scan_id": str(prev_scan_id) if prev_scan_id else None,
            "is_first": prev_scan_id is None,
            "finding_count": len(current_finding_ids),
            "package_count": len(curr_pkg_ids),
            "vuln_count": len(curr_vulns),
            "findings_added": findings_added,
            "findings_removed": findings_removed,
            "findings_upgraded": findings_upgraded,
            "findings_unchanged": findings_unchanged,
            "packages_added": packages_added,
            "packages_removed": packages_removed,
            "packages_upgraded": packages_upgraded,
            "packages_unchanged": packages_unchanged,
            "vulns_added": vulns_added,
            "vulns_removed": vulns_removed,
            "vulns_unchanged": vulns_unchanged,
            "newly_detected_findings": newly_detected_findings_count,
            "newly_detected_vulns": newly_detected_vulns_count,
            "newly_detected_findings_list": newly_detected_findings_list,
            "newly_detected_vulns_list": newly_detected_vulns_list,
        })

    # ------------------------------------------------------------------
    # Merge result — all active items (SBOM ∪ tool scan) with source info
    # ------------------------------------------------------------------

    @app.route('/api/scans/<scan_id>/global-result')
    def get_scan_global_result(scan_id):
        """Return every active finding, vulnerability, and package at the
        time of *scan_id* together with their source (SBOM document name /
        format or scan source label).

        For an SBOM scan the merge result is just that scan's own data.
        For a tool scan the merge result is the union of the latest SBOM
        scan for the same variant **plus** this tool scan.
        """
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400

        scan = _load_scan_with_findings(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404

        scan_type = scan.scan_type or "sbom"
        is_tool_scan = scan_type == "tool"

        # Determine which scans contribute to the global view
        contributing_scan_ids: list = [scan.id]
        sbom_scan = None
        if is_tool_scan:
            all_variant_scans = ScanController.get_by_variant(scan.variant_id)
            sbom_scans = [s for s in all_variant_scans if (s.scan_type or "sbom") == "sbom"]
            if sbom_scans:
                sbom_scan = sbom_scans[-1]
                contributing_scan_ids.append(sbom_scan.id)
        else:
            # SBOM scan: include latest tool scan per source so the global
            # view shows SBOM ∪ all tool-scan sources (matching list view).
            all_variant_scans = ScanController.get_by_variant(scan.variant_id)
            latest_tool_by_source: dict = {}
            for s in all_variant_scans:
                if (s.scan_type or "sbom") == "tool":
                    src = s.scan_source or ""
                    prev = latest_tool_by_source.get(src)
                    if prev is None or s.timestamp > prev.timestamp:
                        latest_tool_by_source[src] = s
            for tool_s in latest_tool_by_source.values():
                if tool_s.id not in contributing_scan_ids:
                    contributing_scan_ids.append(tool_s.id)

        # --- Packages with source ---
        # Packages come from SBOM documents only (tool scans don't add packages)
        pkg_rows = db.session.execute(
            db.select(
                Package.id, Package.name, Package.version,
                SBOMDocument.source_name, SBOMDocument.format, SBOMDocument.scan_id,
            )
            .join(SBOMPackage, SBOMPackage.package_id == Package.id)
            .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
            .where(SBOMDocument.scan_id.in_(contributing_scan_ids))
        ).all()
        # Deduplicate by package id, keep all sources
        pkg_map: dict = {}  # package_id -> dict
        for pid, pname, pversion, src_name, src_fmt, src_scan_id in pkg_rows:
            source_label = f"{src_name} ({src_fmt})" if src_fmt else src_name
            if pid not in pkg_map:
                pkg_map[pid] = {
                    "package_id": str(pid),
                    "package_name": pname or "unknown",
                    "package_version": pversion or "",
                    "sources": [source_label],
                }
            else:
                if source_label not in pkg_map[pid]["sources"]:
                    pkg_map[pid]["sources"].append(source_label)
        packages = sorted(pkg_map.values(), key=lambda p: (p["package_name"], p["package_version"]))

        # --- Findings & vulnerabilities with source ---
        # Load observations from all contributing scans
        loaded_scans: dict = {scan.id: scan}  # already loaded
        for sid in contributing_scan_ids:
            if sid not in loaded_scans:
                loaded = _load_scan_with_findings(sid)
                if loaded:
                    loaded_scans[sid] = loaded

        # Active package IDs = packages from the SBOM scan (not tool scans)
        active_pkg_ids: set = set(pkg_map.keys())

        finding_map: dict = {}   # finding_id -> dict
        vuln_set: dict = {}      # vulnerability_id -> set of sources
        for sid, loaded in loaded_scans.items():
            s_type = loaded.scan_type or "sbom"
            is_tool = s_type == "tool"
            if is_tool:
                source_labels = {
                    "grype": "Grype",
                    "nvd": "NVD CPE",
                    "osv": "OSV",
                }
                source_label = source_labels.get(
                    loaded.scan_source or "", "Vulnerability Scan"
                )
            else:
                # Use SBOM document names as source
                doc_names = []
                for doc in (loaded.sbom_documents if hasattr(loaded, 'sbom_documents') else []):
                    label = f"{doc.source_name} ({doc.format})" if doc.format else doc.source_name
                    doc_names.append(label)
                source_label = ", ".join(doc_names) if doc_names else "SBOM Scan"
            for obs in loaded.observations:
                fid = obs.finding_id
                f = obs.finding
                pkg = f.package
                # For tool-scan findings on an SBOM scan's global view,
                # only include findings whose package is still active
                # (present in the current SBOM).
                if is_tool and not is_tool_scan and f.package_id not in active_pkg_ids:
                    continue
                if fid not in finding_map:
                    finding_map[fid] = {
                        "finding_id": str(fid),
                        "package_name": pkg.name if pkg else "unknown",
                        "package_version": pkg.version if pkg else "",
                        "package_id": str(f.package_id),
                        "vulnerability_id": f.vulnerability_id,
                        "sources": [source_label],
                    }
                else:
                    if source_label not in finding_map[fid]["sources"]:
                        finding_map[fid]["sources"].append(source_label)
                vid = f.vulnerability_id
                vuln_set.setdefault(vid, set()).add(source_label)

        findings = sorted(finding_map.values(), key=lambda f: (f["vulnerability_id"], f["package_name"]))
        vulnerabilities = [
            {"vulnerability_id": vid, "sources": sorted(srcs)}
            for vid, srcs in sorted(vuln_set.items())
        ]

        return jsonify({
            "scan_id": str(scan.id),
            "scan_type": scan_type,
            "packages": packages,
            "findings": findings,
            "vulnerabilities": vulnerabilities,
            "package_count": len(packages),
            "finding_count": len(findings),
            "vuln_count": len(vulnerabilities),
        })

    @app.route('/api/variants/<variant_id>/grype-scan', methods=['POST'])
    def trigger_grype_scan(variant_id):
        """Trigger a Grype vulnerability scan for the given variant.

        Exports the variant's packages as CycloneDX, runs ``grype`` on the
        export, and merges the results back into the DB as a tool scan.
        """
        import threading
        import subprocess
        import tempfile
        import os
        import shutil

        try:
            variant_uuid = uuid_module.UUID(variant_id)
        except ValueError:
            return jsonify({"error": "Invalid variant id"}), 400

        variant = VariantController.get(variant_uuid)
        if variant is None:
            return jsonify({"error": "Variant not found"}), 404

        vid_str = str(variant_uuid)
        if vid_str in _grype_scans_in_progress and _grype_scans_in_progress[vid_str]["status"] == "running":
            return jsonify({"error": "A Grype scan is already in progress for this variant"}), 409

        # Check that grype is available
        if shutil.which("grype") is None:
            return jsonify({"error": "grype binary not found on this system"}), 503

        project = db.session.get(Project, variant.project_id)
        project_name = project.name if project else "unknown"
        variant_name = variant.name

        _grype_scans_in_progress[vid_str] = {
            "status": "running", "error": None, "progress": "starting",
            "logs": [], "total": 4, "done_count": 0,
        }

        def _run_grype_scan():
            try:
                base_dir = os.environ.get(
                    "BASE_DIR",
                    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                )
                grype_tmp = tempfile.mkdtemp(prefix="vulnscout_grype_")
                try:
                    # 1. Export current DB as CycloneDX
                    _grype_scans_in_progress[vid_str]["progress"] = "1/4 Exporting CycloneDX"
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[1/4] Exporting current DB as CycloneDX…"
                    )
                    subprocess.run(
                        ["flask", "--app", "src.bin.webapp", "export",
                         "--format", "cdx16", "--output-dir", grype_tmp],
                        cwd=base_dir, check=True, capture_output=True, text=True,
                        timeout=120,
                    )
                    _grype_scans_in_progress[vid_str]["done_count"] = 1

                    exported_cdx = os.path.join(grype_tmp, "sbom_cyclonedx_v1_6.cdx.json")
                    if not os.path.isfile(exported_cdx):
                        old_logs = _grype_scans_in_progress[vid_str].get("logs", [])
                        old_logs.append("ERROR: CycloneDX export produced no file")
                        _grype_scans_in_progress[vid_str] = {
                            "status": "error",
                            "error": "CycloneDX export produced no file",
                            "progress": None,
                            "logs": old_logs, "total": 4, "done_count": 1,
                        }
                        return
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[1/4] CycloneDX export complete"
                    )

                    # 2. Run grype on the exported SBOM
                    _grype_scans_in_progress[vid_str]["progress"] = "2/4 Running Grype"
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[2/4] Running Grype vulnerability scanner…"
                    )
                    grype_out = os.path.join(grype_tmp, "grype_results.grype.json")
                    with open(grype_out, "w") as gf:
                        subprocess.run(
                            ["grype", "--add-cpes-if-none",
                             f"sbom:{exported_cdx}", "-o", "json"],
                            cwd=base_dir, check=True, text=True,
                            stdout=gf, stderr=subprocess.PIPE,
                            timeout=600,
                        )
                    _grype_scans_in_progress[vid_str]["done_count"] = 2

                    if not os.path.isfile(grype_out) or os.path.getsize(grype_out) == 0:
                        old_logs = _grype_scans_in_progress[vid_str].get("logs", [])
                        old_logs.append("ERROR: Grype produced no output")
                        _grype_scans_in_progress[vid_str] = {
                            "status": "error",
                            "error": "Grype produced no output",
                            "progress": None,
                            "logs": old_logs, "total": 4, "done_count": 2,
                        }
                        return
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[2/4] Grype scan complete"
                    )

                    # 3. Merge Grype results as a tool scan
                    _grype_scans_in_progress[vid_str]["progress"] = "3/4 Merging results"
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[3/4] Merging Grype results into database…"
                    )
                    subprocess.run(
                        ["flask", "--app", "src.bin.webapp", "merge",
                         "--project", project_name, "--variant", variant_name,
                         "--grype", grype_out],
                        cwd=base_dir, check=True, capture_output=True, text=True,
                        timeout=120,
                    )
                    _grype_scans_in_progress[vid_str]["done_count"] = 3
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[3/4] Merge complete"
                    )

                    # 4. Process
                    _grype_scans_in_progress[vid_str]["progress"] = "4/4 Processing"
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[4/4] Processing scan results…"
                    )
                    subprocess.run(
                        ["flask", "--app", "src.bin.webapp", "process"],
                        cwd=base_dir, check=True, capture_output=True, text=True,
                        timeout=300,
                    )
                    _grype_scans_in_progress[vid_str]["done_count"] = 4

                    # Invalidate scan-history cache so next list request recomputes.
                    try:
                        with app.app_context():
                            invalidate_variant_cache(variant_uuid)
                    except Exception:
                        pass  # non-critical; cache rebuilt lazily on next request

                    done_logs = _grype_scans_in_progress[vid_str].get("logs", [])
                    done_logs.append("✓ Grype scan complete")
                    _grype_scans_in_progress[vid_str] = {
                        "status": "done", "error": None,
                        "progress": "Scan complete",
                        "logs": done_logs, "total": 4, "done_count": 4,
                    }
                finally:
                    shutil.rmtree(grype_tmp, ignore_errors=True)
            except subprocess.TimeoutExpired:
                old_logs = _grype_scans_in_progress[vid_str].get("logs", [])
                old_logs.append("ERROR: Grype scan timed out")
                _grype_scans_in_progress[vid_str] = {
                    "status": "error",
                    "error": "Grype scan timed out",
                    "progress": None,
                    "logs": old_logs, "total": 4,
                    "done_count": _grype_scans_in_progress[vid_str].get("done_count", 0),
                }
            except subprocess.CalledProcessError as e:
                old_logs = _grype_scans_in_progress[vid_str].get("logs", [])
                err_msg = f"Command failed: {e.stderr[:500] if e.stderr else str(e)}"
                old_logs.append(f"ERROR: {err_msg}")
                _grype_scans_in_progress[vid_str] = {
                    "status": "error",
                    "error": err_msg,
                    "progress": None,
                    "logs": old_logs, "total": 4,
                    "done_count": _grype_scans_in_progress[vid_str].get("done_count", 0),
                }
            except Exception as e:
                old_logs = _grype_scans_in_progress[vid_str].get("logs", [])
                old_logs.append(f"ERROR: {str(e)[:500]}")
                _grype_scans_in_progress[vid_str] = {
                    "status": "error",
                    "error": str(e)[:500],
                    "progress": None,
                    "logs": old_logs, "total": 4,
                    "done_count": _grype_scans_in_progress[vid_str].get("done_count", 0),
                }

        thread = threading.Thread(
            target=_run_grype_scan,
            name=f"grype-scan-{vid_str}",
            daemon=True,
        )
        thread.start()

        return jsonify({"status": "started", "variant_id": vid_str}), 202

    @app.route('/api/variants/<variant_id>/grype-scan/status')
    def grype_scan_status(variant_id):
        """Check the status of a running Grype scan for the given variant."""
        try:
            variant_uuid = uuid_module.UUID(variant_id)
        except ValueError:
            return jsonify({"error": "Invalid variant id"}), 400

        vid_str = str(variant_uuid)
        info = _grype_scans_in_progress.get(vid_str)
        if info is None:
            return jsonify({"status": "idle"})
        return jsonify(info)

    # ------------------------------------------------------------------
    # NVD CPE Scan — query NVD by CPE for each active package
    # ------------------------------------------------------------------

    _nvd_scans_in_progress: dict = {}  # variant_id -> {"status": str, "error": str|None, "progress": str|None}

    @app.route('/api/variants/<variant_id>/nvd-scan', methods=['POST'])
    def trigger_nvd_scan(variant_id):
        """Trigger an NVD CPE-based vulnerability scan for the given variant.

        For every active package that has CPE identifiers, query the NVD CVE
        API (``cpeName=…``) and create findings/observations for any CVEs
        returned.  The result is stored as a tool scan.
        """
        import threading
        import os

        try:
            variant_uuid = uuid_module.UUID(variant_id)
        except ValueError:
            return jsonify({"error": "Invalid variant id"}), 400

        variant = VariantController.get(variant_uuid)
        if variant is None:
            return jsonify({"error": "Variant not found"}), 404

        vid_str = str(variant_uuid)
        if vid_str in _nvd_scans_in_progress and _nvd_scans_in_progress[vid_str]["status"] == "running":
            return jsonify({"error": "An NVD scan is already in progress for this variant"}), 409

        _nvd_scans_in_progress[vid_str] = {
            "status": "running", "error": None, "progress": "starting",
            "logs": [], "total": 0, "done_count": 0,
        }

        def _run_nvd_scan():
            with app.app_context():
                _do_nvd_scan(vid_str, variant_uuid)

        def _do_nvd_scan(vid_str, variant_uuid):
            try:
                from ..controllers.nvd_db import NVD_DB
                from ..models.vulnerability import Vulnerability as VulnModel
                from ..models.metrics import Metrics as MetricsModel
                from ..models.cvss import CVSS
                from ..models.assessment import Assessment

                nvd_api_key = os.getenv("NVD_API_KEY")
                nvd = NVD_DB(nvd_api_key=nvd_api_key)

                # 1. Get active packages for this variant (latest scans)
                _nvd_scans_in_progress[vid_str]["logs"].append(
                    "Resolving active packages…"
                )
                latest_rows = db.session.execute(
                    db.select(Scan.id, Scan.scan_type)
                    .where(Scan.variant_id == variant_uuid)
                    .order_by(Scan.timestamp.desc())
                ).all()
                latest_ids: list = []
                seen_types: set = set()
                for sid, stype in latest_rows:
                    st = stype or "sbom"
                    if st not in seen_types:
                        seen_types.add(st)
                        latest_ids.append(sid)
                    if len(seen_types) >= 2:
                        break

                if not latest_ids:
                    _nvd_scans_in_progress[vid_str] = {
                        "status": "error",
                        "error": "No scans found for variant",
                        "progress": None,
                    }
                    return

                pkg_sets = _packages_by_scan_ids(latest_ids)
                all_pkg_ids: set = set()
                for s in pkg_sets.values():
                    all_pkg_ids |= s

                if not all_pkg_ids:
                    _nvd_scans_in_progress[vid_str] = {
                        "status": "error",
                        "error": "No packages found for variant",
                        "progress": None,
                    }
                    return

                packages = db.session.execute(
                    db.select(Package).where(Package.id.in_(all_pkg_ids))
                ).scalars().all()

                # 2. Collect CPE names from packages
                # A CPE is queryable when it has at least a non-wildcard
                # product (parts[4]).  Wildcard part/vendor/version are
                # acceptable — the NVD virtualMatchString API handles
                # pattern matching for those.
                cpe_to_pkgs: dict = {}  # cpeName -> list[Package]
                for pkg in packages:
                    for cpe in (pkg.cpe or []):
                        parts = cpe.split(":")
                        if len(parts) >= 6 and parts[4] != "*":
                            cpe_to_pkgs.setdefault(cpe, []).append(pkg)

                if not cpe_to_pkgs:
                    old_logs = _nvd_scans_in_progress[vid_str].get(
                        "logs", []
                    )
                    old_logs.append(
                        "ERROR: No packages with valid CPE identifiers"
                    )
                    _nvd_scans_in_progress[vid_str] = {
                        "status": "error",
                        "error": "No packages with valid CPE identifiers",
                        "progress": None,
                        "logs": old_logs,
                        "total": 0, "done_count": 0,
                    }
                    return

                _nvd_scans_in_progress[vid_str]["logs"].append(
                    f"Found {len(packages)} packages with "
                    f"{len(cpe_to_pkgs)} unique CPEs to query"
                )

                # 3. Create a tool scan
                scan = Scan.create(
                    description="empty description",
                    variant_id=variant_uuid,
                    scan_type="tool",
                    scan_source="nvd",
                )
                total_cpes = len(cpe_to_pkgs)
                _nvd_scans_in_progress[vid_str]["total"] = total_cpes
                cves_found: set = set()
                observation_pairs: set = set()
                assessed_findings: set = set()
                observation_pairs: set = set()

                for idx, (cpe_name, pkgs) in enumerate(
                    cpe_to_pkgs.items(), 1
                ):
                    _nvd_scans_in_progress[vid_str]["progress"] = (
                        f"{idx}/{total_cpes} CPEs"
                    )
                    _nvd_scans_in_progress[vid_str]["logs"].append(
                        f"[{idx}/{total_cpes}] Querying {cpe_name}…"
                    )
                    try:
                        # Use virtualMatchString when the CPE contains
                        # wildcard fields (part/vendor/version) so the
                        # NVD applies pattern matching instead of a
                        # dictionary lookup.
                        cpe_parts = cpe_name.split(":")
                        has_wildcards = (
                            len(cpe_parts) >= 6
                            and (cpe_parts[2] == "*"
                                 or cpe_parts[3] == "*"
                                 or cpe_parts[5] == "*")
                        )
                        nvd_vulns = nvd.api_get_cves_by_cpe(
                            cpe_name,
                            results_per_page=100,
                            use_virtual_match=has_wildcards,
                        )
                    except Exception as e:
                        log_entry = (
                            f"[{idx}/{total_cpes}] ERROR "
                            f"{cpe_name}: {str(e)[:200]}"
                        )
                        _nvd_scans_in_progress[vid_str]["logs"].append(
                            log_entry
                        )
                        _nvd_scans_in_progress[vid_str]["done_count"] = idx
                        print(
                            f"[NVD Scan] Error querying CPE "
                            f"{cpe_name}: {e}",
                            flush=True,
                        )
                        continue

                    cpe_cves = [
                        v.get("cve", {}).get("id", "")
                        for v in nvd_vulns
                        if v.get("cve", {}).get("id")
                    ]
                    if cpe_cves:
                        ids_str = ', '.join(cpe_cves[:10])
                        ellip = '…' if len(cpe_cves) > 10 else ''
                        log_entry = (
                            f"[{idx}/{total_cpes}] {cpe_name} → "
                            f"{len(cpe_cves)} CVE(s): {ids_str}{ellip}"
                        )
                    else:
                        log_entry = (
                            f"[{idx}/{total_cpes}] {cpe_name} → no CVEs"
                        )
                    _nvd_scans_in_progress[vid_str]["logs"].append(
                        log_entry
                    )
                    _nvd_scans_in_progress[vid_str]["done_count"] = idx

                    for nvd_vuln in nvd_vulns:
                        cve = nvd_vuln.get("cve", {})
                        cve_id = cve.get("id", "")
                        if not cve_id:
                            continue

                        cves_found.add(cve_id)

                        # Extract full CVE details from the response
                        details = NVD_DB.extract_cve_details(cve)

                        existing_vuln = db.session.get(
                            VulnModel, cve_id.upper()
                        )
                        if existing_vuln is None:
                            existing_vuln = VulnModel.create_record(
                                id=cve_id,
                                description=details.get("description"),
                                status=details.get("status"),
                                publish_date=details.get("publish_date"),
                                attack_vector=details.get("attack_vector"),
                                links=details.get("links"),
                                weaknesses=details.get("weaknesses"),
                                nvd_last_modified=details.get(
                                    "nvd_last_modified"
                                ),
                            )
                            existing_vuln.add_found_by("nvd")
                        else:
                            existing_vuln.add_found_by("nvd")
                            # Enrich existing CVEs that lack data
                            _update = {}
                            if (not existing_vuln.description
                                    and details.get("description")):
                                _update["description"] = details[
                                    "description"
                                ]
                            if (not existing_vuln.status
                                    and details.get("status")):
                                _update["status"] = details["status"]
                            if (not existing_vuln.publish_date
                                    and details.get("publish_date")):
                                _update["publish_date"] = details[
                                    "publish_date"
                                ]
                            if (not existing_vuln.attack_vector
                                    and details.get("attack_vector")):
                                _update["attack_vector"] = details[
                                    "attack_vector"
                                ]
                            if (not existing_vuln.links
                                    and details.get("links")):
                                _update["links"] = details["links"]
                            if (not existing_vuln.weaknesses
                                    and details.get("weaknesses")):
                                _update["weaknesses"] = details[
                                    "weaknesses"
                                ]
                            if _update:
                                existing_vuln.update_record(
                                    **_update, commit=False
                                )

                        # Persist CVSS metrics
                        if details.get("base_score") is not None:
                            _cvss_v = details.get("cvss_version")
                            _cvss_s = details["base_score"]
                            _cvss_vec = details.get("cvss_vector")
                            _dedup = (
                                cve_id.upper(),
                                _cvss_v,
                                float(_cvss_s),
                            )
                            if _dedup not in MetricsModel._seen:
                                try:
                                    MetricsModel.from_cvss(
                                        CVSS(
                                            version=_cvss_v or "",
                                            vector_string=(
                                                _cvss_vec or ""
                                            ),
                                            author="nvd",
                                            base_score=float(
                                                _cvss_s
                                            ),
                                            exploitability_score=(
                                                float(
                                                    details[
                                                        "cvss_exploitability"
                                                    ]
                                                )
                                                if details.get(
                                                    "cvss_exploitability"
                                                )
                                                is not None
                                                else 0
                                            ),
                                            impact_score=(
                                                float(
                                                    details[
                                                        "cvss_impact"
                                                    ]
                                                )
                                                if details.get(
                                                    "cvss_impact"
                                                )
                                                is not None
                                                else 0
                                            ),
                                        ),
                                        existing_vuln.id,
                                    )
                                except Exception:
                                    pass

                        for pkg in pkgs:
                            finding = Finding.get_or_create(
                                pkg.id, cve_id
                            )
                            pair = (finding.id, scan.id)
                            if pair not in observation_pairs:
                                observation_pairs.add(pair)
                                Observation.create(
                                    finding_id=finding.id,
                                    scan_id=scan.id,
                                    commit=False,
                                )
                            # Create initial assessment if none exists
                            fv_key = (finding.id, variant_uuid)
                            if fv_key not in assessed_findings:
                                assessed_findings.add(fv_key)
                                has_assess = db.session.execute(
                                    db.select(Assessment.id).where(
                                        Assessment.finding_id == finding.id,
                                        Assessment.variant_id == variant_uuid,
                                    ).limit(1)
                                ).scalar_one_or_none()
                                if has_assess is None:
                                    Assessment.create(
                                        status="under_investigation",
                                        simplified_status="Pending Assessment",
                                        finding_id=finding.id,
                                        variant_id=variant_uuid,
                                        origin="nvd",
                                        commit=False,
                                    )

                db.session.commit()

                # Recompute scan-history cache for the affected variant.
                try:
                    recompute_variant_cache(variant_uuid)
                except Exception:
                    pass  # non-critical; cache rebuilt lazily

                done_logs = _nvd_scans_in_progress[vid_str].get(
                    "logs", []
                )
                done_logs.append(
                    f"✓ Scan complete — found {len(cves_found)} "
                    f"unique CVEs across {total_cpes} CPEs"
                )
                _nvd_scans_in_progress[vid_str] = {
                    "status": "done",
                    "error": None,
                    "progress": (
                        f"Found {len(cves_found)} CVEs "
                        f"across {total_cpes} CPEs"
                    ),
                    "logs": done_logs,
                    "total": total_cpes,
                    "done_count": total_cpes,
                }

            except Exception as e:
                db.session.rollback()
                _nvd_scans_in_progress[vid_str] = {
                    "status": "error",
                    "error": str(e)[:500],
                    "progress": None,
                }

        thread = threading.Thread(
            target=_run_nvd_scan,
            name=f"nvd-scan-{vid_str}",
            daemon=True,
        )
        thread.start()

        return jsonify({"status": "started", "variant_id": vid_str}), 202

    @app.route('/api/variants/<variant_id>/nvd-scan/status')
    def nvd_scan_status(variant_id):
        """Check the status of a running NVD scan for the given variant."""
        try:
            variant_uuid = uuid_module.UUID(variant_id)
        except ValueError:
            return jsonify({"error": "Invalid variant id"}), 400

        vid_str = str(variant_uuid)
        info = _nvd_scans_in_progress.get(vid_str)
        if info is None:
            return jsonify({"status": "idle"})
        return jsonify(info)

    # ------------------------------------------------------------------
    # OSV Scan — query OSV.dev by PURL for each active package
    # ------------------------------------------------------------------

    _osv_scans_in_progress: dict = {}  # variant_id -> {status, error, progress, logs, total, done_count}

    @app.route('/api/variants/<variant_id>/osv-scan', methods=['POST'])
    def trigger_osv_scan(variant_id):
        """Trigger an OSV PURL-based vulnerability scan for the given variant.

        For every active package that has PURL identifiers, query the OSV API
        and create findings/observations for any vulnerabilities returned.
        The result is stored as a tool scan.
        """
        import threading

        try:
            variant_uuid = uuid_module.UUID(variant_id)
        except ValueError:
            return jsonify({"error": "Invalid variant id"}), 400

        variant = VariantController.get(variant_uuid)
        if variant is None:
            return jsonify({"error": "Variant not found"}), 404

        vid_str = str(variant_uuid)
        if vid_str in _osv_scans_in_progress and _osv_scans_in_progress[vid_str]["status"] == "running":
            return jsonify({"error": "An OSV scan is already in progress for this variant"}), 409

        _osv_scans_in_progress[vid_str] = {
            "status": "running", "error": None, "progress": "starting",
            "logs": [], "total": 0, "done_count": 0,
        }

        def _run_osv_scan():
            with app.app_context():
                _do_osv_scan(vid_str, variant_uuid)

        def _do_osv_scan(vid_str, variant_uuid):
            try:
                from ..controllers.osv_client import OSVClient
                from ..models.vulnerability import Vulnerability as VulnModel
                from ..models.assessment import Assessment

                osv = OSVClient()

                # 1. Get active packages for this variant
                _osv_scans_in_progress[vid_str]["logs"].append(
                    "Resolving active packages…"
                )
                latest_rows = db.session.execute(
                    db.select(Scan.id, Scan.scan_type)
                    .where(Scan.variant_id == variant_uuid)
                    .order_by(Scan.timestamp.desc())
                ).all()
                latest_ids: list = []
                seen_types: set = set()
                for sid, stype in latest_rows:
                    st = stype or "sbom"
                    if st not in seen_types:
                        seen_types.add(st)
                        latest_ids.append(sid)
                    if len(seen_types) >= 2:
                        break

                if not latest_ids:
                    _osv_scans_in_progress[vid_str] = {
                        "status": "error",
                        "error": "No scans found for variant",
                        "progress": None,
                        "logs": _osv_scans_in_progress[vid_str].get(
                            "logs", []
                        ),
                        "total": 0, "done_count": 0,
                    }
                    return

                pkg_sets = _packages_by_scan_ids(latest_ids)
                all_pkg_ids: set = set()
                for s in pkg_sets.values():
                    all_pkg_ids |= s

                if not all_pkg_ids:
                    _osv_scans_in_progress[vid_str] = {
                        "status": "error",
                        "error": "No packages found for variant",
                        "progress": None,
                        "logs": _osv_scans_in_progress[vid_str].get(
                            "logs", []
                        ),
                        "total": 0, "done_count": 0,
                    }
                    return

                packages = db.session.execute(
                    db.select(Package).where(
                        Package.id.in_(all_pkg_ids)
                    )
                ).scalars().all()

                # 2. Collect packages with PURL identifiers
                pkg_purl_list: list[tuple] = []
                seen_purls: set = set()
                for pkg in packages:
                    for purl in (pkg.purl or []):
                        purl_str = str(purl).strip()
                        if (purl_str
                                and purl_str.startswith("pkg:")
                                and purl_str not in seen_purls):
                            seen_purls.add(purl_str)
                            pkg_purl_list.append((purl_str, pkg))
                            break  # one PURL per package

                if not pkg_purl_list:
                    old_logs = _osv_scans_in_progress[vid_str].get(
                        "logs", []
                    )
                    old_logs.append(
                        "ERROR: No packages with valid PURL identifiers"
                    )
                    _osv_scans_in_progress[vid_str] = {
                        "status": "error",
                        "error": "No packages with valid PURL identifiers",
                        "progress": None,
                        "logs": old_logs,
                        "total": 0, "done_count": 0,
                    }
                    return

                total_pkgs = len(pkg_purl_list)
                _osv_scans_in_progress[vid_str]["total"] = total_pkgs
                _osv_scans_in_progress[vid_str]["logs"].append(
                    f"Found {len(packages)} packages, "
                    f"{total_pkgs} with PURL identifiers to query"
                )

                # 3. Create a tool scan
                scan = Scan.create(
                    description="empty description",
                    variant_id=variant_uuid,
                    scan_type="tool",
                    scan_source="osv",
                )
                vulns_found: set = set()
                observation_pairs: set = set()
                assessed_findings: set = set()

                for idx, (purl_str, pkg) in enumerate(
                    pkg_purl_list, 1
                ):
                    _osv_scans_in_progress[vid_str]["progress"] = (
                        f"{idx}/{total_pkgs} packages"
                    )
                    pkg_label = (
                        f"{pkg.name}@{pkg.version}"
                        if pkg.name else purl_str
                    )
                    _osv_scans_in_progress[vid_str]["logs"].append(
                        f"[{idx}/{total_pkgs}] Querying {pkg_label}…"
                    )
                    try:
                        osv_vulns = osv.query_by_purl(purl_str)
                    except Exception as e:
                        log_entry = (
                            f"[{idx}/{total_pkgs}] ERROR "
                            f"{pkg_label}: {str(e)[:200]}"
                        )
                        _osv_scans_in_progress[vid_str]["logs"].append(
                            log_entry
                        )
                        _osv_scans_in_progress[vid_str][
                            "done_count"
                        ] = idx
                        print(
                            f"[OSV Scan] Error querying PURL "
                            f"{purl_str}: {e}",
                            flush=True,
                        )
                        continue

                    vuln_ids = [
                        v.get("id", "")
                        for v in osv_vulns if v.get("id")
                    ]
                    if vuln_ids:
                        ids_str = ', '.join(vuln_ids[:10])
                        ellip = '…' if len(vuln_ids) > 10 else ''
                        log_entry = (
                            f"[{idx}/{total_pkgs}] {pkg_label} → "
                            f"{len(vuln_ids)} vuln(s): {ids_str}{ellip}"
                        )
                    else:
                        log_entry = (
                            f"[{idx}/{total_pkgs}] {pkg_label}"
                            f" → no vulnerabilities"
                        )
                    _osv_scans_in_progress[vid_str]["logs"].append(
                        log_entry
                    )
                    _osv_scans_in_progress[vid_str]["done_count"] = idx

                    for osv_vuln in osv_vulns:
                        vuln_id = osv_vuln.get("id", "")
                        if not vuln_id:
                            continue

                        all_ids = [vuln_id] + [
                            a for a in osv_vuln.get("aliases", [])
                            if a.startswith("CVE-")
                        ]
                        vulns_found.add(vuln_id)

                        # Extract summary/details from OSV response
                        osv_desc = (
                            osv_vuln.get("summary")
                            or osv_vuln.get("details")
                        )

                        for vid in all_ids:
                            existing_vuln = db.session.get(
                                VulnModel, vid.upper()
                            )
                            if existing_vuln is None:
                                existing_vuln = VulnModel.create_record(
                                    id=vid,
                                    description=osv_desc,
                                    links=[
                                        r.get("url")
                                        for r in osv_vuln.get(
                                            "references", []
                                        )
                                        if r.get("url")
                                    ] or None,
                                )
                                existing_vuln.add_found_by("osv")
                            else:
                                existing_vuln.add_found_by("osv")
                                # Enrich if description is missing
                                if (not existing_vuln.description
                                        and osv_desc):
                                    existing_vuln.update_record(
                                        description=osv_desc,
                                        commit=False,
                                    )

                            finding = Finding.get_or_create(
                                pkg.id, vid
                            )
                            pair = (finding.id, scan.id)
                            if pair not in observation_pairs:
                                observation_pairs.add(pair)
                                Observation.create(
                                    finding_id=finding.id,
                                    scan_id=scan.id,
                                    commit=False,
                                )
                            # Create initial assessment if none exists
                            fv_key = (finding.id, variant_uuid)
                            if fv_key not in assessed_findings:
                                assessed_findings.add(fv_key)
                                has_assess = db.session.execute(
                                    db.select(Assessment.id).where(
                                        Assessment.finding_id == finding.id,
                                        Assessment.variant_id == variant_uuid,
                                    ).limit(1)
                                ).scalar_one_or_none()
                                if has_assess is None:
                                    Assessment.create(
                                        status="under_investigation",
                                        simplified_status="Pending Assessment",
                                        finding_id=finding.id,
                                        variant_id=variant_uuid,
                                        origin="osv",
                                        commit=False,
                                    )

                db.session.commit()

                # Recompute scan-history cache for the affected variant.
                try:
                    recompute_variant_cache(variant_uuid)
                except Exception:
                    pass  # non-critical; cache rebuilt lazily

                done_logs = _osv_scans_in_progress[vid_str].get(
                    "logs", []
                )
                done_logs.append(
                    f"✓ Scan complete — found {len(vulns_found)} "
                    f"unique vulnerabilities across {total_pkgs} "
                    f"packages"
                )
                _osv_scans_in_progress[vid_str] = {
                    "status": "done",
                    "error": None,
                    "progress": (
                        f"Found {len(vulns_found)} vulnerabilities "
                        f"across {total_pkgs} packages"
                    ),
                    "logs": done_logs,
                    "total": total_pkgs,
                    "done_count": total_pkgs,
                }

            except Exception as e:
                db.session.rollback()
                _osv_scans_in_progress[vid_str] = {
                    "status": "error",
                    "error": str(e)[:500],
                    "progress": None,
                    "logs": _osv_scans_in_progress[vid_str].get(
                        "logs", []
                    ),
                    "total": _osv_scans_in_progress[vid_str].get(
                        "total", 0
                    ),
                    "done_count": _osv_scans_in_progress[vid_str].get(
                        "done_count", 0
                    ),
                }

        thread = threading.Thread(
            target=_run_osv_scan,
            name=f"osv-scan-{vid_str}",
            daemon=True,
        )
        thread.start()

        return jsonify({"status": "started", "variant_id": vid_str}), 202

    @app.route('/api/variants/<variant_id>/osv-scan/status')
    def osv_scan_status(variant_id):
        """Check the status of a running OSV scan for the given variant."""
        try:
            variant_uuid = uuid_module.UUID(variant_id)
        except ValueError:
            return jsonify({"error": "Invalid variant id"}), 400

        vid_str = str(variant_uuid)
        info = _osv_scans_in_progress.get(vid_str)
        if info is None:
            return jsonify({"status": "idle"})
        return jsonify(info)

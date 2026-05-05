#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Diff computation logic for the scan history list view and detail modal.

Contains the algorithms that compare consecutive scans, compute global
results (SBOM ∪ tool scans), and serialise the list-view response with
diff badges.
"""

from ..controllers.scans import ScanController
from ..models.scan import Scan
from ..models.observation import Observation
from ..models.finding import Finding
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
from ..models.package import Package
from ..extensions import db

from ._scan_queries import (
    _findings_by_scan_ids,
    _vulns_by_scan_ids,
    _packages_by_scan_ids,
    _package_rows,
    _variant_info,
    _load_scan_with_findings,
    _assessments_by_scan,
    _TOOL_SOURCE_LABELS,
)


# ---------------------------------------------------------------------------
# Package-change classification
# ---------------------------------------------------------------------------

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
# Finding-change classification
# ---------------------------------------------------------------------------

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
# Scan ordering
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
# SBOM baseline helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Global result — contributing scans at a point in time
# ---------------------------------------------------------------------------

def _contributing_scans_at(scan: Scan, all_variant_scans: list[Scan]) -> tuple:
    """Determine the scans that contribute to the global result at *scan*.

    Returns ``(sbom_scan_or_None, tool_scan_dict)`` where *tool_scan_dict*
    is ``{scan_source: Scan}`` — the latest tool scan per source at
    *scan.timestamp* (with *scan* itself replacing any earlier same-source).
    """
    scan_type = scan.scan_type or "sbom"
    is_tool = scan_type == "tool"

    sbom_scans = [
        s for s in all_variant_scans
        if (s.scan_type or "sbom") == "sbom"
    ]
    sbom_scans.sort(key=lambda s: s.timestamp)

    if is_tool:
        sbom_scan = _sbom_active_at(sbom_scans, scan.timestamp)
    else:
        sbom_scan = scan  # the scan IS the SBOM

    # Latest tool scan per source at scan's timestamp
    latest_tool: dict = {}  # source -> Scan
    for s in all_variant_scans:
        if (s.scan_type or "sbom") != "tool":
            continue
        if s.timestamp > scan.timestamp:
            continue
        src = s.scan_source or ""
        prev = latest_tool.get(src)
        if prev is None or s.timestamp > prev.timestamp:
            latest_tool[src] = s
    # The current scan (if tool) replaces same-source
    if is_tool:
        latest_tool[scan.scan_source or ""] = scan

    return sbom_scan, latest_tool


def _global_result_id_sets(
    sbom_scan,
    tool_scans: dict,
    *,
    filter_tool_by_sbom_pkgs: bool = False,
) -> tuple:
    """Return ``(finding_ids, vuln_ids, package_ids)`` for a global result.

    *sbom_scan* is the SBOM scan (or ``None``), *tool_scans* is
    ``{source: Scan}`` — the contributing tool scans.

    Uses a single batch DB query with a JOIN so that vulnerability IDs
    are always accurate (no secondary lookup required).

    When *filter_tool_by_sbom_pkgs* is ``True``, tool-scan findings are
    only included if their package is present in the active SBOM.  This
    prevents cross-variant contamination when the Grype export includes
    packages from all variants, and also ensures that findings for
    packages removed between two SBOMs are correctly classified as
    "removed" rather than "unchanged".

    All call sites should pass ``True``; the default remains ``False``
    only for backward compatibility.
    """
    if sbom_scan is None:
        return set(), set(), set()

    contributing_ids = [sbom_scan.id] + [
        s.id for s in tool_scans.values()
    ]
    contributing_ids = list(dict.fromkeys(contributing_ids))

    sbom_pkg_ids = _packages_by_scan_ids([sbom_scan.id]).get(
        sbom_scan.id, set()
    )

    if filter_tool_by_sbom_pkgs:
        tool_scan_ids: set = {s.id for s in tool_scans.values()}
    else:
        tool_scan_ids = set()  # empty → no filtering

    finding_rows = db.session.execute(
        db.select(
            Observation.scan_id,
            Observation.finding_id,
            Finding.package_id,
            Finding.vulnerability_id,
        )
        .join(Finding, Finding.id == Observation.finding_id)
        .where(Observation.scan_id.in_(contributing_ids))
    ).all()

    global_fids: set = set()
    global_vids: set = set()
    for sid, fid, pkg_id, vid in finding_rows:
        # When filtering is enabled, skip tool-scan findings whose
        # package is not in the active SBOM.
        if sid in tool_scan_ids and pkg_id not in sbom_pkg_ids:
            continue
        global_fids.add(fid)
        global_vids.add(vid)

    return global_fids, global_vids, sbom_pkg_ids


def _global_result_counts(
    scan: Scan,
    all_variant_scans: list[Scan],
) -> tuple:
    """Compute (finding_count, vuln_count, package_count) for the global
    result at *scan* using batch DB queries.

    The global result is: SBOM packages/findings ∪ all tool findings.
    """
    sbom_scan, latest_tool = _contributing_scans_at(scan, all_variant_scans)
    fids, vids, pkg_ids = _global_result_id_sets(
        sbom_scan, latest_tool, filter_tool_by_sbom_pkgs=True)
    return len(fids), len(vids), len(pkg_ids)


def _global_assessment_ids_for(
    sbom_scan,
    latest_tool: dict,
) -> set:
    """Return the set of unique Assessment IDs visible in the global result.

    Applies the same SBOM-package filter as ``_global_result_id_sets``:
    tool-scan assessments are only included if their finding's package
    is present in the active SBOM.
    """
    from ..models.assessment import Assessment

    contributing_ids = [sbom_scan.id] if sbom_scan else []
    contributing_ids += [s.id for s in latest_tool.values()]
    contributing_ids = list(dict.fromkeys(contributing_ids))
    if not contributing_ids:
        return set()

    tool_scan_ids: set = {s.id for s in latest_tool.values()}
    sbom_pkg_ids = _packages_by_scan_ids([sbom_scan.id]).get(
        sbom_scan.id, set()
    ) if sbom_scan else set()

    rows = db.session.execute(
        db.select(Assessment.id, Observation.scan_id, Finding.package_id)
        .select_from(Observation)
        .join(Finding, Finding.id == Observation.finding_id)
        .join(Assessment, Assessment.finding_id == Finding.id)
        .join(Scan, Scan.id == Observation.scan_id)
        .where(
            Observation.scan_id.in_(contributing_ids),
            Assessment.variant_id == Scan.variant_id,
            Assessment.origin != "custom",
        )
    ).all()

    result: set = set()
    for aid, sid, pkg_id in rows:
        # Skip tool-scan assessments whose finding's package is not in the SBOM
        if sid in tool_scan_ids and pkg_id not in sbom_pkg_ids:
            continue
        result.add(aid)
    return result


def _global_assessment_count(
    scan: Scan,
    all_variant_scans: list[Scan],
) -> int:
    """Count unique assessments visible in the global result at *scan*."""
    sbom_scan, latest_tool = _contributing_scans_at(scan, all_variant_scans)
    return len(_global_assessment_ids_for(sbom_scan, latest_tool))


def _contributing_scans_before(
    scan: Scan,
    all_variant_scans: list[Scan],
) -> tuple:
    """Like ``_contributing_scans_at`` but for the state **before** *scan*.

    For a tool scan this means: same SBOM, same other-source tool scans,
    but the *previous* same-source tool scan (if any) instead of *scan*.
    """
    scan_type = scan.scan_type or "sbom"
    is_tool = scan_type == "tool"

    sbom_scans = [
        s for s in all_variant_scans
        if (s.scan_type or "sbom") == "sbom"
    ]
    sbom_scans.sort(key=lambda s: s.timestamp)

    if is_tool:
        sbom_scan = _sbom_active_at(sbom_scans, scan.timestamp)
    else:
        sbom_scan = scan

    # Latest tool scan per source, *excluding* the current scan.
    latest_tool: dict = {}
    for s in all_variant_scans:
        if (s.scan_type or "sbom") != "tool":
            continue
        if s.id == scan.id:
            continue
        if s.timestamp > scan.timestamp:
            continue
        src = s.scan_source or ""
        prev = latest_tool.get(src)
        if prev is None or s.timestamp > prev.timestamp:
            latest_tool[src] = s

    return sbom_scan, latest_tool


def _global_result_full(
    scan: Scan,
    all_variant_scans: list[Scan],
) -> dict:
    """Compute the full global result (packages, findings, vulns with
    sources) for the Scan Result detail modal.

    Returns a dict ready for ``jsonify()``.
    """
    sbom_scan, latest_tool = _contributing_scans_at(scan, all_variant_scans)
    if sbom_scan is None:
        return {
            "scan_id": str(scan.id),
            "scan_type": scan.scan_type or "sbom",
            "packages": [], "findings": [], "vulnerabilities": [], "assessments": [],
            "package_count": 0, "finding_count": 0, "vuln_count": 0, "assessment_count": 0,
        }

    contributing_ids = [sbom_scan.id] + [
        s.id for s in latest_tool.values()
    ]
    contributing_ids = list(dict.fromkeys(contributing_ids))

    # IDs of tool scans — used to filter out findings for packages not
    # present in this variant's SBOM (prevents cross-variant leaks when
    # the Grype export includes packages from all variants).
    tool_scan_ids: set = {s.id for s in latest_tool.values()}

    # --- Packages (from SBOM only) ---
    pkg_rows = db.session.execute(
        db.select(
            Package.id, Package.name, Package.version,
            SBOMDocument.source_name, SBOMDocument.format,
        )
        .join(SBOMPackage, SBOMPackage.package_id == Package.id)
        .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
        .where(SBOMDocument.scan_id == sbom_scan.id)
    ).all()
    pkg_map: dict = {}
    sbom_pkg_ids: set = set()
    for pid, pname, pversion, src_name, src_fmt in pkg_rows:
        sbom_pkg_ids.add(pid)
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
    packages = sorted(
        pkg_map.values(),
        key=lambda p: (p["package_name"], p["package_version"]),
    )

    # --- Build scan_id -> source_label mapping ---
    # For SBOM scan: use SBOM document names
    sbom_loaded = _load_scan_with_findings(sbom_scan.id)
    sbom_doc_names = []
    if sbom_loaded and hasattr(sbom_loaded, 'sbom_documents'):
        for doc in (sbom_loaded.sbom_documents or []):
            label = (
                f"{doc.source_name} ({doc.format})"
                if doc.format else doc.source_name
            )
            sbom_doc_names.append(label)
    sbom_source_label = ", ".join(sbom_doc_names) if sbom_doc_names else "SBOM Scan"

    scan_source_labels: dict = {sbom_scan.id: sbom_source_label}
    for tool_scan in latest_tool.values():
        scan_source_labels[tool_scan.id] = _TOOL_SOURCE_LABELS.get(
            tool_scan.scan_source or "", "Vulnerability Scan"
        )

    # --- Findings & vulns (batch query) ---
    obs_rows = db.session.execute(
        db.select(
            Observation.scan_id, Observation.finding_id,
            Finding.package_id, Finding.vulnerability_id,
            Package.name, Package.version,
        )
        .join(Finding, Finding.id == Observation.finding_id)
        .join(Package, Package.id == Finding.package_id)
        .where(Observation.scan_id.in_(contributing_ids))
    ).all()

    finding_map: dict = {}
    vuln_set: dict = {}
    for sid, fid, pkg_id, vid, pname, pversion in obs_rows:
        # Skip tool-scan findings whose package is not in the SBOM
        if sid in tool_scan_ids and pkg_id not in sbom_pkg_ids:
            continue
        source_label = scan_source_labels.get(sid, "Unknown")
        if fid not in finding_map:
            finding_map[fid] = {
                "finding_id": str(fid),
                "package_name": pname or "unknown",
                "package_version": pversion or "",
                "package_id": str(pkg_id),
                "vulnerability_id": vid,
                "sources": [source_label],
            }
        else:
            if source_label not in finding_map[fid]["sources"]:
                finding_map[fid]["sources"].append(source_label)
        vuln_set.setdefault(vid, set()).add(source_label)

    findings = sorted(
        finding_map.values(),
        key=lambda f: (f["vulnerability_id"], f["package_name"]),
    )
    vulnerabilities = [
        {"vulnerability_id": vid, "sources": sorted(srcs)}
        for vid, srcs in sorted(vuln_set.items())
    ]

    # --- Assessments for active findings in this variant ---
    # Use the same proven JOIN pattern as _assessment_rows_for_scans
    # (Observation → Finding → Assessment + Scan for variant match).
    from ..models.assessment import Assessment

    assessments: list = []
    assess_rows = db.session.execute(
        db.select(
            Assessment.id,
            Finding.vulnerability_id,
            Assessment.status,
            Assessment.simplified_status,
            Assessment.justification,
            Assessment.impact_statement,
            Assessment.status_notes,
            Observation.scan_id,
            Finding.package_id,
        )
        .select_from(Observation)
        .join(Finding, Finding.id == Observation.finding_id)
        .join(Assessment, Assessment.finding_id == Finding.id)
        .join(Scan, Scan.id == Observation.scan_id)
        .where(
            Observation.scan_id.in_(contributing_ids),
            Assessment.variant_id == Scan.variant_id,
            Assessment.origin != "custom",
        )
    ).all()

    seen_assess: set = set()
    for aid, vid, status, simp_status, justification, impact, notes, sid, pkg_id in assess_rows:
        # Skip tool-scan assessments whose finding's package is not in SBOM
        if sid in tool_scan_ids and pkg_id not in sbom_pkg_ids:
            continue
        if aid in seen_assess:
            continue
        seen_assess.add(aid)
        assessments.append({
            "vulnerability_id": vid,
            "status": status or "under_investigation",
            "simplified_status": simp_status or "Pending Assessment",
            "justification": justification or "",
            "impact_statement": impact or "",
            "status_notes": notes or "",
        })
    assessments.sort(key=lambda a: a["vulnerability_id"])

    return {
        "scan_id": str(scan.id),
        "scan_type": scan.scan_type or "sbom",
        "packages": packages,
        "findings": findings,
        "vulnerabilities": vulnerabilities,
        "assessments": assessments,
        "package_count": len(packages),
        "finding_count": len(findings),
        "vuln_count": len(vulnerabilities),
        "assessment_count": len(assessments),
    }


# ---------------------------------------------------------------------------
# List-view serialisation with diff badges
# ---------------------------------------------------------------------------

def _serialize_list_with_diff(scans: list[Scan]) -> list[dict]:
    if not scans:
        return []

    scan_ids = [s.id for s in scans]
    findings_map = _findings_by_scan_ids(scan_ids)
    packages_map = _packages_by_scan_ids(scan_ids)
    vulns_map = _vulns_by_scan_ids(scan_ids)
    prev_map = _prev_scan_map(scans)
    variant_map = _variant_info(list({s.variant_id for s in scans}))
    assessments_map = _assessments_by_scan(scans)

    # For tool scans: determine the SBOM baseline that was active at the
    # time of each tool scan.  This ensures that historical tool scan
    # entries show the "newly detected" counts as they were at scan time,
    # not re-calculated against a later SBOM import.
    _sbom_scans_by_variant(scans)  # pre-warm; used internally by helpers
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

    # Pre-build per-variant scan lists so that contributing-scan helpers
    # only see scans from the same variant (avoids cross-variant leaks).
    _scans_by_variant: dict = {}  # variant_id -> [Scan, …]
    for s in scans:
        _scans_by_variant.setdefault(s.variant_id, []).append(s)

    # Second pass: build result dicts
    # Track latest tool-scan findings/vulns per (variant, source) as we
    # iterate in chronological order so we can compute the "global" result
    # (SBOM ∪ all latest sources) at each point in time.
    # Also track the SBOM baseline that was active at each tool scan's
    # timestamp so historical counts stay stable.
    running_src_findings: dict = {}  # (variant_id, source) -> set
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

        # Assessment counts
        assess_info = assessments_map.get(scan.id, {"total": 0, "added": 0, "unchanged": 0, "removed": 0})
        base["assessment_count"] = assess_info["total"]
        base["assessments_added"] = assess_info["added"]
        base["assessments_unchanged"] = assess_info["unchanged"]
        base["assessments_removed"] = assess_info["removed"]

        is_tool_scan = (scan.scan_type or "sbom") == "tool"

        if is_tool_scan:
            # ---- Tool scan: diff against the GLOBAL state ----
            # Compute the global result BEFORE and AFTER this scan using
            # shared helpers that do a proper DB-level JOIN, so vuln/
            # finding counts are always accurate.
            variant_scans = _scans_by_variant.get(scan.variant_id, [])
            sbom_before, tools_before = _contributing_scans_before(scan, variant_scans)
            sbom_after, tools_after = _contributing_scans_at(scan, variant_scans)

            before_fids, before_vids, _ = _global_result_id_sets(
                sbom_before, tools_before,
                filter_tool_by_sbom_pkgs=True)
            after_fids, after_vids, after_pkg_ids = _global_result_id_sets(
                sbom_after, tools_after,
                filter_tool_by_sbom_pkgs=True)

            # Update running tracker (still needed by the SBOM branch)
            src_key = (scan.variant_id, scan.scan_source)
            running_src_findings[src_key] = curr_f

            base["is_first"] = (prev is None)
            base["packages_added"] = 0
            base["packages_removed"] = 0
            base["packages_upgraded"] = 0
            base["packages_unchanged"] = 0
            base["findings_upgraded"] = 0
            base["findings_unchanged"] = 0
            base["findings_added"] = len(after_fids - before_fids)
            base["findings_removed"] = len(before_fids - after_fids)
            base["vulns_added"] = len(after_vids - before_vids)
            base["vulns_removed"] = len(before_vids - after_vids)
            base["vulns_unchanged"] = 0

            # "Newly detected" ≡ net additions to the global result so
            # that  prev Scan Result + newly_detected == Scan Result.
            base["newly_detected_vulns"] = len(after_vids - before_vids)
            base["newly_detected_findings"] = len(after_fids - before_fids)

            # Assessments: before/after global sets
            before_assess = _global_assessment_ids_for(sbom_before, tools_before)
            after_assess = _global_assessment_ids_for(sbom_after, tools_after)
            base["newly_detected_assessments"] = len(after_assess - before_assess)

            # Branch result = SBOM ∪ THIS tool scan only (one source)
            branch_fids, branch_vids, branch_pkg_ids = _global_result_id_sets(
                sbom_after, {scan.scan_source or "": scan},
                filter_tool_by_sbom_pkgs=True)
            base["branch_finding_count"] = len(branch_fids)
            base["branch_vuln_count"] = len(branch_vids)
            base["branch_package_count"] = len(branch_pkg_ids)

            # Global result = SBOM ∪ ALL tool sources (same helper)
            base["global_finding_count"] = len(after_fids)
            base["global_vuln_count"] = len(after_vids)
            base["global_package_count"] = len(after_pkg_ids)
            base["global_assessment_count"] = _global_assessment_count(scan, variant_scans)

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
            base["is_first"] = False

            upgraded_pairs = entry["upgraded_pairs"]
            prev_pkgs = packages_map.get(prev.id, set())
            base["packages_added"] = entry.get("truly_added_p", len(entry["curr_p"] - prev_pkgs))
            base["packages_removed"] = entry.get("truly_removed_p", len(prev_pkgs - entry["curr_p"]))
            base["packages_upgraded"] = len(upgraded_pairs)

            # --- Compute scan-result sets via the shared helper ---
            # Enable SBOM-package filtering so that tool findings for
            # packages removed between the two SBOMs are correctly
            # classified as "removed" rather than "unchanged".
            variant_scans = _scans_by_variant.get(scan.variant_id, [])
            _, latest_tool = _contributing_scans_at(scan, variant_scans)
            curr_scan_result_f, curr_scan_result_v, _ = (
                _global_result_id_sets(
                    scan, latest_tool,
                    filter_tool_by_sbom_pkgs=True))
            prev_sr_f, prev_sr_v, _ = (
                _global_result_id_sets(
                    prev, latest_tool,
                    filter_tool_by_sbom_pkgs=True))

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
            base["newly_detected_assessments"] = None
            base["branch_finding_count"] = None
            base["branch_vuln_count"] = None
            base["branch_package_count"] = None

            # Scan Result — shared helper (SBOM ∪ filtered tool findings)
            has_tool_scans = any(
                vid == scan.variant_id for (vid, _src) in running_src_findings
            )
            if has_tool_scans:
                variant_scans = _scans_by_variant.get(scan.variant_id, [])
                g_f, g_v, g_p = _global_result_counts(scan, variant_scans)
                base["global_finding_count"] = g_f
                base["global_vuln_count"] = g_v
                base["global_package_count"] = g_p
                global_assess = _global_assessment_count(scan, variant_scans)
                base["global_assessment_count"] = global_assess
                # Tool-scan contributions that already existed are added to
                # "unchanged" only — "detected" stays at what the SBOM found.
                if global_assess > base["assessment_count"]:
                    base["assessments_unchanged"] += global_assess - base["assessment_count"]
            else:
                base["global_finding_count"] = None
                base["global_vuln_count"] = None
                base["global_package_count"] = None
                base["global_assessment_count"] = None

            doc_formats = set()
            for doc in (scan.sbom_documents or []):
                if doc.format:
                    doc_formats.add(doc.format)
            base["formats"] = sorted(doc_formats)

        result.append(base)
    return result

#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid as uuid_module

from flask import jsonify
from sqlalchemy.orm import selectinload

from ..controllers.scans import ScanController
from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController
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


def _serialize_list_with_diff(scans: list[Scan]) -> list[dict]:
    if not scans:
        return []

    scan_ids = [s.id for s in scans]
    findings_map = _findings_by_scan_ids(scan_ids)
    packages_map = _packages_by_scan_ids(scan_ids)
    vulns_map = _vulns_by_scan_ids(scan_ids)
    prev_map = _prev_scan_map(scans)
    variant_map = _variant_info(list({s.variant_id for s in scans}))

    # For tool scans: find the latest SBOM scan per variant so we can compute
    # "newly detected" counts (findings/vulns found by the tool but absent
    # from the SBOM baseline).
    latest_sbom = _latest_sbom_scan_per_variant(scans)
    # We may need findings/vulns for SBOM scans that aren't already in our maps
    # (they already are because all scans in the list are fetched).
    sbom_findings: dict = {}  # variant_id -> set(finding_id)
    sbom_vulns: dict = {}     # variant_id -> set(vulnerability_id)
    for vid, sbom_scan in latest_sbom.items():
        sbom_findings[vid] = findings_map.get(sbom_scan.id, set())
        sbom_vulns[vid] = vulns_map.get(sbom_scan.id, set())

    # First pass: compute package diffs and collect all finding IDs that need
    # package-level info for upgrade classification.
    scan_data = []
    all_fids_needing_lookup: set = set()

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
                pkg_lk = _package_rows(raw_added_p | raw_removed_p)
                truly_added, truly_removed, upgraded = _classify_package_changes(
                    raw_added_p, raw_removed_p, pkg_lk
                )
                entry["truly_added_p"] = len(truly_added)
                entry["truly_removed_p"] = len(truly_removed)
                entry["upgraded_pairs"] = upgraded

                if upgraded:
                    prev_f = findings_map.get(prev.id, set())
                    raw_added_f = curr_f - prev_f
                    raw_removed_f = prev_f - curr_f
                    entry["raw_added_f"] = raw_added_f
                    entry["raw_removed_f"] = raw_removed_f
                    all_fids_needing_lookup |= raw_added_f | raw_removed_f

        scan_data.append(entry)

    # Single batch query: finding_id -> (package_id, vulnerability_id)
    fid_to_info: dict = {}
    if all_fids_needing_lookup:
        rows = db.session.execute(
            db.select(Finding.id, Finding.package_id, Finding.vulnerability_id)
            .where(Finding.id.in_(all_fids_needing_lookup))
        ).all()
        fid_to_info = {r[0]: (r[1], r[2]) for r in rows}

    # Second pass: build result dicts
    # Track latest tool-scan findings/vulns per (variant, source) as we
    # iterate in chronological order so we can compute the "global" result
    # (SBOM ∪ all latest sources) at each point in time.
    running_src_findings: dict = {}  # (variant_id, source) -> set
    running_src_vulns: dict = {}     # (variant_id, source) -> set
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
            # Compare the global result (SBOM ∪ all tool sources) before and
            # after this scan so that added/removed counts reflect the real
            # impact on the combined result, not the delta vs. the previous
            # scan of the same tool type.
            baseline_f = sbom_findings.get(scan.variant_id, set())
            baseline_v = sbom_vulns.get(scan.variant_id, set())
            src_key = (scan.variant_id, scan.scan_source)

            # Global state BEFORE this scan
            global_before_f = set(baseline_f)
            global_before_v = set(baseline_v)
            for (vid, _src), f_ids in running_src_findings.items():
                if vid == scan.variant_id:
                    global_before_f |= f_ids
            for (vid, _src), v_ids in running_src_vulns.items():
                if vid == scan.variant_id:
                    global_before_v |= v_ids

            # Update running tracker for this source
            running_src_findings[src_key] = curr_f
            running_src_vulns[src_key] = curr_v

            # Global state AFTER this scan
            global_f = set(baseline_f)
            global_v = set(baseline_v)
            for (vid, _src), f_ids in running_src_findings.items():
                if vid == scan.variant_id:
                    global_f |= f_ids
            for (vid, _src), v_ids in running_src_vulns.items():
                if vid == scan.variant_id:
                    global_v |= v_ids

            base["is_first"] = (prev is None)
            base["packages_added"] = 0
            base["packages_removed"] = 0
            base["packages_upgraded"] = 0
            base["findings_upgraded"] = 0
            base["findings_added"] = len(global_f - global_before_f)
            base["findings_removed"] = len(global_before_f - global_f)
            base["vulns_added"] = len(global_v - global_before_v)
            base["vulns_removed"] = len(global_before_v - global_v)

            # "Newly detected" = findings/vulns added to the global result.
            # By definition these are NOT in the SBOM baseline since SBOM is
            # part of both global_before and global_after.
            base["newly_detected_findings"] = base["findings_added"]
            base["newly_detected_vulns"] = base["vulns_added"]

            # Branch result = SBOM baseline ∪ this tool scan only
            sbom_scan_obj = latest_sbom.get(scan.variant_id)
            sbom_pkg = packages_map.get(
                sbom_scan_obj.id, set()
            ) if sbom_scan_obj else set()
            base["branch_finding_count"] = len(baseline_f | curr_f)
            base["branch_vuln_count"] = len(baseline_v | curr_v)
            base["branch_package_count"] = len(sbom_pkg)

            # Global result = SBOM baseline ∪ all latest tool-scan sources
            base["global_finding_count"] = len(global_f)
            base["global_vuln_count"] = len(global_v)
            base["global_package_count"] = len(sbom_pkg)

            base["formats"] = []
        elif prev is None:
            base["is_first"] = True
            base["findings_added"] = None
            base["findings_removed"] = None
            base["findings_upgraded"] = None
            base["packages_added"] = None
            base["packages_removed"] = None
            base["packages_upgraded"] = None
            base["vulns_added"] = None
            base["vulns_removed"] = None
        else:
            prev_f = findings_map.get(prev.id, set())
            prev_v = vulns_map.get(prev.id, set())
            base["is_first"] = False

            upgraded_pairs = entry["upgraded_pairs"]
            prev_pkgs = packages_map.get(prev.id, set())
            base["packages_added"] = entry.get("truly_added_p", len(entry["curr_p"] - prev_pkgs))
            base["packages_removed"] = entry.get("truly_removed_p", len(prev_pkgs - entry["curr_p"]))
            base["packages_upgraded"] = len(upgraded_pairs)

            raw_added_f = curr_f - prev_f
            raw_removed_f = prev_f - curr_f

            if upgraded_pairs and entry["raw_added_f"]:
                # Classify findings on upgraded packages
                upgraded_old_ids = {str(old_pkg.id) for old_pkg, _ in upgraded_pairs}
                upgraded_new_ids = {str(new_pkg.id) for _, new_pkg in upgraded_pairs}
                # Vulns on removed side that belong to upgraded old packages
                removed_vulns_on_upgraded = {
                    fid_to_info[fid][1]
                    for fid in raw_removed_f
                    if fid in fid_to_info and str(fid_to_info[fid][0]) in upgraded_old_ids
                }
                upgraded_count = sum(
                    1 for fid in raw_added_f
                    if fid in fid_to_info
                    and str(fid_to_info[fid][0]) in upgraded_new_ids
                    and fid_to_info[fid][1] in removed_vulns_on_upgraded
                )
                base["findings_upgraded"] = upgraded_count
                base["findings_added"] = len(raw_added_f) - upgraded_count
                base["findings_removed"] = len(raw_removed_f) - upgraded_count
            else:
                base["findings_upgraded"] = 0
                base["findings_added"] = len(raw_added_f)
                base["findings_removed"] = len(raw_removed_f)

            base["vulns_added"] = len(curr_v - prev_v)
            base["vulns_removed"] = len(prev_v - curr_v)

        # ---- Non-tool (SBOM) scans: set tool-only fields to None ----
        if not is_tool_scan:
            base["newly_detected_findings"] = None
            base["newly_detected_vulns"] = None
            base["branch_finding_count"] = None
            base["branch_vuln_count"] = None
            base["branch_package_count"] = None

            # Scan Result for SBOM scans = SBOM ∪ all latest tool-scan sources
            has_tool_scans = any(
                vid == scan.variant_id for (vid, _src) in running_src_findings
            )
            if has_tool_scans:
                merge_f = set(curr_f)
                merge_v = set(curr_v)
                for (vid, _src), f_ids in running_src_findings.items():
                    if vid == scan.variant_id:
                        merge_f |= f_ids
                for (vid, _src), v_ids in running_src_vulns.items():
                    if vid == scan.variant_id:
                        merge_v |= v_ids
                base["global_finding_count"] = len(merge_f)
                base["global_vuln_count"] = len(merge_v)
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


def _obs_to_dict(obs: Observation) -> dict:
    f = obs.finding
    pkg = f.package
    return {
        "finding_id": str(f.id),
        "package_name": pkg.name if pkg else "unknown",
        "package_version": pkg.version if pkg else "",
        "package_id": str(f.package_id),
        "vulnerability_id": f.vulnerability_id,
    }


def _classify_finding_changes(findings_added, findings_removed, upgraded_pairs):
    """Separate findings into truly-added, truly-removed, and upgraded.

    A finding is "upgraded" when the same vulnerability_id appears in both
    added and removed sets, and the package_id changed between an upgraded
    package pair.

    Args:
        findings_added: list of obs dicts (from _obs_to_dict) that were added
        findings_removed: list of obs dicts that were removed
        upgraded_pairs: list of (old_pkg, new_pkg) Package objects

    Returns (truly_added, truly_removed, upgraded_findings) where
    upgraded_findings is a list of dicts with vuln_id, pkg_name, old_version, new_version.
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
            break

    truly_added = [f for f in findings_added if f["finding_id"] not in matched_added_ids]
    truly_removed = [f for f in findings_removed if f["finding_id"] not in matched_removed_ids]
    return truly_added, truly_removed, upgraded_findings


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def init_app(app):

    # Track running Grype scans so we can report status / prevent duplicates
    _grype_scans_in_progress: dict = {}  # variant_id -> {status, error, progress, logs, total, done_count}

    @app.route('/api/scans')
    def list_all_scans():
        scans = ScanController.get_all()
        return jsonify(_serialize_list_with_diff(scans))

    @app.route('/api/projects/<project_id>/scans')
    def list_scans_by_project(project_id):
        project = ProjectController.get(project_id)
        if project is None:
            return jsonify({"error": "Project not found"}), 404
        scans = ScanController.get_by_project(project_id)
        return jsonify(_serialize_list_with_diff(scans))

    @app.route('/api/variants/<variant_id>/scans')
    def list_scans_by_variant(variant_id):
        variant = VariantController.get(variant_id)
        if variant is None:
            return jsonify({"error": "Variant not found"}), 404
        scans = ScanController.get_by_variant(variant_id)
        return jsonify(_serialize_list_with_diff(scans))

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

        # --- Findings diff ---
        current_finding_ids = {obs.finding_id for obs in scan.observations}
        curr_vulns = {obs.finding.vulnerability_id for obs in scan.observations}

        if prev_scan_id is None:
            findings_added = [_obs_to_dict(obs) for obs in scan.observations]
            findings_removed: list = []
            vulns_added = sorted(curr_vulns)
            vulns_removed: list = []
        else:
            prev_scan = _load_scan_with_findings(prev_scan_id)
            prev_finding_ids = {obs.finding_id for obs in prev_scan.observations} if prev_scan else set()
            prev_vulns = {obs.finding.vulnerability_id for obs in prev_scan.observations} if prev_scan else set()
            added_fids = current_finding_ids - prev_finding_ids
            removed_fids = prev_finding_ids - current_finding_ids
            findings_added = [_obs_to_dict(obs) for obs in scan.observations if obs.finding_id in added_fids]
            findings_removed = (
                [_obs_to_dict(obs) for obs in prev_scan.observations if obs.finding_id in removed_fids]
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

        # --- Classify findings on upgraded packages ---
        if prev_scan_id is not None and upgraded_pairs:
            findings_added, findings_removed, findings_upgraded = _classify_finding_changes(
                findings_added, findings_removed, upgraded_pairs
            )
        else:
            findings_upgraded = []

        # Sort for stable output
        packages_added.sort(key=lambda p: (p["package_name"], p["package_version"]))
        packages_removed.sort(key=lambda p: (p["package_name"], p["package_version"]))
        packages_upgraded.sort(key=lambda p: (p["package_name"], p["old_version"]))
        findings_upgraded.sort(key=lambda f: (f["package_name"], f["vulnerability_id"]))

        # --- Newly detected (tool scans only): findings/vulns that are in
        # this tool scan but NOT in the latest SBOM scan AND NOT already
        # present in the previous tool scan.
        newly_detected_findings_count = None
        newly_detected_vulns_count = None
        newly_detected_findings_list = None
        newly_detected_vulns_list = None
        if is_tool_scan:
            sbom_scans = [s for s in all_variant_scans if (s.scan_type or "sbom") == "sbom"]
            sbom_fids: set = set()
            sbom_vids: set = set()
            if sbom_scans:
                latest_sbom = sbom_scans[-1]  # ordered by timestamp
                sbom_scan_loaded = _load_scan_with_findings(latest_sbom.id)
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
                _obs_to_dict(obs) for obs in scan.observations
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
            "packages_added": packages_added,
            "packages_removed": packages_removed,
            "packages_upgraded": packages_upgraded,
            "vulns_added": vulns_added,
            "vulns_removed": vulns_removed,
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

        finding_map: dict = {}   # finding_id -> dict
        vuln_set: dict = {}      # vulnerability_id -> set of sources
        for sid, loaded in loaded_scans.items():
            s_type = loaded.scan_type or "sbom"
            if s_type == "tool":
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
                # A CPE is queryable when it has a valid part (a/o/h) and
                # at least a non-wildcard product.  Wildcard vendor is
                # acceptable — the NVD virtualMatchString API handles it.
                _valid_cpe_parts = {"a", "o", "h"}
                cpe_to_pkgs: dict = {}  # cpeName -> list[Package]
                for pkg in packages:
                    for cpe in (pkg.cpe or []):
                        parts = cpe.split(":")
                        if (len(parts) >= 6
                                and parts[2] in _valid_cpe_parts
                                and parts[4] != "*"):
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
                        # wildcard fields (vendor/version) so the NVD
                        # applies pattern matching instead of a
                        # dictionary lookup.
                        cpe_parts = cpe_name.split(":")
                        has_wildcards = (
                            len(cpe_parts) >= 6
                            and (cpe_parts[3] == "*"
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

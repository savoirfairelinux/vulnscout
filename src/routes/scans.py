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
    """Return {scan.id: previous_scan_or_None} grouped by variant, ordered by timestamp."""
    by_variant: dict = {}
    for s in scans:
        by_variant.setdefault(s.variant_id, []).append(s)
    mapping: dict = {}
    for variant_scans in by_variant.values():
        for i, s in enumerate(variant_scans):
            mapping[s.id] = variant_scans[i - 1] if i > 0 else None
    return mapping


# ---------------------------------------------------------------------------
# Helpers — serialisation for list view
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

    # First pass: compute package diffs and collect all finding IDs that need
    # package-level info for upgrade classification.
    scan_data = []
    all_fids_needing_lookup: set = set()

    for scan in scans:
        curr_f = findings_map.get(scan.id, set())
        curr_p = packages_map.get(scan.id, set())
        curr_v = vulns_map.get(scan.id, set())
        prev = prev_map.get(scan.id)

        entry = {
            "scan": scan,
            "curr_f": curr_f, "curr_p": curr_p, "curr_v": curr_v,
            "prev": prev,
            "upgraded_pairs": [],
            "raw_added_f": set(), "raw_removed_f": set(),
        }

        if prev is not None:
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

        if prev is None:
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

    @app.route('/api/scans/<scan_id>/diff')
    def get_scan_diff(scan_id):
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400

        scan = _load_scan_with_findings(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404

        # Locate the previous scan for the same variant
        all_variant_scans = ScanController.get_by_variant(scan.variant_id)
        prev_scan_id = None
        for i, s in enumerate(all_variant_scans):
            if s.id == scan.id and i > 0:
                prev_scan_id = all_variant_scans[i - 1].id
                break

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

        # --- Packages diff ---
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

        return jsonify({
            "scan_id": str(scan.id),
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
        })

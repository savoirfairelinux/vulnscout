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
    prev_map = _prev_scan_map(scans)
    variant_map = _variant_info(list({s.variant_id for s in scans}))

    result = []
    for scan in scans:
        base = ScanController.serialize(scan)
        variant_name, project_name = variant_map.get(scan.variant_id, (None, None))
        base["variant_name"] = variant_name
        base["project_name"] = project_name
        curr_f = findings_map.get(scan.id, set())
        curr_p = packages_map.get(scan.id, set())
        prev = prev_map.get(scan.id)

        base["finding_count"] = len(curr_f)
        base["package_count"] = len(curr_p)

        if prev is None:
            base["is_first"] = True
            base["findings_added"] = None
            base["findings_removed"] = None
            base["packages_added"] = None
            base["packages_removed"] = None
        else:
            prev_f = findings_map.get(prev.id, set())
            prev_p = packages_map.get(prev.id, set())
            base["is_first"] = False
            base["findings_added"] = len(curr_f - prev_f)
            base["findings_removed"] = len(prev_f - curr_f)
            base["packages_added"] = len(curr_p - prev_p)
            base["packages_removed"] = len(prev_p - curr_p)

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
            selectinload(Scan.observations)
            .selectinload(Observation.finding)
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

        if prev_scan_id is None:
            findings_added = [_obs_to_dict(obs) for obs in scan.observations]
            findings_removed: list = []
        else:
            prev_scan = _load_scan_with_findings(prev_scan_id)
            prev_finding_ids = {obs.finding_id for obs in prev_scan.observations} if prev_scan else set()
            added_fids = current_finding_ids - prev_finding_ids
            removed_fids = prev_finding_ids - current_finding_ids
            findings_added = [_obs_to_dict(obs) for obs in scan.observations if obs.finding_id in added_fids]
            findings_removed = (
                [_obs_to_dict(obs) for obs in prev_scan.observations if obs.finding_id in removed_fids]
                if prev_scan else []
            )

        # --- Packages diff ---
        scans_to_query = [scan.id] if prev_scan_id is None else [scan.id, prev_scan_id]
        pkg_sets = _packages_by_scan_ids(scans_to_query)
        curr_pkg_ids = pkg_sets.get(scan.id, set())
        prev_pkg_ids = pkg_sets.get(prev_scan_id, set()) if prev_scan_id else set()

        added_pkg_ids = curr_pkg_ids - prev_pkg_ids
        removed_pkg_ids = prev_pkg_ids - curr_pkg_ids

        all_relevant_pkg_ids = added_pkg_ids | removed_pkg_ids
        pkg_lookup = _package_rows(all_relevant_pkg_ids)

        packages_added = [_pkg_to_dict(pkg_lookup[pid]) for pid in added_pkg_ids if pid in pkg_lookup]
        packages_removed = [_pkg_to_dict(pkg_lookup[pid]) for pid in removed_pkg_ids if pid in pkg_lookup]

        # Sort for stable output
        packages_added.sort(key=lambda p: (p["package_name"], p["package_version"]))
        packages_removed.sort(key=lambda p: (p["package_name"], p["package_version"]))

        return jsonify({
            "scan_id": str(scan.id),
            "previous_scan_id": str(prev_scan_id) if prev_scan_id else None,
            "is_first": prev_scan_id is None,
            "finding_count": len(current_finding_ids),
            "package_count": len(curr_pkg_ids),
            "findings_added": findings_added,
            "findings_removed": findings_removed,
            "packages_added": packages_added,
            "packages_removed": packages_removed,
        })


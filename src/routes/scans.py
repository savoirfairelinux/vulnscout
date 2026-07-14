# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Scan CRUD and list/diff/global-result route handlers.

Computation helpers live in sibling modules:
- ``_scan_queries``  — low-level DB batch queries
- ``_scan_diff``     — diff algorithms & list-view serialisation
"""

import re
import uuid as uuid_module
from datetime import datetime, timezone

from flask import Flask, jsonify, request as flask_request
from flask.typing import ResponseReturnValue

from ..controllers.scans import ScanController
from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController
from ..models.observation import Observation
from ..models.finding import Finding
from ..models.scan import Scan
from ..extensions import db

from ._scan_queries import (
    _packages_by_scan_ids,
    _package_rows,
    _pkg_to_dict,
    _load_scan_with_findings,
    _obs_to_dict,
    _origin_for_scan,
    _assessments_detail_for_scan,
    ObsDict,
)
from ._scan_diff import (
    _classify_package_changes,
    _contributing_scans_at,
    _contributing_scans_before,
    _global_result_id_sets,
    _global_assessment_ids_for,
    _global_result_full,
    serialize_list_with_diff_cached,
)


# ---------------------------------------------------------------------------
# Re-export for backward compatibility with external consumers
# (merger_ci, test_scan, scan_triggers, settings)
# ---------------------------------------------------------------------------
# These are accessed via ``from ..routes.scans import <name>``.
# After all call-sites are updated the re-exports can be removed.
from ._scan_queries import (  # noqa: F401  — re-exports
    _findings_by_scan_ids,
    _vulns_by_scan_ids,
    _variant_info,
    _TOOL_SOURCE_LABELS,
)
from ._scan_diff import (  # noqa: F401  — re-exports
    _classify_finding_changes,
    _prev_scan_map,
    _serialize_list_with_diff,
)


# ---------------------------------------------------------------------------
# Scan export helpers — mirror the frontend strip/transform functions
# ---------------------------------------------------------------------------

def _extract_supplier_name(supplier: str) -> str:
    """Strip SPDX-style prefix and trailing email from a supplier string."""
    s = re.sub(r'^[^:]+:\s*', '', supplier)
    return re.sub(r'\s*\([^)]*\)$', '', s)


def _scan_meta(scan: Scan, variant_name: str | None = None, project_name: str | None = None) -> dict[str, object]:
    """Build scan metadata dict for export."""
    scan_type = scan.scan_type or "sbom"
    ts: str | datetime = scan.timestamp
    if isinstance(ts, datetime):
        ts = ts.isoformat()
    return {
        "scan_id": str(scan.id),
        "timestamp": ts,
        "scan_type": "vulnerability_scan" if scan_type == "tool" else "import_sbom",
        "scan_source": scan.scan_source or None,
        "project_name": project_name or None,
        "variant_id": str(scan.variant_id),
        "variant_name": variant_name or None,
    }


def _strip_finding(entry: dict) -> dict:
    supplier = _extract_supplier_name(entry.get("package_supplier", "") or "")
    result = {
        "vulnerability_id": entry.get("vulnerability_id", ""),
        "package_name": entry.get("package_name", ""),
        "package_version": entry.get("package_version", ""),
    }
    if supplier:
        result["supplier"] = supplier
    return result


def _strip_package(entry: dict) -> dict:
    supplier = _extract_supplier_name(entry.get("package_supplier", "") or "")
    result = {
        "package_name": entry.get("package_name", ""),
        "package_version": entry.get("package_version", ""),
    }
    if supplier:
        result["supplier"] = supplier
    return result


def _strip_package_upgrade(entry: dict) -> dict:
    supplier = _extract_supplier_name(entry.get("package_supplier", "") or "")
    result = {
        "package_name": entry.get("package_name", ""),
        "old_version": entry.get("old_version", ""),
        "new_version": entry.get("new_version", ""),
    }
    if supplier:
        result["supplier"] = supplier
    return result


def _strip_finding_upgrade(entry: dict) -> dict:
    supplier = _extract_supplier_name(entry.get("package_supplier", "") or "")
    result = {
        "vulnerability_id": entry.get("vulnerability_id", ""),
        "package_name": entry.get("package_name", ""),
        "old_version": entry.get("old_version", ""),
        "new_version": entry.get("new_version", ""),
    }
    if supplier:
        result["supplier"] = supplier
    return result


def _strip_assessment(entry: dict) -> dict:
    return {
        "vulnerability_id": entry.get("vulnerability_id", ""),
        "status": entry.get("status", ""),
        "simplified_status": entry.get("simplified_status", ""),
        "justification": entry.get("justification", ""),
        "impact_statement": entry.get("impact_statement", ""),
        "status_notes": entry.get("status_notes", ""),
    }


def _build_diff_export(
    scan: Scan,
    diff: dict,
    variant_name: str | None = None,
    project_name: str | None = None,
) -> dict[str, object]:
    """Build the export-ready dict from a scan and its diff response."""
    meta = _scan_meta(scan, variant_name, project_name)
    is_tool = (scan.scan_type or "sbom") == "tool"

    if is_tool:
        return {
            **meta,
            "vulnerabilities": diff.get("all_vulns") or diff.get("vulns_added", []),
            "findings": [
                _strip_finding(f)
                for f in (diff.get("all_findings") or diff.get("findings_added", []))
            ],
            "newly_detected_vulns": diff.get("newly_detected_vulns_list") or [],
            "newly_detected_findings": [
                _strip_finding(f)
                for f in (diff.get("newly_detected_findings_list") or [])
            ],
            "newly_detected_assessments": [
                _strip_assessment(a)
                for a in (diff.get("newly_detected_assessments_list") or [])
            ],
        }

    # SBOM scan
    base: dict = {
        **meta,
        "vulnerabilities": diff.get("all_vulns") or (diff.get("vulns_added", []) + diff.get("vulns_unchanged", [])),
        "findings": [
            _strip_finding(f)
            for f in (
                diff.get("all_findings")
                or (diff.get("findings_added", []) + diff.get("findings_unchanged", []))
            )
        ],
        "packages": [
            _strip_package(p)
            for p in (diff.get("packages_added", []) + diff.get("packages_unchanged", []))
        ],
        "assessments": [
            _strip_assessment(a)
            for a in (
                list(diff.get("assessments_added") or [])
                + list(diff.get("assessments_unchanged") or [])
            )
        ],
    }

    if not diff.get("is_first", True):
        base["diff"] = {
            "vulns_added": diff.get("vulns_added", []),
            "vulns_removed": diff.get("vulns_removed", []),
            "vulns_unchanged": diff.get("vulns_unchanged", []),
            "findings_added": [_strip_finding(f) for f in diff.get("findings_added", [])],
            "findings_removed": [_strip_finding(f) for f in diff.get("findings_removed", [])],
            "findings_upgraded": [_strip_finding_upgrade(f) for f in diff.get("findings_upgraded", [])],
            "findings_unchanged": [_strip_finding(f) for f in diff.get("findings_unchanged", [])],
            "packages_added": [_strip_package(p) for p in diff.get("packages_added", [])],
            "packages_removed": [_strip_package(p) for p in diff.get("packages_removed", [])],
            "packages_upgraded": [_strip_package_upgrade(p) for p in diff.get("packages_upgraded", [])],
            "packages_unchanged": [_strip_package(p) for p in diff.get("packages_unchanged", [])],
            "assessments_added": [_strip_assessment(a) for a in (diff.get("assessments_added") or [])],
            "assessments_removed": [_strip_assessment(a) for a in (diff.get("assessments_removed") or [])],
            "assessments_unchanged": [_strip_assessment(a) for a in (diff.get("assessments_unchanged") or [])],
        }

    return base


def _build_global_result_export(
    scan: Scan,
    result: dict,
    variant_name: str | None = None,
    project_name: str | None = None,
) -> dict[str, object]:
    """Build the export-ready dict from a scan and its global result."""
    meta = _scan_meta(scan, variant_name, project_name)
    return {
        **meta,
        "packages": [
            {
                "package_name": p.get("package_name", ""),
                "package_version": p.get("package_version", ""),
                **({"supplier": s} if (s := _extract_supplier_name(p.get("package_supplier", "") or "")) else {}),
                "sources": p.get("sources", []),
            }
            for p in result.get("packages", [])
        ],
        "findings": [
            {
                "vulnerability_id": f.get("vulnerability_id", ""),
                "package_name": f.get("package_name", ""),
                "package_version": f.get("package_version", ""),
                **({"supplier": s} if (s := _extract_supplier_name(f.get("package_supplier", "") or "")) else {}),
                "sources": f.get("sources", []),
            }
            for f in result.get("findings", [])
        ],
        "vulnerabilities": [
            {
                "vulnerability_id": v.get("vulnerability_id", ""),
                "sources": v.get("sources", []),
            }
            for v in result.get("vulnerabilities", [])
        ],
        "assessments": [_strip_assessment(a) for a in result.get("assessments", [])],
    }


def _sanitize_filename(name: str) -> str:
    """Sanitize a string for use in a filename."""
    s = re.sub(r'\s+', '_', name)
    s = re.sub(r'[<>:"/\\|?*]+', '', s)
    s = re.sub(r'_+', '_', s)
    return s.strip('_')


def _format_timestamp_for_filename(dt: datetime | str | None = None) -> str:
    """Format a datetime (or now) as YYYYMMDD_HHmmss for filenames."""
    if dt is None:
        d = datetime.now(timezone.utc)
    elif isinstance(dt, str):
        d = datetime.fromisoformat(dt)
    else:
        d = dt
    return d.strftime('%Y%m%d_%H%M%S')


def init_app(app: Flask) -> None:

    @app.route('/api/scans')
    def list_all_scans() -> ResponseReturnValue:
        scans = ScanController.get_all()
        result = serialize_list_with_diff_cached("all", scans)
        return jsonify(result)

    @app.route('/api/projects/<project_id>/scans')
    def list_scans_by_project(project_id: str) -> ResponseReturnValue:
        project = ProjectController.get(project_id)
        if project is None:
            return jsonify({"error": "Project not found"}), 404
        scans = ScanController.get_by_project(project_id)
        result = serialize_list_with_diff_cached(f"project:{project_id}", scans)
        return jsonify(result)

    @app.route('/api/variants/<variant_id>/scans')
    def list_scans_by_variant(variant_id: str) -> ResponseReturnValue:
        variant = VariantController.get(variant_id)
        if variant is None:
            return jsonify({"error": "Variant not found"}), 404
        scans = ScanController.get_by_variant(variant_id)
        result = serialize_list_with_diff_cached(f"variant:{variant_id}", scans)
        return jsonify(result)

    @app.route('/api/scans/<scan_id>', methods=['PATCH'])
    def update_scan(scan_id: str) -> ResponseReturnValue:
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
    def delete_scan(scan_id: str) -> ResponseReturnValue:
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
    def get_scan_diff(scan_id: str) -> ResponseReturnValue:
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400

        scan = _load_scan_with_findings(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404

        diff = _compute_diff_dict(scan)

        scan_type = scan.scan_type or "sbom"
        prev_scan_id = diff["previous_scan_id"]

        newly_detected_findings_list = diff.get("newly_detected_findings_list")
        newly_detected_vulns_list = diff.get("newly_detected_vulns_list")

        return jsonify({
            "scan_id": str(scan.id),
            "scan_type": scan_type,
            "previous_scan_id": str(prev_scan_id) if prev_scan_id else None,
            "is_first": diff["is_first"],
            "finding_count": diff["finding_count"],
            "package_count": diff["package_count"],
            "vuln_count": diff["vuln_count"],
            "findings_added": diff["findings_added"],
            "findings_removed": diff["findings_removed"],
            "findings_upgraded": diff["findings_upgraded"],
            "findings_unchanged": diff["findings_unchanged"],
            "packages_added": diff["packages_added"],
            "packages_removed": diff["packages_removed"],
            "packages_upgraded": diff["packages_upgraded"],
            "packages_unchanged": diff["packages_unchanged"],
            "vulns_added": diff["vulns_added"],
            "vulns_removed": diff["vulns_removed"],
            "vulns_unchanged": diff["vulns_unchanged"],
            "assessment_count": diff["assessment_total"],
            "assessments_added": diff["assessments_added"],
            "assessments_removed": diff["assessments_removed"],
            "assessments_unchanged": diff["assessments_unchanged"],
            "newly_detected_findings": (
                len(newly_detected_findings_list)
                if newly_detected_findings_list is not None
                else None
            ),
            "newly_detected_vulns": (
                len(newly_detected_vulns_list)
                if newly_detected_vulns_list is not None
                else None
            ),
            "newly_detected_findings_list": newly_detected_findings_list,
            "newly_detected_vulns_list": newly_detected_vulns_list,
            "newly_detected_assessments_list": diff.get("newly_detected_assessments_list"),
            "all_findings": diff.get("all_findings"),
            "all_vulns": diff.get("all_vulns"),
        })

    # ------------------------------------------------------------------
    # Merge result — all active items (SBOM ∪ tool scan) with source info
    # ------------------------------------------------------------------

    @app.route('/api/scans/<scan_id>/global-result')
    def get_scan_global_result(scan_id: str) -> ResponseReturnValue:
        """Return every active finding, vulnerability, and package at the
        time of *scan_id* together with their source (SBOM document name /
        format or scan source label).

        Uses the shared ``_global_result_full`` helper so that the counts
        are consistent with the list view's *Scan Result* badges.
        """
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400

        scan = _load_scan_with_findings(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404

        all_variant_scans = ScanController.get_by_variant(scan.variant_id)
        return jsonify(_global_result_full(scan, all_variant_scans))

    # ------------------------------------------------------------------
    # Export endpoints — server-side data transformation for downloads
    # ------------------------------------------------------------------

    def _compute_diff_dict(scan: Scan) -> dict:
        """Compute the diff dict for a scan (same logic as get_scan_diff)."""
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
        _prev_scan = _load_scan_with_findings(prev_scan_id) if prev_scan_id else None

        current_finding_ids = {obs.finding_id for obs in scan.observations}
        curr_vulns = {obs.finding.vulnerability_id for obs in scan.observations}

        if is_tool_scan:
            sbom_before, tools_before = _contributing_scans_before(scan, all_variant_scans)
            sbom_after, tools_after = _contributing_scans_at(scan, all_variant_scans)
            _global_before_f, _global_before_v, _ = _global_result_id_sets(
                sbom_before, tools_before, filter_tool_by_sbom_pkgs=True)
            _global_after_f, _global_after_v, _ = _global_result_id_sets(
                sbom_after, tools_after, filter_tool_by_sbom_pkgs=True)
            added_fids = _global_after_f - _global_before_f
            removed_fids = _global_before_f - _global_after_f
            findings_added = [
                _obs_to_dict(obs, scan_origin)
                for obs in scan.observations if obs.finding_id in added_fids
            ]
            if _prev_scan:
                _prev_origin = _origin_for_scan(_prev_scan)
                findings_removed = [
                    _obs_to_dict(obs, _prev_origin)
                    for obs in _prev_scan.observations if obs.finding_id in removed_fids
                ]
            else:
                findings_removed = []
            vulns_added = sorted(_global_after_v - _global_before_v)
            vulns_removed = sorted(_global_before_v - _global_after_v)
        elif prev_scan_id is None:
            findings_added = [_obs_to_dict(obs, scan_origin) for obs in scan.observations]
            findings_removed = []
            vulns_added = sorted(curr_vulns)
            vulns_removed = []
        else:
            prev_finding_ids = {obs.finding_id for obs in _prev_scan.observations} if _prev_scan else set()
            prev_vulns = {obs.finding.vulnerability_id for obs in _prev_scan.observations} if _prev_scan else set()
            added_fids = current_finding_ids - prev_finding_ids
            removed_fids = prev_finding_ids - current_finding_ids
            findings_added = [
                _obs_to_dict(obs, scan_origin)
                for obs in scan.observations if obs.finding_id in added_fids
            ]
            findings_removed = [
                _obs_to_dict(obs, scan_origin)
                for obs in _prev_scan.observations if obs.finding_id in removed_fids
            ] if _prev_scan else []
            vulns_added = sorted(curr_vulns - prev_vulns)
            vulns_removed = sorted(prev_vulns - curr_vulns)

        if is_tool_scan:
            curr_pkg_ids = set()
            packages_added = []
            packages_removed = []
            packages_upgraded = []
        else:
            scans_to_query = [scan.id] if prev_scan_id is None else [scan.id, prev_scan_id]
            pkg_sets = _packages_by_scan_ids(scans_to_query)
            curr_pkg_ids = pkg_sets.get(scan.id, set())
            prev_pkg_ids = pkg_sets.get(prev_scan_id, set()) if prev_scan_id else set()
            raw_added_pkg_ids = curr_pkg_ids - prev_pkg_ids
            raw_removed_pkg_ids = prev_pkg_ids - curr_pkg_ids
            all_relevant_pkg_ids = raw_added_pkg_ids | raw_removed_pkg_ids
            pkg_lookup = _package_rows(all_relevant_pkg_ids)
            truly_added_ids, truly_removed_ids, upgraded_pairs_list = _classify_package_changes(
                raw_added_pkg_ids, raw_removed_pkg_ids, pkg_lookup)
            packages_added = [_pkg_to_dict(pkg_lookup[pid]) for pid in truly_added_ids if pid in pkg_lookup]
            packages_removed = [_pkg_to_dict(pkg_lookup[pid]) for pid in truly_removed_ids if pid in pkg_lookup]
            packages_upgraded = [
                {"package_name": old_pkg.name or "unknown", "old_version": old_pkg.version or "",
                 "new_version": new_pkg.version or "", "old_package_id": str(old_pkg.id),
                 "new_package_id": str(new_pkg.id), "package_supplier": old_pkg.supplier or ""}
                for old_pkg, new_pkg in upgraded_pairs_list
            ]

        # Classify findings for SBOM with previous
        if not is_tool_scan and prev_scan_id is not None:
            _, latest_tool = _contributing_scans_at(scan, all_variant_scans)
            curr_sr_fids, curr_sr_vids, _ = _global_result_id_sets(
                scan, latest_tool, filter_tool_by_sbom_pkgs=True)
            prev_sr_fids, prev_sr_vids, _ = _global_result_id_sets(
                _prev_scan, latest_tool, filter_tool_by_sbom_pkgs=True)
            fid_obs_map = {}
            fid_info = {}
            for obs in scan.observations:
                fid_obs_map[obs.finding_id] = _obs_to_dict(obs, scan_origin)
                fid_info[obs.finding_id] = (obs.finding.package_id, obs.finding.vulnerability_id)
            for obs in (_prev_scan.observations if _prev_scan else []):
                if obs.finding_id not in fid_obs_map:
                    fid_obs_map[obs.finding_id] = _obs_to_dict(obs, scan_origin)
                if obs.finding_id not in fid_info:
                    fid_info[obs.finding_id] = (obs.finding.package_id, obs.finding.vulnerability_id)
            for tool_scan_obj in latest_tool.values():
                tool_loaded = _load_scan_with_findings(tool_scan_obj.id)
                if not tool_loaded:
                    continue
                tool_origin = _origin_for_scan(tool_loaded)
                for obs in tool_loaded.observations:
                    if obs.finding_id not in fid_obs_map:
                        fid_obs_map[obs.finding_id] = _obs_to_dict(obs, tool_origin)
                    if obs.finding_id not in fid_info:
                        fid_info[obs.finding_id] = (obs.finding.package_id, obs.finding.vulnerability_id)

            sr_new_fids = curr_sr_fids - prev_sr_fids
            sr_gone_fids = prev_sr_fids - curr_sr_fids
            sr_unchanged_fids = prev_sr_fids & curr_sr_fids

            upgraded_old_ids_set = {old_pkg.id for old_pkg, _ in upgraded_pairs_list}  # noqa: F841
            upgraded_new_ids_set = {new_pkg.id for _, new_pkg in upgraded_pairs_list}
            upgraded_old_to_new = {old_pkg.id: (old_pkg, new_pkg) for old_pkg, new_pkg in upgraded_pairs_list}
            _rem_by_vuln: dict[str, list[tuple[uuid_module.UUID, uuid_module.UUID]]] = {}
            for fid in sr_gone_fids:
                info = fid_info.get(fid)
                if info and info[0] in upgraded_old_ids_set:
                    _rem_by_vuln.setdefault(info[1], []).append((fid, info[0]))
            sr_upgraded_fids_new = set()
            sr_upgraded_fids_gone = set()
            findings_upgraded_list = []
            for fid in sr_new_fids:
                info = fid_info.get(fid)
                if info and info[0] in upgraded_new_ids_set:
                    candidates = _rem_by_vuln.get(info[1], [])
                    if candidates:
                        old_fid, old_pkg_id = candidates.pop(0)
                        sr_upgraded_fids_new.add(fid)
                        sr_upgraded_fids_gone.add(old_fid)
                        old_pkg, new_pkg = upgraded_old_to_new[old_pkg_id]
                        obs_dict: ObsDict | None = fid_obs_map.get(fid)
                        findings_upgraded_list.append({
                            "vulnerability_id": info[1], "package_name": old_pkg.name or "unknown",
                            "old_version": old_pkg.version or "", "new_version": new_pkg.version or "",
                            "package_supplier": old_pkg.supplier or "",
                            "origin": obs_dict["origin"] if obs_dict else scan_origin,
                        })
            findings_added = [fid_obs_map[fid] for fid in sr_new_fids - sr_upgraded_fids_new if fid in fid_obs_map]
            findings_removed = [fid_obs_map[fid] for fid in sr_gone_fids - sr_upgraded_fids_gone if fid in fid_obs_map]
            findings_upgraded = findings_upgraded_list
            findings_unchanged = [fid_obs_map[fid] for fid in sr_unchanged_fids if fid in fid_obs_map]
            vulns_added = sorted(curr_sr_vids - prev_sr_vids)
            vulns_removed = sorted(prev_sr_vids - curr_sr_vids)
            vulns_unchanged = sorted(prev_sr_vids & curr_sr_vids)
            unchanged_pkg_ids = curr_pkg_ids & prev_pkg_ids
            for old_pkg, new_pkg in upgraded_pairs_list:
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
            findings_upgraded = []
            findings_unchanged = []
            vulns_unchanged = []
            packages_unchanged = []
        else:
            findings_upgraded = []
            findings_unchanged = []
            vulns_unchanged = []
            packages_unchanged = []

        # Newly detected (tool scans only)
        newly_detected_findings_list = None
        newly_detected_vulns_list = None
        newly_detected_assessments_list = None
        if is_tool_scan:
            _new_vids = _global_after_v - _global_before_v
            _new_fids = _global_after_f - _global_before_f
            newly_detected_vulns_list = sorted(_new_vids)
            newly_detected_findings_list = [
                _obs_to_dict(obs, scan_origin)
                for obs in scan.observations if obs.finding_id in _new_fids
            ]
            from ..models.assessment import Assessment as _Assessment
            _before_assess_ids = _global_assessment_ids_for(sbom_before, tools_before)
            _after_assess_ids = _global_assessment_ids_for(sbom_after, tools_after)
            _new_assess_ids = _after_assess_ids - _before_assess_ids
            if _new_assess_ids:
                from ..models.finding import Finding as _Finding
                _assess_rows = db.session.execute(
                    db.select(_Assessment.id, _Finding.vulnerability_id, _Assessment.status,
                              _Assessment.simplified_status, _Assessment.justification,
                              _Assessment.impact_statement, _Assessment.status_notes)
                    .join(_Finding, _Finding.id == _Assessment.finding_id)
                    .where(_Assessment.id.in_(_new_assess_ids))
                ).all()
                newly_detected_assessments_list = sorted([
                    {"vulnerability_id": vid, "status": status or "under_investigation",
                     "simplified_status": simp or "Pending Assessment", "justification": just or "",
                     "impact_statement": impact or "", "status_notes": notes or ""}
                    for _aid, vid, status, simp, just, impact, notes in _assess_rows
                ], key=lambda a: a["vulnerability_id"])
            else:
                newly_detected_assessments_list = []

        all_findings_list = None
        all_vulns_list = None
        if is_tool_scan:
            all_findings_list = [_obs_to_dict(obs, scan_origin) for obs in scan.observations]
            all_vulns_list = sorted(curr_vulns)

        _next_scan_ts = None
        for s in all_variant_scans:
            if s.timestamp > scan.timestamp:
                if _next_scan_ts is None or s.timestamp < _next_scan_ts:
                    _next_scan_ts = s.timestamp
        assess_detail = _assessments_detail_for_scan(scan, next_scan_ts=_next_scan_ts, prev_scan=_prev_scan)

        return {
            "previous_scan_id": prev_scan_id,
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
            "assessment_total": assess_detail["total"],
            "assessments_added": assess_detail["added"],
            "assessments_removed": assess_detail["removed"],
            "assessments_unchanged": assess_detail["unchanged_list"],
            "newly_detected_findings_list": newly_detected_findings_list,
            "newly_detected_vulns_list": newly_detected_vulns_list,
            "newly_detected_assessments_list": newly_detected_assessments_list,
            "all_findings": all_findings_list,
            "all_vulns": all_vulns_list,
        }

    @app.route('/api/scans/<scan_id>/export-diff')
    def export_scan_diff(scan_id: str) -> ResponseReturnValue:
        """Export a single scan's diff as a cleaned JSON download."""
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400

        scan = _load_scan_with_findings(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404

        variant_map = _variant_info([scan.variant_id])
        vname, pname = variant_map.get(scan.variant_id, (None, None))

        diff = _compute_diff_dict(scan)
        export_data = _build_diff_export(scan, diff, vname, pname)

        proj = _sanitize_filename(pname or "project")
        variant = _sanitize_filename(vname or str(scan.variant_id))
        ts = _format_timestamp_for_filename(scan.timestamp)
        filename = f"scan_diff_{proj}_{variant}_{ts}.json"

        response = jsonify(export_data)
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    @app.route('/api/scans/<scan_id>/export-result')
    def export_scan_result(scan_id: str) -> ResponseReturnValue:
        """Export a single scan's global result as a cleaned JSON download."""
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400

        scan = _load_scan_with_findings(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404

        variant_map = _variant_info([scan.variant_id])
        vname, pname = variant_map.get(scan.variant_id, (None, None))

        all_variant_scans = ScanController.get_by_variant(scan.variant_id)
        result = _global_result_full(scan, all_variant_scans)
        export_data = _build_global_result_export(scan, result, vname, pname)

        proj = _sanitize_filename(pname or "project")
        variant = _sanitize_filename(vname or str(scan.variant_id))
        ts = _format_timestamp_for_filename(scan.timestamp)
        filename = f"scan_total_{proj}_{variant}_{ts}.json"

        response = jsonify(export_data)
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    @app.route('/api/scans/export')
    def export_all_scans() -> ResponseReturnValue:
        """Export all visible scans (optionally filtered by variant/project).

        Query params:
          - variant_id: filter to a single variant
          - project_id: filter to a single project
          - type: 'diff' or 'total' (default: 'diff')
        Returns a JSON array of export objects grouped per variant, with
        Content-Disposition for download.
        """
        export_type = flask_request.args.get("type", "diff")
        if export_type not in ("diff", "total"):
            return jsonify({"error": "type must be 'diff' or 'total'"}), 400

        variant_id = flask_request.args.get("variant_id")
        project_id = flask_request.args.get("project_id")

        if variant_id:
            try:
                uuid_module.UUID(variant_id)
            except ValueError:
                return jsonify({"error": "Invalid variant_id"}), 400
            scans = ScanController.get_by_variant(variant_id)
        elif project_id:
            try:
                uuid_module.UUID(project_id)
            except ValueError:
                return jsonify({"error": "Invalid project_id"}), 400
            project = ProjectController.get(project_id)
            if project is None:
                return jsonify({"error": "Project not found"}), 404
            scans = ScanController.get_by_project(project_id)
        else:
            scans = ScanController.get_all()

        if not scans:
            return jsonify([])

        MAX_EXPORT_SCANS = 200
        if len(scans) > MAX_EXPORT_SCANS:
            return jsonify({
                "error": f"Too many scans ({len(scans)}). "
                         f"Maximum is {MAX_EXPORT_SCANS}. "
                         "Filter by variant_id or project_id to reduce the set."
            }), 400

        # Group scans by (project_name, variant_id) to produce one file per group
        variant_ids = list({s.variant_id for s in scans})
        variant_map = _variant_info(variant_ids)

        groups: dict = {}
        for scan in scans:
            vname, pname = variant_map.get(scan.variant_id, (None, None))
            key = f"{pname or ''}::{scan.variant_id}"
            groups.setdefault(key, []).append((scan, vname, pname))

        all_exports = []
        for group_scans in groups.values():
            group_data = []
            for scan, vname, pname in group_scans:
                loaded = _load_scan_with_findings(scan.id)
                if not loaded:
                    continue
                if export_type == "diff":
                    diff = _compute_diff_dict(loaded)
                    group_data.append(_build_diff_export(loaded, diff, vname, pname))
                else:
                    all_variant_scans = ScanController.get_by_variant(scan.variant_id)
                    result = _global_result_full(loaded, all_variant_scans)
                    group_data.append(_build_global_result_export(loaded, result, vname, pname))
            all_exports.extend(group_data)

        ts = _format_timestamp_for_filename()
        filename = f"scans_{export_type}_{ts}.json"

        response = jsonify(all_exports)
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Scan CRUD and list/diff/global-result route handlers.

Computation helpers live in sibling modules:
- ``_scan_queries``  — low-level DB batch queries
- ``_scan_diff``     — diff algorithms & list-view serialisation
- ``_scan_cache``    — scan_diff_cache read/write/invalidate
"""

import uuid as uuid_module

from flask import jsonify

from ..controllers.scans import ScanController
from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController
from ..models.observation import Observation
from ..models.finding import Finding
from ..extensions import db

from ._scan_queries import (
    _packages_by_scan_ids,
    _package_rows,
    _pkg_to_dict,
    _load_scan_with_findings,
    _obs_to_dict,
    _origin_for_scan,
)
from ._scan_diff import (
    _classify_package_changes,
    _contributing_scans_at,
    _contributing_scans_before,
    _global_result_id_sets,
    _global_result_full,
    _serialize_list_with_diff,
)
from ._scan_cache import (
    _read_cache,
    _store_cache,
    recompute_variant_cache,
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
)
from ._scan_cache import (  # noqa: F401  — re-exports
    invalidate_variant_cache,
)


def init_app(app):

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

        if is_tool_scan:
            # Tool scan: diff against the GLOBAL state using the same
            # helpers as the list view (_contributing_scans_at/before +
            # _global_result_id_sets) so that numbers are always in sync.
            sbom_before, tools_before = _contributing_scans_before(
                scan, all_variant_scans)
            sbom_after, tools_after = _contributing_scans_at(
                scan, all_variant_scans)
            _global_before_f, _global_before_v, _ = _global_result_id_sets(
                sbom_before, tools_before,
                filter_tool_by_sbom_pkgs=True)
            _global_after_f, _global_after_v, _ = _global_result_id_sets(
                sbom_after, tools_after,
                filter_tool_by_sbom_pkgs=True)

            added_fids = _global_after_f - _global_before_f
            removed_fids = _global_before_f - _global_after_f

            findings_added = [
                _obs_to_dict(obs, scan_origin)
                for obs in scan.observations if obs.finding_id in added_fids
            ]
            # Removed findings come from the previous same-source scan
            if prev_scan_id:
                _prev_loaded = _load_scan_with_findings(prev_scan_id)
                _prev_origin = (
                    _origin_for_scan(_prev_loaded) if _prev_loaded
                    else scan_origin
                )
                findings_removed = [
                    _obs_to_dict(obs, _prev_origin)
                    for obs in (_prev_loaded.observations if _prev_loaded else [])
                    if obs.finding_id in removed_fids
                ]
            else:
                findings_removed: list = []
            vulns_added = sorted(_global_after_v - _global_before_v)
            vulns_removed = sorted(_global_before_v - _global_after_v)
        elif prev_scan_id is None:
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
            findings_added = [
                _obs_to_dict(obs, scan_origin)
                for obs in scan.observations if obs.finding_id in added_fids
            ]
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
            # Use the same shared helpers as the list view so that
            # counts are always in sync.  Enable SBOM-package filtering
            # so tool findings for removed packages classify correctly.
            _, latest_tool = _contributing_scans_at(scan, all_variant_scans)
            curr_sr_fids, curr_sr_vids, _ = _global_result_id_sets(
                scan, latest_tool, filter_tool_by_sbom_pkgs=True)
            prev_sr_fids, prev_sr_vids, _ = _global_result_id_sets(
                prev_scan, latest_tool,  # type: ignore[possibly-undefined]
                filter_tool_by_sbom_pkgs=True)

            # Build finding_id → (obs_dict, origin) lookup for full output.
            # We still need to load observations for the detail response.
            fid_obs_map: dict = {}  # finding_id → obs dict
            fid_info: dict = {}     # finding_id → (pkg_id, vuln_id)
            for obs in scan.observations:
                fid = obs.finding_id
                fid_obs_map[fid] = _obs_to_dict(obs, scan_origin)
                fid_info[fid] = (obs.finding.package_id, obs.finding.vulnerability_id)
            for obs in prev_scan.observations:  # type: ignore[possibly-undefined]
                fid = obs.finding_id
                if fid not in fid_obs_map:
                    fid_obs_map[fid] = _obs_to_dict(obs, scan_origin)
                if fid not in fid_info:
                    fid_info[fid] = (obs.finding.package_id, obs.finding.vulnerability_id)
            for tool_scan_obj in latest_tool.values():
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
        # Vulns from THIS scan not in the previous global result,
        # plus findings linked to those new vulns.
        newly_detected_findings_count = None
        newly_detected_vulns_count = None
        newly_detected_findings_list = None
        newly_detected_vulns_list = None

        if is_tool_scan:
            # Use the filtered global sets so that
            # prev Scan Result + newly_detected == Scan Result.
            _new_vids = _global_after_v - _global_before_v
            _new_fids = _global_after_f - _global_before_f
            newly_detected_vulns_count = len(_new_vids)
            newly_detected_vulns_list = sorted(_new_vids)
            newly_detected_findings_list = [
                _obs_to_dict(obs, scan_origin)
                for obs in scan.observations
                if obs.finding_id in _new_fids
            ]
            newly_detected_findings_count = len(newly_detected_findings_list)

        # For tool scans, provide flat lists of ALL findings/vulns from this scan
        all_findings_list = None
        all_vulns_list = None
        if is_tool_scan:
            all_findings_list = [
                _obs_to_dict(obs, scan_origin)
                for obs in scan.observations
            ]
            all_vulns_list = sorted(curr_vulns)

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
            "all_findings": all_findings_list,
            "all_vulns": all_vulns_list,
        })

    # ------------------------------------------------------------------
    # Merge result — all active items (SBOM ∪ tool scan) with source info
    # ------------------------------------------------------------------

    @app.route('/api/scans/<scan_id>/global-result')
    def get_scan_global_result(scan_id):
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

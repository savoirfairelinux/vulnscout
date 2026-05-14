# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""NVD CVE Refresh controller.

Refreshes existing CVE metadata from NVD without creating new findings.
Uses CPE batch fetching as primary strategy, per-CVE fallback for stragglers.
"""

import datetime
from typing import Optional


def build_cpe_map(
    target_cve_ids: set,
    findings: list,
    package_by_id: dict,
) -> dict:
    """Build {cpe_name: set(cve_ids)} for the given target CVE IDs.

    *findings* is a list of Finding objects (or mocks with .vulnerability_id
    and .package_id).  *package_by_id* maps package UUID → Package object
    (with .cpe list attribute).

    CPEs with wildcard at position [3] (vendor) are excluded — they require
    virtualMatchString and can't be used for targeted CPE batch lookup.
    """
    cpe_to_cves: dict = {}
    for finding in findings:
        vuln_id = str(finding.vulnerability_id).upper()
        if vuln_id not in target_cve_ids:
            continue
        pkg = package_by_id.get(finding.package_id)
        if pkg is None or not pkg.cpe:
            continue
        for cpe in pkg.cpe:
            parts = cpe.split(":")
            if len(parts) < 5 or parts[3] == "*":
                continue
            cpe_to_cves.setdefault(cpe, set()).add(vuln_id)
    return cpe_to_cves


def apply_nvd_update(vuln_record, details: dict, now: datetime.datetime) -> bool:
    """Compare NVD *details* against *vuln_record* and update in place if different.

    Returns True if any field changed (and update_record was called),
    False if nothing differed.  Always sets nvd_fetched_at when a change occurs.
    None values in *details* are treated as "no data" and never overwrite.
    """
    update_kwargs: dict = {}

    fields = [
        ("description", "description"),
        ("status", "status"),
        ("attack_vector", "attack_vector"),
        ("links", "links"),
        ("weaknesses", "weaknesses"),
        ("publish_date", "publish_date"),
        ("nvd_last_modified", "nvd_last_modified"),
    ]
    for detail_key, model_attr in fields:
        new_val = details.get(detail_key)
        if new_val is not None and new_val != getattr(vuln_record, model_attr):
            update_kwargs[model_attr] = new_val

    if not update_kwargs:
        return False

    update_kwargs["nvd_fetched_at"] = now
    update_kwargs["nvd_data_updated_at"] = now
    update_kwargs["commit"] = False
    vuln_record.update_record(**update_kwargs)
    return True


def collect_target_cve_ids(
    variant_uuid,
    project_uuid,
    requested_cve_ids: Optional[list],
) -> list:
    """Return the list of CVE IDs to refresh.

    If *requested_cve_ids* is provided, return those directly (explicit list
    sent by frontend for "refresh matching current filters" mode).
    Otherwise return all CVEs linked to active findings for the variant/project
    where the assessment status is 'under_investigation' (Pending Assessment).
    """
    if requested_cve_ids is not None:
        return [cid.upper() for cid in requested_cve_ids if cid]

    from ..extensions import db
    from ..models.finding import Finding
    from ..models.observation import Observation
    from ..models.assessment import Assessment
    from ..helpers.active_scans import (
        active_scan_ids_for_variant,
        active_scan_ids_for_project,
    )

    if project_uuid:
        scan_ids = active_scan_ids_for_project(project_uuid)
    else:
        scan_ids = active_scan_ids_for_variant(variant_uuid)

    if not scan_ids:
        return []

    rows = db.session.execute(
        db.select(Finding.vulnerability_id.distinct())
        .join(Observation, Observation.finding_id == Finding.id)
        .join(
            Assessment,
            db.and_(
                Assessment.finding_id == Finding.id,
                Assessment.variant_id == variant_uuid,
            ),
        )
        .where(Observation.scan_id.in_(scan_ids))
        .where(Assessment.status == "under_investigation")
    ).all()
    return [row[0].upper() for row in rows]


def run_nvd_refresh(
    variant_uuid,
    project_uuid,
    requested_cve_ids: Optional[list],
    progress: dict,
) -> dict:
    """Run the full NVD refresh.  Updates *progress* dict in place.

    Returns a summary dict: {"refreshed": int, "changed": int, "failed": int}.
    Designed to run inside a Flask app_context (background thread).
    """
    import os
    from ..extensions import db
    from ..models.vulnerability import Vulnerability
    from ..models.finding import Finding
    from ..models.package import Package
    from ..controllers.nvd_db import NVD_DB

    nvd = NVD_DB(nvd_api_key=os.getenv("NVD_API_KEY"))
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Collect CVE IDs to refresh
    progress["logs"].append("Collecting CVEs to refresh…")
    target_ids = set(collect_target_cve_ids(variant_uuid, project_uuid, requested_cve_ids))

    if not target_ids:
        progress["status"] = "done"
        progress["progress"] = "No CVEs to refresh"
        progress["logs"].append("No CVEs found for the selected scope.")
        return {"refreshed": 0, "changed": 0, "failed": 0}

    progress["total"] = len(target_ids)
    progress["logs"].append(f"Found {len(target_ids)} CVE(s) to refresh.")

    # 2. Load findings + packages for CPE map
    findings = db.session.execute(
        db.select(Finding)
        .where(Finding.vulnerability_id.in_(list(target_ids)))
    ).scalars().all()

    pkg_ids = {f.package_id for f in findings}
    packages = db.session.execute(
        db.select(Package).where(Package.id.in_(list(pkg_ids)))
    ).scalars().all()
    package_by_id = {p.id: p for p in packages}

    cpe_map = build_cpe_map(target_ids, list(findings), package_by_id)
    progress["logs"].append(
        f"Built CPE map: {len(cpe_map)} unique CPE(s) covering "
        f"{sum(len(v) for v in cpe_map.values())} CVE references."
    )

    # 3. CPE batch fetch
    resolved: set = set()
    failed: set = set()
    changed_count = 0

    total_cpes = len(cpe_map)
    for idx, (cpe_name, _) in enumerate(cpe_map.items(), 1):
        progress["progress"] = f"{idx}/{total_cpes} CPEs"
        progress["logs"].append(f"[{idx}/{total_cpes}] Batch query: {cpe_name}…")
        try:
            cpe_parts = cpe_name.split(":")
            has_wildcards = len(cpe_parts) >= 6 and (
                cpe_parts[2] == "*" or cpe_parts[3] == "*" or cpe_parts[5] == "*"
            )
            nvd_vulns = nvd.api_get_cves_by_cpe(
                cpe_name, results_per_page=100, use_virtual_match=has_wildcards
            )
        except Exception as e:
            progress["logs"].append(f"  ERROR on {cpe_name}: {str(e)[:200]}")
            continue

        for nvd_vuln in nvd_vulns:
            cve = nvd_vuln.get("cve", {})
            cve_id = cve.get("id", "").upper()
            if cve_id not in target_ids or cve_id in resolved:
                continue
            resolved.add(cve_id)
            rec = Vulnerability.get_by_id(cve_id)
            if rec is None:
                continue
            details = NVD_DB.extract_cve_details(cve)
            if apply_nvd_update(rec, details, now):
                changed_count += 1
            else:
                # Stamp fetch time even when content is unchanged
                rec.update_record(nvd_fetched_at=now, commit=False)

        progress["done_count"] = idx

    # 4. Straggler individual pass
    stragglers = target_ids - resolved
    if stragglers:
        progress["logs"].append(
            f"Straggler pass: {len(stragglers)} CVE(s) not found via CPE batch."
        )
    for idx2, cve_id in enumerate(sorted(stragglers), 1):
        progress["logs"].append(f"  [{idx2}/{len(stragglers)}] Individual fetch: {cve_id}…")
        try:
            status, data = nvd.api_get_cve(cve_id)
            if status == 200 and data.get("vulnerabilities"):
                cve = data["vulnerabilities"][0]["cve"]
                details = NVD_DB.extract_cve_details(cve)
                rec = Vulnerability.get_by_id(cve_id)
                if rec is not None:
                    if apply_nvd_update(rec, details, now):
                        changed_count += 1
                resolved.add(cve_id)
            else:
                # Update nvd_fetched_at only (not nvd_data_updated_at)
                rec = Vulnerability.get_by_id(cve_id)
                if rec is not None:
                    rec.update_record(nvd_fetched_at=now, commit=False)
                failed.add(cve_id)
        except Exception as e:
            progress["logs"].append(f"    ERROR: {str(e)[:200]}")
            failed.add(cve_id)

    db.session.commit()

    summary = {
        "refreshed": len(resolved),
        "changed": changed_count,
        "failed": len(failed),
    }
    progress["status"] = "done"
    progress["progress"] = (
        f"Done — {len(resolved)}/{len(target_ids)} refreshed, "
        f"{changed_count} updated, {len(failed)} failed"
    )
    progress["logs"].append(f"✓ Refresh complete. {summary}")
    return summary

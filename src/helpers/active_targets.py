# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Active (variant, package) targets of a vulnerability."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from ..extensions import db
from ..models import Finding, Package, SBOMDocument, SBOMPackage
from ..models.observation import Observation
from ..models.scan import Scan
from ..models.variant import Variant
from .active_scans import active_package_ids_for_scans, active_sbom_scan_ids_for_variant


def variant_active_packages(vuln_id: str, project_uuid: UUID | None = None) -> list[dict[str, Any]]:
    """For each variant observing *vuln_id*, list its findings and the packages still in its active SBOM.

    Backs ``GET /api/vulnerabilities/<id>/variant-active-packages`` and ``flask ai-assess``.
    """
    findings = Finding.get_by_vulnerability(vuln_id)
    # package_id -> string_id for the packages affected by this vulnerability
    pkg_string_by_id: dict[UUID, str] = {}
    for f in findings:
        if f.package_id and f.package:
            pkg_string_by_id[f.package_id] = f.package.string_id

    # Distinct variants and findings for this vuln
    # (Finding -> Observation -> Scan -> Variant).
    seen_variant_ids: set[UUID] = set()
    variant_ids: list[UUID] = []
    finding_ids_by_variant: dict[UUID, set[UUID]] = {}
    for finding in findings:
        for obs in Observation.get_by_finding(finding.id):
            scan = db.session.get(Scan, obs.scan_id)
            if scan is None:
                continue
            if project_uuid is not None:
                variant = db.session.get(Variant, scan.variant_id)
                if variant is None or variant.project_id != project_uuid:
                    continue
            finding_ids_by_variant.setdefault(scan.variant_id, set()).add(finding.id)
            if scan.variant_id not in seen_variant_ids:
                seen_variant_ids.add(scan.variant_id)
                variant_ids.append(scan.variant_id)

    result: list[dict[str, Any]] = []
    vuln_pkg_ids = set(pkg_string_by_id.keys())
    for vid in variant_ids:
        active_scan_ids = active_sbom_scan_ids_for_variant(vid)
        active_ids = active_package_ids_for_scans(active_scan_ids, restrict_to_package_ids=vuln_pkg_ids)
        active_packages = [sid for pid, sid in pkg_string_by_id.items() if pid in active_ids]
        active_identities = set(db.session.execute(
            db.select(Package.name, Package.version)
            .join(SBOMPackage, Package.id == SBOMPackage.package_id)
            .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
            .where(SBOMDocument.scan_id.in_(active_scan_ids))
            .distinct()
        ).all()) if active_scan_ids else set()
        variant_findings: list[dict[str, str | bool]] = []
        for finding in findings:
            if finding.id not in finding_ids_by_variant.get(vid, set()) or finding.package is None:
                continue
            variant_findings.append({
                "finding_id": str(finding.id),
                "package": finding.package.string_id,
                "outdated": (finding.package.name, finding.package.version) not in active_identities,
            })
        result.append({
            "variant_id": str(vid),
            "active_packages": active_packages,
            "findings": sorted(
                variant_findings,
                key=lambda item: (str(item.get("package", "")), str(item.get("finding_id", ""))),
            ),
        })
    return result

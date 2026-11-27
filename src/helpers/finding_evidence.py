# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from dataclasses import dataclass, field
from typing import Collection, TypedDict

from sqlalchemy import select
from sqlalchemy.orm import aliased

from ..extensions import db
from ..models import Finding, Observation, Package, Scan, SBOMDocument, SBOMPackage, Variant
from .active_scans import active_scan_ids_for_variant


@dataclass
class FindingPackages:
    display: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    writable: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    scan_ids: dict[str, set[uuid.UUID]] = field(default_factory=dict)
    writable_targets: set[tuple[uuid.UUID, uuid.UUID]] = field(default_factory=set)


def finding_packages_for_scans(
    scan_ids: list[uuid.UUID], vulnerability_ids: Collection[str] | None = None,
    *, historical: bool = False, collect_writable_targets: bool = False,
) -> FindingPackages:
    """Collect display packages and exact writable targets from scoped scans."""
    targets = FindingPackages()
    if not scan_ids:
        return targets
    sbom_variants = set(db.session.scalars(
        db.select(Scan.variant_id).where(
            Scan.id.in_(scan_ids), db.or_(Scan.scan_type != "tool", Scan.scan_type.is_(None))
        ).distinct()
    ))
    snapshots = (
        db.select(
            Scan.id, Scan.variant_id, Scan.scan_type,
            Package.id, Package.name, Package.version, Package.supplier,
        )
        .select_from(Scan)
        .join(SBOMDocument, SBOMDocument.scan_id == Scan.id)
        .join(SBOMPackage, SBOMPackage.sbom_document_id == SBOMDocument.id)
        .join(Package, Package.id == SBOMPackage.package_id)
        .where(Scan.id.in_(scan_ids))
        .distinct()
    )
    if vulnerability_ids is not None and len(vulnerability_ids) == 1:
        observed_package = aliased(Package)
        # Keep matching name/version across suppliers for supplierless tool findings.
        snapshots = snapshots.where(
            select(Finding.id).join(observed_package, observed_package.id == Finding.package_id)
            .where(
                Finding.vulnerability_id.in_(vulnerability_ids),
                observed_package.name.is_not_distinct_from(Package.name),
                observed_package.version.is_not_distinct_from(Package.version),
            ).exists()
        )
    sbom_packages: set[tuple[uuid.UUID, uuid.UUID]] = set()
    documented_packages: dict[tuple[uuid.UUID, str, str], dict[uuid.UUID, str]] = {}
    for scan_id, variant_id, scan_type, package_id, name, version, supplier in db.session.execute(snapshots):
        if scan_type != "tool":
            sbom_packages.add((variant_id, package_id))
        else:
            target = f"{name}@{version}::{supplier}" if supplier else f"{name}@{version}"
            documented_packages.setdefault((scan_id, name, version), {})[package_id] = target

    query = (
        db.select(
            Finding.vulnerability_id, Scan.id, Scan.variant_id, Scan.scan_type,
            Package.id, Package.name, Package.version, Package.supplier, Finding.id,
        )
        .select_from(Finding)
        .join(Observation, Observation.finding_id == Finding.id)
        .join(Scan, Scan.id == Observation.scan_id)
        .join(Package, Package.id == Finding.package_id)
        .where(Observation.scan_id.in_(scan_ids))
    )
    if vulnerability_ids is not None:
        query = query.where(Finding.vulnerability_id.in_(vulnerability_ids))
    for row in db.session.execute(query):
        vid, scan_id, variant_id, scan_type, package_id, name, version, supplier, finding_id = row
        target = f"{name}@{version}::{supplier}" if supplier else f"{name}@{version}"
        package_targets = {package_id: target}
        if scan_type == "tool":
            documented = documented_packages.get((scan_id, name, version), {})
            if historical:
                # Keep exact observations; only same-scan evidence can add aliases.
                if not supplier:
                    package_targets.update(documented)
            elif variant_id in sbom_variants:
                if not supplier:
                    package_targets.update(documented)
                package_targets = {
                    pid: value for pid, value in package_targets.items() if (variant_id, pid) in sbom_packages
                }
        if package_targets:
            variant_key = str(variant_id)
            targets.display.setdefault(vid, {}).setdefault(variant_key, set()).update(package_targets.values())
            targets.scan_ids.setdefault(vid, set()).add(scan_id)
            if not historical and package_id in package_targets:
                targets.writable.setdefault(vid, {}).setdefault(variant_key, set()).add(target)
                if collect_writable_targets:
                    targets.writable_targets.add((variant_id, finding_id))
    return targets


class EditorFinding(TypedDict):
    finding_id: str
    package: str
    outdated: bool


class EditorVariantTargets(TypedDict):
    variant_id: str
    active_packages: list[str]
    findings: list[EditorFinding]


def variant_finding_targets(vuln_id: str, project_id: uuid.UUID | None) -> list[EditorVariantTargets]:
    """List published editor targets, classifying them with the exact-current write guard."""
    observations = (
        db.select(Finding.id.label("finding_id"), Finding.package_id, Scan.variant_id)
        .select_from(Finding)
        .join(Observation, Finding.id == Observation.finding_id)
        .join(Scan, Scan.id == Observation.scan_id)
        .where(Finding.vulnerability_id == vuln_id, Scan.in_progress.is_(False))
    )
    if project_id is not None:
        observations = observations.join(Variant, Scan.variant_id == Variant.id).where(Variant.project_id == project_id)
    observed_targets = observations.distinct().subquery()
    query = db.select(observed_targets.c.finding_id, Package, observed_targets.c.variant_id).join_from(
        observed_targets, Package, observed_targets.c.package_id == Package.id
    )
    observed: dict[uuid.UUID, list[tuple[str, str]]] = {}
    for finding_id, package, variant_id in db.session.execute(query):
        observed.setdefault(variant_id, []).append((package.string_id, str(finding_id)))
    scan_ids = [scan_id for variant_id in observed for scan_id in active_scan_ids_for_variant(variant_id)]
    writable = finding_packages_for_scans(scan_ids, [vuln_id]).writable.get(vuln_id, {})
    result: list[EditorVariantTargets] = []
    for variant_id, findings in sorted(observed.items()):
        variant_key = str(variant_id)
        active_packages = writable.get(variant_key, set())
        result.append({
            "variant_id": variant_key,
            "active_packages": sorted(active_packages),
            "findings": [
                {"finding_id": finding_id, "package": package, "outdated": package not in active_packages}
                for package, finding_id in sorted(findings)
            ],
        })
    return result

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Resolve Explorer evidence before presenting it as findings or SBOM inventory."""

from dataclasses import dataclass, field
from typing import Collection, Mapping, TypeVar
from uuid import UUID

from flask.typing import ResponseReturnValue

from ..extensions import db
from ..helpers.active_scans import scan_strategy_key
from ..helpers.finding_evidence import FindingPackages, finding_packages_for_scans
from ..models import Package, Scan, Variant, SBOMDocument, SBOMObservation, SBOMPackage
from ._scan_helpers import parse_uuid_or_400

T = TypeVar("T")


@dataclass
class EvidenceScope:
    variants: dict[UUID, str]
    selected: list[UUID]
    operation: str
    pair: bool
    comparing: bool
    historical: bool
    active_by_variant: dict[UUID, list[UUID]]
    active_sboms_by_variant: dict[UUID, list[UUID]]
    all_by_variant: dict[UUID, list[UUID]]

    @property
    def contributing_variants(self) -> list[UUID]:
        ids = self.selected
        if self.operation == "difference":
            return ids[1:] if self.pair else ids[:1]
        return list(self.variants)

    @property
    def override_variants(self) -> list[UUID]:
        # Pair comparisons have always displayed the compared variant's overrides.
        return self.selected[1:] if self.pair else self.contributing_variants

    def select(self, evidence: Mapping[UUID, set[T]]) -> set[T]:
        ids = self.selected
        if not ids:
            return set()
        sets = [evidence.get(vid, set()) for vid in ids]
        if self.operation == "intersection":
            return sets[0].intersection(*sets[1:])
        if self.operation == "difference":
            if self.pair:
                return sets[1] - sets[0]
            return sets[0].difference(*sets[1:])
        return sets[0].union(*sets[1:])

    def scans(self, by_variant: dict[UUID, list[UUID]]) -> list[UUID]:
        return [scan_id for vid in self.contributing_variants for scan_id in by_variant[vid]]

    @property
    def visible_scans_by_variant(self) -> dict[UUID, list[UUID]]:
        return self.all_by_variant if self.historical else self.active_by_variant


def resolve_evidence_scope(
    args: Mapping[str, str], *, historical: bool | None = None, allow_unscoped_cross_project: bool = False,
) -> tuple[EvidenceScope | None, ResponseReturnValue | None]:
    variant_id = args.get("variant_id")
    compare_id = args.get("compare_variant_id")
    multi_ids = args.get("variant_ids")
    project_id = args.get("project_id")
    pair = bool(compare_id)
    comparing = pair or bool(multi_ids)
    operation = args.get("operation", "difference" if pair else "union") if comparing else "union"
    if pair and (not variant_id or multi_ids) or multi_ids and variant_id:
        return None, ({"error": "Invalid variant comparison scope"}, 400)
    if pair and operation != "intersection":
        operation = "difference"
    elif not pair and operation not in {"difference", "intersection", "union"}:
        operation = "union"

    raw_ids = []
    if variant_id:
        raw_ids.append(("variant_id", variant_id))
    if compare_id:
        raw_ids.append(("compare_variant_id", compare_id))
    if multi_ids:
        raw_ids.extend(("variant_ids", value.strip()) for value in multi_ids.split(",") if value.strip())
    selected = []
    for label, value in raw_ids:
        parsed, err = parse_uuid_or_400(value, label)
        if err is not None or parsed is None:
            return None, err if err is not None else ({"error": "Internal error"}, 500)
        selected.append(parsed)
    if comparing and len(selected) < 2:
        return None, ({"error": "Select at least two variants for comparison"}, 400)

    project = None
    if project_id:
        project, err = parse_uuid_or_400(project_id, "project_id")
        if err is not None:
            return None, err
    query = db.select(Variant.id, Variant.name, Variant.project_id).order_by(Variant.id)
    if selected:
        query = query.where(Variant.id.in_(selected))
    elif project is not None:
        query = query.where(Variant.project_id == project)
    rows = {vid: (name, pid) for vid, name, pid in db.session.execute(query)}
    if comparing:
        if rows.keys() != set(selected):
            return None, ({"error": "Comparison variant not found"}, 404)
        projects = {pid for _, pid in rows.values()}
        if project is not None:
            projects.add(project)
        if len(projects) != 1 and (project is not None or not allow_unscoped_cross_project):
            return None, ({"error": "Comparison variants must belong to the same selected project"}, 400)
    elif project is not None and any(pid != project for _, pid in rows.values()):
        return None, ({"error": "Variant must belong to the selected project"}, 400)
    variants = {vid: rows[vid][0] for vid in dict.fromkeys(selected or rows) if vid in rows}
    historical = args.get("include_outdated", "").lower() in ("1", "true", "yes") if historical is None else historical

    active: dict[UUID, list[UUID]] = {vid: [] for vid in variants}
    sboms: dict[UUID, list[UUID]] = {vid: [] for vid in variants}
    all_scans: dict[UUID, list[UUID]] = {vid: [] for vid in variants}
    seen: set[tuple[UUID, bool, str | None]] = set()
    if variants:
        for scan_id, vid, scan_type, source in db.session.execute(
            db.select(Scan.id, Scan.variant_id, Scan.scan_type, Scan.scan_source)
            .where(Scan.variant_id.in_(variants), Scan.in_progress.is_(False))
            .order_by(Scan.timestamp.desc(), Scan.id.desc())
        ):
            all_scans[vid].append(scan_id)
            key = (vid, *scan_strategy_key(scan_type, source))
            if key not in seen:
                seen.add(key)
                active[vid].append(scan_id)
            if scan_type in (None, "sbom") and not sboms[vid]:
                sboms[vid].append(scan_id)
    return EvidenceScope(
        variants, selected if comparing else list(variants), operation, pair, comparing, historical,
        active, sboms, all_scans,
    ), None


@dataclass
class VulnerabilityEvidence:
    ids: set[str]
    current: FindingPackages
    visible: FindingPackages
    variants: dict[str, set[UUID]]
    finding_variants: dict[str, set[UUID]]
    scan_ids: list[UUID]
    scans_by_vulnerability: dict[str, set[UUID]]


def vulnerability_evidence(
    scope: EvidenceScope, requested_ids: Collection[str] | None = None,
) -> VulnerabilityEvidence:
    all_active = [scan_id for ids in scope.active_by_variant.values() for scan_id in ids]
    current = finding_packages_for_scans(all_active, requested_ids)
    visible = current
    if scope.historical:
        all_scans = [scan_id for ids in scope.all_by_variant.values() for scan_id in ids]
        visible = finding_packages_for_scans(all_scans, requested_ids, historical=True)
        for vuln_id, active_targets in current.display.items():
            for variant_key, packages in active_targets.items():
                visible.display.setdefault(vuln_id, {}).setdefault(variant_key, set()).update(packages)
            visible.scan_ids.setdefault(vuln_id, set()).update(current.scan_ids[vuln_id])

    # Standalone SBOM observations are display evidence, never writable targets.
    scans = [scan_id for ids in scope.visible_scans_by_variant.values() for scan_id in ids]
    by_variant: dict[UUID, set[str]] = {vid: set() for vid in scope.variants}
    finding_variants: dict[str, set[UUID]] = {}
    for vuln_id, variants in visible.display.items():
        finding_variants[vuln_id] = variant_ids = {UUID(vid) for vid in variants}
        for finding_variant in variant_ids:
            by_variant[finding_variant].add(vuln_id)
    if scans:
        observations = (
            db.select(SBOMObservation.vulnerability_id, Scan.variant_id, Scan.id,
                      Package.name, Package.version, Package.supplier)
            .join(SBOMDocument, SBOMDocument.id == SBOMObservation.sbom_document_id)
            .join(Scan, Scan.id == SBOMDocument.scan_id)
            .outerjoin(Package, Package.id == SBOMObservation.package_id)
            .where(SBOMDocument.scan_id.in_(scans), db.or_(Scan.scan_type != "tool", Scan.scan_type.is_(None)))
            .distinct()
        )
        if requested_ids is not None:
            observations = observations.where(SBOMObservation.vulnerability_id.in_(requested_ids))
        active_scan_set = set(all_active)
        for vuln_id, vid, scan_id, name, version, supplier in db.session.execute(observations):
            by_variant[vid].add(vuln_id)
            for targets in (visible, current) if scope.historical and scan_id in active_scan_set else (visible,):
                targets.scan_ids.setdefault(vuln_id, set()).add(scan_id)
                if name is not None:
                    package = f"{name}@{version}::{supplier}" if supplier else f"{name}@{version}"
                    targets.display.setdefault(vuln_id, {}).setdefault(str(vid), set()).add(package)
    ids = scope.select(by_variant)
    contributors = set(scope.contributing_variants)
    keys = {str(vid) for vid in contributors}
    variants_by_vulnerability: dict[str, set[UUID]] = {}
    for vid in contributors:
        for vuln_id in by_variant[vid] & ids:
            variants_by_vulnerability.setdefault(vuln_id, set()).add(vid)

    def restrict(targets: FindingPackages) -> FindingPackages:
        def filter_map(mapping: dict[str, dict[str, set[str]]]) -> dict[str, dict[str, set[str]]]:
            return {vuln_id: {vid: packages for vid, packages in by_vid.items() if vid in keys}
                    for vuln_id, by_vid in mapping.items() if vuln_id in ids}
        return FindingPackages(filter_map(targets.display), filter_map(targets.writable))

    visible_scans = scope.scans(scope.visible_scans_by_variant)
    contributor_scans = set(visible_scans)
    return VulnerabilityEvidence(
        ids, restrict(current), restrict(visible), variants_by_vulnerability,
        {vuln_id: variants & contributors for vuln_id, variants in finding_variants.items() if vuln_id in ids},
        visible_scans,
        {vuln_id: visible.scan_ids[vuln_id] & contributor_scans for vuln_id in ids},
    )


@dataclass
class PackageEvidenceScope:
    ids: set[UUID]
    active_by_variant: dict[UUID, set[UUID]]
    documents: list[tuple[UUID, UUID, UUID, UUID, str | None, str | None]] = field(default_factory=list)


def package_evidence(scope: EvidenceScope, package_ids: set[UUID] | None = None) -> PackageEvidenceScope:
    active_scans = {scan for ids in scope.active_sboms_by_variant.values() for scan in ids}
    scans = set(active_scans)
    if scope.historical:
        scans.update(scan for ids in scope.all_by_variant.values() for scan in ids)
    active: dict[UUID, set[UUID]] = {vid: set() for vid in scope.variants}
    visible: dict[UUID, set[UUID]] = {vid: set() for vid in scope.variants}
    result = PackageEvidenceScope(set(), active)
    if scans and (package_ids is None or package_ids):
        query = (
            db.select(
                SBOMPackage.package_id, SBOMDocument.id, Scan.id, Scan.variant_id,
                SBOMDocument.format, SBOMDocument.source_name,
            )
            .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
            .join(Scan, Scan.id == SBOMDocument.scan_id)
            .where(Scan.id.in_(scans), db.or_(Scan.scan_type == "sbom", Scan.scan_type.is_(None)))
        )
        if package_ids is not None:
            query = query.where(SBOMPackage.package_id.in_(package_ids))
        for package, doc, scan, vid, fmt, source in db.session.execute(query):
            visible[vid].add(package)
            if scan in active_scans:
                active[vid].add(package)
            result.documents.append((package, doc, vid, scan, fmt, source))
    result.ids = scope.select(visible)
    return result

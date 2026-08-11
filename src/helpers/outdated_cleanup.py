# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Remove records currently classified as outdated.

Package staleness is scoped to a variant: a finding observation is outdated
when its package name/version is absent from that variant's latest SBOM.  The
same package row can be active in a different variant, so this module removes
only stale variant-scoped evidence before pruning records that have become
unreferenced everywhere.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any, TypeVar, cast
import uuid

from sqlalchemy import tuple_
from sqlalchemy.engine import CursorResult

from ..extensions import db, write_lock
from ..models.assessment import Assessment
from ..models.finding import Finding
from ..models.metrics import Metrics
from ..models.observation import Observation
from ..models.package import Package
from ..models.project import Project
from ..models.sbom_document import SBOMDocument
from ..models.sbom_observation import SBOMObservation
from ..models.sbom_package import SBOMPackage
from ..models.scan import Scan
from ..models.time_estimate import TimeEstimate
from ..models.variant import Variant
from ..models.vuln_refresh import VulnRefresh
from ..models.vulnerability import Vulnerability
from .assessment_staleness import annotate_assessments_outdated

PackageIdentity = tuple[str | None, str | None]
StalePackagePair = tuple[uuid.UUID, uuid.UUID]
UNKNOWN_PROJECT = "Unknown project"
UNKNOWN_VARIANT = "Unknown variant"
_SQL_PARAMETER_CHUNK_SIZE = 400
T = TypeVar("T")


def _chunked(values: Iterable[T]) -> Iterator[list[T]]:
    items = list(values)
    for offset in range(0, len(items), _SQL_PARAMETER_CHUNK_SIZE):
        yield items[offset:offset + _SQL_PARAMETER_CHUNK_SIZE]


def _delete_in_chunks(model: type[Any], column: Any, values: Iterable[Any]) -> None:
    for chunk in _chunked(values):
        db.session.execute(db.delete(model).where(column.in_(chunk)))


def _active_identities_by_variant() -> dict[uuid.UUID, set[PackageIdentity]]:
    """Return active package name/version pairs for every variant.

    The active SBOM scan for a variant is its single latest SBOM-type scan,
    matching :func:`active_sbom_scan_ids_for_variant`.  This resolves every
    variant with two queries total instead of two queries per variant.
    """
    latest_sbom_by_variant: dict[uuid.UUID, uuid.UUID] = {}
    for scan_id, variant_id in db.session.execute(
        db.select(Scan.id, Scan.variant_id)
        .where(db.or_(Scan.scan_type == "sbom", Scan.scan_type.is_(None)))
        .order_by(Scan.variant_id, Scan.timestamp.desc(), Scan.id.desc())
    ):
        latest_sbom_by_variant.setdefault(variant_id, scan_id)

    scan_to_variant = {scan_id: variant_id for variant_id, scan_id in latest_sbom_by_variant.items()}
    identities_by_variant: dict[uuid.UUID, set[PackageIdentity]] = {
        variant_id: set() for variant_id in latest_sbom_by_variant
    }
    for scan_ids in _chunked(scan_to_variant):
        for scan_id, name, version in db.session.execute(
            db.select(SBOMDocument.scan_id, Package.name, Package.version)
            .join(SBOMPackage, SBOMPackage.package_id == Package.id)
            .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
            .where(SBOMDocument.scan_id.in_(scan_ids))
            .distinct()
        ):
            variant_id = scan_to_variant.get(scan_id)
            if variant_id is not None:
                identities_by_variant[variant_id].add((name, version))
    return identities_by_variant


def _stale_observations(
    active_identities_by_variant: dict[uuid.UUID, set[PackageIdentity]],
) -> tuple[list[uuid.UUID], set[StalePackagePair], set[uuid.UUID]]:
    """Return stale observation IDs and package/variant pairs matching staleness.

    Only the columns needed for the staleness decision are selected, avoiding
    the cost of materialising a full ``Observation`` entity per row.
    """
    observation_ids: list[uuid.UUID] = []
    package_pairs: set[StalePackagePair] = set()
    finding_ids: set[uuid.UUID] = set()
    rows = db.session.execute(
        db.select(
            Observation.id, Observation.finding_id,
            Finding.package_id, Package.name, Package.version, Scan.variant_id,
        )
        .join(Finding, Finding.id == Observation.finding_id)
        .join(Package, Package.id == Finding.package_id)
        .join(Scan, Scan.id == Observation.scan_id)
    )
    for observation_id, finding_id, package_id, name, version, variant_id in rows:
        if (name, version) in active_identities_by_variant.get(variant_id, set()):
            continue
        observation_ids.append(observation_id)
        package_pairs.add((package_id, variant_id))
        finding_ids.add(finding_id)
    return observation_ids, package_pairs, finding_ids


def _stale_sbom_package_pairs(
    active_identities_by_variant: dict[uuid.UUID, set[PackageIdentity]],
) -> set[StalePackagePair]:
    """Return historical SBOM package links absent from each variant's active SBOM."""
    pairs: set[StalePackagePair] = set()
    for package_id, name, version, variant_id in db.session.execute(
        db.select(SBOMPackage.package_id, Package.name, Package.version, Scan.variant_id)
        .join(Package, Package.id == SBOMPackage.package_id)
        .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
        .join(Scan, Scan.id == SBOMDocument.scan_id)
    ):
        if (name, version) not in active_identities_by_variant.get(variant_id, set()):
            pairs.add((package_id, variant_id))
    return pairs


def _outdated_assessments() -> list[dict]:
    """Return custom assessment data matching the public staleness predicate."""
    rows = db.session.execute(
        db.select(
            Assessment.id,
            Assessment.origin,
            Assessment.variant_id,
            Assessment.finding_id,
            Finding.vulnerability_id,
            Package.name,
            Package.version,
            Package.supplier,
        )
        .outerjoin(Finding, Finding.id == Assessment.finding_id)
        .outerjoin(Package, Package.id == Finding.package_id)
        .where(Assessment.origin == "custom", Assessment.variant_id.is_not(None))
    )
    assessments: list[dict] = []
    ids_by_string: dict[str, uuid.UUID] = {}
    for assessment_id, origin, variant_id, finding_id, vulnerability_id, name, version, supplier in rows:
        package_id = f"{name}@{version}" if name is not None else ""
        if package_id and supplier:
            package_id += f"::{supplier}"
        assessments.append({
            "id": str(assessment_id),
            "origin": origin,
            "variant_id": str(variant_id),
            "finding_id": finding_id,
            "vuln_id": vulnerability_id or "",
            "packages": [package_id] if package_id else [],
        })
        ids_by_string[str(assessment_id)] = assessment_id
    annotate_assessments_outdated(assessments)
    return [
        {**assessment, "uuid": ids_by_string[assessment["id"]]}
        for assessment in assessments
        if assessment["outdated"]
    ]


SbomCompositeKey = tuple[uuid.UUID, uuid.UUID]


def _stale_sbom_rows(
    model: type[SBOMPackage] | type[SBOMObservation],
    package_pairs: set[StalePackagePair],
) -> list[tuple[SbomCompositeKey, StalePackagePair]]:
    """Return ``((sbom_document_id, package_id), (package_id, variant_id))`` rows.

    The composite ``(sbom_document_id, package_id)`` key works for both the
    ``SBOMPackage`` junction table (its full primary key) and ``SBOMObservation``
    (uniquely scopes every stale record to its document + package).
    """
    package_ids = {package_id for package_id, _ in package_pairs}
    if not package_ids:
        return []
    rows: list[tuple[SbomCompositeKey, StalePackagePair]] = []
    for package_id_chunk in _chunked(package_ids):
        for sbom_document_id, record_package_id, variant_id in db.session.execute(
            db.select(model.sbom_document_id, model.package_id, Scan.variant_id)
            .join(SBOMDocument, SBOMDocument.id == model.sbom_document_id)
            .join(Scan, Scan.id == SBOMDocument.scan_id)
            .where(model.package_id.in_(package_id_chunk))
        ):
            if record_package_id is None:
                continue
            pair: StalePackagePair = (record_package_id, variant_id)
            if pair in package_pairs:
                rows.append(((sbom_document_id, record_package_id), pair))
    return rows


def outdated_data_preview() -> dict[str, object]:
    """Return the stale package data and assessments selected for deletion."""
    active_identities = _active_identities_by_variant()
    stale_observations, package_pairs, _ = _stale_observations(active_identities)
    package_pairs.update(_stale_sbom_package_pairs(active_identities))
    assessments = _outdated_assessments()
    package_ids = {package_id for package_id, _ in package_pairs}
    variant_ids = {variant_id for _, variant_id in package_pairs}
    variant_ids.update(uuid.UUID(assessment["variant_id"]) for assessment in assessments)
    package_labels: dict[uuid.UUID, str] = {}
    for package_id_chunk in _chunked(package_ids):
        package_labels.update({
            package_id: package.string_id
            for package_id, package in db.session.execute(
                db.select(Package.id, Package).where(Package.id.in_(package_id_chunk))
            )
        })
    variant_details: dict[str, dict[str, str]] = {}
    for variant_id_chunk in _chunked(variant_ids):
        variant_details.update({
            str(variant_id): {"project": project_name, "variant": variant_name}
            for variant_id, project_name, variant_name in db.session.execute(
                db.select(Variant.id, Project.name, Variant.name)
                .join(Project, Project.id == Variant.project_id)
                .where(Variant.id.in_(variant_id_chunk))
            )
        })

    vulnerabilities_by_pair: dict[StalePackagePair, set[str]] = {}
    linked_data_by_pair: dict[StalePackagePair, dict[str, int]] = {}
    observation_ids = stale_observations
    for observation_id_chunk in _chunked(observation_ids):
        for package_id, variant_id, vulnerability_id in db.session.execute(
            db.select(Finding.package_id, Scan.variant_id, Finding.vulnerability_id)
            .join(Observation, Observation.finding_id == Finding.id)
            .join(Scan, Scan.id == Observation.scan_id)
            .where(Observation.id.in_(observation_id_chunk))
        ):
            pair = (package_id, variant_id)
            vulnerabilities_by_pair.setdefault(pair, set()).add(vulnerability_id)
            linked_data_by_pair.setdefault(
                pair, {"observations": 0, "sbom_packages": 0, "sbom_observations": 0}
            )["observations"] += 1
    for _sbom_package_id, pair in _stale_sbom_rows(SBOMPackage, package_pairs):
        linked_data_by_pair.setdefault(
            pair, {"observations": 0, "sbom_packages": 0, "sbom_observations": 0}
        )["sbom_packages"] += 1
    for _sbom_observation_id, pair in _stale_sbom_rows(SBOMObservation, package_pairs):
        linked_data_by_pair.setdefault(
            pair, {"observations": 0, "sbom_packages": 0, "sbom_observations": 0}
        )["sbom_observations"] += 1

    packages = [
        {
            "package": package_labels[package_id],
            "project": variant_details.get(str(variant_id), {}).get("project", UNKNOWN_PROJECT),
            "variant": variant_details.get(str(variant_id), {}).get("variant", UNKNOWN_VARIANT),
            "vulnerabilities": sorted(vulnerabilities_by_pair.get((package_id, variant_id), set())),
            "linked_data": linked_data_by_pair.get(
                (package_id, variant_id),
                {"observations": 0, "sbom_packages": 0, "sbom_observations": 0},
            ),
        }
        for package_id, variant_id in sorted(
            package_pairs,
            key=lambda pair: (package_labels[pair[0]], variant_details.get(str(pair[1]), {}).get("variant", "")),
        )
    ]
    return {
        "candidate_ids": {
            "observations": sorted(str(observation_id) for observation_id in stale_observations),
            "assessments": sorted(str(assessment["uuid"]) for assessment in assessments),
            "package_pairs": sorted(
                [
                    {"package_id": str(package_id), "variant_id": str(variant_id)}
                    for package_id, variant_id in package_pairs
                ],
                key=lambda pair: (pair["package_id"], pair["variant_id"]),
            ),
        },
        "packages": packages,
        "assessments": [
            {
                "vulnerability": assessment["vuln_id"],
                "package": assessment["packages"][0] if assessment["packages"] else "Unknown package",
                "project": variant_details.get(assessment["variant_id"], {}).get("project", UNKNOWN_PROJECT),
                "variant": variant_details.get(assessment["variant_id"], {}).get("variant", UNKNOWN_VARIANT),
            }
            for assessment in assessments
        ],
    }


def _delete_stale_sbom_records(package_pairs: set[StalePackagePair]) -> tuple[int, int]:
    """Remove SBOM links and SBOM observations for stale package/variant pairs."""
    sbom_package_rows = _stale_sbom_rows(SBOMPackage, package_pairs)
    sbom_observation_rows = _stale_sbom_rows(SBOMObservation, package_pairs)
    sbom_package_keys = {key for key, _ in sbom_package_rows}
    sbom_observation_keys = {key for key, _ in sbom_observation_rows}
    for key_chunk in _chunked(sbom_package_keys):
        db.session.execute(
            db.delete(SBOMPackage).where(
                tuple_(SBOMPackage.sbom_document_id, SBOMPackage.package_id).in_(key_chunk)
            )
        )
    for key_chunk in _chunked(sbom_observation_keys):
        db.session.execute(
            db.delete(SBOMObservation).where(
                tuple_(SBOMObservation.sbom_document_id, SBOMObservation.package_id).in_(key_chunk)
            )
        )
    return len(sbom_package_rows), len(sbom_observation_rows)


def _delete_superseded_packageless_sbom_observations() -> int:
    """Remove package-less observations from non-active SBOM documents."""
    active_scan_ids: set[uuid.UUID] = set()
    active_variants: set[uuid.UUID] = set()
    for scan_id, variant_id in db.session.execute(
        db.select(Scan.id, Scan.variant_id)
        .where(db.or_(Scan.scan_type == "sbom", Scan.scan_type.is_(None)))
        .order_by(Scan.variant_id, Scan.timestamp.desc(), Scan.id.desc())
    ):
        if variant_id not in active_variants:
            active_scan_ids.add(scan_id)
            active_variants.add(variant_id)
    statement = (
        db.delete(SBOMObservation)
        .where(SBOMObservation.package_id.is_(None))
        .where(SBOMObservation.sbom_document_id.in_(
            db.select(SBOMDocument.id).where(~SBOMDocument.scan_id.in_(active_scan_ids))
        ))
    )
    result = cast(CursorResult[Any], db.session.execute(statement))
    return result.rowcount


def _delete_orphaned_findings(finding_ids: set[uuid.UUID]) -> tuple[int, set[str]]:
    """Delete candidate findings only when no non-outdated data still needs them."""
    if not finding_ids:
        return 0, set()
    rows: list[tuple[uuid.UUID, str]] = []
    for finding_id_chunk in _chunked(finding_ids):
        rows.extend(
            (finding_id, vulnerability_id)
            for finding_id, vulnerability_id in db.session.execute(
                db.select(Finding.id, Finding.vulnerability_id)
                .where(Finding.id.in_(finding_id_chunk))
                .where(~Finding.observations.any())
                .where(~Finding.assessments.any())
                .where(~Finding.time_estimates.any())
            ).all()
        )
    ids = [row[0] for row in rows]
    vulnerability_ids = {row[1] for row in rows}
    _delete_in_chunks(Finding, Finding.id, ids)
    return len(ids), vulnerability_ids


def _delete_orphaned_vulnerabilities(vulnerability_ids: set[str]) -> int:
    """Delete vulnerability aggregates with no remaining package evidence.

    Dependent ``Metrics`` and ``VulnRefresh`` rows are removed first: bulk
    ``DELETE`` bypasses the ORM's ``delete-orphan`` cascade, so the child rows
    must be cleared explicitly to avoid leaving orphans behind.
    """
    if not vulnerability_ids:
        return 0
    ids: list[str] = []
    for vulnerability_id_chunk in _chunked(vulnerability_ids):
        ids.extend(db.session.execute(
            db.select(Vulnerability.id)
            .where(Vulnerability.id.in_(vulnerability_id_chunk))
            .where(~Vulnerability.findings.any())
            .where(~Vulnerability.sbom_observations.any())
        ).scalars())
    _delete_in_chunks(Metrics, Metrics.vulnerability_id, ids)
    _delete_in_chunks(VulnRefresh, VulnRefresh.vuln_id, ids)
    _delete_in_chunks(Vulnerability, Vulnerability.id, ids)
    return len(ids)


def _delete_orphaned_packages(package_pairs: set[StalePackagePair]) -> int:
    """Delete candidate packages only after every related record is gone."""
    package_ids = {package_id for package_id, _ in package_pairs}
    if not package_ids:
        return 0
    ids: list[uuid.UUID] = []
    for package_id_chunk in _chunked(package_ids):
        ids.extend(db.session.execute(
            db.select(Package.id)
            .where(Package.id.in_(package_id_chunk))
            .where(~Package.findings.any())
            .where(~Package.sbom_packages.any())
            .where(~Package.sbom_observations.any())
        ).scalars())
    _delete_in_chunks(Package, Package.id, ids)
    return len(ids)


def delete_outdated_data(candidate_ids: dict[str, object] | None = None) -> dict[str, int]:
    """Delete every package observation and custom assessment marked outdated.

    The predicates deliberately mirror ``/api/packages?outdated_only=true``
    and ``annotate_assessments_outdated``.  Shared records are retained until
    no scan, assessment, or SBOM relation references them.
    """
    with write_lock():
        active_identities = _active_identities_by_variant()
        stale_observation_ids, stale_package_pairs, stale_finding_ids = _stale_observations(active_identities)
        stale_package_pairs.update(_stale_sbom_package_pairs(active_identities))
        outdated_assessments = _outdated_assessments()
        outdated_assessment_ids = [assessment["uuid"] for assessment in outdated_assessments]
        current_candidates = {
            "observations": sorted(str(observation_id) for observation_id in stale_observation_ids),
            "assessments": sorted(str(assessment_id) for assessment_id in outdated_assessment_ids),
            "package_pairs": sorted(
                [
                    {"package_id": str(package_id), "variant_id": str(variant_id)}
                    for package_id, variant_id in stale_package_pairs
                ],
                key=lambda pair: (pair["package_id"], pair["variant_id"]),
            ),
        }
        if candidate_ids is not None and candidate_ids != current_candidates:
            raise ValueError(_STALE_PREVIEW_MESSAGE)
        outdated_finding_ids = {
            assessment["finding_id"]
            for assessment in outdated_assessments
            if assessment["finding_id"] is not None
        }
        _delete_in_chunks(Assessment, Assessment.id, outdated_assessment_ids)
        _delete_in_chunks(Observation, Observation.id, stale_observation_ids)
        sbom_packages_deleted, sbom_observations_deleted = _delete_stale_sbom_records(stale_package_pairs)
        sbom_observations_deleted += _delete_superseded_packageless_sbom_observations()
        findings_deleted, vulnerability_ids = _delete_orphaned_findings(
            stale_finding_ids | outdated_finding_ids
        )
        vulnerabilities_deleted = _delete_orphaned_vulnerabilities(vulnerability_ids)
        packages_deleted = _delete_orphaned_packages(stale_package_pairs)
        db.session.commit()

    from ..routes._scan_diff import invalidate_scan_list_cache
    invalidate_scan_list_cache()

    return {
        "assessments_deleted": len(outdated_assessment_ids),
        "observations_deleted": len(stale_observation_ids),
        "sbom_packages_deleted": sbom_packages_deleted,
        "sbom_observations_deleted": sbom_observations_deleted,
        "findings_deleted": findings_deleted,
        "vulnerabilities_deleted": vulnerabilities_deleted,
        "packages_deleted": packages_deleted,
    }


_SCAN_CHANGE_FIELDS = (
    "packages_added",
    "packages_removed",
    "packages_upgraded",
    "findings_added",
    "findings_removed",
    "findings_upgraded",
    "vulns_added",
    "vulns_removed",
    "assessments_added",
    "assessments_removed",
)
_STALE_PREVIEW_MESSAGE = "Cleanup preview is no longer current"


def empty_scans_preview() -> list[dict[str, str]]:
    """Return non-initial scans whose complete history diff is empty.

    Uses an uncached scan-history serialisation so destructive cleanup is based
    on the current assessments and findings rather than a stale list response.
    """
    from ..routes._scan_diff import _serialize_list_with_diff

    scans = _serialize_list_with_diff(Scan.get_all())
    return [
        {
            "id": item["id"],
            "description": item["description"] or "",
            "timestamp": item["timestamp"],
            "project": item.get("project_name") or UNKNOWN_PROJECT,
            "variant": item.get("variant_name") or UNKNOWN_VARIANT,
        }
        for item in scans
        if not item.get("is_first")
        and item.get("scan_type") == "tool"
        and all(item.get(field) == 0 for field in _SCAN_CHANGE_FIELDS)
    ]


def delete_empty_scans(candidate_ids: list[str] | None = None) -> dict[str, int]:
    """Delete scans selected by :func:`empty_scans_preview`."""
    with write_lock():
        current_ids = [scan["id"] for scan in empty_scans_preview()]
        if candidate_ids is not None and sorted(candidate_ids) != sorted(current_ids):
            raise ValueError(_STALE_PREVIEW_MESSAGE)
        scan_ids = [uuid.UUID(scan_id) for scan_id in current_ids]
        for scan_id in scan_ids:
            scan = db.session.get(Scan, scan_id)
            if scan is not None:
                db.session.delete(scan)
        db.session.commit()

    from ..routes._scan_diff import invalidate_scan_list_cache
    invalidate_scan_list_cache()
    return {"scans_deleted": len(scan_ids)}


def orphaned_vulnerabilities_preview() -> list[dict[str, str | int]]:
    """Return vulnerabilities that have no evidence in any variant scan.

    Two queries total: one selects the orphaned vulnerability IDs, the other
    aggregates their assessment counts, avoiding a per-vulnerability lazy load.
    """
    orphan_ids = list(db.session.execute(
        db.select(Vulnerability.id)
        .where(~Vulnerability.findings.any(Finding.observations.any()))
        .where(~Vulnerability.findings.any(Finding.time_estimates.any()))
        .where(~Vulnerability.metrics.any(Metrics.variant_id.is_not(None)))
        .where(~Vulnerability.sbom_observations.any())
        .order_by(Vulnerability.id)
    ).scalars())
    if not orphan_ids:
        return []
    assessment_counts: dict[str, int] = {}
    for orphan_id_chunk in _chunked(orphan_ids):
        assessment_counts.update({
            vulnerability_id: count
            for vulnerability_id, count in db.session.execute(
                db.select(Finding.vulnerability_id, db.func.count(Assessment.id))
                .join(Assessment, Assessment.finding_id == Finding.id)
                .where(Finding.vulnerability_id.in_(orphan_id_chunk))
                .group_by(Finding.vulnerability_id)
            ).all()
        })
    return [
        {"id": vulnerability_id, "assessments": assessment_counts.get(vulnerability_id, 0)}
        for vulnerability_id in orphan_ids
    ]


def delete_orphaned_vulnerabilities(candidate_ids: list[str] | None = None) -> dict[str, int]:
    """Delete CVEs absent from every project/variant and their assessments.

    Bulk ``DELETE`` statements replace the ORM cascade: child rows (findings and
    their assessments / time-estimates / observations, plus per-CVE metrics and
    refresh metadata) are cleared explicitly in foreign-key order.
    """
    with write_lock():
        vulnerability_ids = [str(item["id"]) for item in orphaned_vulnerabilities_preview()]
        if candidate_ids is not None and sorted(candidate_ids) != sorted(vulnerability_ids):
            raise ValueError(_STALE_PREVIEW_MESSAGE)
        if not vulnerability_ids:
            return {"vulnerabilities_deleted": 0, "assessments_deleted": 0, "findings_deleted": 0}

        finding_ids: list[uuid.UUID] = []
        for vulnerability_id_chunk in _chunked(vulnerability_ids):
            finding_ids.extend(db.session.execute(
                db.select(Finding.id).where(Finding.vulnerability_id.in_(vulnerability_id_chunk))
            ).scalars())
        assessments_deleted = 0
        for finding_id_chunk in _chunked(finding_ids):
            assessments_deleted += db.session.execute(
                db.select(db.func.count(Assessment.id)).where(Assessment.finding_id.in_(finding_id_chunk))
            ).scalar_one()
        _delete_in_chunks(Assessment, Assessment.finding_id, finding_ids)
        _delete_in_chunks(TimeEstimate, TimeEstimate.finding_id, finding_ids)
        _delete_in_chunks(Observation, Observation.finding_id, finding_ids)
        _delete_in_chunks(Finding, Finding.id, finding_ids)
        _delete_in_chunks(Metrics, Metrics.vulnerability_id, vulnerability_ids)
        _delete_in_chunks(VulnRefresh, VulnRefresh.vuln_id, vulnerability_ids)
        _delete_in_chunks(Vulnerability, Vulnerability.id, vulnerability_ids)
        db.session.commit()

    from ..routes._scan_diff import invalidate_scan_list_cache
    invalidate_scan_list_cache()
    return {
        "vulnerabilities_deleted": len(vulnerability_ids),
        "assessments_deleted": assessments_deleted,
        "findings_deleted": len(finding_ids),
    }

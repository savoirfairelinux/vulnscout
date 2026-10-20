# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Persist proven West JSON-LD components as ordinary packages."""

from collections import Counter, defaultdict
import logging
import uuid

from packageurl import PackageURL
from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import Session

from ..models import Package, SBOMDocument, SBOMPackage, Scan
from ..models.assessment import Assessment
from ..models.assessment_review import AssessmentReview
from ..models.assessment_target import AssessmentTarget
from ..models.finding import Finding
from ..models.observation import Observation
from ..models.package_dependency import PackageDependency
from ..models.sbom_observation import SBOMObservation
from ..models.time_estimate import TimeEstimate
from .package_versions import is_source_revision, package_version_info

logger = logging.getLogger(__name__)


def _canonical_purls(purls: list[str], name: str) -> list[str]:
    result = []
    for purl in purls:
        try:
            if PackageURL.from_string(purl).name == name:
                result.append(purl)
        except ValueError:
            logger.warning("Cannot identify the package name in invalid PURL: %s", purl)
    return result


def _metadata(group: dict, packages: dict, links: list[SBOMPackage]) -> dict | None:
    members = {uuid.UUID(member["package_id"]) for member in group["members"]}
    if not members.issubset(packages):
        return None
    evidence = {
        field: sorted({value for link in links if link.package_id in members
                       for value in getattr(link, field) or []})
        for field in ("cpe", "purl", "source_urls", "source_revisions")
    }
    infos = [package_version_info(packages[member].version, evidence["purl"], evidence["cpe"],
                                  evidence["source_urls"], evidence["source_revisions"])
             for member in members]
    releases = {info["release_version"] for info in infos if info["release_version"]}
    revisions = {info["source_revision"] for info in infos if info["source_revision"]}
    if (len(releases) > 1 or len(revisions) > 1
            or any(info["version_conflict"] or info["revision_conflict"] for info in infos)):
        return None
    evidence["source_revisions"] = sorted(revisions)
    release_identifiers = {item["identifier"] for info in infos for item in info["version_evidence"]
                           if not is_source_revision(item["version"])}
    for field in ("cpe", "purl"):
        evidence[field].sort(key=lambda value: (value not in release_identifiers, value))
    return {"name": group["name"], "version": next(iter(releases), ""), **evidence}


def _merge_finding_references(session: Session, mappings: dict, documents: dict,
                              original_links: list[SBOMPackage]) -> None:
    """Move references before deleting findings, bypassing assessment delete reapers."""
    affected = {member for mapping in mappings.values() for member, parent in mapping.items() if member != parent}
    if not affected:
        return
    scans = {scan.id: scan for scan in session.scalars(select(Scan))}
    by_variant: dict[tuple, set] = defaultdict(set)
    for link in original_links:
        document = documents[link.sbom_document_id]
        parent = mappings.get(document.scan_id, {}).get(link.package_id, link.package_id)
        by_variant[link.package_id, scans[document.scan_id].variant_id].add(parent)
    all_parents: dict[uuid.UUID, set[uuid.UUID]] = defaultdict(set)
    for (member, _), parents in by_variant.items():
        all_parents[member].update(parents)

    def parents_for(member, variant_id=None, scan_id=None):
        if scan_id in mappings:
            return {mappings[scan_id].get(member, member)}
        if scan_id is not None:
            scan = scans[scan_id]
            eligible = [other for other in scans.values() if other.variant_id == scan.variant_id
                        and (other.scan_type or "sbom") == "sbom" and other.timestamp <= scan.timestamp]
            if eligible:
                latest = max(eligible, key=lambda other: other.timestamp)
                return {mappings.get(latest.id, {}).get(member, member)}
            variant_id = scan.variant_id
        return by_variant.get((member, variant_id), all_parents[member] or {member})

    findings = list(session.execute(
        select(Finding.id, Finding.package_id, Finding.vulnerability_id).where(Finding.package_id.in_(affected)),
    ))
    resolved: dict[tuple, uuid.UUID] = {}

    def finding_for(package_id, vulnerability_id):
        key = package_id, vulnerability_id
        if key not in resolved:
            finding_id = session.scalar(select(Finding.id).where(
                Finding.package_id == package_id, Finding.vulnerability_id == vulnerability_id,
            ))
            if finding_id is None:
                finding_id = uuid.uuid4()
                session.execute(insert(Finding).values(
                    id=finding_id, package_id=package_id, vulnerability_id=vulnerability_id,
                ))
            resolved[key] = finding_id
        return resolved[key]

    for finding_id, member, vulnerability_id in findings:
        parents = all_parents[member]
        if len(parents) == 1 and member not in parents:
            parent_id = next(iter(parents))
            existing_finding = session.scalar(select(Finding.id).where(
                Finding.package_id == parent_id, Finding.vulnerability_id == vulnerability_id,
            ))
            if existing_finding is None:
                session.execute(update(Finding).where(Finding.id == finding_id).values(package_id=parent_id),
                                execution_options={"synchronize_session": False})
                resolved[parent_id, vulnerability_id] = finding_id
                continue
        for parent in all_parents[member]:
            finding_for(parent, vulnerability_id)
        observations = list(session.execute(select(Observation.__table__).where(
            Observation.finding_id == finding_id,
        )).mappings())
        for observation in observations:
            parents = parents_for(member, scan_id=observation["scan_id"])
            for parent in parents:
                target = finding_for(parent, vulnerability_id)
                exists = session.scalar(select(Observation.id).where(
                    Observation.finding_id == target, Observation.scan_id == observation["scan_id"],
                ))
                if exists is None:
                    session.execute(insert(Observation).values(
                        id=uuid.uuid4(), finding_id=target, scan_id=observation["scan_id"],
                    ))
            if member not in parents:
                session.execute(delete(Observation).where(Observation.id == observation["id"]),
                                execution_options={"synchronize_session": False})
        for target in list(session.execute(select(AssessmentTarget.__table__).where(
            AssessmentTarget.finding_id == finding_id,
        )).mappings()):
            parents = parents_for(member, variant_id=target["variant_id"])
            for parent in parents:
                replacement = {**target, "finding_id": finding_for(parent, vulnerability_id)}
                existing_target = session.execute(select(AssessmentTarget.__table__).filter_by(**replacement)).first()
                if existing_target is None:
                    session.execute(insert(AssessmentTarget).values(**replacement))
            if member not in parents:
                session.execute(delete(AssessmentTarget).filter_by(**target),
                                execution_options={"synchronize_session": False})
        for model, key_fields, data_fields in (
            (TimeEstimate, ("variant_id",),
             ("optimistic", "likely", "pessimistic")),
            (AssessmentReview, ("assessment_id", "variant_id"),
             ("status", "status_notes", "justification", "impact_statement", "workaround",
              "responses", "rationale", "reviewed_fingerprint")),
        ):
            for row in list(session.execute(select(model.__table__).where(
                model.finding_id == finding_id,
            )).mappings()):
                parents = parents_for(member, variant_id=row["variant_id"])
                for parent in parents:
                    new_finding = finding_for(parent, vulnerability_id)
                    key = {"finding_id": new_finding, **{field: row[field] for field in key_fields}}
                    existing = session.execute(select(model.__table__).filter_by(**key)).mappings().first()
                    if existing is not None:
                        if any(existing[field] != row[field] for field in data_fields):
                            raise ValueError(
                                f"Cannot consolidate {member}: conflicting {model.__tablename__} "
                                f"for finding {new_finding}. Resolve the duplicate records before retrying."
                            )
                    else:
                        session.execute(insert(model).values(**{**row, **key, "id": uuid.uuid4()}))
                if member not in parents:
                    session.execute(delete(model).where(model.id == row["id"]),
                                    execution_options={"synchronize_session": False})
        # Retain an original finding when it also belongs to an unrelated SBOM.
        keep_original = member in all_parents[member]
        for reference_model in (Observation, AssessmentTarget, AssessmentReview, TimeEstimate):
            if keep_original:
                continue
            session.execute(delete(reference_model).where(reference_model.finding_id == finding_id),
                            execution_options={"synchronize_session": False})
        if not keep_original:
            session.execute(delete(Finding).where(Finding.id == finding_id),
                            execution_options={"synchronize_session": False})


def consolidate_jsonld_packages(session: Session) -> bool:
    """Consolidate recorded, unprocessed groups in the caller's transaction."""
    documents = {document.id: document for document in session.scalars(select(SBOMDocument))}
    pending_scans = {document.scan_id for document in documents.values()
                     for group in document.jsonld_groups or [] if not group.get("canonical_package_id")}
    if not pending_scans:
        return False
    links = list(session.scalars(select(SBOMPackage)))
    by_scan: dict[uuid.UUID, list[SBOMPackage]] = defaultdict(list)
    by_member: dict[uuid.UUID, list[SBOMPackage]] = defaultdict(list)
    for link in links:
        by_scan[documents[link.sbom_document_id].scan_id].append(link)
        by_member[link.package_id].append(link)
    packages = {package.id: package for package in session.scalars(
        select(Package).where(Package.id.in_({
            link.package_id for scan_id in pending_scans for link in by_scan[scan_id]
        })),
    )}
    plans = []
    for scan_id in pending_scans:
        groups = [group for document in documents.values() if document.scan_id == scan_id
                  for group in document.jsonld_groups or [] if not group.get("canonical_package_id")]
        occurrences = Counter(member["package_id"] for group in groups for member in group["members"])
        excluded = {link.package_id for link in by_scan[scan_id]
                    if documents[link.sbom_document_id].jsonld_groups is None}
        for group in groups:
            if any(occurrences[member["package_id"]] > 1 or uuid.UUID(member["package_id"]) in excluded
                   for member in group["members"]):
                continue
            metadata = _metadata(group, packages, by_scan[scan_id])
            if metadata is not None:
                members = sorted(group["members"], key=lambda item: item["role"] != "build")
                supplier = next((packages[uuid.UUID(member["package_id"])].supplier
                                 for member in members if packages[uuid.UUID(member["package_id"])].supplier), "")
                plans.append((scan_id, group, metadata, supplier))
    if not plans:
        return False
    destinations: dict[tuple, set] = defaultdict(set)
    for scan_id, group, metadata, supplier in plans:
        key = metadata["name"], metadata["version"], supplier
        for member in group["members"]:
            destinations[scan_id, uuid.UUID(member["package_id"])].add(key)
    mappings: dict[uuid.UUID, dict[uuid.UUID, uuid.UUID]] = defaultdict(dict)
    metadata_by_parent: dict[tuple, dict] = {}
    canonical_ids = set()
    for scan_id, group, metadata, supplier in plans:
        key = metadata["name"], metadata["version"], supplier
        parent = session.scalar(select(Package).where(
            Package.name == key[0], Package.version == key[1], Package.supplier == key[2],
        ))
        members = sorted(group["members"], key=lambda item: item["role"] != "build")
        if parent is None:
            for member in members:
                member_id = uuid.UUID(member["package_id"])
                if member_id not in canonical_ids and all(
                    destinations.get((documents[link.sbom_document_id].scan_id, member_id)) == {key}
                    for link in by_member[member_id]
                ):
                    parent = packages[member_id]
                    break
        if parent is None:
            parent = Package()
            session.add(parent)
        parent.name, parent.version, parent.supplier = key
        for field in ("cpe", "purl", "source_revisions"):
            setattr(parent, field, list(dict.fromkeys([*metadata[field], *(getattr(parent, field) or [])])))
        # Grype's normal parser derives names from the first PURL.
        canonical_purls = _canonical_purls(metadata["purl"], metadata["name"])
        if not canonical_purls:
            canonical_purls = [str(PackageURL.from_string(parent.generate_generic_purl()))]
        metadata["purl"] = list(dict.fromkeys([*canonical_purls, *metadata["purl"]]))
        parent.purl = list(dict.fromkeys([*canonical_purls, *(parent.purl or [])]))
        if not parent.licences or parent.licences in {"NOASSERTION", "NONE"}:
            parent.licences = next((packages[uuid.UUID(member["package_id"])].licences
                                    for member in members
                                    if packages[uuid.UUID(member["package_id"])].licences
                                    not in {None, "", "NOASSERTION", "NONE"}), "")
        session.flush()
        canonical_ids.add(parent.id)
        metadata["type"] = (
            "built" if group["built"] or metadata_by_parent.get((scan_id, parent.id), {}).get("type") == "built"
            else "workspace"
        )
        metadata_by_parent[scan_id, parent.id] = metadata
        for member in group["members"]:
            mappings[scan_id][uuid.UUID(member["package_id"])] = parent.id
        for document in documents.values():
            if document.scan_id == scan_id and group in (document.jsonld_groups or []):
                document.jsonld_groups = [
                    {**entry, "canonical_package_id": str(parent.id)} if entry == group else entry
                    for entry in document.jsonld_groups or []
                ]
    associations = {(link.sbom_document_id, link.package_id): link for link in links}
    for link in links:
        scan_id = documents[link.sbom_document_id].scan_id
        parent_id = mappings.get(scan_id, {}).get(link.package_id)
        if parent_id is None:
            continue
        association_key = link.sbom_document_id, parent_id
        target = associations.get(association_key)
        if target is None:
            target = SBOMPackage(sbom_document_id=association_key[0], package_id=association_key[1])
            associations[association_key] = target
            session.add(target)
        metadata = metadata_by_parent[scan_id, parent_id]
        for field in ("cpe", "purl", "source_urls", "source_revisions"):
            setattr(target, field, list(dict.fromkeys([*metadata[field], *(getattr(target, field) or [])])))
    for link in associations.values():
        document = documents[link.sbom_document_id]
        metadata = metadata_by_parent.get((document.scan_id, link.package_id))
        if metadata is not None and document.jsonld_groups is not None:
            link.type = metadata["type"]
    session.flush()
    document_ids = {document.id for document in documents.values() if document.scan_id in mappings}
    edges = set()
    for document_id, source, dependency in session.execute(select(
        PackageDependency.sbom_document_id, PackageDependency.package_id, PackageDependency.dependency_id,
    ).where(PackageDependency.sbom_document_id.in_(document_ids))):
        mapping = mappings[documents[document_id].scan_id]
        source, dependency = mapping.get(source, source), mapping.get(dependency, dependency)
        if source != dependency:
            edges.add((document_id, source, dependency))
    session.execute(delete(PackageDependency).where(PackageDependency.sbom_document_id.in_(document_ids)),
                    execution_options={"synchronize_session": False})
    for link in links:
        parent_id = mappings.get(documents[link.sbom_document_id].scan_id, {}).get(link.package_id)
        if parent_id is not None and parent_id != link.package_id:
            session.execute(delete(SBOMPackage).where(
                SBOMPackage.sbom_document_id == link.sbom_document_id, SBOMPackage.package_id == link.package_id,
            ), execution_options={"synchronize_session": False})
    if edges:
        session.execute(insert(PackageDependency), [
            {"sbom_document_id": doc, "package_id": source, "dependency_id": dependency}
            for doc, source, dependency in edges
        ])
    _merge_finding_references(session, mappings, documents, links)
    for observation in session.scalars(select(SBOMObservation).where(
        SBOMObservation.sbom_document_id.in_(document_ids),
    )):
        if observation.package_id is not None:
            observation.package_id = mappings[documents[observation.sbom_document_id].scan_id].get(
                observation.package_id, observation.package_id,
            )
    session.flush()
    candidates = {member for mapping in mappings.values() for member in mapping} - canonical_ids
    for member in candidates:
        if (session.scalar(select(SBOMPackage.package_id).where(SBOMPackage.package_id == member).limit(1)) is None
                and session.scalar(select(Finding.id).where(Finding.package_id == member).limit(1)) is None
                and session.scalar(select(SBOMObservation.id).where(
                    SBOMObservation.package_id == member).limit(1)) is None):
            session.execute(delete(Package).where(Package.id == member),
                            execution_options={"synchronize_session": False})
    session.flush()
    for record in list(session.identity_map.values()):
        if isinstance(record, Assessment):
            record.packages = []
    session.expire_all()
    return True

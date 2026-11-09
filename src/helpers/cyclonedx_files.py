# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Persist CycloneDX observations without interpreting them as compilation proof."""

from collections import defaultdict
import uuid

from ..extensions import db
from ..models import Package, PackageSourceFile, SBOMBuild, SBOMDocument, SBOMFile, SBOMFileBuild, SBOMPackage


def has_recorded_files(component: dict) -> bool:
    """Identify roots with file evidence even when no dependency graph is present."""
    return bool((component.get("evidence") or {}).get("occurrences")) or any(
        reference.get("type") == "formulation" for reference in component.get("externalReferences", [])
    ) or any(
        child.get("type") == "file" or has_recorded_files(child) for child in component.get("components", [])
    )


def record_cyclonedx_files(
    document: SBOMDocument, data: dict, references: dict[str, str], aliases: dict[str, str],
) -> None:
    """Read raw JSON: the library model does not retain formulation or occurrences.

    Only nesting, occurrences, and explicit local formulation references establish
    package ownership. Dependency edges and other documents are deliberately ignored.
    """
    build_ids = db.select(SBOMBuild.id).where(SBOMBuild.sbom_document_id == document.id)
    db.session.execute(db.delete(SBOMFileBuild).where(db.or_(
        SBOMFileBuild.file_document_id == document.id, SBOMFileBuild.build_id.in_(build_ids),
    )))
    db.session.execute(db.delete(PackageSourceFile).where(db.or_(
        PackageSourceFile.sbom_document_id == document.id, PackageSourceFile.file_document_id == document.id,
    )))
    db.session.execute(db.delete(SBOMFile).where(SBOMFile.sbom_document_id == document.id))
    db.session.execute(db.delete(SBOMBuild).where(SBOMBuild.sbom_document_id == document.id))
    try:
        version = tuple(int(part) for part in data.get("specVersion", "").split("."))
    except ValueError:
        return
    if version < (1, 5):
        return

    links = {link.package_id: link for link in db.session.scalars(
        db.select(SBOMPackage).where(SBOMPackage.sbom_document_id == document.id)
    )}
    for link in links.values():
        link.compiled_sources_complete = False

    def scoped(kind: str, ref: str) -> str:
        return f"urn:vulnscout:cdx:{document.id}:{kind}:{ref}"

    files: dict[str, SBOMFile] = {}
    owners: dict[str, set[uuid.UUID]] = defaultdict(set)
    formula_owners: dict[str, set[uuid.UUID]] = defaultdict(set)
    formula_files: dict[str, set[str]] = defaultdict(set)
    serial = data.get("serialNumber", "")
    bom_link = f"urn:cdx:{serial.removeprefix('urn:uuid:')}/{data.get('version', 1)}#"
    formulas = {
        formula["bom-ref"]: formula for formula in data.get("formulation", [])
        if isinstance(formula, dict) and isinstance(formula.get("bom-ref"), str)
    }

    def package_id(component: dict) -> uuid.UUID | None:
        if component.get("type") == "file":
            return None
        ref = component.get("bom-ref")
        string_id = references.get(ref) if isinstance(ref, str) else None
        if string_id is None:
            string_id = aliases.get(f"{component.get('name')}@{component.get('version') or ''}")
        package = Package.get_by_string_id(string_id) if string_id else None
        return package.id if package is not None and package.id in links else None

    def add_file(ref: str, path: str, properties: dict, owner: uuid.UUID | None, formula: str | None) -> None:
        if ref not in files:
            files[ref] = SBOMFile(
                sbom_document_id=document.id, spdx_id=ref, path=path, properties=properties,
            )
            db.session.add(files[ref])
        if owner is not None:
            owners[ref].add(owner)
        if formula is not None:
            formula_files[formula].add(ref)

    def walk(component: dict, pointer: str, owner: uuid.UUID | None = None, formula: str | None = None) -> None:
        if not isinstance(component, dict):
            return
        if component.get("type") == "file":
            name = component.get("name")
            if isinstance(name, str) and name:
                ref = component.get("bom-ref")
                identifier = scoped("ref", ref) if isinstance(ref, str) else scoped("path", pointer)
                add_file(identifier, name, component, owner, formula)
        else:
            # A nested software component owns its own evidence, not its parent's.
            component_owner = package_id(component) if formula is None else None
            if component_owner is not None or component.get("type") in {
                "application", "framework", "library", "operating-system", "firmware", "device-driver",
            }:
                owner = component_owner
            for reference in component.get("externalReferences", []):
                if reference.get("type") != "formulation":
                    continue
                url = reference.get("url", "")
                local_ref = url[len(bom_link):] if url.startswith(bom_link) else url.removeprefix("#")
                if local_ref in formulas and owner is not None:
                    formula_owners[local_ref].add(owner)
            evidence = component.get("evidence") or {}
            for index, occurrence in enumerate(evidence.get("occurrences", [])):
                location = occurrence.get("location")
                if not isinstance(location, str) or not location:
                    continue
                ref = occurrence.get("bom-ref")
                identifier = scoped("ref", ref) if isinstance(ref, str) else scoped(
                    "path", f"{pointer}/evidence/occurrences/{index}",
                )
                add_file(identifier, location, {"component": component, "occurrence": occurrence}, owner, formula)
        for index, child in enumerate(component.get("components", [])):
            walk(child, f"{pointer}/components/{index}", owner, formula)

    root = (data.get("metadata") or {}).get("component")
    if isinstance(root, dict):
        walk(root, "/metadata/component")
    for index, component in enumerate(data.get("components", [])):
        walk(component, f"/components/{index}")
    for index, formula in enumerate(data.get("formulation", [])):
        formula_ref = formula.get("bom-ref", f"/formulation/{index}")
        for child_index, component in enumerate(formula.get("components", [])):
            walk(component, f"/formulation/{index}/components/{child_index}", formula=formula_ref)
        # Formulation is recorded as build context, never as compiler source proof.
        build = SBOMBuild(
            sbom_document_id=document.id, spdx_id=scoped("formula", formula_ref),
            build_type="urn:cyclonedx:formulation",
            parameters=[{"key": "cyclonedx:formulation", "value": formula}], outputs=[], compiled=False,
        )
        db.session.add(build)
        db.session.flush()
        for ref in formula_files[formula_ref]:
            owners[ref].update(formula_owners[formula_ref])
            db.session.add(SBOMFileBuild(
                file_document_id=document.id, spdx_id=ref, build_id=build.id,
            ))
    db.session.flush()
    db.session.add_all(
        PackageSourceFile(
            sbom_document_id=document.id, package_id=owner, file_document_id=document.id, spdx_id=ref,
        )
        for ref, package_ids in owners.items() for owner in package_ids
    )

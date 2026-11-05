# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Portable observations for SBOM formats without equivalent native fields."""

import json

from ..extensions import db
from ..models import Package, PackageDependency, SBOMDocument
from .export_files import file_metadata

EVIDENCE_PROPERTY = "vulnscout:sbom-evidence:v1"
EVIDENCE_PREFIX = "VulnScout SBOM evidence v1:\n"

SPDX2_SCOPES = {
    "BUILD_DEPENDENCY_OF": "build", "RUNTIME_DEPENDENCY_OF": "runtime",
    "DEV_DEPENDENCY_OF": "development", "TEST_DEPENDENCY_OF": "test",
}
SPDX2_REVERSE = {
    "DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "DEV_DEPENDENCY_OF",
    "OPTIONAL_DEPENDENCY_OF", "PROVIDED_DEPENDENCY_OF", "TEST_DEPENDENCY_OF",
}


def dependency_relationships(packages, *, spdx3: bool) -> list[tuple[str, str, str, str]]:
    """Translate direction and explicit lifecycle qualifiers without inventing scope."""
    relationships = set()
    scope_types = {scope: kind for kind, scope in SPDX2_SCOPES.items()}
    for record in dependency_records(packages):
        source, target = record["source"], record["target"]
        for declaration in record["declarations"] or [{}]:
            kind = declaration.get("relationship_type", "")
            scope = declaration.get("lifecycle_scope", "")
            if spdx3:
                scope = scope or SPDX2_SCOPES.get(kind, "")
                native_kind = {
                    "OPTIONAL_DEPENDENCY_OF": "hasOptionalDependency",
                    "PROVIDED_DEPENDENCY_OF": "hasProvidedDependency",
                }.get(kind, kind if kind in {
                    "dependsOn", "hasPrerequisite", "hasOptionalDependency", "hasProvidedDependency",
                } else "dependsOn")
                if scope not in {"build", "design", "development", "other", "runtime", "test"}:
                    scope = ""
                reverse = False
            else:
                native_kind = kind if kind in SPDX2_REVERSE | {"DEPENDS_ON"} else (
                    {"hasOptionalDependency": "OPTIONAL_DEPENDENCY_OF",
                     "hasProvidedDependency": "PROVIDED_DEPENDENCY_OF"}.get(kind, scope_types.get(scope, "DEPENDS_ON"))
                )
                reverse = native_kind in SPDX2_REVERSE
                scope = ""
            relationships.add((target if reverse else source, source if reverse else target, native_kind, scope))
    return sorted(relationships)


def dependency_records(packages) -> list[dict]:
    """Keep declarations separate by active dependent document, not just package pair."""
    if not packages._export_document_ids:
        return []
    exported = {package.id: sid for sid, package in packages._cache.items()}
    return [{
        "document_id": str(row.sbom_document_id),
        "source": exported[row.package_id], "target": exported[row.dependency_id],
        "declarations": row.declarations or [],
    } for row in db.session.scalars(
        db.select(PackageDependency)
        .where(PackageDependency.sbom_document_id.in_(packages._export_document_ids))
        .order_by(PackageDependency.sbom_document_id, PackageDependency.package_id, PackageDependency.dependency_id)
    ) if row.package_id in exported and row.dependency_id in exported]


def export_evidence(packages, references: dict[str, str], *, include_files: bool = False) -> dict:
    """Remap live package links while retaining original producer metadata as evidence."""
    package_ids = {str(package.id): references[sid] for sid, package in packages._cache.items()}
    dependencies = [{
        **record, "source": references[record["source"]], "target": references[record["target"]],
    } for record in dependency_records(packages)]
    targets = []
    if packages._export_document_ids:
        for document in db.session.scalars(
            db.select(SBOMDocument).where(SBOMDocument.id.in_(packages._export_document_ids))
            .order_by(SBOMDocument.id)
        ):
            for target in document.build_targets or []:
                owners = [package_ids[owner] for owner in target["package_ids"] if owner in package_ids]
                if owners:
                    targets.append({
                        **target, "package_ids": owners,
                        "source_document": target.get("source_document", {
                            "id": str(document.id), "source_name": document.source_name, "format": document.format,
                        }),
                    })
    result = {
        "dependencies": dependencies, "build_targets": targets,
        "scope": "recorded observations only; not a full build graph or proof of source completeness",
    }
    if include_files:
        result["unrecorded_packages"] = [
            references[sid] for sid, package in packages._cache.items() if package.source_file_count is None
        ]
        result["files"] = [{
            "id": f"urn:vulnscout:recorded-file:{index}", "path": record["path"],
            "properties": file_metadata(record, spdx3=True),
            "packages": [references[owner] for owner in record["packages"] if owner in references],
        } for index, record in enumerate(packages.recorded_files())]
    return result


def read_evidence(data: dict) -> dict | None:
    def objects(value):
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    comments = [annotation.get("comment") for annotation in objects(data.get("annotations"))]
    comments.extend(node.get("comment") for node in objects(data.get("@graph"))
                    if node.get("type") == "SpdxDocument")
    values = [comment[len(EVIDENCE_PREFIX):] for comment in comments
              if isinstance(comment, str) and comment.startswith(EVIDENCE_PREFIX)]
    metadata = data.get("metadata")
    properties = objects(metadata.get("properties") if isinstance(metadata, dict) else None)
    values.extend(prop.get("value") for prop in properties
                  if prop.get("name") == EVIDENCE_PROPERTY)
    for value in values:
        try:
            evidence = json.loads(value)
        except (ValueError, TypeError):
            continue
        if (isinstance(evidence, dict) and isinstance(evidence.get("dependencies"), list)
                and isinstance(evidence.get("build_targets"), list)):
            return evidence
    return None


def evidence_file_graph(evidence: dict) -> dict:
    """Use the existing inventory recorder, without reconstructing build topology."""
    graph = []
    owners: set[str] = set()
    files = evidence.get("files")
    for file in files if isinstance(files, list) else []:
        if not (isinstance(file, dict) and isinstance(file.get("id"), str)
                and isinstance(file.get("path"), str) and isinstance(file.get("properties"), dict)
                and isinstance(file.get("packages"), list)):
            continue
        graph.append({
            "type": "software_File", "spdxId": file["id"], "name": file["path"],
            "_file_properties": file["properties"],
        })
        graph.extend({
            "relationshipType": "contains", "from": owner, "to": [file["id"]],
        } for owner in file.get("packages", []) if isinstance(owner, str))
        owners.update(owner for owner in file["packages"] if isinstance(owner, str))
    graph.extend({"type": "software_Package", "spdxId": owner} for owner in sorted(owners))
    unknown = evidence.get("unrecorded_packages")
    return {
        "@graph": graph, "_compilation_complete": False,
        "_unknown_inventories": [ref for ref in unknown if isinstance(ref, str)] if isinstance(unknown, list) else [],
    }


def _valid_target(target) -> bool:
    if not (isinstance(target, dict) and isinstance(target.get("id"), str)
            and isinstance(target.get("name"), str) and isinstance(target.get("package_ids"), list)
            and isinstance(target.get("languages"), list)):
        return False
    return all(
        isinstance(language, dict) and isinstance(language.get("language"), str)
        and all(isinstance(language.get(kind), list) and all(isinstance(value, str) for value in language[kind])
                for kind in ("flags", "defines"))
        for language in target["languages"]
    )


def restore_evidence(document: SBOMDocument, evidence: dict, references: dict[str, str]) -> None:
    """Restore portable evidence only for package references resolved by this document."""
    members = {
        ref: package.id for ref, sid in references.items()
        if (package := Package.get_by_string_id(sid)) is not None
    }
    targets = []
    for target in evidence["build_targets"]:
        if not _valid_target(target):
            continue
        owners = [str(members[ref]) for ref in target["package_ids"] if isinstance(ref, str) and ref in members]
        if owners:
            targets.append({**target, "package_ids": owners})
    if targets:
        document.build_targets = targets
    # Multiple original documents can contribute the same normalized edge.
    declarations: dict[tuple, list[dict]] = {}
    for record in evidence["dependencies"]:
        if not isinstance(record, dict):
            continue
        source, target = record.get("source"), record.get("target")
        if not isinstance(source, str) or not isinstance(target, str) or source not in members or target not in members:
            continue
        raw = record.get("declarations")
        if not isinstance(raw, list) or not all(
            isinstance(declaration, dict)
            and all(isinstance(declaration.get(field), str) for field in (
                "relationship_type", "lifecycle_scope", "source_document_id", "source_name",
            )) for declaration in raw
        ):
            continue
        key = (members[source], members[target])
        values = declarations.setdefault(key, [])
        for declaration in raw:
            if declaration not in values:
                values.append(declaration)
    for (source, target), values in declarations.items():
        row = db.session.get(PackageDependency, (document.id, source, target))
        if row is not None:
            row.declarations = values or None
    db.session.flush()

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Resolve SPDX 3 file/build evidence across companion documents of one scan."""

from collections import defaultdict
import logging
import uuid

from ..extensions import db
from ..models import Package, PackageSourceFile, SBOMDocument, SBOMFile, SBOMPackage

logger = logging.getLogger(__name__)


def record_source_files(documents: list[tuple[SBOMDocument, dict, dict[str, str], dict[str, str]]]) -> None:
    """Persist files after package consolidation; never resolve across scans."""
    if not documents:
        return
    assert len({document.scan_id for document, *_ in documents}) == 1
    document_ids = {document.id for document, *_ in documents}
    db.session.execute(db.delete(PackageSourceFile).where(db.or_(
        PackageSourceFile.sbom_document_id.in_(document_ids), PackageSourceFile.file_document_id.in_(document_ids),
    )))
    db.session.execute(db.delete(SBOMFile).where(SBOMFile.sbom_document_id.in_(document_ids)))
    canonical = {
        member["id"]: uuid.UUID(group["canonical_package_id"])
        for document, *_ in documents for group in document.jsonld_groups or []
        if group.get("canonical_package_id") for member in group["members"]
    }
    nodes: dict[str, tuple[SBOMDocument, dict]] = {}
    packages: dict[str, tuple[uuid.UUID, uuid.UUID]] = {}
    edges: dict[str, set[tuple[str, str]]] = defaultdict(set)
    ambiguous: set[str] = set()
    malformed = False
    for document, data, references, namespaces in documents:
        def key(ref: str) -> str:
            prefix, separator, suffix = ref.partition(':')
            return namespaces.get(prefix, prefix + ':') + suffix if separator else f'{document.id}:{ref}'

        for ref, string_id in references.items():
            package_id = canonical.get(string_id)
            if package_id is None:
                package = Package.get_by_string_id(string_id)
                package_id = package.id if package else None
            if package_id is not None:
                packages[key(ref)] = document.id, package_id
        for item in data.get('@graph', []):
            if not isinstance(item, dict):
                continue
            element_ref = item.get('spdxId')
            if item.get('type') == 'software_File' and (
                not isinstance(element_ref, str) or not isinstance(item.get('name'), str) or not item['name']
            ):
                malformed = True
            if isinstance(element_ref, str):
                identifier = key(element_ref)
                if identifier in nodes and nodes[identifier][1] != item:
                    ambiguous.add(identifier)
                else:
                    nodes[identifier] = document, item
            source, targets = item.get('from'), item.get('to', [])
            if isinstance(targets, str):
                targets = [targets]
            if item.get('relationshipType') in {'hasInput', 'hasOutput'} and (
                not isinstance(source, str) or not isinstance(targets, list)
                or any(not isinstance(target, str) for target in targets)
            ):
                malformed = True
            if isinstance(source, str) and isinstance(targets, list):
                for target in targets:
                    if isinstance(target, str):
                        edges[item.get('relationshipType', '')].add((key(source), key(target)))
    for ref in ambiguous:
        nodes.pop(ref, None)
        packages.pop(ref, None)
    files: dict[str, SBOMFile] = {}
    for ref, (document, item) in nodes.items():
        if item.get('type') != 'software_File' or not isinstance(item.get('name'), str) or not item['name']:
            continue
        file = SBOMFile(sbom_document_id=document.id, spdx_id=ref, path=item['name'], properties=item)
        db.session.add(file)
        files[ref] = file
    contains: dict[str, set[str]] = defaultdict(set)
    for owner, child in edges['contains']:
        contains[owner].add(child)
    owners: dict[str, set[str]] = defaultdict(set)
    for owner in packages:
        pending = list(contains[owner])
        seen: set[str] = set()
        while pending:
            child = pending.pop()
            if child in seen:
                continue
            seen.add(child)
            if child in files:
                owners[child].add(owner)
            # Nested package inventories belong to that package, not its dependents.
            if child not in packages:
                pending.extend(contains[child])
    outputs: dict[str, set[str]] = defaultdict(set)
    inputs: dict[str, set[str]] = defaultdict(set)
    for build, target in edges['hasOutput']:
        outputs[build].add(target)
    for build, source in edges['hasInput']:
        inputs[build].add(source)
    output_files = {target for targets in outputs.values() for target in targets}
    input_files = {source for sources in inputs.values() for source in sources}
    # West also lists intermediate objects as inputs without separate compiler
    # build nodes. They are retained as files, not evidence of compiled source.
    binaries = {
        ref for ref, file in files.items()
        if file.path.lower().endswith(('.o', '.obj', '.a', '.so', '.dll', '.exe', '.elf', '.bin', '.hex', '.uf2'))
    }
    artifacts = (output_files - input_files) | binaries
    complete = not ambiguous and not malformed and all(
        build in nodes and nodes[build][1].get('type') == 'build_Build' and target in nodes
        and (nodes[target][1].get('type') != 'software_File' or target in files)
        for build, target in edges['hasInput'] | edges['hasOutput']
    )
    if not complete:
        logger.warning("Incomplete SPDX build references in scan %s; compiled-source refinement disabled",
                       documents[0][0].scan_id)
    compiled: dict[str, list[dict]] = defaultdict(list)
    associations: dict[str, set[str]] = defaultdict(set)
    for ref in files:
        if ref not in artifacts:
            associations[ref].update(owners[ref])
    for build, sources in inputs.items():
        if build not in nodes or nodes[build][1].get('type') != 'build_Build' or not outputs[build]:
            continue
        build_document, build_node = nodes[build]
        target_owners = {owner for target in outputs[build] for owner in owners[target]}
        target_owners.update(target for target in outputs[build] if target in packages)
        for source in sources:
            if source not in files or source in artifacts:
                continue
            compiled[source].append({
                "spdx_id": build, "document_name": build_document.source_name,
                "build_type": build_node.get('build_buildType'),
                "parameters": build_node.get('build_parameter', []), "outputs": sorted(outputs[build]),
            })
            associations[source].update(target_owners)
    db.session.flush()
    links = {(link.sbom_document_id, link.package_id): link for link in db.session.scalars(
        db.select(SBOMPackage).where(SBOMPackage.sbom_document_id.in_(document_ids))
    )}
    for link in links.values():
        link.compiled_sources_complete = complete
    rows: dict[tuple, PackageSourceFile] = {}
    for ref, package_refs in associations.items():
        file = files[ref]
        for package_ref in package_refs:
            document_id, package_id = packages[package_ref]
            if (document_id, package_id) not in links:
                continue
            if not compiled[ref]:
                links[document_id, package_id].compiled_sources_complete = False
            association_key = document_id, package_id, file.sbom_document_id, ref
            rows[association_key] = PackageSourceFile(
                sbom_document_id=document_id, package_id=package_id,
                file_document_id=file.sbom_document_id, spdx_id=ref, builds=compiled[ref],
            )
    db.session.add_all(rows.values())

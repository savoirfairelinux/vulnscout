# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Resolve SPDX file/build evidence across companion documents of one scan."""

from collections import defaultdict
import logging
import re
import uuid

from ..extensions import db
from ..models import Package, PackageSourceFile, SBOMBuild, SBOMDocument, SBOMFile, SBOMFileBuild, SBOMPackage
from ..models.sbom_file import has_compilation_evidence
from .export_files import (
    recorded_evidence, spdx2_annotation_inventory, INVENTORY_UNKNOWN_COMMENT, SPDX2_ASSOCIATION_COMMENT,
)

logger = logging.getLogger(__name__)


def spdx2_file_graph(document: SBOMDocument, data: dict, references: dict[str, str]) -> tuple[dict, dict[str, str]]:
    """Adapt SPDX 2 containment without treating package provenance as compilation."""
    from ..controllers.packages import _spdx_key

    namespace = data.get('documentNamespace')
    if not isinstance(namespace, str):
        namespace = None
    external_documents = {
        ref['externalDocumentId']: ref['spdxDocument']
        for ref in data.get('externalDocumentRefs') or []
        if isinstance(ref, dict) and isinstance(ref.get('externalDocumentId'), str)
        and isinstance(ref.get('spdxDocument'), str)
    }

    def key(ref: str) -> str:
        qualified = _spdx_key(ref, namespace, external_documents)
        return f'{qualified[0]}#{qualified[1]}' if qualified else f'{document.id}:{ref}'

    annotated_files, annotated_relationships = spdx2_annotation_inventory(data)
    graph: list[dict] = []
    for package in data.get('packages') or []:
        if not isinstance(package, dict) or not isinstance(package.get('SPDXID'), str):
            continue
        owner = key(package['SPDXID'])
        graph.append({'type': 'software_Package', 'spdxId': owner})
        graph.extend(
            {'relationshipType': 'contains', 'from': owner, 'to': [key(ref)]}
            for ref in package.get('hasFiles') or [] if isinstance(ref, str)
        )
    for file in [*(data.get('files') or []), *annotated_files]:
        if not isinstance(file, dict):
            continue
        ref = file.get('SPDXID')
        graph.append({
            'type': 'software_File', 'spdxId': key(ref) if isinstance(ref, str) else None,
            'name': file.get('fileName'), '_file_properties': file,
        })
    for relation in [*(data.get('relationships') or []), *annotated_relationships]:
        if not isinstance(relation, dict):
            continue
        source, target = relation.get('spdxElementId'), relation.get('relatedSpdxElement')
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        kind = relation.get('relationshipType')
        if kind == 'OTHER' and relation.get('comment') == SPDX2_ASSOCIATION_COMMENT:
            kind = 'CONTAINS'
        if kind == 'CONTAINED_BY':
            source, target = target, source
        if kind in {'CONTAINS', 'CONTAINED_BY'}:
            graph.append({'relationshipType': 'contains', 'from': key(source), 'to': [key(target)]})
    unknown_inventories = [
        key(package['SPDXID']) for package in data.get('packages') or []
        if isinstance(package, dict) and isinstance(package.get('SPDXID'), str)
        and package.get('filesAnalyzed') is False
    ]
    return {'@graph': graph, '_compilation_complete': False, '_unknown_inventories': unknown_inventories}, {
        key(ref): string_id for ref, string_id in references.items()
    }


def record_source_files(documents: list[tuple[SBOMDocument, dict, dict[str, str], dict[str, str]]]) -> None:
    """Persist files after package consolidation; never resolve across scans."""
    if not documents:
        return
    assert len({document.scan_id for document, *_ in documents}) == 1
    document_ids = {document.id for document, *_ in documents}
    build_ids = db.select(SBOMBuild.id).where(SBOMBuild.sbom_document_id.in_(document_ids))
    db.session.execute(db.delete(SBOMFileBuild).where(db.or_(
        SBOMFileBuild.file_document_id.in_(document_ids), SBOMFileBuild.build_id.in_(build_ids),
    )))
    db.session.execute(db.delete(PackageSourceFile).where(db.or_(
        PackageSourceFile.sbom_document_id.in_(document_ids), PackageSourceFile.file_document_id.in_(document_ids),
    )))
    db.session.execute(db.delete(SBOMFile).where(SBOMFile.sbom_document_id.in_(document_ids)))
    db.session.execute(db.delete(SBOMBuild).where(SBOMBuild.sbom_document_id.in_(document_ids)))
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
            if item.get('relationshipType') in {'hasInput', 'hasOutput', 'contains'} and (
                not isinstance(source, str) or not source or not isinstance(targets, list) or not targets
                or any(not isinstance(target, str) or not target for target in targets)
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
        file = SBOMFile(sbom_document_id=document.id, spdx_id=ref, path=item['name'],
                        properties=item.get('_file_properties', item))
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
    output_files.update(
        ref for ref, file_owners in owners.items()
        if any(nodes[owner][1].get('software_primaryPurpose') == 'install' for owner in file_owners)
    )
    # West also lists intermediate objects as inputs without separate compiler
    # build nodes. They are retained as files, not evidence of compiled source.
    binaries = {
        ref for ref, file in files.items()
        if file.path.lower().endswith((
            '.o', '.obj', '.a', '.so', '.dylib', '.dll', '.exe', '.elf', '.bin', '.hex', '.uf2',
        ))
        or re.search(r'\.so(?:\.\d+)+$', file.path.lower())
        or 'BINARY' in (file.properties.get('fileTypes') or [])
        or file.properties.get('software_primaryPurpose') in {'executable', 'library', 'firmware', 'archive'}
    }
    artifacts = (output_files - input_files) | binaries
    resolved = not ambiguous and not malformed and all(
        build in nodes and nodes[build][1].get('type') == 'build_Build' and target in nodes
        and (nodes[target][1].get('type') != 'software_File' or target in files)
        for build, target in edges['hasInput'] | edges['hasOutput']
    ) and all(
        owner in nodes and target in nodes
        and (nodes[target][1].get('type') != 'software_File' or target in files)
        for owner, target in edges['contains']
    )
    if not resolved:
        logger.warning(
            "Incomplete SPDX build or containment references in scan %s; compiled-source refinement disabled",
            documents[0][0].scan_id,
        )
    complete = resolved and all(data.get('_compilation_complete', True) for _, data, *_ in documents)
    # Export comments retain observations, not the graph needed to prove completeness.
    if any(recorded_evidence(file.properties) is not None for file in files.values()):
        complete = False
    compiled: dict[str, list[SBOMBuild]] = defaultdict(list)
    incomplete_packages: set[tuple[uuid.UUID, uuid.UUID]] = set()
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
        source_refs = sources.intersection(files).difference(artifacts)
        is_compilation = has_compilation_evidence([{
            "build_type": build_node.get('build_buildType'), "parameters": build_node.get('build_parameter'),
        }])
        if not is_compilation or sources != source_refs:
            incomplete_packages.update(packages[owner] for owner in target_owners)
        if not source_refs:
            continue
        record = SBOMBuild(
            sbom_document_id=build_document.id, spdx_id=build, build_type=build_node.get('build_buildType'),
            parameters=build_node.get('build_parameter', []), outputs=sorted(outputs[build]),
            compiled=is_compilation,
        )
        db.session.add(record)
        for source in source_refs:
            compiled[source].append(record)
            associations[source].update(target_owners)
    db.session.flush()
    db.session.add_all(
        SBOMFileBuild(file_document_id=files[ref].sbom_document_id, spdx_id=ref, build_id=build.id)
        for ref, builds in compiled.items() for build in builds
    )
    links = {(link.sbom_document_id, link.package_id): link for link in db.session.scalars(
        db.select(SBOMPackage).where(SBOMPackage.sbom_document_id.in_(document_ids))
    )}
    unknown = {
        packages[ref] for _, data, *_ in documents for ref in data.get('_unknown_inventories', [])
        if ref in packages
    }
    unknown.update(
        packages[ref] for ref, (_, node) in nodes.items()
        if ref in packages and node.get("comment") == INVENTORY_UNKNOWN_COMMENT
    )
    unknown -= {packages[owner] for file_owners in owners.values() for owner in file_owners}
    for link_key, link in links.items():
        link.compiled_sources_complete = (
            None if link_key in unknown else complete and link_key not in incomplete_packages
        )
    rows: dict[tuple, PackageSourceFile] = {}
    for ref, package_refs in associations.items():
        file = files[ref]
        for package_ref in package_refs:
            document_id, package_id = packages[package_ref]
            if (document_id, package_id) not in links:
                continue
            if not any(build.compiled for build in compiled[ref]):
                links[document_id, package_id].compiled_sources_complete = False
            association_key = document_id, package_id, file.sbom_document_id, ref
            rows[association_key] = PackageSourceFile(
                sbom_document_id=document_id, package_id=package_id,
                file_document_id=file.sbom_document_id, spdx_id=ref,
            )
    db.session.add_all(rows.values())
    restore_recorded_builds(list(files.values()))


def restore_recorded_builds(files: list[SBOMFile]) -> None:
    """Restore explicitly labelled observations without inventing build relationships."""
    import json

    builds: dict[tuple, SBOMBuild] = {}
    for file in files:
        evidence = recorded_evidence(file.properties)
        if evidence is None:
            continue
        seen: set[tuple] = set()
        for item in evidence["builds"]:
            if not isinstance(item, dict) or not isinstance(item.get("spdx_id"), str):
                continue
            parameters, outputs = item.get("parameters"), item.get("outputs")
            build_type = item.get("build_type")
            if (not isinstance(parameters, list) or not isinstance(outputs, list)
                    or any(not isinstance(output, str) for output in outputs)
                    or (build_type is not None and not isinstance(build_type, str))):
                continue
            original_id = item["spdx_id"]
            ref = original_id if original_id.startswith("urn:vulnscout:recorded-build:") else (
                "urn:vulnscout:recorded-build:" + str(uuid.uuid5(
                    uuid.NAMESPACE_URL, json.dumps([item.get("document_id"), original_id]),
                ))
            )
            key = file.sbom_document_id, ref
            if key in seen:
                continue
            seen.add(key)
            if key not in builds:
                build = SBOMBuild(
                    sbom_document_id=file.sbom_document_id, spdx_id=ref, build_type=build_type,
                    parameters=parameters, outputs=outputs,
                    compiled=item.get("compiled") is True and has_compilation_evidence([item]),
                )
                db.session.add(build)
                db.session.flush()
                builds[key] = build
            db.session.add(SBOMFileBuild(
                file_document_id=file.sbom_document_id, spdx_id=file.spdx_id, build_id=builds[key].id,
            ))

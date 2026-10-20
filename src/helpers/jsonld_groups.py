# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Record explicit West JSON-LD provenance for package consolidation."""

from collections import defaultdict
import hashlib
from typing import TYPE_CHECKING

from ..extensions import db
from ..models import Package, SBOMDocument

if TYPE_CHECKING:
    from ..controllers.packages import PackagesController


def is_zephyr_jsonld(data: dict) -> bool:
    return any(isinstance(item, dict) and item.get('type') == 'SoftwareAgent'
               and item.get('name') == 'West SPDX Generator' for item in data.get('@graph', []))


def record_jsonld_groups(documents: list[tuple[SBOMDocument, dict, dict[str, str], dict[str, str]]],
                         packages: "PackagesController") -> None:
    """Resolve companion-document groups within one ingestion scan, never by suffix alone."""
    nodes: dict[str, dict] = {}
    references: dict[str, str] = {}
    edges: dict[str, set[tuple[str, str]]] = defaultdict(set)
    eligible = []
    for document, data, refs, namespaces in documents:
        graph = data.get('@graph', [])
        if not is_zephyr_jsonld(data):
            document.jsonld_groups = None
            continue
        eligible.append(document)
        document.jsonld_groups = []

        def key(ref: str) -> str:
            prefix, separator, suffix = ref.partition(':')
            if not separator:
                return f'{document.id}:{ref}'
            return namespaces.get(prefix, prefix + ':') + suffix

        references.update({key(ref): string_id for ref, string_id in refs.items()})
        for item in graph:
            if not isinstance(item, dict):
                continue
            ref = item.get('spdxId')
            if isinstance(ref, str):
                nodes[key(ref)] = item
            source, targets = item.get('from'), item.get('to', [])
            if isinstance(targets, str):
                targets = [targets]
            if isinstance(source, str) and isinstance(targets, list):
                for target in targets:
                    if isinstance(target, str):
                        edges[item.get('relationshipType', '')].add((key(source), key(target)))
    if not eligible:
        return
    owners: dict[str, set[str]] = defaultdict(set)
    for owner, member in edges['contains']:
        if owner in references:
            owners[member].add(owner)
    source_of: dict[str, set[str]] = defaultdict(set)
    outputs: dict[str, set[str]] = defaultdict(set)
    for build, target in edges['hasOutput']:
        outputs[build].update(owners.get(target, ()))
        if target in references:
            outputs[build].add(target)
    for build, source in edges['hasInput']:
        origins = owners.get(source, set()) | ({source} if source in references else set())
        for output in outputs.get(build, ()):
            source_of[output].update(origins)
    variants = edges['variantOf'] | {(target, source) for source, target in edges['hasVariant']}
    groups = []
    for source, dependency in sorted(variants):
        source_node, dependency_node = nodes.get(source, {}), nodes.get(dependency, {})
        source_name = source_node.get('name', '')
        if (source not in references or dependency not in references
                or source_node.get('software_primaryPurpose') != 'source'
                or not source_name.endswith('-sources')):
            continue
        name = source_name.removesuffix('-sources')
        if dependency_node.get('name') != name + '-deps':
            continue
        built = []
        for target_name in (name, f'modules__{name}'):
            built = [ref for ref, origins in source_of.items()
                     if source in origins and nodes.get(ref, {}).get('name') == target_name
                     and ref in references]
            if built:
                break
        if not built:
            # External modules can use generated CMake names rather than their module name.
            candidates = [ref for ref, origins in source_of.items()
                          if origins == {source} and ref in references]
            if len(candidates) == 1:
                built = candidates
        if len(built) > 1:
            built = []
        members = [(source, 'source'), (dependency, 'upstream'), *((ref, 'build') for ref in built)]
        entries: list[dict[str, str]] = []
        for ref, role in members:
            package_id = packages.get_or_resolve_db_id(references[ref])
            if package_id is None:
                break
            package = db.session.get(Package, package_id)
            assert package is not None
            entries.append({'package_id': str(package_id), 'id': package.string_id,
                            'name': package.name or '', 'version': package.version or '', 'role': role})
        if len(entries) != len(members):
            continue
        member_ids = sorted(entry['id'] for entry in entries)
        digest = hashlib.sha256('\n'.join(member_ids).encode()).hexdigest()[:20]
        groups.append({'id': f'jsonld:{digest}', 'name': name, 'members': entries, 'built': bool(built)})
    eligible[0].jsonld_groups = groups

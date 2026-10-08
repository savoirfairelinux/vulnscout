# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Dependency graphs scoped to active SBOM documents."""

import uuid

from flask import Flask, request
from flask.typing import ResponseReturnValue
from sqlalchemy.orm import load_only

from ..extensions import db
from ..helpers.active_scans import active_sbom_scan_ids_for_project, active_sbom_scan_ids_for_variant
from ..models import Package, PackageDependency, SBOMDocument, SBOMPackage, Scan, Variant
from ._scan_helpers import parse_uuid_or_400


def init_app(app: Flask) -> None:
    @app.route('/api/package-dependencies')
    def package_dependencies() -> ResponseReturnValue:
        """Return packages and directed edges per active SBOM document.

        OpenAPI:
        query variant_id uuid optional Scope to one variant.
        query project_id uuid optional Scope to one project.
        query variant_ids string optional Comma-separated variant IDs for comparison.
        query compare_variant_id uuid optional Compare against variant_id.
        query operation string optional Difference, intersection, or union.
        query counts string optional Return only per-package in/out totals when 1.
        response 200 JsonObject Document-scoped packages and edges.
        """
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')
        variant_ids = request.args.get('variant_ids')
        compare_variant_id = request.args.get('compare_variant_id')
        operation = request.args.get('operation')
        if not any((variant_id, project_id, variant_ids)):
            return {'error': 'A project or variant scope is required'}, 400
        scan_ids: set[uuid.UUID] = set()
        selection_scans: list[set[uuid.UUID]] = []
        compare_mode = bool(variant_id and compare_variant_id)
        if variant_id and compare_variant_id:
            base, error = parse_uuid_or_400(variant_id, 'variant_id')
            if error:
                return error
            compare, error = parse_uuid_or_400(compare_variant_id, 'compare_variant_id')
            if error:
                return error
            assert base is not None and compare is not None
            base_scans = set(active_sbom_scan_ids_for_variant(base))
            compare_scans = set(active_sbom_scan_ids_for_variant(compare))
            selection_scans = [base_scans, compare_scans]
            scan_ids = base_scans | compare_scans if operation == 'intersection' else compare_scans
        elif variant_ids is not None:
            raw_ids = [value.strip() for value in variant_ids.split(',')]
            if not raw_ids or any(not value for value in raw_ids):
                return {'error': 'Invalid variant_ids'}, 400
            for value in raw_ids:
                parsed, error = parse_uuid_or_400(value, 'variant_ids')
                if error:
                    return error
                assert parsed is not None
                variant_scans = set(active_sbom_scan_ids_for_variant(parsed))
                selection_scans.append(variant_scans)
                scan_ids.update(variant_scans)
        elif variant_id:
            parsed, error = parse_uuid_or_400(variant_id, 'variant_id')
            if error:
                return error
            assert parsed is not None
            scan_ids.update(active_sbom_scan_ids_for_variant(parsed))
        else:
            assert project_id is not None
            parsed, error = parse_uuid_or_400(project_id, 'project_id')
            if error:
                return error
            assert parsed is not None
            scan_ids.update(active_sbom_scan_ids_for_project(parsed))

        counts_only = request.args.get('counts') == '1'
        if not scan_ids:
            return {'counts': {}, 'unrecorded': []} if counts_only else {'documents': []}
        allowed_ids = None
        if selection_scans and (operation == 'intersection' or compare_mode):
            def package_ids(ids: set[uuid.UUID]) -> set[uuid.UUID]:
                if not ids:
                    return set()
                return set(db.session.execute(
                    db.select(SBOMPackage.package_id)
                    .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
                    .where(SBOMDocument.scan_id.in_(ids))
                ).scalars())

            selected = [package_ids(ids) for ids in selection_scans]
            if operation == 'intersection':
                allowed_ids = set.intersection(*selected)
            else:
                allowed_ids = selected[1] - selected[0]
        if counts_only:
            scan_members: dict[uuid.UUID, set[uuid.UUID]] = {}
            recorded_ids: set[uuid.UUID] = set()
            for scan_id, package_id, recorded in db.session.execute(
                db.select(SBOMDocument.scan_id, SBOMPackage.package_id, SBOMDocument.dependencies_recorded)
                .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
                .where(SBOMDocument.scan_id.in_(scan_ids))
            ):
                if allowed_ids is None or package_id in allowed_ids:
                    scan_members.setdefault(scan_id, set()).add(package_id)
                    if recorded:
                        recorded_ids.add(package_id)
            unrecorded_ids = set().union(*scan_members.values()) - recorded_ids
            edge_pairs = {
                (package_id, dependency_id) for scan_id, package_id, dependency_id in db.session.execute(
                    db.select(SBOMDocument.scan_id, PackageDependency.package_id, PackageDependency.dependency_id)
                    .join(SBOMDocument, SBOMDocument.id == PackageDependency.sbom_document_id)
                    .where(SBOMDocument.scan_id.in_(scan_ids))
                )
                if package_id in scan_members.get(scan_id, ()) and dependency_id in scan_members.get(scan_id, ())
            }
            edge_package_ids = ({package_id for package_id, _ in edge_pairs}
                                | {dependency_id for _, dependency_id in edge_pairs})
            names = {package.id: package.string_id for package in db.session.execute(
                db.select(Package).where(Package.id.in_(edge_package_ids | unrecorded_ids))
                .options(load_only(Package.name, Package.version, Package.supplier))
            ).scalars()}
            counts: dict[str, dict[str, int]] = {}
            # A dependency flows in to the package that uses it and out to its dependents.
            for package_id, dependency_id in edge_pairs:
                counts.setdefault(names[package_id], {'in': 0, 'out': 0})['in'] += 1
                counts.setdefault(names[dependency_id], {'in': 0, 'out': 0})['out'] += 1
            # Packages only in documents never parsed with dependency support have no data rather than zero.
            return {'counts': counts, 'unrecorded': sorted(names[package_id] for package_id in unrecorded_ids)}
        documents = db.session.execute(
            db.select(SBOMDocument.id, SBOMDocument.scan_id, SBOMDocument.source_name, Variant.id, Variant.name,
                      SBOMDocument.dependencies_recorded)
            .join(Scan, Scan.id == SBOMDocument.scan_id)
            .join(Variant, Variant.id == Scan.variant_id)
            .where(SBOMDocument.scan_id.in_(scan_ids))
            .order_by(Variant.name, SBOMDocument.source_name, SBOMDocument.id)
        ).all()
        ids = [document_id for document_id, *_ in documents]
        # Join through the scan index: a long document-id IN list makes SQLite scan every package.
        rows: list[tuple[uuid.UUID, Package]] = [
            (document_id, package) for document_id, package in db.session.execute(
                db.select(SBOMPackage.sbom_document_id, Package)
                .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
                .join(Package, Package.id == SBOMPackage.package_id)
                .where(SBOMDocument.scan_id.in_(scan_ids))
                .options(load_only(Package.name, Package.version, Package.supplier))
            )
        ]
        if allowed_ids is not None:
            rows = [(document_id, package) for document_id, package in rows if package.id in allowed_ids]
        public_ids = {package.id: package.string_id for _, package in rows}
        members: dict[uuid.UUID, set[uuid.UUID]] = {document_id: set() for document_id in ids}
        for document_id, package in rows:
            members[document_id].add(package.id)
        scan_of = {document_id: scan_id for document_id, scan_id, *_ in documents}
        scan_packages: dict[uuid.UUID, set[uuid.UUID]] = {}
        for document_id, document_members in members.items():
            scan_packages.setdefault(scan_of[document_id], set()).update(document_members)
        edges = db.session.execute(
            db.select(PackageDependency.sbom_document_id, PackageDependency.package_id, PackageDependency.dependency_id)
            .join(SBOMDocument, SBOMDocument.id == PackageDependency.sbom_document_id)
            .where(SBOMDocument.scan_id.in_(scan_ids))
        ).all()
        result = {
            document_id: {'id': str(document_id), 'source_name': source_name,
                          'variant_id': str(variant_id), 'variant_name': variant_name,
                          'dependencies_recorded': recorded, 'packages': [], 'edges': []}
            for document_id, _, source_name, variant_id, variant_name, recorded in documents
        }
        for document_id, package in rows:
            result[document_id]['packages'].append({
                'id': package.string_id, 'name': package.name, 'version': package.version,
            })
        for document_id, package_id, dependency_id in edges:
            if package_id in members[document_id] and dependency_id in scan_packages[scan_of[document_id]]:
                result[document_id]['edges'].append({
                    'package_id': public_ids[package_id], 'dependency_id': public_ids[dependency_id],
                })
        for document in result.values():
            document['packages'].sort(key=lambda package: (package['name'] or '', package['version'] or ''))
            document['edges'].sort(key=lambda edge: (edge['package_id'], edge['dependency_id']))
        return {'documents': list(result.values())}

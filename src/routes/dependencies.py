"""Dependency graphs scoped to active SBOM documents."""

import uuid

from flask import Flask, request
from flask.typing import ResponseReturnValue

from ..extensions import db
from ..helpers.active_scans import active_sbom_scan_ids_for_project, active_sbom_scan_ids_for_variant
from ..models import Package, PackageDependency, SBOMDocument, SBOMPackage
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

        if not scan_ids:
            return {'documents': []}
        allowed_ids = None
        if selection_scans and (operation == 'intersection' or compare_variant_id):
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
        documents = list(db.session.execute(
            db.select(SBOMDocument).where(SBOMDocument.scan_id.in_(scan_ids))
            .order_by(SBOMDocument.source_name, SBOMDocument.id)
        ).scalars())
        ids = [document.id for document in documents]
        rows: list[tuple[uuid.UUID, Package]] = [
            (document_id, package) for document_id, package in db.session.execute(
                db.select(SBOMPackage.sbom_document_id, Package)
                .join(Package, Package.id == SBOMPackage.package_id)
                .where(SBOMPackage.sbom_document_id.in_(ids))
            )
        ]
        if allowed_ids is not None:
            rows = [(document_id, package) for document_id, package in rows if package.id in allowed_ids]
        public_ids = {package.id: package.string_id for _, package in rows}
        members: dict[uuid.UUID, set[uuid.UUID]] = {document.id: set() for document in documents}
        for document_id, package in rows:
            members[document_id].add(package.id)
        edges = db.session.execute(
            db.select(PackageDependency.sbom_document_id, PackageDependency.package_id, PackageDependency.dependency_id)
            .where(PackageDependency.sbom_document_id.in_(ids))
        ).all()
        result = {
            document.id: {'id': str(document.id), 'source_name': document.source_name,
                          'packages': [], 'edges': []}
            for document in documents
        }
        for document_id, package in rows:
            result[document_id]['packages'].append({
                'id': package.string_id, 'name': package.name, 'version': package.version,
            })
        for document_id, package_id, dependency_id in edges:
            if package_id in members[document_id] and dependency_id in members[document_id]:
                result[document_id]['edges'].append({
                    'package_id': public_ids[package_id], 'dependency_id': public_ids[dependency_id],
                })
        for document in result.values():
            document['packages'].sort(key=lambda package: (package['name'] or '', package['version'] or ''))
            document['edges'].sort(key=lambda edge: (edge['package_id'], edge['dependency_id']))
        return {'documents': list(result.values())}

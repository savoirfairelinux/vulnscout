"""Dependency graphs scoped to active SBOM documents."""

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
        response 200 JsonObject Document-scoped packages and edges.
        """
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')
        variant_ids = request.args.get('variant_ids')
        if not any((variant_id, project_id, variant_ids)):
            return {'error': 'A project or variant scope is required'}, 400
        scan_ids = set()
        if variant_ids is not None:
            raw_ids = [value.strip() for value in variant_ids.split(',')]
            if not raw_ids or any(not value for value in raw_ids):
                return {'error': 'Invalid variant_ids'}, 400
            for value in raw_ids:
                parsed, error = parse_uuid_or_400(value, 'variant_ids')
                if error:
                    return error
                assert parsed is not None
                scan_ids.update(active_sbom_scan_ids_for_variant(parsed))
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
        documents = list(db.session.execute(
            db.select(SBOMDocument).where(SBOMDocument.scan_id.in_(scan_ids))
            .order_by(SBOMDocument.source_name, SBOMDocument.id)
        ).scalars())
        ids = [document.id for document in documents]
        rows = db.session.execute(
            db.select(SBOMPackage.sbom_document_id, Package)
            .join(Package, Package.id == SBOMPackage.package_id)
            .where(SBOMPackage.sbom_document_id.in_(ids))
        ).all()
        public_ids = {package.id: package.string_id for _, package in rows}
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
            result[document_id]['edges'].append({
                'package_id': public_ids[package_id], 'dependency_id': public_ids[dependency_id],
            })
        for document in result.values():
            document['packages'].sort(key=lambda package: (package['name'] or '', package['version'] or ''))
            document['edges'].sort(key=lambda edge: (edge['package_id'], edge['dependency_id']))
        return {'documents': list(result.values())}

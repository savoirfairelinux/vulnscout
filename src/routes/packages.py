# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from flask import Flask
from flask.typing import ResponseReturnValue

from ..models.package import Package
from ..models.scan import Scan
from ..models.variant import Variant
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
from ..extensions import db
from ..helpers.active_scans import (
    active_sbom_scan_ids_for_variant,
    active_sbom_scan_ids_for_project,
)
from ._scan_queries import _packages_by_scan_ids, _package_rows
from ._scan_helpers import parse_uuid_or_400


def init_app(app: Flask) -> None:

    @app.route('/api/packages')
    def index_pkg() -> ResponseReturnValue:
        from flask import request
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')
        compare_variant_id = request.args.get('compare_variant_id')
        variant_ids = request.args.get('variant_ids')
        if variant_id and compare_variant_id:
            base_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if base_uuid is None:
                return {"error": "Internal error"}, 500
            compare_uuid, err = parse_uuid_or_400(compare_variant_id, "compare_variant_id")
            if err:
                return err
            if compare_uuid is None:
                return {"error": "Internal error"}, 500
            operation = request.args.get('operation', 'difference')

            def _pkg_ids_for_variant(variant_uuid: uuid.UUID) -> set[uuid.UUID]:
                scan_ids = active_sbom_scan_ids_for_variant(variant_uuid)
                if not scan_ids:
                    return set()
                return set(db.session.execute(
                    db.select(Package.id)
                    .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                    .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                    .where(SBOMDocument.scan_id.in_(scan_ids))
                    .distinct()
                ).scalars().all())

            if operation == 'intersection':
                base_ids = _pkg_ids_for_variant(base_uuid)
                compare_ids = _pkg_ids_for_variant(compare_uuid)
                result_ids = list(base_ids & compare_ids)
                pkgs = list(db.session.execute(
                    db.select(Package)
                    .where(Package.id.in_(result_ids))
                    .order_by(Package.name)
                ).scalars().all()) if result_ids else []
            else:  # difference (default): packages in compare but NOT in base
                exclude_ids = list(_pkg_ids_for_variant(base_uuid))
                compare_scan_ids = active_sbom_scan_ids_for_variant(compare_uuid)
                if not compare_scan_ids:
                    pkgs = []
                else:
                    pkg_ids_sub = (
                        db.select(Package.id)
                        .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                        .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                        .where(SBOMDocument.scan_id.in_(compare_scan_ids))
                        .distinct()
                    )
                    if exclude_ids:
                        pkg_ids_sub = pkg_ids_sub.where(~Package.id.in_(exclude_ids))
                    pkgs = list(db.session.execute(
                        db.select(Package)
                        .where(Package.id.in_(pkg_ids_sub))
                        .order_by(Package.name)
                    ).scalars().all())
            active_scan_ids = []  # compare mode: do not restrict by scan
        elif variant_ids:
            # Multi-variant mode: union or intersection of the packages present
            # in two or more selected variants.
            raw_ids = [s.strip() for s in variant_ids.split(',') if s.strip()]
            parsed_uuids: list[uuid.UUID] = []
            for raw_id in raw_ids:
                parsed, err = parse_uuid_or_400(raw_id, "variant_ids")
                if err:
                    return err
                if parsed is None:
                    return {"error": "Internal error"}, 500
                parsed_uuids.append(parsed)
            operation = request.args.get('operation', 'union')

            def _multi_pkg_ids_for_variant(variant_uuid: uuid.UUID) -> set[uuid.UUID]:
                scan_ids = active_sbom_scan_ids_for_variant(variant_uuid)
                if not scan_ids:
                    return set()
                return set(db.session.execute(
                    db.select(Package.id)
                    .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                    .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                    .where(SBOMDocument.scan_id.in_(scan_ids))
                    .distinct()
                ).scalars().all())

            id_sets = [_multi_pkg_ids_for_variant(u) for u in parsed_uuids]
            if not id_sets:
                multi_result_ids: list[uuid.UUID] = []
            elif operation == 'intersection':
                multi_result_ids = list(set.intersection(*id_sets))
            else:  # union (default)
                multi_result_ids = list(set.union(*id_sets))
            pkgs = list(db.session.execute(
                db.select(Package)
                .where(Package.id.in_(multi_result_ids))
                .order_by(Package.name)
            ).scalars().all()) if multi_result_ids else []
            # Restrict enrichment to the active SBOM scans of the selected variants
            active_scan_ids = [
                sid
                for parsed in parsed_uuids
                for sid in active_sbom_scan_ids_for_variant(parsed)
            ]
        elif variant_id:
            variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if variant_uuid is None:
                return {"error": "Internal error"}, 500
            sbom_ids = active_sbom_scan_ids_for_variant(variant_uuid)
            if not sbom_ids:
                pkgs = []
            else:
                pkg_sets = _packages_by_scan_ids(sbom_ids)
                all_pkg_ids = set().union(*pkg_sets.values()) if pkg_sets else set()
                pkg_lookup = _package_rows(all_pkg_ids)
                pkgs = sorted(pkg_lookup.values(), key=lambda p: p.name)
            active_scan_ids = sbom_ids
        elif project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if project_uuid is None:
                return {"error": "Internal error"}, 500
            sbom_ids = active_sbom_scan_ids_for_project(project_uuid)
            if not sbom_ids:
                pkgs = []
            else:
                pkg_sets = _packages_by_scan_ids(sbom_ids)
                all_pkg_ids = set().union(*pkg_sets.values()) if pkg_sets else set()
                pkg_lookup = _package_rows(all_pkg_ids)
                pkgs = sorted(pkg_lookup.values(), key=lambda p: p.name)
            active_scan_ids = sbom_ids
        else:
            pkgs = Package.get_all()
            active_scan_ids = []
        result = [pkg.to_dict() for pkg in pkgs]

        for p in result:
            p.setdefault("variants", [])
            p.setdefault("sources", [])
            p.setdefault("sbom_documents", [])

        # Enrich each package with its variants and sources derived from the
        # SBOMPackage → SBOMDocument → Scan → Variant chain so that the
        # frontend can display them even for packages with 0 vulnerabilities.
        # Fetch the comparatively small document metadata first, then fetch
        # only package/document UUID pairs.  The previous five-table DISTINCT
        # query repeated text metadata for every package/document association
        # and made SQLAlchemy materialize a very large joined result.
        pkg_ids = [pkg.id for pkg in pkgs]
        if pkg_ids:
            document_query = (
                db.select(
                    SBOMDocument.id.label("document_id"),
                    Variant.name.label("variant_name"),
                    SBOMDocument.format.label("doc_format"),
                    SBOMDocument.source_name.label("doc_source_name"),
                )
                .join(Scan, SBOMDocument.scan_id == Scan.id)
                .join(Variant, Scan.variant_id == Variant.id)
            )
            # Restrict to active (non-deprecated) scan documents only
            if active_scan_ids:
                document_query = document_query.where(SBOMDocument.scan_id.in_(active_scan_ids))
            if variant_id:
                _v = db.session.get(Variant, uuid.UUID(variant_id))
                if _v and _v.project_id:
                    document_query = document_query.where(
                        Variant.project_id == _v.project_id
                    )
                else:
                    document_query = document_query.where(
                        Scan.variant_id == uuid.UUID(variant_id)
                    )
            elif project_id:
                document_query = document_query.where(Variant.project_id == uuid.UUID(project_id))

            document_rows = db.session.execute(document_query).all()
            document_meta = {
                row.document_id: row
                for row in document_rows
            }
            document_ids = list(document_meta)
            association_rows = db.session.execute(
                db.select(SBOMPackage.package_id, SBOMPackage.sbom_document_id)
                .where(SBOMPackage.sbom_document_id.in_(document_ids))
            ).all() if document_ids else []

            # Build lookup by package UUID to avoid conflating similarly-named
            # package rows (e.g. different supplier or near-identical versions).
            meta: dict = {}
            selected_package_ids = {str(package_id) for package_id in pkg_ids}
            for package_id, document_id in association_rows:
                row = document_meta[document_id]
                key = str(package_id)
                if key not in selected_package_ids:
                    continue
                if key not in meta:
                    meta[key] = {"variants": set(), "sources": set(), "sbom_documents": set()}
                if row.variant_name:
                    meta[key]["variants"].add(row.variant_name)
                if row.doc_format:
                    meta[key]["sources"].add(row.doc_format)
                if row.doc_source_name:
                    meta[key]["sbom_documents"].add(row.doc_source_name)

            for p in result:
                key = str(p.get("package_id", ""))
                info = meta.get(key, {})
                p["variants"] = sorted(info.get("variants", set()))
                p["sources"] = sorted(info.get("sources", set()))
                p["sbom_documents"] = sorted(info.get("sbom_documents", set()))

        if request.args.get('format', 'list') == "dict":
            return {p["name"] + "@" + p["version"]: p for p in result}
        return result

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from flask import Flask
from flask.typing import ResponseReturnValue

from ..models.package import Package
from ..models.finding import Finding
from ..models.observation import Observation
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
        include_outdated = request.args.get('include_outdated', '').lower() in ('1', 'true', 'yes')
        outdated_only = request.args.get('outdated_only', '').lower() in ('1', 'true', 'yes')
        include_outdated = include_outdated or outdated_only
        if include_outdated and not any((variant_id, project_id, variant_ids)):
            return {"error": "A variant or project scope is required for outdated packages"}, 400
        scope_variant_ids: list[uuid.UUID] = []
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
            scope_variant_ids = [compare_uuid]
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

            if outdated_only:
                pkgs = []
            elif operation == 'intersection':
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
            scope_variant_ids = parsed_uuids
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

            if outdated_only:
                pkgs = []
            else:
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
            scope_variant_ids = [variant_uuid]
            sbom_ids = active_sbom_scan_ids_for_variant(variant_uuid)
            if outdated_only or not sbom_ids:
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
            scope_variant_ids = [variant.id for variant in Variant.get_by_project(project_uuid)]
            sbom_ids = active_sbom_scan_ids_for_project(project_uuid)
            if outdated_only or not sbom_ids:
                pkgs = []
            else:
                pkg_sets = _packages_by_scan_ids(sbom_ids)
                all_pkg_ids = set().union(*pkg_sets.values()) if pkg_sets else set()
                pkg_lookup = _package_rows(all_pkg_ids)
                pkgs = sorted(pkg_lookup.values(), key=lambda p: p.name)
            active_scan_ids = sbom_ids
        else:
            pkgs = [] if outdated_only else Package.get_all()
            active_scan_ids = []
            scope_variant_ids = [variant.id for variant in Variant.get_all()]
        result = [pkg.to_dict() for pkg in pkgs]

        for p in result:
            p.setdefault("variants", [])
            p.setdefault("sources", [])
            p.setdefault("sbom_documents", [])
            p["outdated"] = False

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

        if include_outdated and scope_variant_ids:
            # A finding is outdated for a variant when the package name/version
            # it observed historically is absent from that variant's active
            # SBOM.  Match by name/version rather than package UUID so scanner
            # findings without supplier metadata still match supplier-qualified
            # packages from the SBOM.
            active_identities_by_variant: dict[uuid.UUID, set[tuple[str, str]]] = {}
            for scope_variant_id in scope_variant_ids:
                scan_ids = active_sbom_scan_ids_for_variant(scope_variant_id)
                if not scan_ids:
                    active_identities_by_variant[scope_variant_id] = set()
                    continue
                active_identities_by_variant[scope_variant_id] = {
                    (name, version)
                    for name, version in db.session.execute(
                        db.select(Package.name, Package.version)
                        .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                        .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                        .where(SBOMDocument.scan_id.in_(scan_ids))
                        .distinct()
                    )
                }

            historical_rows = db.session.execute(
                db.select(Finding, Package, Variant, Scan.scan_source)
                .join(Package, Finding.package_id == Package.id)
                .join(Observation, Observation.finding_id == Finding.id)
                .join(Scan, Observation.scan_id == Scan.id)
                .join(Variant, Scan.variant_id == Variant.id)
                .where(Variant.id.in_(scope_variant_ids))
                .distinct()
            ).all()

            outdated_rows: dict[tuple[uuid.UUID, uuid.UUID], dict] = {}
            for finding, package, variant, scan_source in historical_rows:
                if (package.name, package.version) in active_identities_by_variant.get(variant.id, set()):
                    continue
                outdated_key = (package.id, variant.id)
                if outdated_key not in outdated_rows:
                    item = package.to_dict()
                    item.update({
                        "variants": [variant.name],
                        "variant_id": str(variant.id),
                        "sources": [],
                        "sbom_documents": [],
                        "outdated": True,
                        "finding_ids": [],
                        "vulnerability_ids": [],
                    })
                    outdated_rows[outdated_key] = item
                item = outdated_rows[outdated_key]
                finding_id = str(finding.id)
                if finding_id not in item["finding_ids"]:
                    item["finding_ids"].append(finding_id)
                if finding.vulnerability_id not in item["vulnerability_ids"]:
                    item["vulnerability_ids"].append(finding.vulnerability_id)
                if scan_source and scan_source not in item["sources"]:
                    item["sources"].append(scan_source)

            for item in outdated_rows.values():
                item["finding_ids"].sort()
                item["vulnerability_ids"].sort()
                item["sources"].sort()
            result.extend(sorted(
                outdated_rows.values(),
                key=lambda item: (item["name"], item["version"], item["variants"]),
            ))

        if request.args.get('format', 'list') == "dict":
            dict_result = {}
            for package in result:
                key = package["name"] + "@" + package["version"]
                if package["outdated"]:
                    key += "@" + package["variant_id"]
                dict_result[key] = package
            return dict_result
        return result

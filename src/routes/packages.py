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
                return set(db.session.execute(
                    db.select(Package.id)
                    .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                    .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                    .join(Scan, SBOMDocument.scan_id == Scan.id)
                    .where(Scan.variant_id == variant_uuid)
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
                pkg_ids_sub = (
                    db.select(Package.id)
                    .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                    .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                    .join(Scan, SBOMDocument.scan_id == Scan.id)
                    .where(Scan.variant_id == compare_uuid)
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
        # Restrict to the current project/variant scope to avoid showing
        # variant names from other projects.
        pkg_ids = [pkg.id for pkg in pkgs]
        if pkg_ids:
            enrich_query = (
                db.select(
                    Package.id.label("package_id"),
                    Package.name,
                    Package.version,
                    Variant.name.label("variant_name"),
                    SBOMDocument.format.label("doc_format"),
                    SBOMDocument.source_name.label("doc_source_name"),
                )
                .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                .join(Scan, SBOMDocument.scan_id == Scan.id)
                .join(Variant, Scan.variant_id == Variant.id)
                .where(Package.id.in_(pkg_ids))
            )
            # Restrict to active (non-deprecated) scan documents only
            if active_scan_ids:
                enrich_query = enrich_query.where(SBOMDocument.scan_id.in_(active_scan_ids))
            if variant_id:
                _v = db.session.get(Variant, uuid.UUID(variant_id))
                if _v and _v.project_id:
                    enrich_query = enrich_query.where(
                        Variant.project_id == _v.project_id
                    )
                else:
                    enrich_query = enrich_query.where(
                        Scan.variant_id == uuid.UUID(variant_id)
                    )
            elif project_id:
                enrich_query = enrich_query.where(Variant.project_id == uuid.UUID(project_id))
            rows = db.session.execute(enrich_query).all()

            # Build lookup by package UUID to avoid conflating similarly-named
            # package rows (e.g. different supplier or near-identical versions).
            meta: dict = {}
            for row in rows:
                key = str(row.package_id)
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

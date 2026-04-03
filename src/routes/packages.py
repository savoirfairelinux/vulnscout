#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from sqlalchemy import func
from ..models.package import Package
from ..models.scan import Scan
from ..models.variant import Variant
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
from ..extensions import db


def _latest_scan_id_for_variant(variant_uuid):
    """Return the ID of the most recent Scan for the given variant, or None."""
    return db.session.execute(
        db.select(Scan.id)
        .where(Scan.variant_id == variant_uuid)
        .order_by(Scan.timestamp.desc())
        .limit(1)
    ).scalar_one_or_none()


def _latest_scan_ids_for_project(project_uuid):
    """Return a list of Scan IDs – the latest scan for each variant in the project."""
    latest_ts_sub = (
        db.select(Scan.variant_id, func.max(Scan.timestamp).label("max_ts"))
        .join(Variant, Scan.variant_id == Variant.id)
        .where(Variant.project_id == project_uuid)
        .group_by(Scan.variant_id)
        .subquery()
    )
    return list(db.session.execute(
        db.select(Scan.id)
        .join(
            latest_ts_sub,
            (Scan.variant_id == latest_ts_sub.c.variant_id)
            & (Scan.timestamp == latest_ts_sub.c.max_ts),
        )
    ).scalars().all())


def init_app(app):

    @app.route('/api/packages')
    def index_pkg():
        from flask import request
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')
        compare_variant_id = request.args.get('compare_variant_id')
        if variant_id and compare_variant_id:
            try:
                base_uuid = uuid.UUID(variant_id)
                compare_uuid = uuid.UUID(compare_variant_id)
            except ValueError:
                return {"error": "Invalid variant_id or compare_variant_id"}, 400
            operation = request.args.get('operation', 'difference')

            def _pkg_ids_for_variant(variant_uuid):
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
                query = (
                    db.select(Package)
                    .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                    .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                    .join(Scan, SBOMDocument.scan_id == Scan.id)
                    .where(Scan.variant_id == compare_uuid)
                    .distinct()
                    .order_by(Package.name)
                )
                if exclude_ids:
                    query = query.where(~Package.id.in_(exclude_ids))
                pkgs = list(db.session.execute(query).scalars().all())
        elif variant_id:
            try:
                variant_uuid = uuid.UUID(variant_id)
            except ValueError:
                return {"error": "Invalid variant_id"}, 400
            latest_id = _latest_scan_id_for_variant(variant_uuid)
            if latest_id is None:
                pkgs = []
            else:
                pkgs = list(db.session.execute(
                    db.select(Package)
                    .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                    .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                    .where(SBOMDocument.scan_id == latest_id)
                    .distinct()
                    .order_by(Package.name)
                ).scalars().all())
        elif project_id:
            try:
                project_uuid = uuid.UUID(project_id)
            except ValueError:
                return {"error": "Invalid project_id"}, 400
            latest_ids = _latest_scan_ids_for_project(project_uuid)
            if not latest_ids:
                pkgs = []
            else:
                pkgs = list(db.session.execute(
                    db.select(Package)
                    .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                    .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                    .where(SBOMDocument.scan_id.in_(latest_ids))
                    .distinct()
                    .order_by(Package.name)
                ).scalars().all())
        else:
            pkgs = Package.get_all()
        result = [pkg.to_dict() for pkg in pkgs]

        # Enrich each package with its variants and sources derived from the
        # SBOMPackage → SBOMDocument → Scan → Variant chain so that the
        # frontend can display them even for packages with 0 vulnerabilities.
        pkg_ids = [pkg.id for pkg in pkgs]
        if pkg_ids:
            rows = db.session.execute(
                db.select(
                    Package.name,
                    Package.version,
                    Variant.name.label("variant_name"),
                    SBOMDocument.format.label("doc_format"),
                )
                .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                .join(Scan, SBOMDocument.scan_id == Scan.id)
                .join(Variant, Scan.variant_id == Variant.id)
                .where(Package.id.in_(pkg_ids))
            ).all()

            # Build lookup: "name@version" → {variants: set, sources: set}
            meta: dict = {}
            for row in rows:
                key = f"{row.name}@{row.version}"
                if key not in meta:
                    meta[key] = {"variants": set(), "sources": set()}
                if row.variant_name:
                    meta[key]["variants"].add(row.variant_name)
                if row.doc_format:
                    meta[key]["sources"].add(row.doc_format)

            for p in result:
                key = f"{p['name']}@{p['version']}"
                info = meta.get(key, {})
                p["variants"] = sorted(info.get("variants", set()))
                p["sources"] = sorted(info.get("sources", set()))

        if request.args.get('format', 'list') == "dict":
            return {p["name"] + "@" + p["version"]: p for p in result}
        return result

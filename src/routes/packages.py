#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from ..models.package import Package
from ..models.scan import Scan
from ..models.variant import Variant
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
from ..extensions import db


def _latest_scan_id_for_variant(variant_uuid):
    """Return the active Scan IDs for the given variant.

    The current view is the union of the latest SBOM scan and the latest tool
    scan (if any).  Returns a list of 0–2 scan IDs.
    """
    rows = db.session.execute(
        db.select(Scan.id, Scan.scan_type)
        .where(Scan.variant_id == variant_uuid)
        .order_by(Scan.timestamp.desc())
    ).all()
    ids: list = []
    seen_types: set = set()
    for scan_id, scan_type in rows:
        st = scan_type or "sbom"
        if st not in seen_types:
            seen_types.add(st)
            ids.append(scan_id)
        if len(seen_types) >= 2:
            break
    return ids


def _latest_scan_ids_for_project(project_uuid):
    """Return the active Scan IDs for each variant in the project."""
    rows = db.session.execute(
        db.select(Scan.id, Scan.variant_id, Scan.scan_type, Scan.timestamp)
        .join(Variant, Scan.variant_id == Variant.id)
        .where(Variant.project_id == project_uuid)
        .order_by(Scan.variant_id, Scan.timestamp.desc())
    ).all()
    ids: list = []
    seen: dict = {}
    for scan_id, vid, scan_type, _ts in rows:
        st = scan_type or "sbom"
        variant_seen = seen.setdefault(vid, set())
        if st not in variant_seen:
            variant_seen.add(st)
            ids.append(scan_id)
    return ids


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
        elif variant_id:
            try:
                variant_uuid = uuid.UUID(variant_id)
            except ValueError:
                return {"error": "Invalid variant_id"}, 400
            latest_ids = _latest_scan_id_for_variant(variant_uuid)
            if not latest_ids:
                pkgs = []
            else:
                pkg_ids_sub = (
                    db.select(Package.id)
                    .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                    .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                    .where(SBOMDocument.scan_id.in_(latest_ids))
                    .distinct()
                )
                pkgs = list(db.session.execute(
                    db.select(Package)
                    .where(Package.id.in_(pkg_ids_sub))
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
                pkg_ids_sub = (
                    db.select(Package.id)
                    .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                    .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                    .where(SBOMDocument.scan_id.in_(latest_ids))
                    .distinct()
                )
                pkgs = list(db.session.execute(
                    db.select(Package)
                    .where(Package.id.in_(pkg_ids_sub))
                    .order_by(Package.name)
                ).scalars().all())
        else:
            pkgs = Package.get_all()
        result = [pkg.to_dict() for pkg in pkgs]

        # Enrich each package with its variants and sources derived from the
        # SBOMPackage → SBOMDocument → Scan → Variant chain so that the
        # frontend can display them even for packages with 0 vulnerabilities.
        # Restrict to the current project/variant scope to avoid showing
        # variant names from other projects.
        pkg_ids = [pkg.id for pkg in pkgs]
        if pkg_ids:
            enrich_query = (
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
            )
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

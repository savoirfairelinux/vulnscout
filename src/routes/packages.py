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
from ..models.finding import Finding
from ..models.observation import Observation
from ..models.assessment import Assessment as DBAssessment, STATUS_TO_SIMPLIFIED as _S2S
from ..models.metrics import Metrics as DBMetrics
from ..extensions import db

_SEVERITY_INDEX = {"NONE": 0, "UNKNOWN": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}


def _score_to_severity(score) -> str:
    if score is None or score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


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
        current_scan_ids: list = []
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

            compare_latest_id = _latest_scan_id_for_variant(compare_uuid)
            current_scan_ids = [compare_latest_id] if compare_latest_id else []

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
            latest_id = _latest_scan_id_for_variant(variant_uuid)
            current_scan_ids = [latest_id] if latest_id else []
            if latest_id is None:
                pkgs = []
            else:
                pkg_ids_sub = (
                    db.select(Package.id)
                    .join(SBOMPackage, Package.id == SBOMPackage.package_id)
                    .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                    .where(SBOMDocument.scan_id == latest_id)
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
            current_scan_ids = latest_ids
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

            # Enrich each package with vulnerability counts per simplified_status
            # and highest severity per simplified_status group.
            finding_q = (
                db.select(Finding.package_id, Finding.vulnerability_id)
                .where(Finding.package_id.in_(pkg_ids))
                .distinct()
            )
            if current_scan_ids:
                finding_q = (
                    finding_q
                    .join(Observation, Finding.id == Observation.finding_id)
                    .where(Observation.scan_id.in_(current_scan_ids))
                )
            pkg_vuln_pairs = db.session.execute(finding_q).all()

            all_linked_vuln_ids = list({str(r.vulnerability_id) for r in pkg_vuln_pairs})

            # Latest assessment simplified_status per vulnerability
            # Use a GROUP BY subquery so we only fetch one row per vuln (latest timestamp).
            vuln_status: dict[str, str] = {}
            if all_linked_vuln_ids:
                latest_ts_sub = (
                    db.select(
                        Finding.vulnerability_id.label("v_id"),
                        func.max(DBAssessment.timestamp).label("max_ts"),
                    )
                    .join(Finding, DBAssessment.finding_id == Finding.id)
                    .where(Finding.vulnerability_id.in_(all_linked_vuln_ids))
                    .group_by(Finding.vulnerability_id)
                    .subquery()
                )
                assess_rows = db.session.execute(
                    db.select(
                        Finding.vulnerability_id,
                        DBAssessment.simplified_status,
                        DBAssessment.status,
                    )
                    .join(Finding, DBAssessment.finding_id == Finding.id)
                    .join(
                        latest_ts_sub,
                        (Finding.vulnerability_id == latest_ts_sub.c.v_id)
                        & (DBAssessment.timestamp == latest_ts_sub.c.max_ts),
                    )
                    .distinct()
                ).all()
                for row in assess_rows:
                    vid = str(row.vulnerability_id)
                    simplified = row.simplified_status or _S2S.get(row.status or "", "Pending Assessment")
                    vuln_status[vid] = simplified

            # Max CVSS score per vulnerability
            vuln_max_score: dict[str, float] = {}
            if all_linked_vuln_ids:
                score_rows = db.session.execute(
                    db.select(
                        DBMetrics.vulnerability_id,
                        func.max(DBMetrics.score).label("max_score"),
                    )
                    .where(DBMetrics.vulnerability_id.in_(all_linked_vuln_ids))
                    .group_by(DBMetrics.vulnerability_id)
                ).all()
                for row in score_rows:
                    if row.max_score is not None:
                        vuln_max_score[str(row.vulnerability_id)] = float(row.max_score)

            # Aggregate counts and max severity per (package, simplified_status)
            pkg_vuln_counts: dict[str, dict[str, int]] = {}
            pkg_max_sev: dict[str, dict[str, dict]] = {}
            for row in pkg_vuln_pairs:
                pid = str(row.package_id)
                vid = str(row.vulnerability_id)
                status = vuln_status.get(vid, "Pending Assessment")

                pkg_vuln_counts.setdefault(pid, {})
                pkg_vuln_counts[pid][status] = pkg_vuln_counts[pid].get(status, 0) + 1

                pkg_max_sev.setdefault(pid, {})
                score = vuln_max_score.get(vid)
                sev_label = _score_to_severity(score)
                sev_idx = _SEVERITY_INDEX.get(sev_label, 0)
                current_sev = pkg_max_sev[pid].get(status, {"label": "NONE", "index": 0})
                if sev_idx > current_sev["index"]:
                    pkg_max_sev[pid][status] = {"label": sev_label, "index": sev_idx}

            for p, pkg in zip(result, pkgs):
                pid = str(pkg.id)
                p["vulnerabilities"] = pkg_vuln_counts.get(pid, {})
                p["maxSeverity"] = pkg_max_sev.get(pid, {})

        if request.args.get('format', 'list') == "dict":
            return {p["name"] + "@" + p["version"]: p for p in result}
        return result

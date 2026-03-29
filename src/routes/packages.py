#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from sqlalchemy import func
from ..models.package import Package
from ..models.finding import Finding
from ..models.observation import Observation
from ..models.scan import Scan
from ..models.variant import Variant
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
        if variant_id:
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
                    .join(Finding, Package.id == Finding.package_id)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .where(Observation.scan_id == latest_id)
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
                    .join(Finding, Package.id == Finding.package_id)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .where(Observation.scan_id.in_(latest_ids))
                    .distinct()
                    .order_by(Package.name)
                ).scalars().all())
        else:
            pkgs = Package.get_all()
        result = [pkg.to_dict() for pkg in pkgs]
        if request.args.get('format', 'list') == "dict":
            return {p["name"] + "@" + p["version"]: p for p in result}
        return result

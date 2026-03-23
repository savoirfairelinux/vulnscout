#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from ..models.package import Package
from ..models.finding import Finding
from ..models.observation import Observation
from ..models.scan import Scan
from ..models.variant import Variant
from ..extensions import db


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
            pkgs = list(db.session.execute(
                db.select(Package)
                .join(Finding, Package.id == Finding.package_id)
                .join(Observation, Finding.id == Observation.finding_id)
                .join(Scan, Observation.scan_id == Scan.id)
                .where(Scan.variant_id == variant_uuid)
                .distinct()
                .order_by(Package.name)
            ).scalars().all())
        elif project_id:
            try:
                project_uuid = uuid.UUID(project_id)
            except ValueError:
                return {"error": "Invalid project_id"}, 400
            pkgs = list(db.session.execute(
                db.select(Package)
                .join(Finding, Package.id == Finding.package_id)
                .join(Observation, Finding.id == Observation.finding_id)
                .join(Scan, Observation.scan_id == Scan.id)
                .join(Variant, Scan.variant_id == Variant.id)
                .where(Variant.project_id == project_uuid)
                .distinct()
                .order_by(Package.name)
            ).scalars().all())
        else:
            pkgs = Package.get_all()
        result = [pkg.to_dict() for pkg in pkgs]
        if request.args.get('format', 'list') == "dict":
            return {p["name"] + "@" + p["version"]: p for p in result}
        return result

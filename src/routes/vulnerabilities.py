#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from flask import request
from sqlalchemy import func
from sqlalchemy.orm import selectinload
from ..models.vulnerability import Vulnerability
from ..models.finding import Finding
from ..models.observation import Observation
from ..models.package import Package
from ..models.scan import Scan
from ..models.variant import Variant
from ..models.metrics import Metrics
from ..models.cvss import CVSS
from ..models.iso8601_duration import Iso8601Duration
from ..extensions import db
from ..helpers.verbose import verbose

TIME_ESTIMATES_PATH = "/scan/outputs/time_estimates.json"


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


def _parse_effort_hours(value) -> int:
    """Parse an effort value (ISO 8601 duration string or integer hours) to whole hours."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(Iso8601Duration(value).total_seconds // 3600)
    raise ValueError(f"Invalid effort value: {value!r}")


def init_app(app):

    if "TIME_ESTIMATES_PATH" not in app.config:
        app.config["TIME_ESTIMATES_PATH"] = TIME_ESTIMATES_PATH

    @app.route('/api/vulnerabilities')
    def index_vulns():
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
            base_latest_id = _latest_scan_id_for_variant(base_uuid)
            compare_latest_id = _latest_scan_id_for_variant(compare_uuid)
            current_scan_ids = [compare_latest_id] if compare_latest_id else []
            opts = (
                selectinload(Vulnerability.findings).selectinload(Finding.package),
                selectinload(Vulnerability.metrics),
            )
            if base_latest_id is None:
                base_ids = set()
            else:
                base_ids = set(db.session.execute(
                    db.select(Vulnerability.id)
                    .join(Finding, Vulnerability.id == Finding.vulnerability_id)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .where(Observation.scan_id == base_latest_id)
                    .distinct()
                ).scalars().all())
            operation = request.args.get('operation', 'difference')
            if operation == 'intersection':
                if compare_latest_id is None:
                    records = []
                else:
                    compare_ids = set(db.session.execute(
                        db.select(Vulnerability.id)
                        .join(Finding, Vulnerability.id == Finding.vulnerability_id)
                        .join(Observation, Finding.id == Observation.finding_id)
                        .where(Observation.scan_id == compare_latest_id)
                        .distinct()
                    ).scalars().all())
                    intersection_ids = list(base_ids & compare_ids)
                    records = list(db.session.execute(
                        db.select(Vulnerability)
                        .options(*opts)
                        .where(Vulnerability.id.in_(intersection_ids))
                        .order_by(Vulnerability.id)
                    ).scalars().all()) if intersection_ids else []
            else:  # difference (default): vulns in compare but NOT in base
                if compare_latest_id is None:
                    records = []
                else:
                    query = (
                        db.select(Vulnerability)
                        .options(*opts)
                        .join(Finding, Vulnerability.id == Finding.vulnerability_id)
                        .join(Observation, Finding.id == Observation.finding_id)
                        .where(Observation.scan_id == compare_latest_id)
                        .distinct()
                        .order_by(Vulnerability.id)
                    )
                    if base_ids:
                        query = query.where(~Vulnerability.id.in_(list(base_ids)))
                    records = list(db.session.execute(query).scalars().all())
        elif variant_id:
            try:
                variant_uuid = uuid.UUID(variant_id)
            except ValueError:
                return {"error": "Invalid variant_id"}, 400
            latest_id = _latest_scan_id_for_variant(variant_uuid)
            current_scan_ids = [latest_id] if latest_id else []
            if latest_id is None:
                records = []
            else:
                records = list(db.session.execute(
                    db.select(Vulnerability)
                    .options(
                        selectinload(Vulnerability.findings).selectinload(Finding.package),
                        selectinload(Vulnerability.metrics),
                    )
                    .join(Finding, Vulnerability.id == Finding.vulnerability_id)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .where(Observation.scan_id == latest_id)
                    .distinct()
                    .order_by(Vulnerability.id)
                ).scalars().all())
        elif project_id:
            try:
                project_uuid = uuid.UUID(project_id)
            except ValueError:
                return {"error": "Invalid project_id"}, 400
            latest_ids = _latest_scan_ids_for_project(project_uuid)
            current_scan_ids = latest_ids
            if not latest_ids:
                records = []
            else:
                records = list(db.session.execute(
                    db.select(Vulnerability)
                    .options(
                        selectinload(Vulnerability.findings).selectinload(Finding.package),
                        selectinload(Vulnerability.metrics),
                    )
                    .join(Finding, Vulnerability.id == Finding.vulnerability_id)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .where(Observation.scan_id.in_(latest_ids))
                    .distinct()
                    .order_by(Vulnerability.id)
                ).scalars().all())
        else:
            records = Vulnerability.get_all()
        vulns = [r.to_dict() for r in records]

        vuln_ids = [v["id"] for v in vulns]
        if vuln_ids:
            # packages_current: packages from the specific scan(s) used for this query
            if current_scan_ids:
                pkg_rows = db.session.execute(
                    db.select(Finding.vulnerability_id, Package.name, Package.version)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .join(Package, Finding.package_id == Package.id)
                    .where(Observation.scan_id.in_(current_scan_ids))
                    .where(Finding.vulnerability_id.in_(vuln_ids))
                    .distinct()
                ).all()
                pkgs_current_by_vuln: dict = {}
                for vuln_id, pkg_name, pkg_version in pkg_rows:
                    pkgs_current_by_vuln.setdefault(str(vuln_id), []).append(f"{pkg_name}@{pkg_version}")
                for v in vulns:
                    v["packages_current"] = sorted(pkgs_current_by_vuln.get(v["id"], []))
            else:
                for v in vulns:
                    v["packages_current"] = list(v["packages"])

            # Enrich each vuln dict with sorted variant names, restricted to latest scans
            latest_ts_sub = (
                db.select(Scan.variant_id, func.max(Scan.timestamp).label("max_ts"))
                .group_by(Scan.variant_id)
                .subquery()
            )
            latest_scan_sub = (
                db.select(Scan.id)
                .join(
                    latest_ts_sub,
                    (Scan.variant_id == latest_ts_sub.c.variant_id)
                    & (Scan.timestamp == latest_ts_sub.c.max_ts),
                )
                .subquery()
            )
            rows = db.session.execute(
                db.select(Finding.vulnerability_id, Variant.name)
                .join(Observation, Finding.id == Observation.finding_id)
                .join(Scan, Observation.scan_id == Scan.id)
                .join(Variant, Scan.variant_id == Variant.id)
                .where(Finding.vulnerability_id.in_(vuln_ids))
                .where(Observation.scan_id.in_(db.select(latest_scan_sub.c.id)))
                .distinct()
            ).all()
            variant_names_by_vuln: dict = {}
            for vuln_id, variant_name in rows:
                variant_names_by_vuln.setdefault(str(vuln_id), []).append(variant_name)
            for v in vulns:
                v["variants"] = sorted(variant_names_by_vuln.get(v["id"], []))

        if request.args.get('format', 'list') == "dict":
            return {v["id"]: v for v in vulns}
        return vulns

    @app.route('/api/vulnerabilities/<id>', methods=['GET', 'PATCH'])
    def update_vuln(id):
        record = Vulnerability.get_by_id(id)
        if not record:
            return "Not found", 404

        if request.method == 'PATCH':
            payload_data = request.get_json()
            if payload_data is None:
                return {"error": "Invalid request data"}, 400

            if "effort" in payload_data:
                # Store effort on the first finding's time-estimate
                eff = payload_data["effort"]
                if not all(k in eff for k in ("optimistic", "likely", "pessimistic")):
                    return "Invalid effort values", 400
                try:
                    opt = _parse_effort_hours(eff["optimistic"])
                    lik = _parse_effort_hours(eff["likely"])
                    pes = _parse_effort_hours(eff["pessimistic"])
                except (ValueError, TypeError):
                    return "Invalid effort values", 400
                if not (opt <= lik <= pes):
                    return "Invalid effort values", 400
                variant_id = payload_data.get("variant_id")
                if variant_id is not None:
                    try:
                        variant_id = uuid.UUID(variant_id)
                    except (ValueError, AttributeError):
                        return {"error": "Invalid variant_id"}, 400
                try:
                    from ..models.time_estimate import TimeEstimate
                    for finding in (record.findings or []):
                        if variant_id is not None:
                            existing = TimeEstimate.get_by_finding_and_variant(finding.id, variant_id)
                        else:
                            existing = finding.time_estimate
                        if existing is not None:
                            existing.update(optimistic=opt, likely=lik, pessimistic=pes)
                        else:
                            TimeEstimate.create(
                                finding_id=finding.id, variant_id=variant_id,
                                optimistic=opt, likely=lik, pessimistic=pes
                            )
                        break
                except Exception as e:
                    verbose(f"[PATCH /api/vulnerabilities/{record.id} effort] {e}")

            if "cvss" in payload_data:
                new_cvss = payload_data["cvss"]
                required_keys = {"base_score", "vector_string", "version"}
                if not required_keys.issubset(new_cvss.keys()):
                    return "Invalid CVSS data", 400
                cvss_obj = CVSS.from_dict(new_cvss)
                try:
                    Metrics.from_cvss(cvss_obj, record.id)
                except Exception as e:
                    verbose(f"[PATCH /api/vulnerabilities/{record.id} cvss] {e}")

        return record.to_dict()

    @app.route('/api/vulnerabilities/batch', methods=['PATCH'])
    def update_vulns_batch():
        payload_data = request.get_json()
        if (not payload_data
                or "vulnerabilities" not in payload_data
                or not isinstance(payload_data["vulnerabilities"], list)):
            return {"error": "Invalid request data. Expected: {vulnerabilities: [...]}"}, 400

        results = []
        errors = []

        for item in payload_data["vulnerabilities"]:
            if not isinstance(item, dict) or "id" not in item:
                errors.append({"error": "Invalid vulnerability data", "item": item})
                continue

            record = Vulnerability.get_by_id(item["id"])
            if not record:
                errors.append({"id": item["id"], "error": "Vulnerability not found"})
                continue

            if "effort" in item:
                eff = item["effort"]
                if not all(k in eff for k in ("optimistic", "likely", "pessimistic")):
                    errors.append({"id": item["id"], "error": "Invalid effort values"})
                    continue
                try:
                    opt = _parse_effort_hours(eff["optimistic"])
                    lik = _parse_effort_hours(eff["likely"])
                    pes = _parse_effort_hours(eff["pessimistic"])
                except (ValueError, TypeError):
                    errors.append({"id": item["id"], "error": "Invalid effort values"})
                    continue
                if not (opt <= lik <= pes):
                    errors.append({"id": item["id"], "error": "Invalid effort values"})
                    continue
                item_variant_id = item.get("variant_id")
                if item_variant_id is not None:
                    try:
                        item_variant_id = uuid.UUID(item_variant_id)
                    except (ValueError, AttributeError):
                        errors.append({"id": item["id"], "error": "Invalid variant_id"})
                        continue
                try:
                    from ..models.time_estimate import TimeEstimate
                    for finding in (record.findings or []):
                        if item_variant_id is not None:
                            existing = TimeEstimate.get_by_finding_and_variant(finding.id, item_variant_id)
                        else:
                            existing = finding.time_estimate
                        if existing is not None:
                            existing.update(optimistic=opt, likely=lik, pessimistic=pes)
                        else:
                            TimeEstimate.create(
                                finding_id=finding.id, variant_id=item_variant_id,
                                optimistic=opt, likely=lik, pessimistic=pes
                            )
                        break
                except Exception as e:
                    verbose(f"[PATCH /api/vulnerabilities/batch {item['id']!r} effort] {e}")

            if "cvss" in item:
                new_cvss = item["cvss"]
                required_keys = {"base_score", "vector_string", "version"}
                if not required_keys.issubset(new_cvss.keys()):
                    errors.append({"id": item["id"], "error": "Invalid CVSS data"})
                    continue
                cvss_obj = CVSS.from_dict(new_cvss)
                try:
                    Metrics.from_cvss(cvss_obj, record.id)
                except Exception as e:
                    verbose(f"[PATCH /api/vulnerabilities/batch {item['id']!r} cvss] {e}")

            results.append(record.to_dict())

        response = {
            "status": "success" if results else "error",
            "vulnerabilities": results,
            "count": len(results)
        }
        if errors:
            response["errors"] = errors
            response["error_count"] = len(errors)
        return response, 200 if results else 400

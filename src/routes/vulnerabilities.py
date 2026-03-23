#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from flask import request
from sqlalchemy.orm import selectinload
from ..models.vulnerability import Vulnerability
from ..models.finding import Finding
from ..models.observation import Observation
from ..models.scan import Scan
from ..models.variant import Variant
from ..models.metrics import Metrics
from ..models.cvss import CVSS
from ..models.iso8601_duration import Iso8601Duration
from ..extensions import db
from ..helpers.verbose import verbose

TIME_ESTIMATES_PATH = "/scan/outputs/time_estimates.json"


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
        if variant_id:
            try:
                variant_uuid = uuid.UUID(variant_id)
            except ValueError:
                return {"error": "Invalid variant_id"}, 400
            records = list(db.session.execute(
                db.select(Vulnerability)
                .options(
                    selectinload(Vulnerability.findings).selectinload(Finding.package),
                    selectinload(Vulnerability.metrics),
                )
                .join(Finding, Vulnerability.id == Finding.vulnerability_id)
                .join(Observation, Finding.id == Observation.finding_id)
                .join(Scan, Observation.scan_id == Scan.id)
                .where(Scan.variant_id == variant_uuid)
                .distinct()
                .order_by(Vulnerability.id)
            ).scalars().all())
        elif project_id:
            try:
                project_uuid = uuid.UUID(project_id)
            except ValueError:
                return {"error": "Invalid project_id"}, 400
            records = list(db.session.execute(
                db.select(Vulnerability)
                .options(
                    selectinload(Vulnerability.findings).selectinload(Finding.package),
                    selectinload(Vulnerability.metrics),
                )
                .join(Finding, Vulnerability.id == Finding.vulnerability_id)
                .join(Observation, Finding.id == Observation.finding_id)
                .join(Scan, Observation.scan_id == Scan.id)
                .join(Variant, Scan.variant_id == Variant.id)
                .where(Variant.project_id == project_uuid)
                .distinct()
                .order_by(Vulnerability.id)
            ).scalars().all())
        else:
            records = Vulnerability.get_all()
        vulns = [r.to_dict() for r in records]
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
                try:
                    from ..models.time_estimate import TimeEstimate
                    for finding in (record.findings or []):
                        existing = finding.time_estimate
                        if existing is not None:
                            existing.update(optimistic=opt, likely=lik, pessimistic=pes)
                        else:
                            TimeEstimate.create(finding_id=finding.id, optimistic=opt, likely=lik, pessimistic=pes)
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
                try:
                    from ..models.time_estimate import TimeEstimate
                    for finding in (record.findings or []):
                        existing = finding.time_estimate
                        if existing is not None:
                            existing.update(optimistic=opt, likely=lik, pessimistic=pes)
                        else:
                            TimeEstimate.create(finding_id=finding.id, optimistic=opt, likely=lik, pessimistic=pes)
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

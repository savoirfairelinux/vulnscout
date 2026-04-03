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
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
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


# Formats that are exclusively vulnerability scanners (never pure package BOMs)
_DEDICATED_SCANNER_FORMATS = frozenset({"grype", "yocto_cve_check"})

# Mapping from SBOMDocument.format to the legacy found_by string the front-end expects
_FORMAT_TO_FOUND_BY: dict[str, str] = {
    "grype": "grype",
    "spdx": "spdx3",
    "cdx": "cyclonedx",
    "openvex": "openvex",
    "yocto_cve_check": "yocto",
}


def _populate_found_by(
    records: list,
    variant_uuid=None,
    project_uuid=None,
) -> None:
    """Populate the transient found_by list on each record from SBOMDocument.format.

    Walks the Finding -> SBOMPackage -> SBOMDocument chain to discover which
    SBOM document formats are linked to each vulnerability's affected packages,
    then maps them to the legacy found_by strings consumed by the frontend chart.

    Attribution logic to avoid false-positives from package-list SBOM files:
    - ``grype`` and ``yocto_cve_check`` are dedicated scanners: they only list
      packages that are affected by a vulnerability, so their presence is always
      authoritative.
    - ``spdx``, ``cdx``, ``openvex`` are dual-purpose (package list OR security
      file): they are only attributed as a source for a given
      (vulnerability, package) pair when NO dedicated scanner document also
      contains that same package.  This prevents a plain SPDX package BOM from
      being incorrectly credited as a vulnerability discovery source.

    When variant_uuid or project_uuid is provided, only SBOM documents
    belonging to that variant or project are considered.
    """
    if not records:
        return

    vuln_ids = [r.id for r in records]

    # Build the base query explicitly from Finding so that SBOMDocument does not
    # end up in the implicit FROM clause (which would happen if we referenced
    # SBOMDocument.format without select_from(), causing a cartesian product or
    # a silent no-op when the second .join(SBOMDocument) is evaluated).
    base_query = (
        db.select(Finding.vulnerability_id, Finding.package_id, SBOMDocument.format)
        .select_from(Finding)
        .join(SBOMPackage, SBOMPackage.package_id == Finding.package_id)
        .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
        .where(SBOMDocument.format.isnot(None))
    )

    if variant_uuid is not None:
        base_query = (
            base_query
            .join(Scan, Scan.id == SBOMDocument.scan_id)
            .where(Scan.variant_id == variant_uuid)
        )
    elif project_uuid is not None:
        base_query = (
            base_query
            .join(Scan, Scan.id == SBOMDocument.scan_id)
            .join(Variant, Variant.id == Scan.variant_id)
            .where(Variant.project_id == project_uuid)
        )
    else:
        base_query = base_query.where(Finding.vulnerability_id.in_(vuln_ids))  # no need for full query on all variants

    rows = db.session.execute(base_query.distinct()).all()

    # Group collected formats by (vuln_id, package_id)
    # pkg_formats: {(vuln_id, package_id): set of formats}
    pkg_formats: dict[tuple, set[str]] = {}
    for vuln_id, pkg_id, fmt in rows:
        key = (vuln_id, str(pkg_id))
        pkg_formats.setdefault(key, set()).add(fmt)

    # Determine the sources to attribute for each vulnerability
    found_by_map: dict[str, set[str]] = {}
    for (vuln_id, _pkg_id), formats in pkg_formats.items():
        dedicated = formats & _DEDICATED_SCANNER_FORMATS
        # Only use dedicated scanners when present; fall back to all formats otherwise
        sources = dedicated if dedicated else formats
        for fmt in sources:
            mapped = _FORMAT_TO_FOUND_BY.get(fmt, fmt)
            found_by_map.setdefault(vuln_id, set()).add(mapped)

    for record in records:
        for scanner in found_by_map.get(record.id, set()):
            record.add_found_by(scanner)


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
            _scope_variant = compare_uuid
            _scope_project = None
            opts = (
                selectinload(Vulnerability.findings).selectinload(Finding.package),
                selectinload(Vulnerability.findings).selectinload(Finding.time_estimate),
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
            _scope_variant = variant_uuid
            _scope_project = None
            latest_id = _latest_scan_id_for_variant(variant_uuid)
            current_scan_ids = [latest_id] if latest_id else []
            if latest_id is None:
                records = []
            else:
                records = list(db.session.execute(
                    db.select(Vulnerability)
                    .options(
                        selectinload(Vulnerability.findings).selectinload(Finding.package),
                        selectinload(Vulnerability.findings).selectinload(Finding.time_estimate),
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
            _scope_variant = None
            _scope_project = project_uuid
            latest_ids = _latest_scan_ids_for_project(project_uuid)
            current_scan_ids = latest_ids
            if not latest_ids:
                records = []
            else:
                from ..models.time_estimate import TimeEstimate

                # Subquery for vulnerability IDs visible in these scans,
                # used to avoid huge literal IN-lists in secondary queries.
                vuln_ids_subq = (
                    db.select(Finding.vulnerability_id)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .where(Observation.scan_id.in_(latest_ids))
                    .distinct()
                    .scalar_subquery()
                )

                records = list(db.session.execute(
                    db.select(Vulnerability)
                    .where(Vulnerability.id.in_(vuln_ids_subq))
                    .order_by(Vulnerability.id)
                ).scalars().all())

                # Bulk-load metrics per vulnerability
                metric_rows = db.session.execute(
                    db.select(Metrics)
                    .where(Metrics.vulnerability_id.in_(vuln_ids_subq))
                ).scalars().all()
                metrics_by_vuln: dict[str, list] = {}
                for m in metric_rows:
                    metrics_by_vuln.setdefault(m.vulnerability_id, []).append(m)

                # Bulk-load packages per vulnerability
                pkg_rows = db.session.execute(
                    db.select(Finding.vulnerability_id, Package.name, Package.version)
                    .join(Package, Finding.package_id == Package.id)
                    .where(Finding.vulnerability_id.in_(vuln_ids_subq))
                    .distinct()
                ).all()
                pkgs_by_vuln: dict[str, list[str]] = {}
                for vid, pname, pver in pkg_rows:
                    pkgs_by_vuln.setdefault(vid, []).append(f"{pname}@{pver}")

                # Bulk-load effort (time estimates) per vulnerability
                te_rows = db.session.execute(
                    db.select(
                        Finding.vulnerability_id,
                        TimeEstimate.optimistic,
                        TimeEstimate.likely,
                        TimeEstimate.pessimistic,
                    )
                    .join(Finding, TimeEstimate.finding_id == Finding.id)
                    .where(Finding.vulnerability_id.in_(vuln_ids_subq))
                ).all()
                effort_by_vuln: dict[str, tuple] = {}
                for vid, opti, like, pess in te_rows:
                    if vid not in effort_by_vuln:
                        effort_by_vuln[vid] = (opti, like, pess)

                # Pre-populate transient fields so to_dict() won't lazy-load findings
                from sqlalchemy.orm import attributes as orm_attrs
                for r in records:
                    r.packages = pkgs_by_vuln.get(r.id, [])
                    te = effort_by_vuln.get(r.id)
                    if te:
                        opti, like, pess = te

                        def _h(v):
                            if v is None:
                                return None
                            return Iso8601Duration(f"PT{v}H")
                        r.effort = {
                            "optimistic": _h(opti),
                            "likely": _h(like),
                            "pessimistic": _h(pess),
                        }
                    # Mark findings and metrics as loaded to prevent lazy-load
                    orm_attrs.set_committed_value(r, 'findings', [])
                    orm_attrs.set_committed_value(r, 'metrics', metrics_by_vuln.get(r.id, []))

        else:
            records = Vulnerability.get_all()
            _scope_variant = None
            _scope_project = None
        _populate_found_by(records, _scope_variant, _scope_project)
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
            # and scoped to the current project/variant to avoid cross-project leaks.
            latest_ts_base = (
                db.select(Scan.variant_id, func.max(Scan.timestamp).label("max_ts"))
            )
            if _scope_variant is not None:
                latest_ts_base = latest_ts_base.where(Scan.variant_id == _scope_variant)
            elif _scope_project is not None:
                latest_ts_base = (
                    latest_ts_base
                    .join(Variant, Scan.variant_id == Variant.id)
                    .where(Variant.project_id == _scope_project)
                )
            latest_ts_sub = latest_ts_base.group_by(Scan.variant_id).subquery()
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

            # Enrich with the date of the earliest scan where each vuln was first observed
            first_scan_rows = db.session.execute(
                db.select(Finding.vulnerability_id, func.min(Scan.timestamp))
                .join(Observation, Finding.id == Observation.finding_id)
                .join(Scan, Observation.scan_id == Scan.id)
                .where(Finding.vulnerability_id.in_(vuln_ids))
                .group_by(Finding.vulnerability_id)
            ).all()
            first_scan_by_vuln: dict = {}
            for vuln_id, min_ts in first_scan_rows:
                first_scan_by_vuln[str(vuln_id)] = min_ts.isoformat() if min_ts else None
            for v in vulns:
                v["first_scan_date"] = first_scan_by_vuln.get(v["id"])

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

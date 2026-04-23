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
from ..helpers.datetime_utils import ensure_utc_iso
from ..models.variant import Variant
from ..models.metrics import Metrics
from ..models.cvss import CVSS
from ..models.iso8601_duration import Iso8601Duration
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
from ..extensions import db
from ..helpers.verbose import verbose
from ..helpers.active_scans import (
    active_scan_ids_for_variant,
    active_scan_ids_for_project,
    active_package_ids_for_scans,
)

TIME_ESTIMATES_PATH = "/scan/outputs/time_estimates.json"


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

# Mapping from Scan.scan_source to the found_by string for tool scans
_TOOL_SOURCE_TO_FOUND_BY: dict[str, str] = {
    "nvd": "nvd_cpe",
    "osv": "osv",
}


def _populate_found_by(
    records: list,
    variant_uuid=None,
    project_uuid=None,
    active_scan_ids: list | None = None,
) -> None:
    """Populate the transient found_by list on each record.

    For each vulnerability, find the **earliest** scan that first observed
    it and attribute it to that scan's source (SBOMDocument format or
    tool scan_source).  The first scan that introduced a CVE gets credit.
    """
    if not records:
        return

    vuln_ids = [r.id for r in records]

    # For every vuln, get the scan that first observed it (min timestamp).
    first_scan_subq = (
        db.select(
            Finding.vulnerability_id,
            func.min(Scan.timestamp).label("min_ts"),
        )
        .join(Observation, Observation.finding_id == Finding.id)
        .join(Scan, Scan.id == Observation.scan_id)
        .where(Finding.vulnerability_id.in_(vuln_ids))
        .group_by(Finding.vulnerability_id)
    ).subquery()

    # Now join back to get the scan details for that earliest observation.
    rows = db.session.execute(
        db.select(
            Finding.vulnerability_id,
            Scan.scan_type,
            Scan.scan_source,
            SBOMDocument.format.label("doc_format"),
        )
        .select_from(Finding)
        .join(Observation, Observation.finding_id == Finding.id)
        .join(Scan, Scan.id == Observation.scan_id)
        .join(
            first_scan_subq,
            db.and_(
                first_scan_subq.c.vulnerability_id == Finding.vulnerability_id,
                first_scan_subq.c.min_ts == Scan.timestamp,
            ),
        )
        .outerjoin(
            SBOMDocument,
            db.and_(
                SBOMDocument.scan_id == Scan.id,
                SBOMDocument.format.isnot(None),
            ),
        )
        .distinct()
    ).all()

    # When a scan has multiple SBOMDocuments (e.g. spdx + grype in same
    # merge), collect all formats and prefer non-dedicated scanner formats
    # (spdx, cdx) over dedicated ones (grype) for attribution.
    vuln_formats: dict[str, dict] = {}
    for vuln_id, scan_type, scan_source, doc_format in rows:
        entry = vuln_formats.setdefault(vuln_id, {
            "doc_formats": set(),
            "scan_type": scan_type,
            "scan_source": scan_source,
        })
        if doc_format is not None:
            entry["doc_formats"].add(doc_format)

    found_by_map: dict[str, set[str]] = {}
    for vuln_id, entry in vuln_formats.items():
        doc_formats = entry["doc_formats"]
        if doc_formats:
            # Prefer non-dedicated (spdx, cdx, openvex) over dedicated (grype, yocto)
            non_dedicated = doc_formats - _DEDICATED_SCANNER_FORMATS
            chosen = non_dedicated if non_dedicated else doc_formats
            for fmt in chosen:
                mapped = _FORMAT_TO_FOUND_BY.get(fmt, fmt)
                found_by_map.setdefault(vuln_id, set()).add(mapped)
        elif entry["scan_source"] is not None:
            mapped = _TOOL_SOURCE_TO_FOUND_BY.get(entry["scan_source"], entry["scan_source"])
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
            base_latest_ids = active_scan_ids_for_variant(base_uuid)
            compare_latest_ids = active_scan_ids_for_variant(compare_uuid)
            current_scan_ids = compare_latest_ids
            _scope_variant = compare_uuid
            _scope_project = None
            opts = (
                selectinload(Vulnerability.findings).selectinload(Finding.package),
                selectinload(Vulnerability.findings).selectinload(Finding.time_estimate),
                selectinload(Vulnerability.metrics),
            )

            def _vuln_ids_for_scans(scan_ids):
                """Vuln IDs from *scan_ids*, filtering tool scans to active packages."""
                if not scan_ids:
                    return set()
                _pkg_ids = active_package_ids_for_scans(scan_ids)
                q = (
                    db.select(Vulnerability.id)
                    .join(Finding, Vulnerability.id == Finding.vulnerability_id)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .join(Scan, Observation.scan_id == Scan.id)
                    .where(Observation.scan_id.in_(scan_ids))
                )
                if _pkg_ids:
                    q = q.where(
                        db.or_(
                            Scan.scan_type.is_(None),
                            Scan.scan_type == "sbom",
                            Finding.package_id.in_(_pkg_ids),
                        )
                    )
                return set(db.session.execute(q.distinct()).scalars().all())

            base_ids = _vuln_ids_for_scans(base_latest_ids)
            operation = request.args.get('operation', 'difference')
            if operation == 'intersection':
                if not compare_latest_ids:
                    records = []
                else:
                    compare_ids = _vuln_ids_for_scans(compare_latest_ids)
                    intersection_ids = list(base_ids & compare_ids)
                    records = list(db.session.execute(
                        db.select(Vulnerability)
                        .options(*opts)
                        .where(Vulnerability.id.in_(intersection_ids))
                        .order_by(Vulnerability.id)
                    ).scalars().all()) if intersection_ids else []
            else:  # difference (default): vulns in compare but NOT in base
                if not compare_latest_ids:
                    records = []
                else:
                    compare_pkg_ids = active_package_ids_for_scans(compare_latest_ids)
                    query = (
                        db.select(Vulnerability)
                        .options(*opts)
                        .join(Finding, Vulnerability.id == Finding.vulnerability_id)
                        .join(Observation, Finding.id == Observation.finding_id)
                        .join(Scan, Observation.scan_id == Scan.id)
                        .where(Observation.scan_id.in_(compare_latest_ids))
                    )
                    if compare_pkg_ids:
                        query = query.where(
                            db.or_(
                                Scan.scan_type.is_(None),
                                Scan.scan_type == "sbom",
                                Finding.package_id.in_(compare_pkg_ids),
                            )
                        )
                    query = query.distinct().order_by(Vulnerability.id)
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
            latest_ids = active_scan_ids_for_variant(variant_uuid)
            current_scan_ids = latest_ids
            if not latest_ids:
                records = []
            else:
                # Restrict tool-scan findings to packages still in the SBOM
                _active_pkg_ids = active_package_ids_for_scans(latest_ids)
                _obs_filter = Observation.scan_id.in_(latest_ids)
                if _active_pkg_ids:
                    # Include observation when: SBOM scan, OR package in SBOM
                    _obs_filter = db.and_(
                        _obs_filter,
                        db.or_(
                            Scan.scan_type.is_(None),
                            Scan.scan_type == "sbom",
                            Finding.package_id.in_(_active_pkg_ids),
                        ),
                    )
                records = list(db.session.execute(
                    db.select(Vulnerability)
                    .options(
                        selectinload(Vulnerability.findings).selectinload(Finding.package),
                        selectinload(Vulnerability.findings).selectinload(Finding.time_estimate),
                        selectinload(Vulnerability.metrics),
                    )
                    .join(Finding, Vulnerability.id == Finding.vulnerability_id)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .join(Scan, Observation.scan_id == Scan.id)
                    .where(_obs_filter)
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
            latest_ids = active_scan_ids_for_project(project_uuid)
            current_scan_ids = latest_ids
            if not latest_ids:
                records = []
            else:
                from ..models.time_estimate import TimeEstimate

                # Subquery for vulnerability IDs visible in these scans,
                # used to avoid huge literal IN-lists in secondary queries.
                # Restrict tool-scan findings to packages still in the SBOM.
                _active_pkg_ids = active_package_ids_for_scans(latest_ids)
                vuln_ids_base = (
                    db.select(Finding.vulnerability_id)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .join(Scan, Observation.scan_id == Scan.id)
                    .where(Observation.scan_id.in_(latest_ids))
                )
                if _active_pkg_ids:
                    vuln_ids_base = vuln_ids_base.where(
                        db.or_(
                            Scan.scan_type.is_(None),
                            Scan.scan_type == "sbom",
                            Finding.package_id.in_(_active_pkg_ids),
                        )
                    )
                vuln_ids_subq = vuln_ids_base.distinct().scalar_subquery()

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
        _populate_found_by(records, _scope_variant, _scope_project,
                           active_scan_ids=current_scan_ids or None)
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

            # Enrich each vuln dict with sorted variant names, restricted to
            # the active scans (latest SBOM + latest per-source tool scans)
            # so that the result is consistent with the vulnerabilities shown.
            if current_scan_ids:
                # Re-use the same scan IDs that were used to load vulns
                active_scan_ids = current_scan_ids
            else:
                # Fallback (no variant/project scope): compute active scans
                # for every variant using the same multi-source logic.
                if _scope_variant is not None:
                    active_scan_ids = active_scan_ids_for_variant(_scope_variant)
                elif _scope_project is not None:
                    active_scan_ids = active_scan_ids_for_project(_scope_project)
                else:
                    # All variants across all projects
                    all_variant_ids = [
                        vid for (vid,) in db.session.execute(
                            db.select(Variant.id)
                        ).all()
                    ]
                    active_scan_ids = []
                    for vid in all_variant_ids:
                        active_scan_ids.extend(active_scan_ids_for_variant(vid))
            if active_scan_ids:
                rows = db.session.execute(
                    db.select(Finding.vulnerability_id, Variant.name)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .join(Scan, Observation.scan_id == Scan.id)
                    .join(Variant, Scan.variant_id == Variant.id)
                    .where(Finding.vulnerability_id.in_(vuln_ids))
                    .where(Observation.scan_id.in_(active_scan_ids))
                    .distinct()
                ).all()
            else:
                rows = []
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
                first_scan_by_vuln[str(vuln_id)] = ensure_utc_iso(min_ts)
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

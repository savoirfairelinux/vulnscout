# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import datetime
import os
import dataclasses

from flask import jsonify, request
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload, aliased, attributes as orm_attrs
from ..models import (
    Vulnerability,
    Finding,
    Observation,
    Package,
    Scan,
    Variant,
    Metrics,
    SBOMDocument,
    SBOMPackage,
    Iso8601Duration
)
from ..helpers.datetime_utils import ensure_utc_iso
from ..extensions import db
from ..controllers.nvd_db import NVD_DB
from ..controllers.nvd_apply import apply_nvd_update
from ..controllers.epss_db import EPSS_DB
from ..helpers.active_scans import (
    active_scan_ids_for_variant,
    active_scan_ids_for_project,
    active_package_ids_for_scans,
)
from ..helpers.vuln_helpers import (
    _validate_effort,
    _validate_and_apply_cvss,
    _apply_effort,
)
from ._scan_helpers import parse_uuid_or_400

TIME_ESTIMATES_PATH = "/scan/outputs/time_estimates.json"


def _sbom_pkg_filter(pkg_ids):
    """Return a SQLAlchemy filter clause restricting tool-scan findings to SBOM packages.

    Assumes the query already joins ``Finding`` and ``Scan``.  When
    *pkg_ids* is empty the function returns ``None`` (no filter needed).
    """
    if not pkg_ids:
        return None
    return db.or_(
        Scan.scan_type.is_(None),
        Scan.scan_type == "sbom",
        Finding.package_id.in_(pkg_ids),
    )


# Formats that are exclusively vulnerability scanners (never pure package BOMs)
_DEDICATED_SCANNER_FORMATS = frozenset({"grype", "yocto_cve_check"})

# Mapping from SBOMDocument.format to the found_by string exposed by the API
_FORMAT_TO_FOUND_BY: dict[str, str] = {
    "grype": "grype",
    "spdx": "spdx3",
    "cdx": "cyclonedx",
    "openvex": "openvex",
}

# Mapping from Scan.scan_source to the found_by string for tool scans
_TOOL_SOURCE_TO_FOUND_BY: dict[str, str] = {
    "nvd": "nvd_cpe",
    "osv": "osv",
}


@dataclasses.dataclass
class _Effort:
    optimistic: int | None
    likely: int | None
    pessimistic: int | None

    def to_dict(self):
        return {
            "optimistic": str(Iso8601Duration(f"PT{self.optimistic}H")) if self.optimistic else None,
            "likely": str(Iso8601Duration(f"PT{self.likely}H")) if self.likely else None,
            "pessimistic": str(Iso8601Duration(f"PT{self.pessimistic}H")) if self.pessimistic else None,
        }


@dataclasses.dataclass
class _ScopedOverrides:
    cvss: list[Metrics]
    effort: _Effort


def _variant_scoped_metrics_and_effort_overrides(
    records: list[Vulnerability], variant_uuid
) -> dict[str, _ScopedOverrides]:
    """Build response-level overrides for variant-scoped metrics/effort.

    Returns a mapping keyed by vulnerability id with:
      - ``cvss``: selected metric dicts (scoped first, legacy fallback)
      - ``effort``: selected effort dict (scoped first, legacy fallback)
    """
    if not records:
        return {}

    vuln_ids = [r.id for r in records]

    metric_rows = db.session.execute(
        db.select(Metrics).where(
            Metrics.vulnerability_id.in_(vuln_ids),
            db.or_(Metrics.variant_id == variant_uuid, Metrics.variant_id.is_(None)),
        )
    ).scalars().all()

    metrics_by_vuln: dict[str, dict[str, list]] = {}
    for m in metric_rows:
        bucket = metrics_by_vuln.setdefault(m.vulnerability_id, {"scoped": [], "fallback": []})
        if m.variant_id == variant_uuid:
            bucket["scoped"].append(m)
        else:
            bucket["fallback"].append(m)

    from ..models.time_estimate import TimeEstimate

    raw_te_rows = db.session.execute(
        db.select(
            Finding.vulnerability_id,
            TimeEstimate.variant_id,
            TimeEstimate.optimistic,
            TimeEstimate.likely,
            TimeEstimate.pessimistic,
        )
        .join(Finding, TimeEstimate.finding_id == Finding.id)
        .where(
            Finding.vulnerability_id.in_(vuln_ids),
            db.or_(TimeEstimate.variant_id == variant_uuid, TimeEstimate.variant_id.is_(None)),
        )
    ).all()

    effort_by_vuln: dict[str, _Effort] = {}
    fallback_effort_by_vuln: dict[str, _Effort] = {}
    for vuln_id, te_variant_id, opti, like, pess in raw_te_rows:
        packed = _Effort(opti, like, pess)
        if te_variant_id == variant_uuid and vuln_id not in effort_by_vuln:
            effort_by_vuln[vuln_id] = packed
        elif te_variant_id is None and vuln_id not in fallback_effort_by_vuln:
            fallback_effort_by_vuln[vuln_id] = packed

    overrides: dict[str, _ScopedOverrides] = {}
    for r in records:
        metric_bucket = metrics_by_vuln.get(r.id, {"scoped": [], "fallback": []})
        selected_metrics = metric_bucket["scoped"] or metric_bucket["fallback"]

        chosen_effort = effort_by_vuln.get(r.id) or fallback_effort_by_vuln.get(r.id)
        overrides[str(r.id)] = _ScopedOverrides(selected_metrics, chosen_effort or _Effort(None, None, None))

    return overrides


def _apply_variant_scoped_overrides_to_vuln_dicts(
    vulns: dict[str, dict], overrides: dict[str, _ScopedOverrides]
) -> None:
    """Apply variant-scoped metrics/effort overrides to serialized vulnerability dicts."""
    if not vulns or not overrides:
        return

    for vuln_id, vuln in vulns.items():
        scoped = overrides.get(str(vuln_id))
        if scoped is None:
            continue
        vuln.setdefault("severity", {})["cvss"] = [m.to_dict() for m in scoped.cvss]
        vuln["effort"] = scoped.effort.to_dict()


def _variant_ids_for_vulnerability(vulnerability_id: str) -> list:
    """Return distinct variant IDs where a vulnerability is observed."""
    rows = db.session.execute(
        db.select(Scan.variant_id)
        .join(Observation, Observation.scan_id == Scan.id)
        .join(Finding, Observation.finding_id == Finding.id)
        .where(Finding.vulnerability_id == vulnerability_id)
        .distinct()
    ).all()
    return [variant_id for (variant_id,) in rows]


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
        scan_source = entry["scan_source"]
        if doc_formats:
            # Prefer non-dedicated (spdx, cdx, openvex) over dedicated (grype, yocto)
            non_dedicated = doc_formats - _DEDICATED_SCANNER_FORMATS
            chosen = non_dedicated if non_dedicated else doc_formats
            for fmt in chosen:
                assert isinstance(fmt, str)
                mapped = _FORMAT_TO_FOUND_BY.get(fmt, fmt)
                found_by_map.setdefault(vuln_id, set()).add(mapped)
        elif scan_source is not None:
            assert isinstance(scan_source, str)
            mapped = _TOOL_SOURCE_TO_FOUND_BY.get(scan_source, scan_source)
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
        variant_scoped_overrides: dict[str, _ScopedOverrides] = {}
        current_scan_ids: list = []
        if variant_id and compare_variant_id:
            base_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            compare_uuid, err = parse_uuid_or_400(compare_variant_id, "compare_variant_id")
            if err:
                return err
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
                _flt = _sbom_pkg_filter(_pkg_ids)
                if _flt is not None:
                    q = q.where(_flt)
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
                        select(Vulnerability)
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
                        select(Vulnerability)
                        .options(*opts)
                        .join(Finding, Vulnerability.id == Finding.vulnerability_id)
                        .join(Observation, Finding.id == Observation.finding_id)
                        .join(Scan, Observation.scan_id == Scan.id)
                        .where(Observation.scan_id.in_(compare_latest_ids))
                    )
                    _flt = _sbom_pkg_filter(compare_pkg_ids)
                    if _flt is not None:
                        query = query.where(_flt)
                    query = query.distinct().order_by(Vulnerability.id)
                    if base_ids:
                        query = query.where(~Vulnerability.id.in_(list(base_ids)))
                    records = list(db.session.execute(query).scalars().all())
            variant_scoped_overrides = _variant_scoped_metrics_and_effort_overrides(records, compare_uuid)
        elif variant_id:
            variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            _scope_variant = variant_uuid
            _scope_project = None
            latest_ids = active_scan_ids_for_variant(variant_uuid)
            current_scan_ids = latest_ids
            if not latest_ids:
                records = []
            else:
                # Filter tool-scan findings to only include packages
                # present in the active SBOM, preventing stale/cross-variant
                # vulns from appearing in the Vulnerability tab.
                _pkg_ids = active_package_ids_for_scans(latest_ids)
                query = (
                    select(Vulnerability)
                    .options(
                        selectinload(Vulnerability.findings).selectinload(Finding.package),
                        selectinload(Vulnerability.findings).selectinload(Finding.time_estimate),
                        selectinload(Vulnerability.metrics),
                    )
                    .join(Finding, Vulnerability.id == Finding.vulnerability_id)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .join(Scan, Observation.scan_id == Scan.id)
                    .where(Observation.scan_id.in_(latest_ids))
                )
                _flt = _sbom_pkg_filter(_pkg_ids)
                if _flt is not None:
                    query = query.where(_flt)
                records = list(db.session.execute(
                    query.distinct().order_by(Vulnerability.id)
                ).scalars().all())
                # Bulk-load packages expanded to all same-name+version supplier variants.
                # to_dict() falls back to findings, but those only contain the directly-linked
                # package (no supplier from Grype). Pre-populate r.packages instead.
                if records:
                    _PkgVariant = aliased(Package)
                    _pkg_var_rows = db.session.execute(
                        db.select(
                            Finding.vulnerability_id, _PkgVariant.name,
                            _PkgVariant.version, _PkgVariant.supplier
                        )
                        .join(Package, Finding.package_id == Package.id)
                        .join(_PkgVariant, (
                            (_PkgVariant.name == Package.name) & (_PkgVariant.version == Package.version)
                        ))
                        .where(Finding.vulnerability_id.in_([r.id for r in records]))
                        .distinct()
                    ).all()
                    _pkgs_by_vuln_var: dict[str, list[str]] = {}
                    for _vid, _pname, _pver, _psup in _pkg_var_rows:
                        _sid = f"{_pname}@{_pver}::{_psup}" if _psup else f"{_pname}@{_pver}"
                        _pkgs_by_vuln_var.setdefault(str(_vid), []).append(_sid)
                    for r in records:
                        r.packages = _pkgs_by_vuln_var.get(str(r.id), [])
                variant_scoped_overrides = _variant_scoped_metrics_and_effort_overrides(records, variant_uuid)
        elif project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            _scope_variant = None
            _scope_project = project_uuid
            latest_ids = active_scan_ids_for_project(project_uuid)
            current_scan_ids = latest_ids
            if not latest_ids:
                records = []
            else:
                from ..models.time_estimate import TimeEstimate

                # Filter tool-scan findings by active SBOM packages
                _pkg_ids = active_package_ids_for_scans(latest_ids)

                # Subquery for vulnerability IDs visible in these scans,
                # used to avoid huge literal IN-lists in secondary queries.
                vuln_ids_base = (
                    db.select(Finding.vulnerability_id)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .join(Scan, Observation.scan_id == Scan.id)
                    .where(Observation.scan_id.in_(latest_ids))
                )
                _flt = _sbom_pkg_filter(_pkg_ids)
                if _flt is not None:
                    vuln_ids_base = vuln_ids_base.where(_flt)
                vuln_ids_subq = vuln_ids_base.distinct().scalar_subquery()

                records = list(db.session.execute(
                    select(Vulnerability)
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

                # Bulk-load packages per vulnerability, expanding to all same-name+version
                # supplier variants so that Grype-linked packages (no supplier) also surface
                # SBOM packages that carry supplier information.
                _PkgVariant = aliased(Package)
                pkg_rows = db.session.execute(
                    db.select(Finding.vulnerability_id, _PkgVariant.name, _PkgVariant.version, _PkgVariant.supplier)
                    .join(Package, Finding.package_id == Package.id)
                    .join(_PkgVariant, (_PkgVariant.name == Package.name) & (_PkgVariant.version == Package.version))
                    .where(Finding.vulnerability_id.in_(vuln_ids_subq))
                    .distinct()
                ).all()
                pkgs_by_vuln: dict[str, list[str]] = {}
                for vid, pname, pver, psup in pkg_rows:
                    sid = f"{pname}@{pver}::{psup}" if psup else f"{pname}@{pver}"
                    pkgs_by_vuln.setdefault(vid, []).append(sid)

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
        vulns = {r.id: r.to_dict() for r in records}
        _apply_variant_scoped_overrides_to_vuln_dicts(vulns, variant_scoped_overrides)
        vuln_ids = vulns.keys()

        if vulns:
            # packages_current: packages from the specific scan(s), expanded to include all
            # same-name+version supplier variants present in the active SBOM scans.
            # This ensures that Grype-linked packages (no supplier) also surface SBOM packages.
            if current_scan_ids:
                _PkgVariant2 = aliased(Package)
                pkg_rows = db.session.execute(
                    db.select(Finding.vulnerability_id, _PkgVariant2.name, _PkgVariant2.version, _PkgVariant2.supplier)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .join(Package, Finding.package_id == Package.id)
                    .join(_PkgVariant2, (_PkgVariant2.name == Package.name) & (_PkgVariant2.version == Package.version))
                    .outerjoin(SBOMPackage, SBOMPackage.package_id == _PkgVariant2.id)
                    .outerjoin(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
                    .where(Observation.scan_id.in_(current_scan_ids))
                    .where(Finding.vulnerability_id.in_(vuln_ids))
                    .where(db.or_(
                        SBOMDocument.scan_id.in_(current_scan_ids),
                        _PkgVariant2.id == Package.id,
                    ))
                    .distinct()
                ).all()
                pkgs_current_by_vuln: dict = {}
                for vuln_id, pkg_name, pkg_version, pkg_sup in pkg_rows:
                    sid = f"{pkg_name}@{pkg_version}::{pkg_sup}" if pkg_sup else f"{pkg_name}@{pkg_version}"
                    pkgs_current_by_vuln.setdefault(str(vuln_id), []).append(sid)
                for v in vulns.values():
                    v["packages_current"] = sorted(pkgs_current_by_vuln.get(v["id"], []))
            else:
                for v in vulns.values():
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
            for vuln_id, vuln in vulns.items():
                vuln["variants"] = sorted(variant_names_by_vuln.get(vuln_id, []))

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
            for vuln_id, vuln in vulns.items():
                vuln["first_scan_date"] = first_scan_by_vuln.get(vuln_id)

        match request.args.get('format', 'list'):
            case "list":
                return list(vulns.values())
            case "dict":
                return vulns
            case _ as fmt:
                raise ValueError("Unknown format", fmt)

    @app.get('/api/vulnerabilities/<id>')
    def get_vuln(id):
        record = Vulnerability.get_by_id(id)
        if not record:
            return "Not found", 404

        variant_id = request.args.get("variant_id")
        response = record.to_dict()
        if variant_id:
            variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            overrides = _variant_scoped_metrics_and_effort_overrides([record], variant_uuid)
            _apply_variant_scoped_overrides_to_vuln_dicts({response["id"]: response}, overrides)
        return response

    @app.patch('/api/vulnerabilities/<id>')
    def patch_vuln(id):
        record = Vulnerability.get_by_id(id)
        if not record:
            return "Not found", 404

        payload_data = request.get_json()
        if payload_data is None:
            return {"error": "Invalid request data"}, 400
        response_variant_id = None
        _updated_effort: dict | None = None

        if "effort" in payload_data:
            eff = payload_data["effort"]
            opt, lik, pes, err = _validate_effort(eff)
            if err:
                return err, 400
            variant_id = payload_data.get("variant_id")
            if variant_id is not None:
                variant_id, err = parse_uuid_or_400(variant_id, "variant_id")
                if err:
                    return err
                target_variant_ids = [variant_id]
            else:
                target_variant_ids = _variant_ids_for_vulnerability(record.id)
                if not target_variant_ids:
                    target_variant_ids = [None]

            for target_variant_id in target_variant_ids:
                _apply_effort(record, target_variant_id, opt, lik, pes,
                              log_prefix=f"PATCH /api/vulnerabilities/{record.id}")

            if len(target_variant_ids) == 1 and target_variant_ids[0] is not None:
                response_variant_id = target_variant_ids[0]
            _updated_effort = {
                "optimistic": str(Iso8601Duration(f"PT{opt}H")),
                "likely": str(Iso8601Duration(f"PT{lik}H")),
                "pessimistic": str(Iso8601Duration(f"PT{pes}H")),
            }

        if "cvss" in payload_data:
            variant_id = payload_data.get("variant_id")
            if variant_id is not None:
                variant_id, err = parse_uuid_or_400(variant_id, "variant_id")
                if err:
                    return err
                target_variant_ids = [variant_id]
            else:
                target_variant_ids = _variant_ids_for_vulnerability(record.id)
                if not target_variant_ids:
                    target_variant_ids = [None]

            if isinstance(payload_data["cvss"], dict):
                payload_data["cvss"].setdefault("origin", "custom")

            for target_variant_id in target_variant_ids:
                cvss_err = _validate_and_apply_cvss(
                    payload_data["cvss"], record.id, target_variant_id,
                    log_prefix=f"PATCH /api/vulnerabilities/{record.id}")
                if cvss_err:
                    return cvss_err, 400

            if len(target_variant_ids) == 1 and target_variant_ids[0] is not None:
                response_variant_id = target_variant_ids[0]
            db.session.expire(record, ['metrics'])

        response = record.to_dict()
        if response_variant_id is not None:
            overrides = _variant_scoped_metrics_and_effort_overrides([record], response_variant_id)
            _apply_variant_scoped_overrides_to_vuln_dicts({response["id"]: response}, overrides)
        if _updated_effort is not None and response_variant_id is None:
            response["effort"] = _updated_effort
        return response

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

            response_variant_id = None
            _updated_effort: dict | None = None

            if "effort" in item:
                eff = item["effort"]
                opt, lik, pes, err = _validate_effort(eff)
                if err:
                    errors.append({"id": item["id"], "error": err})
                    continue
                item_variant_id = item.get("variant_id")
                if item_variant_id is not None:
                    item_variant_id, err = parse_uuid_or_400(item_variant_id, "variant_id")
                    if err:
                        errors.append({"id": item["id"], "error": "Invalid variant_id"})
                        continue
                    target_variant_ids = [item_variant_id]
                else:
                    target_variant_ids = _variant_ids_for_vulnerability(record.id)
                    if not target_variant_ids:
                        target_variant_ids = [None]

                for target_variant_id in target_variant_ids:
                    _apply_effort(record, target_variant_id, opt, lik, pes,
                                  log_prefix=f"PATCH /api/vulnerabilities/batch {item['id']!r}")

                if len(target_variant_ids) == 1 and target_variant_ids[0] is not None:
                    response_variant_id = target_variant_ids[0]
                _updated_effort = {
                    "optimistic": str(Iso8601Duration(f"PT{opt}H")),
                    "likely": str(Iso8601Duration(f"PT{lik}H")),
                    "pessimistic": str(Iso8601Duration(f"PT{pes}H")),
                }

            if "cvss" in item:
                cvss_variant_id = item.get("variant_id")
                if cvss_variant_id is not None:
                    cvss_variant_id, err = parse_uuid_or_400(cvss_variant_id, "variant_id")
                    if err:
                        errors.append({"id": item["id"], "error": "Invalid variant_id"})
                        continue
                    target_variant_ids = [cvss_variant_id]
                else:
                    target_variant_ids = _variant_ids_for_vulnerability(record.id)
                    if not target_variant_ids:
                        target_variant_ids = [None]

                if isinstance(item["cvss"], dict):
                    item["cvss"].setdefault("origin", "custom")

                cvss_failed = False
                for target_variant_id in target_variant_ids:
                    cvss_err = _validate_and_apply_cvss(
                        item["cvss"], record.id, target_variant_id,
                        log_prefix=f"PATCH /api/vulnerabilities/batch {item['id']!r}")
                    if cvss_err:
                        errors.append({"id": item["id"], "error": cvss_err})
                        cvss_failed = True
                        break

                if cvss_failed:
                    continue

                if len(target_variant_ids) == 1 and target_variant_ids[0] is not None:
                    response_variant_id = target_variant_ids[0]
                db.session.expire(record, ['metrics'])

            result_dict = record.to_dict()
            if response_variant_id is not None:
                overrides = _variant_scoped_metrics_and_effort_overrides([record], response_variant_id)
                _apply_variant_scoped_overrides_to_vuln_dicts({result_dict["id"]: result_dict}, overrides)
            if _updated_effort is not None and response_variant_id is None:
                result_dict["effort"] = _updated_effort
            results.append(result_dict)

        response = {
            "status": "success" if results else "error",
            "vulnerabilities": results,
            "count": len(results)
        }
        if errors:
            response["errors"] = errors
            response["error_count"] = len(errors)
        return response, 200 if results else 400

    @app.route('/api/vulnerabilities/<cve_id>/nvd-refresh', methods=['POST'])
    def refresh_single_cve(cve_id):
        cve_id_upper = cve_id.upper()
        rec = db.session.get(Vulnerability, cve_id_upper)
        if rec is None:
            return jsonify({"error": "CVE not found"}), 404

        api_key = os.getenv("NVD_API_KEY")
        try:
            nvd = NVD_DB(nvd_api_key=api_key)
            status_code, data = nvd.api_get_cve(cve_id_upper, max_retries=0)
        except Exception as e:
            return jsonify({
                "error": f"NVD API unavailable: {e}",
                "error_code": "unavailable",
                "api_key_configured": bool(api_key),
            }), 503

        if status_code == 429:
            return jsonify({
                "error": "NVD API rate limit exceeded",
                "error_code": "rate_limited",
                "api_key_configured": bool(api_key),
            }), 429
        if status_code in (401, 403):
            return jsonify({
                "error": f"NVD API rejected credentials (HTTP {status_code})",
                "error_code": "unauthorized",
                "api_key_configured": bool(api_key),
            }), status_code
        if status_code != 200 or not data.get("vulnerabilities"):
            return jsonify({
                "error": "NVD API returned no data for this CVE",
                "error_code": "unavailable",
                "api_key_configured": bool(api_key),
            }), 503

        cve = data["vulnerabilities"][0]["cve"]
        details = NVD_DB.extract_cve_details(cve)
        now = datetime.datetime.now(datetime.timezone.utc)
        apply_nvd_update(rec, details, now)

        # Update CVSS metric record if NVD returned score data
        base_score = details.get("base_score")
        cvss_version = details.get("cvss_version")
        cvss_vector = details.get("cvss_vector")
        if base_score is not None and cvss_version is not None:
            existing = db.session.execute(
                db.select(Metrics).where(
                    Metrics.vulnerability_id == rec.id,
                    Metrics.version == cvss_version,
                )
            ).scalar_one_or_none()
            if existing is not None:
                if float(existing.score or 0) != float(base_score) or existing.vector != cvss_vector:
                    existing.score = base_score
                    existing.vector = cvss_vector or existing.vector
            else:
                db.session.add(Metrics(
                    vulnerability_id=rec.id,
                    version=cvss_version,
                    score=base_score,
                    vector=cvss_vector or "",
                    author="nvd",
                ))

        db.session.commit()

        # After commit, mapped columns are expired but transient attributes
        # still hold pre-update values. Reload mapped columns then re-derive
        # all transient attrs so to_dict() returns fresh data.
        db.session.refresh(rec)
        rec._init_transient()

        # Repopulate transient severity scores from now-committed metrics so
        # to_dict() returns correct min/max without a full controller preload.
        for m in (rec.metrics or []):
            if m.score is not None:
                score = float(m.score)
                if rec.severity_min_score is None or score < rec.severity_min_score:
                    rec.severity_min_score = score
                if rec.severity_max_score is None or score > rec.severity_max_score:
                    rec.severity_max_score = score

        return jsonify({"vulnerabilities": [rec.to_dict()]}), 200

    @app.route('/api/vulnerabilities/<cve_id>/epss-refresh', methods=['POST'])
    def refresh_single_cve_epss(cve_id):
        cve_id_upper = cve_id.upper()
        rec = db.session.get(Vulnerability, cve_id_upper)
        if rec is None:
            return jsonify({"error": "CVE not found"}), 404

        epss_data = EPSS_DB().api_get_epss(cve_id_upper)
        if epss_data is None:
            return jsonify({"error": "EPSS API returned no data for this CVE"}), 503

        now = datetime.datetime.now(datetime.timezone.utc)
        rec.update_record(
            epss_score=epss_data["score"],
            epss_fetched_at=now,
            commit=False,
        )
        db.session.commit()

        db.session.refresh(rec)
        rec._init_transient()
        # Set percentile in transient epss dict (not stored in DB)
        rec.epss["percentile"] = epss_data.get("percentile")

        # Repopulate transient severity scores from committed metrics
        for m in (rec.metrics or []):
            if m.score is not None:
                score = float(m.score)
                if rec.severity_min_score is None or score < rec.severity_min_score:
                    rec.severity_min_score = score
                if rec.severity_max_score is None or score > rec.severity_max_score:
                    rec.severity_max_score = score

        return jsonify({"vulnerabilities": [rec.to_dict()]}), 200

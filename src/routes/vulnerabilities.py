# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import datetime
import decimal
import dataclasses
import typing
import re
import urllib.error
import uuid

from flask import jsonify, request, Flask
from flask.typing import ResponseReturnValue
from sqlalchemy import func, select, ColumnElement
from sqlalchemy.orm import joinedload, selectinload, aliased, attributes as orm_attrs
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
    SBOMObservation,
    Iso8601Duration
)
from ..helpers.datetime_utils import ensure_utc_iso
from ..extensions import db
from ..controllers.scc_engine import get_cve_json
from ..controllers.nvd_db import NVD_DB
from ..controllers.nvd_extract import extract_cve_details
from ..controllers.nvd_apply import apply_nvd_update
from ..controllers.epss_db import EPSS_DB
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.conditions_parser import ConditionParser
from ..helpers.active_scans import (
    active_scan_ids_for_variant,
    active_scan_ids_for_project,
    active_package_ids_for_scans,
)
from ..helpers.vuln_helpers import (
    validate_effort,
    validate_and_apply_cvss,
    apply_effort,
    Effort
)
from ._scan_helpers import parse_uuid_or_400
from ._scan_queries import VulnerabilityText, fetch_vulnerabilities_texts

TIME_ESTIMATES_PATH = "/scan/outputs/time_estimates.json"
MATCH_CONDITION_MAX_LENGTH = 1_000
MATCH_CONDITION_MAX_ITEMS = 50_000
_GHSA_RE = re.compile(r'^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$')


def _attack_vector_from_vector(vector: str) -> str | None:
    """Return the normalized CVSS attack vector used by Explorer filters."""
    for token, label in (
        ("AV:N", "NETWORK"),
        ("AV:A", "ADJACENT"),
        ("AV:L", "LOCAL"),
        ("AV:P", "PHYSICAL"),
    ):
        if token in vector:
            return label
    return None


def _sbom_pkg_filter(pkg_ids: set[uuid.UUID]) -> "ColumnElement[bool] | None":
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


def _vuln_ids_for_scans(scan_ids: list[uuid.UUID]) -> set[str]:
    """Vuln IDs from *scan_ids*, filtering tool scans to active SBOM packages."""
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


# Formats that are exclusively vulnerability scanners (never pure package BOMs)
# Mapping from SBOMDocument.format to the found_by string exposed by the API
_FORMAT_TO_FOUND_BY: dict[str, str] = {
    "grype": "grype",
    "yocto_cve_check": "yocto_cve_check",
    "spdx": "spdx3",
    "cdx": "cyclonedx",
    "openvex": "openvex",
    "yocto_vex": "yocto_vex",
}

# Mapping from Scan.scan_source to the found_by string for tool scans
_TOOL_SOURCE_TO_FOUND_BY: dict[str, str] = {
    "nvd": "nvd_cpe",
    "osv": "osv",
}


def effort_to_dict(effort: Effort) -> dict[typing.Literal["optimistic", "likely", "pessimistic"], str | None]:
    return {
        "optimistic": str(Iso8601Duration(f"PT{effort.optimistic}H")) if effort.optimistic else None,
        "likely": str(Iso8601Duration(f"PT{effort.likely}H")) if effort.likely else None,
        "pessimistic": str(Iso8601Duration(f"PT{effort.pessimistic}H")) if effort.pessimistic else None,
    }


@dataclasses.dataclass
class _ScopedOverrides:
    cvss: list[Metrics]
    effort: Effort


def _variant_scoped_metrics_and_effort_overrides(
    records: list[Vulnerability], variant_uuid: uuid.UUID
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

    effort_by_vuln: dict[str, Effort] = {}
    fallback_effort_by_vuln: dict[str, Effort] = {}
    for vuln_id, te_variant_id, opti, like, pess in raw_te_rows:
        packed = Effort(opti, like, pess)
        if te_variant_id == variant_uuid and vuln_id not in effort_by_vuln:
            effort_by_vuln[vuln_id] = packed
        elif te_variant_id is None and vuln_id not in fallback_effort_by_vuln:
            fallback_effort_by_vuln[vuln_id] = packed

    overrides: dict[str, _ScopedOverrides] = {}
    for r in records:
        metric_bucket = metrics_by_vuln.get(r.id, {"scoped": [], "fallback": []})
        # CVSS is a union: global (scanner, variant_id IS NULL) scores are
        # standard data shown for every variant, plus this variant's own
        # custom scores. Custom scores add to — they don't hide — scanner data.
        selected_metrics = metric_bucket["fallback"] + metric_bucket["scoped"]

        # Effort is a single value per vuln: a variant-scoped estimate overrides
        # the global one, falling back to global when none is set.
        chosen_effort = effort_by_vuln.get(r.id) or fallback_effort_by_vuln.get(r.id)
        overrides[str(r.id)] = _ScopedOverrides(selected_metrics, chosen_effort or Effort(None, None, None))

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
        vuln["effort"] = effort_to_dict(scoped.effort)


def _variant_ids_for_vulnerability(vulnerability_id: str) -> list[uuid.UUID | None]:
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
    records: list[Vulnerability],
    variant_uuid: uuid.UUID | None = None,
    project_uuid: uuid.UUID | None = None,
    active_scan_ids: list[uuid.UUID] | None = None,
) -> None:
    """Populate transient found_by with factual provenance.

    Attribution strategy:
      1) Exact per-file provenance from SBOMObservation -> SBOMDocument.format
      2) Fallback for vulns without an observation-backed format: derive from
         observing scans/documents in scope, without preference heuristics.
    """
    if not records:
        return

    vuln_ids = [r.id for r in records]

    found_by_map: dict[str, set[str]] = {}

    # 1) Exact provenance from existing SBOMObservations.
    provenance_q = (
        db.select(SBOMObservation.vulnerability_id, SBOMDocument.format)
        .join(SBOMDocument, SBOMObservation.sbom_document_id == SBOMDocument.id)
        .where(SBOMObservation.vulnerability_id.in_(vuln_ids))
        .where(SBOMDocument.format.isnot(None))
    )
    if active_scan_ids:
        provenance_q = provenance_q.where(SBOMDocument.scan_id.in_(active_scan_ids))
    provenance_rows = db.session.execute(provenance_q.distinct()).all()

    for vuln_id, doc_format in provenance_rows:
        if not isinstance(doc_format, str):
            continue
        mapped = _FORMAT_TO_FOUND_BY.get(doc_format, doc_format)
        found_by_map.setdefault(vuln_id, set()).add(mapped)

    unresolved_vuln_ids = [vid for vid in vuln_ids if vid not in found_by_map]

    # 2) Fallback: derive from observing scans/documents in scope. Fetch the
    # observation-to-scan rows separately from document metadata: joining
    # every finding observation to every document in its scan creates a very
    # large intermediate result on scans with many findings and documents.
    if unresolved_vuln_ids:
        fallback_q = (
            db.select(
                Finding.vulnerability_id,
                Scan.id.label("scan_id"),
                Scan.scan_source,
            )
            .select_from(Finding)
            .join(Observation, Observation.finding_id == Finding.id)
            .join(Scan, Scan.id == Observation.scan_id)
            .where(Finding.vulnerability_id.in_(unresolved_vuln_ids))
        )
        if active_scan_ids:
            fallback_q = fallback_q.where(Observation.scan_id.in_(active_scan_ids))
        fallback_rows = db.session.execute(fallback_q.distinct()).all()

        fallback_scan_ids = {scan_id for _, scan_id, _ in fallback_rows}
        formats_by_scan: dict[uuid.UUID, set[str]] = {}
        if fallback_scan_ids:
            format_rows = db.session.execute(
                db.select(SBOMDocument.scan_id, SBOMDocument.format)
                .where(
                    SBOMDocument.scan_id.in_(fallback_scan_ids),
                    SBOMDocument.format.isnot(None),
                )
                .distinct()
            ).all()
            for scan_id, doc_format in format_rows:
                if isinstance(doc_format, str):
                    formats_by_scan.setdefault(scan_id, set()).add(doc_format)

        for vuln_id, scan_id, scan_source in fallback_rows:
            doc_formats = formats_by_scan.get(scan_id, set())
            if doc_formats:
                for doc_format in doc_formats:
                    mapped = _FORMAT_TO_FOUND_BY.get(doc_format, doc_format)
                    found_by_map.setdefault(vuln_id, set()).add(mapped)
            elif isinstance(scan_source, str):
                mapped = _TOOL_SOURCE_TO_FOUND_BY.get(scan_source, scan_source)
                found_by_map.setdefault(vuln_id, set()).add(mapped)

    for record in records:
        for scanner in found_by_map.get(record.id, set()):
            record.add_found_by(scanner)


def init_app(app: Flask) -> None:

    if "TIME_ESTIMATES_PATH" not in app.config:
        app.config["TIME_ESTIMATES_PATH"] = TIME_ESTIMATES_PATH

    @app.post('/api/vulnerabilities/match-condition')
    def match_condition() -> ResponseReturnValue:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return {"error": "Request body must be a JSON object"}, 400

        condition = payload.get("condition")
        items = payload.get("items")
        if not isinstance(condition, str) or not condition.strip():
            return {"error": "condition must be a non-empty string"}, 400
        if len(condition) > MATCH_CONDITION_MAX_LENGTH:
            return {"error": f"condition must be at most {MATCH_CONDITION_MAX_LENGTH} characters"}, 400
        if not isinstance(items, list):
            return {"error": "items must be a list"}, 400
        if len(items) > MATCH_CONDITION_MAX_ITEMS:
            return {"error": f"items must contain at most {MATCH_CONDITION_MAX_ITEMS} entries"}, 400

        parser = ConditionParser()
        matching_ids: list[str] = []
        try:
            for item in items:
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("id"), str)
                    or not isinstance(item.get("data"), dict)
                ):
                    return {"error": "Each item must contain a string id and an object data field"}, 400
                if parser.evaluate(condition, item["data"]):
                    matching_ids.append(item["id"])
        except Exception as exc:
            return {"error": f"Invalid match condition: {exc}"}, 400

        return jsonify({"matching_ids": matching_ids})

    @app.route('/api/vulnerabilities')
    def index_vulns() -> ResponseReturnValue:
        """List vulnerabilities with optional variant and project filters.

        Supports single-variant, project-wide, pairwise comparison, and
        multi-variant union or intersection modes.

        OpenAPI:
        query variant_id uuid optional Restrict to a single variant.
        query project_id uuid optional Restrict to a single project.
        query compare_variant_id uuid optional Compare against a second variant.
        query variant_ids string optional Comma-separated list of variant IDs.
        query operation string optional Comparison mode such as difference, intersection, or union.
        query format string optional Response format such as list or dict.
        response 200 JsonObject Vulnerability collection.
        """
        response_format = request.args.get('format', 'list')
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')
        compare_variant_id = request.args.get('compare_variant_id')
        variant_ids = request.args.get('variant_ids')
        variant_scoped_overrides: dict[str, _ScopedOverrides] = {}
        current_scan_ids: list[uuid.UUID] = []
        records: list[Vulnerability] = []
        _scope_variant: uuid.UUID | None = None
        _scope_project: uuid.UUID | None = None
        if variant_id and compare_variant_id:
            base_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if base_uuid is None:
                return {"error": "Internal error"}, 500
            compare_uuid, err = parse_uuid_or_400(compare_variant_id, "compare_variant_id")
            if err:
                return err
            if compare_uuid is None:
                return {"error": "Internal error"}, 500
            base_latest_ids = active_scan_ids_for_variant(base_uuid)
            compare_latest_ids = active_scan_ids_for_variant(compare_uuid)
            current_scan_ids = compare_latest_ids
            _scope_variant = compare_uuid
            _scope_project = None
            opts = (
                selectinload(Vulnerability.findings).selectinload(Finding.package),
                selectinload(Vulnerability.findings).selectinload(Finding.time_estimates),
                selectinload(Vulnerability.metrics),
                joinedload(Vulnerability.refresh),
            )

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
        elif variant_ids:
            # Multi-variant mode: union or intersection of the vulnerabilities
            # present in two or more selected variants.
            raw_ids = [s.strip() for s in variant_ids.split(',') if s.strip()]
            parsed_uuids: list[uuid.UUID] = []
            for raw_id in raw_ids:
                parsed, err = parse_uuid_or_400(raw_id, "variant_ids")
                if err:
                    return err
                if parsed is None:
                    return {"error": "Internal error"}, 500
                parsed_uuids.append(parsed)
            operation = request.args.get('operation', 'union')
            _scope_variant = None
            _scope_project = None
            opts = (
                selectinload(Vulnerability.findings).selectinload(Finding.package),
                selectinload(Vulnerability.findings).selectinload(Finding.time_estimates),
                selectinload(Vulnerability.metrics),
                joinedload(Vulnerability.refresh),
            )
            per_variant_scan_ids = {u: active_scan_ids_for_variant(u) for u in parsed_uuids}
            current_scan_ids = []
            for _ids in per_variant_scan_ids.values():
                current_scan_ids.extend(_ids)
            id_sets = [_vuln_ids_for_scans(per_variant_scan_ids[u]) for u in parsed_uuids]
            if not id_sets:
                result_ids: list = []
            elif operation == 'intersection':
                result_ids = list(set.intersection(*id_sets))
            else:  # union (default)
                result_ids = list(set.union(*id_sets))
            records = list(db.session.execute(
                select(Vulnerability)
                .options(*opts)
                .where(Vulnerability.id.in_(result_ids))
                .order_by(Vulnerability.id)
            ).scalars().all()) if result_ids else []
        elif variant_id:
            variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if variant_uuid is None:
                return {"error": "Internal error"}, 500
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
                        selectinload(Vulnerability.findings).selectinload(Finding.time_estimates),
                        selectinload(Vulnerability.metrics),
                        joinedload(Vulnerability.refresh),
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
                    _affx_q = (
                        db.select(
                            Finding.vulnerability_id, _PkgVariant.name,
                            _PkgVariant.version, _PkgVariant.supplier
                        )
                        .join(Package, Finding.package_id == Package.id)
                        .join(_PkgVariant, (
                            (_PkgVariant.name == Package.name) & (_PkgVariant.version == Package.version)
                        ))
                        .outerjoin(SBOMPackage, SBOMPackage.package_id == _PkgVariant.id)
                        .outerjoin(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
                        .where(Finding.vulnerability_id.in_([r.id for r in records]))
                        .where(db.or_(
                            SBOMDocument.scan_id.in_(latest_ids),
                            _PkgVariant.id == Package.id,
                        ))
                        .distinct()
                    )
                    if _pkg_ids:
                        _affx_q = _affx_q.where(Finding.package_id.in_(_pkg_ids))
                    _pkg_var_rows = db.session.execute(_affx_q).all()
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
            if project_uuid is None:
                return {"error": "Internal error"}, 500
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
                    .options(joinedload(Vulnerability.refresh))
                    .where(Vulnerability.id.in_(vuln_ids_subq))
                    .order_by(Vulnerability.id)
                ).scalars().all())

                # Variants that belong to this project — used to scope custom
                # CVSS/effort so overrides from other projects don't leak in.
                # Standard (scanner) metrics live globally (variant_id IS NULL)
                # and are shown for every project.
                project_variant_ids = [v.id for v in Variant.get_by_project(project_uuid)]
                if project_variant_ids:
                    _metric_var_filter = db.or_(
                        Metrics.variant_id.in_(project_variant_ids),
                        Metrics.variant_id.is_(None),
                    )
                else:
                    _metric_var_filter = Metrics.variant_id.is_(None)

                # Bulk-load metrics per vulnerability: global scanner rows plus
                # this project's custom rows.
                metric_rows = db.session.execute(
                    db.select(Metrics)
                    .where(Metrics.vulnerability_id.in_(vuln_ids_subq), _metric_var_filter)
                ).scalars().all()
                _global_metrics: dict[str, list] = {}
                _custom_metrics: dict[str, list] = {}
                _custom_metric_keys: dict[str, set] = {}
                for m in metric_rows:
                    if m.variant_id is not None:
                        # Keep one custom metric per variant so each variant's
                        # score gets its own gauge, while still collapsing exact
                        # duplicates within the same variant.
                        key = (
                            m.variant_id,
                            m.version,
                            float(m.score) if m.score is not None else None,
                            m.vector,
                            m.author,
                            m.origin,
                        )
                        seen = _custom_metric_keys.setdefault(m.vulnerability_id, set())
                        if key in seen:
                            continue
                        seen.add(key)
                        _custom_metrics.setdefault(m.vulnerability_id, []).append(m)
                    else:
                        _global_metrics.setdefault(m.vulnerability_id, []).append(m)
                # Union: global scanner data + project custom overrides.
                metrics_by_vuln: dict[str, list] = {}
                for vid in set(_global_metrics) | set(_custom_metrics):
                    metrics_by_vuln[vid] = _global_metrics.get(vid, []) + _custom_metrics.get(vid, [])

                # Bulk-load packages per vulnerability, expanding to all same-name+version
                # supplier variants so that Grype-linked packages (no supplier) also surface
                # SBOM packages that carry supplier information.
                _PkgVariant = aliased(Package)
                _pkg_q = (
                    db.select(Finding.vulnerability_id, _PkgVariant.name, _PkgVariant.version, _PkgVariant.supplier)
                    .join(Package, Finding.package_id == Package.id)
                    .join(_PkgVariant, (_PkgVariant.name == Package.name) & (_PkgVariant.version == Package.version))
                    .outerjoin(SBOMPackage, SBOMPackage.package_id == _PkgVariant.id)
                    .outerjoin(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
                    .where(Finding.vulnerability_id.in_(vuln_ids_subq))
                    .where(db.or_(
                        SBOMDocument.scan_id.in_(latest_ids),
                        _PkgVariant.id == Package.id,
                    ))
                    .distinct()
                )
                if _pkg_ids:
                    _pkg_q = _pkg_q.where(Finding.package_id.in_(_pkg_ids))
                pkg_rows = db.session.execute(_pkg_q).all()
                pkgs_by_vuln: dict[str, list[str]] = {}
                for vid, pname, pver, psup in pkg_rows:
                    sid = f"{pname}@{pver}::{psup}" if psup else f"{pname}@{pver}"
                    pkgs_by_vuln.setdefault(vid, []).append(sid)

                # Bulk-load effort (time estimates) per vulnerability, scoped to
                # this project's variants (plus global NULL rows). Project-scoped
                # estimates take precedence over global ones.
                if project_variant_ids:
                    _te_var_filter = db.or_(
                        TimeEstimate.variant_id.in_(project_variant_ids),
                        TimeEstimate.variant_id.is_(None),
                    )
                else:
                    _te_var_filter = TimeEstimate.variant_id.is_(None)
                te_rows = db.session.execute(
                    db.select(
                        Finding.vulnerability_id,
                        TimeEstimate.variant_id,
                        TimeEstimate.optimistic,
                        TimeEstimate.likely,
                        TimeEstimate.pessimistic,
                    )
                    .join(Finding, TimeEstimate.finding_id == Finding.id)
                    .where(Finding.vulnerability_id.in_(vuln_ids_subq), _te_var_filter)
                ).all()
                effort_by_vuln: dict[str, tuple] = {}
                _fallback_effort_by_vuln: dict[str, tuple] = {}
                for vid, te_variant_id, opti, like, pess in te_rows:
                    if te_variant_id is not None:
                        if vid not in effort_by_vuln:
                            effort_by_vuln[vid] = (opti, like, pess)
                    elif vid not in _fallback_effort_by_vuln:
                        _fallback_effort_by_vuln[vid] = (opti, like, pess)
                for vid, fallback in _fallback_effort_by_vuln.items():
                    if vid not in effort_by_vuln:
                        effort_by_vuln[vid] = fallback

                # Pre-populate transient fields so to_dict() won't lazy-load findings
                for r in records:
                    r.packages = pkgs_by_vuln.get(r.id, [])
                    te = effort_by_vuln.get(r.id)
                    if te:
                        opti, like, pess = te

                        def _h(v: int | None) -> Iso8601Duration | None:
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
        # The frontend consumes the richer ``texts`` field and never reads the
        # legacy top-level description.  Omitting this duplicate from the list
        # response saves substantial transfer and JSON parsing on large scans;
        # the single-vulnerability endpoint still returns the complete record.
        for vuln in vulns.values():
            vuln.pop("description", None)
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
                    all_variant_ids: list[uuid.UUID] = [
                        vid for (vid,) in db.session.execute(
                            db.select(Variant.id)
                        ).all()
                    ]
                    active_scan_ids = []
                    for variant_uuid_item in all_variant_ids:
                        active_scan_ids.extend(active_scan_ids_for_variant(variant_uuid_item))
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

            # Descriptions are only needed by the detail modal.  The compact
            # Explorer response deliberately skips this relatively expensive
            # query and lets the single-vulnerability endpoint load them when
            # a row is opened.
            if response_format != "compact":
                all_vuln_texts = fetch_vulnerabilities_texts(
                    vuln_ids,
                    include_packages=True,
                    scan_ids=active_scan_ids,
                )
                for vuln_id, vuln_texts in all_vuln_texts.items():
                    vuln = vulns[vuln_id]
                    vuln["texts"] = list(map(VulnerabilityText.to_dict, vuln_texts))

        match response_format:
            case "list":
                return list(vulns.values())
            case "compact":
                for vuln in vulns.values():
                    vuln.pop("texts", None)
                    vuln.pop("urls", None)
                    vuln["details_loaded"] = False
                    cvss_entries = vuln.get("severity", {}).get("cvss", [])
                    vuln["severity"]["cvss"] = [
                        {
                            "version": cvss.get("version", ""),
                            "base_score": cvss.get("base_score", 0.0),
                            "attack_vector": _attack_vector_from_vector(
                                cvss.get("vector_string", "")
                            ),
                        }
                        for cvss in cvss_entries
                    ]
                return list(vulns.values())
            case "dict":
                return vulns
            case _ as fmt:
                raise ValueError("Unknown format", fmt)

    @app.post('/api/vulnerabilities/search-descriptions')
    def search_vulnerability_descriptions() -> ResponseReturnValue:
        """Return vulnerability IDs whose scoped descriptions contain each term."""
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return {"error": "Expected a JSON object"}, 400

        raw_vuln_ids = payload.get("vulnerability_ids")
        raw_terms = payload.get("terms")
        if not isinstance(raw_vuln_ids, list) or not all(
            isinstance(vuln_id, str) for vuln_id in raw_vuln_ids
        ):
            return {"error": "vulnerability_ids must be a list of strings"}, 400
        if not isinstance(raw_terms, list) or not all(
            isinstance(term, str) for term in raw_terms
        ):
            return {"error": "terms must be a list of strings"}, 400
        if len(raw_vuln_ids) > 100_000:
            return {"error": "Too many vulnerability IDs"}, 400
        if len(raw_terms) > 50 or any(len(term) > 256 for term in raw_terms):
            return {"error": "Too many or excessively long search terms"}, 400

        vuln_ids = list(dict.fromkeys(raw_vuln_ids))
        terms = list(dict.fromkeys(term.casefold() for term in raw_terms if term))
        matches: dict[str, set[str]] = {term: set() for term in terms}
        if not vuln_ids or not terms:
            return {"matches": {term: [] for term in terms}}

        scan_ids: list[uuid.UUID] | None = None
        variant_id = request.args.get("variant_id")
        project_id = request.args.get("project_id")
        if variant_id:
            variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if variant_uuid is None:
                return {"error": "Internal error"}, 500
            scan_ids = active_scan_ids_for_variant(variant_uuid)
        elif project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if project_uuid is None:
                return {"error": "Internal error"}, 500
            scan_ids = active_scan_ids_for_project(project_uuid)

        description_rows = db.session.execute(
            db.select(Vulnerability.id, Vulnerability.description)
            .where(Vulnerability.id.in_(vuln_ids))
            .where(Vulnerability.description.is_not(None))
        ).all()

        observation_query = (
            db.select(SBOMObservation.vulnerability_id, SBOMObservation.description)
            .where(SBOMObservation.vulnerability_id.in_(vuln_ids))
        )
        if scan_ids is not None:
            observation_query = (
                observation_query
                .join(SBOMDocument, SBOMObservation.sbom_document_id == SBOMDocument.id)
                .where(SBOMDocument.scan_id.in_(scan_ids))
            )
        observation_rows = db.session.execute(observation_query).all()

        for vuln_id, content in (*description_rows, *observation_rows):
            if not isinstance(content, str):
                continue
            folded_content = content.casefold()
            for term in terms:
                if term in folded_content:
                    matches[term].add(str(vuln_id))

        return {
            "matches": {
                term: sorted(matched_ids)
                for term, matched_ids in matches.items()
            }
        }

    @app.get('/api/vulnerabilities/<id>')
    def get_vuln(id: str) -> ResponseReturnValue:
        """Return a single vulnerability.

        OpenAPI:
        query variant_id uuid optional Apply variant-scoped CVSS and effort overrides.
        response 200 JsonObject Vulnerability payload.
        response 404 Error Vulnerability not found.
        """
        record = Vulnerability.get_by_id(id)
        if not record:
            return "Not found", 404

        variant_id = request.args.get("variant_id")
        project_id = request.args.get("project_id")
        response = record.to_dict()
        text_variant_ids: list[uuid.UUID] | None = None
        if variant_id:
            variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if variant_uuid is None:
                return {"error": "Internal error"}, 500
            overrides = _variant_scoped_metrics_and_effort_overrides([record], variant_uuid)
            _apply_variant_scoped_overrides_to_vuln_dicts({response["id"]: response}, overrides)
            text_variant_ids = [variant_uuid]
        elif project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if project_uuid is None:
                return {"error": "Internal error"}, 500
            text_variant_ids = [v.id for v in Variant.get_by_project(project_uuid)]
            metric_filter = Metrics.variant_id.is_(None)
            if text_variant_ids:
                metric_filter = db.or_(
                    Metrics.variant_id.in_(text_variant_ids),
                    Metrics.variant_id.is_(None),
                )
            scoped_metrics = db.session.execute(
                db.select(Metrics).where(
                    Metrics.vulnerability_id == record.id,
                    metric_filter,
                )
            ).scalars().all()
            response.setdefault("severity", {})["cvss"] = [
                metric.to_dict() for metric in scoped_metrics
            ]
        else:
            variant_uuid = None

        vuln_texts = fetch_vulnerabilities_texts(
            [id],
            variant_ids=text_variant_ids,
            include_packages=True,
        )
        response["texts"] = list(map(VulnerabilityText.to_dict, vuln_texts[id]))

        return response

    @app.get('/api/vulnerabilities/<id>/variant-snapshots')
    def get_vuln_variant_snapshots(id: str) -> ResponseReturnValue:
        """Return variant-scoped effort and custom CVSS for every variant that
        observes this vulnerability, in a single response.

        Replaces the previous per-variant N+1 fetch performed by the modal.

        OpenAPI:
        query project_id uuid optional Restrict snapshots to variants from one project.
        response 200 JsonObject Variant-scoped vulnerability snapshots.
        response 404 Error Vulnerability not found.
        """
        record = Vulnerability.get_by_id(id)
        if not record:
            return "Not found", 404

        variant_uuids = _variant_ids_for_vulnerability(record.id)

        project_id = request.args.get("project_id")
        if project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            allowed = set(db.session.execute(
                db.select(Variant.id).where(Variant.project_id == project_uuid)
            ).scalars().all())
            variant_uuids = [v for v in variant_uuids if v in allowed]

        snapshots: list[dict] = []
        for variant_uuid in variant_uuids:
            if variant_uuid is None:
                continue
            overrides = _variant_scoped_metrics_and_effort_overrides([record], variant_uuid)
            scoped = overrides.get(str(record.id))
            if scoped is None:
                continue
            custom_cvss = [
                m.to_dict() for m in scoped.cvss
                if (m.origin or "scanner") == "custom"
            ]
            snapshots.append({
                "variant_id": str(variant_uuid),
                "effort": effort_to_dict(scoped.effort),
                "custom_cvss": custom_cvss,
            })

        return jsonify(snapshots)

    @app.patch('/api/vulnerabilities/<id>')
    def patch_vuln(id: str) -> ResponseReturnValue:
        """Update variant-scoped effort or custom CVSS data for a vulnerability.

        OpenAPI:
        body JsonObject optional Vulnerability update payload.
        response 200 JsonObject Updated vulnerability payload.
        response 400 Error Invalid update payload.
        response 404 Error Vulnerability not found.
        """
        record = Vulnerability.get_by_id(id)
        if not record:
            return "Not found", 404

        payload_data = request.get_json()
        if payload_data is None:
            return {"error": "Invalid request data"}, 400
        response_variant_id: uuid.UUID | None = None
        _updated_effort: Effort | None = None

        if "effort" in payload_data:
            eff = payload_data["effort"]
            _updated_effort, err = validate_effort(eff)
            if err:
                return err, 400
            if _updated_effort is None:
                return {"error": "Internal error"}, 500

            variant_id = payload_data.get("variant_id")
            if variant_id is not None:
                variant_uuid, uuid_err = parse_uuid_or_400(variant_id, "variant_id")
                if uuid_err:
                    return uuid_err
                if variant_uuid is None:
                    return {"error": "Internal error"}, 500
                target_variant_ids: list[uuid.UUID | None] = [variant_uuid]
            else:
                target_variant_ids = _variant_ids_for_vulnerability(record.id)
                if not target_variant_ids:
                    target_variant_ids = [None]

            for target_variant_id in target_variant_ids:
                apply_effort(
                    record,
                    target_variant_id,
                    _updated_effort,
                    log_prefix=f"PATCH /api/vulnerabilities/{record.id}",
                )

            if len(target_variant_ids) == 1 and target_variant_ids[0] is not None:
                response_variant_id = target_variant_ids[0]

        if "cvss" in payload_data:
            variant_id = payload_data.get("variant_id")
            if variant_id is not None:
                variant_uuid, uuid_err = parse_uuid_or_400(variant_id, "variant_id")
                if uuid_err:
                    return uuid_err
                if variant_uuid is None:
                    return {"error": "Internal error"}, 500
                target_variant_ids = [variant_uuid]
            else:
                target_variant_ids = _variant_ids_for_vulnerability(record.id)
                if not target_variant_ids:
                    target_variant_ids = [None]

            if isinstance(payload_data["cvss"], dict):
                payload_data["cvss"].setdefault("origin", "custom")

            for target_variant_id in target_variant_ids:
                cvss_err = validate_and_apply_cvss(
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
            response["effort"] = effort_to_dict(_updated_effort)
        return response

    @app.route('/api/vulnerabilities/batch', methods=['PATCH'])
    def update_vulns_batch() -> ResponseReturnValue:
        """Update multiple vulnerabilities in a single request.

        OpenAPI:
        body JsonObject optional Batch vulnerability update payload.
        response 200 JsonObject Batch update summary.
        response 400 Error Invalid batch payload.
        """
        payload_data = request.get_json()
        if (not payload_data
                or "vulnerabilities" not in payload_data
                or not isinstance(payload_data["vulnerabilities"], list)):
            return {"error": "Invalid request data. Expected: {vulnerabilities: [...]}"}, 400

        results: list[dict] = []
        errors: list[dict] = []

        for item in payload_data["vulnerabilities"]:
            if not isinstance(item, dict) or "id" not in item:
                errors.append({"error": "Invalid vulnerability data", "item": item})
                continue

            record = Vulnerability.get_by_id(item["id"])
            if not record:
                errors.append({"id": item["id"], "error": "Vulnerability not found"})
                continue

            response_variant_id: uuid.UUID | None = None
            _updated_effort: Effort | None = None

            if "effort" in item:
                eff = item["effort"]
                _updated_effort, err = validate_effort(eff)
                if err:
                    errors.append({"id": item["id"], "error": err})
                    continue
                if _updated_effort is None:
                    errors.append({"id": item["id"], "error": "Internal error"})
                    continue
                item_variant_id = item.get("variant_id")
                if item_variant_id is not None:
                    item_variant_uuid, uuid_err = parse_uuid_or_400(item_variant_id, "variant_id")
                    if uuid_err:
                        errors.append({"id": item["id"], "error": "Invalid variant_id"})
                        continue
                    if item_variant_uuid is None:
                        errors.append({"id": item["id"], "error": "Internal error"})
                        continue
                    target_variant_ids: list[uuid.UUID | None] = [item_variant_uuid]
                else:
                    target_variant_ids = _variant_ids_for_vulnerability(record.id)
                    if not target_variant_ids:
                        target_variant_ids = [None]

                for target_variant_id in target_variant_ids:
                    apply_effort(
                        record,
                        target_variant_id,
                        _updated_effort,
                        log_prefix=f"PATCH /api/vulnerabilities/batch {item['id']!r}",
                    )

                if len(target_variant_ids) == 1 and target_variant_ids[0] is not None:
                    response_variant_id = target_variant_ids[0]

            if "cvss" in item:
                cvss_variant_id = item.get("variant_id")
                if cvss_variant_id is not None:
                    cvss_variant_uuid, uuid_err = parse_uuid_or_400(cvss_variant_id, "variant_id")
                    if uuid_err:
                        errors.append({"id": item["id"], "error": "Invalid variant_id"})
                        continue
                    if cvss_variant_uuid is None:
                        errors.append({"id": item["id"], "error": "Internal error"})
                        continue
                    target_variant_ids = [cvss_variant_uuid]
                else:
                    target_variant_ids = _variant_ids_for_vulnerability(record.id)
                    if not target_variant_ids:
                        target_variant_ids = [None]

                if isinstance(item["cvss"], dict):
                    item["cvss"].setdefault("origin", "custom")

                cvss_failed = False
                for target_variant_id in target_variant_ids:
                    cvss_err = validate_and_apply_cvss(
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
                result_dict["effort"] = effort_to_dict(_updated_effort)
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
    def refresh_single_cve(cve_id: str) -> ResponseReturnValue:
        """Refresh NVD data for a single CVE.

        OpenAPI:
        body JsonObject optional Request body containing mode: local or api.
        response 200 JsonObject Refreshed vulnerability payload.
        response 404 Error CVE not found.
        response 429 Error NVD API rate limit exceeded.
        response 503 Error NVD data source unavailable.
        """
        cve_id_upper = cve_id.upper()
        rec = db.session.get(Vulnerability, cve_id_upper)
        if rec is None:
            return jsonify({"error": "CVE not found"}), 404

        body = request.get_json(force=True, silent=True) or {}
        mode = body.get("mode", "local")  # "local" (default) or "api"

        if mode == "api":
            import os as _os
            api_key = _os.getenv("NVD_API_KEY")
            api_key_configured = bool(api_key)
            try:
                nvd = NVD_DB(nvd_api_key=api_key)
                status_code, data_api = nvd.api_get_cve(cve_id_upper, max_retries=0)
            except Exception as e:
                return jsonify({
                    "error": f"NVD API unavailable: {e}",
                    "error_code": "unavailable",
                    "api_key_configured": api_key_configured,
                }), 503
            if status_code == 429:
                return jsonify({
                    "error": "NVD API rate limit exceeded",
                    "error_code": "rate_limited",
                    "api_key_configured": api_key_configured,
                }), 429
            if status_code in (401, 403):
                return jsonify({
                    "error": f"NVD API rejected credentials (HTTP {status_code})",
                    "error_code": "unauthorized",
                    "api_key_configured": api_key_configured,
                }), status_code
            if status_code != 200 or not data_api.get("vulnerabilities"):
                return jsonify({
                    "error": "NVD API returned no data for this CVE",
                    "error_code": "unavailable",
                    "api_key_configured": api_key_configured,
                }), 503
            cve_obj = data_api["vulnerabilities"][0]["cve"]
            details = NVD_DB.extract_cve_details(cve_obj)
        else:
            cve_obj = get_cve_json(cve_id_upper)
            if cve_obj is None:
                return jsonify({
                    "error": "CVE not found in local NVD database",
                    "error_code": "unavailable",
                }), 503
            details = extract_cve_details(cve_obj)
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
                    Metrics.variant_id.is_(None),
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

        data = rec.to_dict()

        # Note: we don't have "variant" information here so we fetch all texts.
        # This can be incoherent.
        vuln_texts = fetch_vulnerabilities_texts([cve_id_upper], variant_ids=None)
        data["texts"] = list(map(VulnerabilityText.to_dict, vuln_texts[cve_id_upper]))

        return jsonify({"vulnerabilities": [data]}), 200

    @app.route('/api/vulnerabilities/<cve_id>/epss-refresh', methods=['POST'])
    def refresh_single_cve_epss(cve_id: str) -> ResponseReturnValue:
        """Refresh EPSS data for a single CVE.

        OpenAPI:
        response 200 JsonObject Refreshed vulnerability payload.
        response 404 Error CVE not found.
        response 503 Error EPSS data source unavailable.
        """
        cve_id_upper = cve_id.upper()
        rec = db.session.get(Vulnerability, cve_id_upper)
        if rec is None:
            return jsonify({"error": "CVE not found"}), 404

        epss_data = EPSS_DB().api_get_epss(cve_id_upper)
        if epss_data is None:
            return jsonify({"error": "EPSS API returned no data for this CVE"}), 503

        now = datetime.datetime.now(datetime.timezone.utc)
        new_score = decimal.Decimal(str(epss_data["score"]))
        update_kwargs: dict = {"epss_score": new_score, "epss_fetched_at": now, "commit": False}
        if rec.epss_score is None or rec.epss_score != new_score:
            update_kwargs["epss_data_updated_at"] = now
        rec.update_record(**update_kwargs)
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

    @app.route('/api/vulnerabilities/<ghsa_id>/ghsa-refresh', methods=['POST'])
    def refresh_single_ghsa(ghsa_id: str) -> ResponseReturnValue:
        """Refresh GitHub advisory metadata for a single GHSA identifier.

        OpenAPI:
        response 200 JsonObject Refreshed vulnerability payload.
        response 400 Error Invalid GHSA identifier.
        response 404 Error GHSA advisory not found.
        response 502 Error Upstream GitHub advisory error.
        response 503 Error GitHub advisory data source unavailable.
        """
        ghsa_id_upper = ghsa_id.upper()
        if not _GHSA_RE.match(ghsa_id_upper):
            return jsonify({"error": "Only valid GHSA identifiers (GHSA-xxxx-xxxx-xxxx) are supported"}), 400
        rec = db.session.get(Vulnerability, ghsa_id_upper)
        if rec is None:
            return jsonify({"error": "GHSA advisory not found"}), 404

        try:
            published_at = VulnerabilitiesController._fetch_ghsa_published(ghsa_id_upper)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return jsonify({"error": "Advisory not found in GitHub Advisory Database"}), 404
            return jsonify({"error": f"GitHub Advisory Database returned HTTP {e.code}"}), 502
        except urllib.error.URLError:
            return jsonify({"error": "Failed to reach GitHub Advisory Database"}), 503
        if published_at is None:
            return jsonify({"error": "GitHub Advisory Database returned no published date"}), 503

        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            publish_date = datetime.date.fromisoformat(published_at[:10])
        except (ValueError, AttributeError):
            return jsonify({"error": "GitHub Advisory Database returned an unparseable date"}), 503
        update_kwargs: dict = {
            "publish_date": publish_date,
            "ghsa_fetched_at": now,
            "commit": False,
        }
        if rec.publish_date != publish_date:
            update_kwargs["ghsa_data_updated_at"] = now
        rec.update_record(**update_kwargs)
        db.session.commit()

        db.session.refresh(rec)
        rec._init_transient()

        for m in (rec.metrics or []):
            if m.score is not None:
                score = float(m.score)
                if rec.severity_min_score is None or score < rec.severity_min_score:
                    rec.severity_min_score = score
                if rec.severity_max_score is None or score > rec.severity_max_score:
                    rec.severity_max_score = score

        data = rec.to_dict()
        vuln_texts = fetch_vulnerabilities_texts([ghsa_id_upper], variant_ids=None)
        data["texts"] = list(map(VulnerabilityText.to_dict, vuln_texts[ghsa_id_upper]))

        return jsonify({"vulnerabilities": [data]}), 200

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
from ..models.assessment import Assessment as DBAssessment, STATUS_TO_SIMPLIFIED as _S2S
from ..models.time_estimate import TimeEstimate
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


def _sql_compute_facets_global() -> dict:
    """Compute facets for the unscoped vulnerability listing via SQL aggregations.

    Avoids hydrating the full vuln set; used by the paginated fast path.
    Set members match what _compute_facets() would produce when no client
    filters are applied, except ``sources`` which is approximated from the
    same SBOMDocument.format mapping used by _populate_found_by().
    """
    severities: set[str] = set()
    # Severity is computed from the max metrics.score per vuln, bucketed
    # the same way CVSS.severity() does. Match the lowercase labels that
    # _populate_facets() would have produced from to_dict() output.
    max_score_rows = db.session.execute(
        db.select(func.max(Metrics.score))
        .where(Metrics.score.isnot(None))
        .group_by(Metrics.vulnerability_id)
    ).all()
    for (s,) in max_score_rows:
        if s is None:
            continue
        sf = float(s)
        if sf < 4:
            severities.add("low")
        elif sf < 7:
            severities.add("medium")
        elif sf < 9:
            severities.add("high")
        else:
            severities.add("critical")
    # Vulns without any metrics fall back to status/"unknown"
    has_no_metrics = db.session.execute(
        db.select(Vulnerability.id)
        .outerjoin(Metrics, Vulnerability.id == Metrics.vulnerability_id)
        .where(Metrics.id.is_(None))
        .limit(1)
    ).first() is not None
    if has_no_metrics:
        severities.add("unknown")

    statuses = {
        s for (s,) in db.session.execute(
            db.select(DBAssessment.simplified_status)
            .where(DBAssessment.simplified_status.isnot(None))
            .distinct()
        ).all() if s
    }
    has_unassessed = db.session.execute(
        db.select(Vulnerability.id)
        .outerjoin(Finding, Vulnerability.id == Finding.vulnerability_id)
        .outerjoin(DBAssessment, DBAssessment.finding_id == Finding.id)
        .where(DBAssessment.id.is_(None))
        .limit(1)
    ).first() is not None
    if has_unassessed:
        statuses.add("Pending Assessment")

    formats = {
        f for (f,) in db.session.execute(
            db.select(SBOMDocument.format)
            .where(SBOMDocument.format.isnot(None))
            .distinct()
        ).all() if f
    }
    sources = {_FORMAT_TO_FOUND_BY.get(f, f) for f in formats}

    attack_vectors: set[str] = set()
    av_rows = db.session.execute(
        db.select(Metrics.vector).where(Metrics.vector.isnot(None)).distinct()
    ).all()
    _AV_MAP = {"AV:N": "NETWORK", "AV:A": "ADJACENT", "AV:L": "LOCAL", "AV:P": "PHYSICAL"}
    for (vec,) in av_rows:
        if not vec:
            continue
        for token, label in _AV_MAP.items():
            if token in vec:
                attack_vectors.add(label)

    first_scan_ts: set[int] = set()
    rows = db.session.execute(
        db.select(func.min(Scan.timestamp))
        .select_from(Finding)
        .join(Observation, Finding.id == Observation.finding_id)
        .join(Scan, Observation.scan_id == Scan.id)
        .group_by(Finding.vulnerability_id)
    ).all()
    for (min_ts,) in rows:
        if min_ts is not None:
            first_scan_ts.add(int(round(min_ts.timestamp())) * 1000)

    return {
        "severities": sorted(severities),
        "statuses": sorted(statuses),
        "sources": sorted(sources),
        "attack_vectors": sorted(attack_vectors),
        "first_scan_dates": sorted(first_scan_ts),
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
            .where(Finding.vulnerability_id.in_(vuln_ids))
        )
    elif project_uuid is not None:
        base_query = (
            base_query
            .join(Scan, Scan.id == SBOMDocument.scan_id)
            .join(Variant, Variant.id == Scan.variant_id)
            .where(Variant.project_id == project_uuid)
            .where(Finding.vulnerability_id.in_(vuln_ids))
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


# ---- Server-side pagination, sorting & filtering helpers ----

_SEVERITY_SORT_ORDER = ['none', 'unknown', 'low', 'medium', 'high', 'critical']
_STATUS_SORT_ORDER = ['unknown', 'Pending Assessment', 'Exploitable', 'Not affected', 'Fixed']
_AV_SORT_ORDER = [None, 'PHYSICAL', 'LOCAL', 'ADJACENT', 'NETWORK']


def _compute_facets(vulns: list[dict]) -> dict:
    """Compute filter-option metadata from the *full* (unfiltered) enriched list."""
    severities: set[str] = set()
    statuses: set[str] = set()
    sources: set[str] = set()
    attack_vectors: set[str] = set()
    first_scan_ts: set[int] = set()
    for v in vulns:
        sev = (v.get("severity") or {}).get("severity")
        if sev:
            severities.add(sev)
        st = v.get("simplified_status")
        if st:
            statuses.add(st)
        for s in (v.get("found_by") or []):
            if s:
                sources.add(s)
        for cvss in (v.get("severity") or {}).get("cvss", []):
            av = cvss.get("attack_vector")
            if av:
                attack_vectors.add(av)
        fsd = v.get("first_scan_date")
        if fsd:
            try:
                import datetime as _dt
                ts = int(round(_dt.datetime.fromisoformat(fsd).timestamp())) * 1000
                first_scan_ts.add(ts)
            except (ValueError, TypeError):
                pass
    return {
        "severities": sorted(severities),
        "statuses": sorted(statuses),
        "sources": sorted(sources),
        "attack_vectors": sorted(attack_vectors),
        "first_scan_dates": sorted(first_scan_ts),
    }


def _matches_search(vuln: dict, search: str) -> bool:
    """Match a vuln dict against a search string using the same AND/OR/NOT
    semantics as the frontend Fuse.js extended search."""
    searchable = " ".join([
        vuln.get("id", ""),
        " ".join(vuln.get("packages", [])),
        " ".join(str(v) for v in (vuln.get("texts") or {}).values()),
    ]).lower()
    or_groups = [g.strip() for g in search.split("|") if g.strip()]
    for group in or_groups:
        terms = group.split()
        if all(
            (t[1:].lower() not in searchable) if (t.startswith("-") and len(t) > 1)
            else (t.lower() in searchable)
            for t in terms
        ):
            return True
    return False


def _apply_server_filters(vulns: list[dict], args) -> list[dict]:
    """Apply query-param filters to the enriched vuln list."""
    result = vulns

    search = (args.get("search") or "").strip()
    if search and len(search) > 2:
        result = [v for v in result if _matches_search(v, search)]

    severity = args.get("severity")
    if severity:
        allowed = set(severity.split(","))
        result = [v for v in result if (v.get("severity") or {}).get("severity") in allowed]

    status = args.get("simplified_status")
    if status:
        allowed = set(status.split(","))
        result = [v for v in result if v.get("simplified_status") in allowed]

    source = args.get("found_by")
    if source:
        allowed = set(source.split(","))
        result = [v for v in result if allowed & set(v.get("found_by") or [])]

    package = args.get("package")
    if package:
        allowed = set(package.split(","))
        result = [v for v in result if allowed & set(v.get("packages_current") or [])]

    epss_min = args.get("epss_min", type=float)
    epss_max = args.get("epss_max", type=float)
    if epss_min is not None or epss_max is not None:
        def _epss_ok(v):
            score = (v.get("epss") or {}).get("score")
            if score is None:
                return False
            pct = score * 100
            if epss_min is not None and pct < epss_min:
                return False
            if epss_max is not None and pct > epss_max:
                return False
            return True
        result = [v for v in result if _epss_ok(v)]

    sev_min = args.get("severity_min", type=float)
    sev_max = args.get("severity_max", type=float)
    if sev_min is not None or sev_max is not None:
        def _sev_score_ok(v):
            score = (v.get("severity") or {}).get("max_score")
            if score is None:
                return False
            if sev_min is not None and score < sev_min:
                return False
            if sev_max is not None and score > sev_max:
                return False
            return True
        result = [v for v in result if _sev_score_ok(v)]

    av = args.get("attack_vector")
    if av:
        allowed = set(av.split(","))
        result = [
            v for v in result
            if allowed & {
                c.get("attack_vector") for c in (v.get("severity") or {}).get("cvss", [])
                if c.get("attack_vector")
            }
        ]

    pub_filter = args.get("published_date_filter")
    if pub_filter:
        import datetime as _dt
        pub_value = args.get("published_date_value", "")
        pub_from = args.get("published_date_from", "")
        pub_to = args.get("published_date_to", "")
        pub_days = args.get("published_days_value", "")
        filtered: list[dict] = []
        for v in result:
            pub = v.get("published")
            if not pub:
                continue
            try:
                pub_date = _dt.date.fromisoformat(pub)
            except (ValueError, TypeError):
                continue
            keep = True
            if pub_filter == "is" and pub_value:
                keep = pub_date == _dt.date.fromisoformat(pub_value)
            elif pub_filter == ">=" and pub_value:
                keep = pub_date >= _dt.date.fromisoformat(pub_value)
            elif pub_filter == "<=" and pub_value:
                keep = pub_date <= _dt.date.fromisoformat(pub_value)
            elif pub_filter == "between" and pub_from and pub_to:
                keep = _dt.date.fromisoformat(pub_from) <= pub_date <= _dt.date.fromisoformat(pub_to)
            elif pub_filter == "days_ago" and pub_days:
                try:
                    cutoff = _dt.date.today() - _dt.timedelta(days=int(pub_days))
                    keep = pub_date >= cutoff
                except ValueError:
                    pass
            if keep:
                filtered.append(v)
        result = filtered

    fsd = args.get("first_scan_date")
    if fsd:
        allowed_ts = set(fsd.split(","))

        def _fsd_ok(v):
            d = v.get("first_scan_date")
            if not d:
                return False
            try:
                import datetime as _dt
                ts = str(int(round(_dt.datetime.fromisoformat(d).timestamp())) * 1000)
                return ts in allowed_ts
            except (ValueError, TypeError):
                return False
        result = [v for v in result if _fsd_ok(v)]

    return result


def _apply_server_sort(vulns: list[dict], sort_by: str, sort_dir: str) -> list[dict]:
    """Sort the enriched vuln list by a column identifier."""
    reverse = sort_dir.lower() == "desc"

    def _key(v):  # noqa: C901
        if sort_by == "id":
            return v.get("id", "")
        if sort_by == "severity.severity":
            sev = (v.get("severity") or {}).get("severity", "").lower()
            try:
                return _SEVERITY_SORT_ORDER.index(sev)
            except ValueError:
                return -1
        if sort_by == "severity.max_score":
            return (v.get("severity") or {}).get("max_score") or 0
        if sort_by == "epss":
            return (v.get("epss") or {}).get("score") or 0
        if sort_by == "simplified_status":
            st = v.get("simplified_status", "")
            try:
                return _STATUS_SORT_ORDER.index(st)
            except ValueError:
                return -1
        if sort_by == "effort.likely":
            eff = (v.get("effort") or {}).get("likely")
            if eff:
                try:
                    return Iso8601Duration(eff).total_seconds
                except Exception:
                    return 0
            return 0
        if sort_by == "assessments":
            aa = v.get("assessments") or []
            if not aa:
                return ""
            return max((a.get("last_update") or a.get("timestamp") or "") for a in aa)
        if sort_by == "published":
            return v.get("published") or ""
        if sort_by == "first_scan_date":
            return v.get("first_scan_date") or ""
        if sort_by == "attack_vector":
            avs = [c.get("attack_vector") for c in (v.get("severity") or {}).get("cvss", []) if c.get("attack_vector")]
            if not avs:
                return -1
            return max((_AV_SORT_ORDER.index(a) if a in _AV_SORT_ORDER else -1) for a in avs)
        return v.get("id", "")

    return sorted(vulns, key=_key, reverse=reverse)


def init_app(app):

    if "TIME_ESTIMATES_PATH" not in app.config:
        app.config["TIME_ESTIMATES_PATH"] = TIME_ESTIMATES_PATH

    @app.route('/api/vulnerabilities')
    def index_vulns():
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')
        compare_variant_id = request.args.get('compare_variant_id')
        current_scan_ids: list = []

        # ------------------------------------------------------------------
        # Fast path: paginated, unscoped, no client filters or custom sort.
        # The default frontend page-load hits this. Loads only the page-size
        # records (vs all 11k) and computes facets via SQL aggregations.
        # ------------------------------------------------------------------
        _page_arg = request.args.get('page', type=int)
        _fmt = request.args.get('format', 'list')
        _filter_keys = {
            "search", "severity", "simplified_status", "found_by", "package",
            "epss_min", "epss_max", "severity_min", "severity_max",
            "attack_vector", "published_date_filter", "first_scan_date",
        }
        _has_filters = any(request.args.get(k) for k in _filter_keys)
        _sort_by = request.args.get('sort_by', 'id')
        _sort_dir = request.args.get('sort_dir', 'asc')
        _fast_path_eligible = (
            _page_arg is not None
            and _fmt != "dict"
            and not (variant_id or project_id or compare_variant_id)
            and not _has_filters
            and _sort_by == "id"
            and _sort_dir in ("asc", "desc")
        )
        if _fast_path_eligible:
            page_size = min(max(request.args.get('page_size', 50, type=int), 1), 500)
            page = max(_page_arg, 1)
            start = (page - 1) * page_size

            total = db.session.execute(
                db.select(func.count(Vulnerability.id))
            ).scalar() or 0

            order_clause = (
                Vulnerability.id.desc() if _sort_dir == "desc" else Vulnerability.id.asc()
            )
            page_records = list(db.session.execute(
                db.select(Vulnerability)
                .order_by(order_clause)
                .limit(page_size)
                .offset(start)
            ).scalars().all())

            page_vuln_ids = [r.id for r in page_records]
            if page_vuln_ids:
                # Bulk-load metrics, packages, effort for just this page
                metric_rows = db.session.execute(
                    db.select(Metrics).where(Metrics.vulnerability_id.in_(page_vuln_ids))
                ).scalars().all()
                metrics_by_vuln: dict[str, list] = {}
                for m in metric_rows:
                    metrics_by_vuln.setdefault(m.vulnerability_id, []).append(m)

                pkg_rows = db.session.execute(
                    db.select(Finding.vulnerability_id, Package.name, Package.version)
                    .join(Package, Finding.package_id == Package.id)
                    .where(Finding.vulnerability_id.in_(page_vuln_ids))
                    .distinct()
                ).all()
                pkgs_by_vuln: dict[str, list[str]] = {}
                for vid, pname, pver in pkg_rows:
                    pkgs_by_vuln.setdefault(vid, []).append(f"{pname}@{pver}")

                te_rows = db.session.execute(
                    db.select(
                        Finding.vulnerability_id,
                        TimeEstimate.optimistic,
                        TimeEstimate.likely,
                        TimeEstimate.pessimistic,
                    )
                    .join(Finding, TimeEstimate.finding_id == Finding.id)
                    .where(Finding.vulnerability_id.in_(page_vuln_ids))
                ).all()
                effort_by_vuln: dict[str, tuple] = {}
                for vid, opti, like, pess in te_rows:
                    if vid not in effort_by_vuln:
                        effort_by_vuln[vid] = (opti, like, pess)

                from sqlalchemy.orm import attributes as orm_attrs
                for r in page_records:
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
                    orm_attrs.set_committed_value(r, 'findings', [])
                    orm_attrs.set_committed_value(
                        r, 'metrics', metrics_by_vuln.get(r.id, [])
                    )

            _populate_found_by(page_records, None, None)
            page_vulns = [r.to_dict() for r in page_records]

            if page_vuln_ids:
                # packages_current = packages (no scope)
                for v in page_vulns:
                    v["packages_current"] = list(v["packages"])

                # variants enrichment via latest-scan join
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
                    .where(Finding.vulnerability_id.in_(page_vuln_ids))
                    .where(Observation.scan_id.in_(db.select(latest_scan_sub.c.id)))
                    .distinct()
                ).all()
                variant_names_by_vuln: dict = {}
                for vuln_id, variant_name in rows:
                    variant_names_by_vuln.setdefault(str(vuln_id), []).append(variant_name)
                for v in page_vulns:
                    v["variants"] = sorted(variant_names_by_vuln.get(v["id"], []))

                first_scan_rows = db.session.execute(
                    db.select(Finding.vulnerability_id, func.min(Scan.timestamp))
                    .join(Observation, Finding.id == Observation.finding_id)
                    .join(Scan, Observation.scan_id == Scan.id)
                    .where(Finding.vulnerability_id.in_(page_vuln_ids))
                    .group_by(Finding.vulnerability_id)
                ).all()
                first_scan_by_vuln: dict = {}
                for vuln_id, min_ts in first_scan_rows:
                    first_scan_by_vuln[str(vuln_id)] = min_ts.isoformat() if min_ts else None
                for v in page_vulns:
                    v["first_scan_date"] = first_scan_by_vuln.get(v["id"])

                assess_rows = db.session.execute(
                    db.select(
                        Finding.vulnerability_id,
                        DBAssessment.id,
                        DBAssessment.status,
                        DBAssessment.simplified_status,
                        DBAssessment.status_notes,
                        DBAssessment.justification,
                        DBAssessment.impact_statement,
                        DBAssessment.workaround,
                        DBAssessment.timestamp,
                        DBAssessment.responses,
                        DBAssessment.variant_id,
                        DBAssessment.finding_id,
                        Package.name,
                        Package.version,
                    )
                    .join(Finding, DBAssessment.finding_id == Finding.id)
                    .join(Package, Finding.package_id == Package.id, isouter=True)
                    .where(Finding.vulnerability_id.in_(page_vuln_ids))
                    .order_by(Finding.vulnerability_id, DBAssessment.timestamp)
                ).all()
                assessments_by_vuln: dict = {}
                for row in assess_rows:
                    vid = str(row.vulnerability_id)
                    ts = row.timestamp.isoformat() if row.timestamp else ""
                    pkg_str = f"{row.name}@{row.version}" if row.name else ""
                    simplified = row.simplified_status or _S2S.get(row.status or "", "Pending Assessment")
                    assessments_by_vuln.setdefault(vid, []).append({
                        "id": str(row.id),
                        "vuln_id": vid,
                        "packages": [pkg_str] if pkg_str else [],
                        "variant_id": str(row.variant_id) if row.variant_id else None,
                        "status": row.status or "",
                        "simplified_status": simplified,
                        "status_notes": row.status_notes or "",
                        "justification": row.justification or "",
                        "impact_statement": row.impact_statement or "",
                        "responses": list(row.responses or []),
                        "workaround": row.workaround or "",
                        "timestamp": ts,
                        "last_update": ts,
                    })
                for v in page_vulns:
                    vid = v["id"]
                    v_assessments = assessments_by_vuln.get(vid, [])
                    v["assessments"] = v_assessments
                    if v_assessments:
                        latest = v_assessments[-1]
                        v["status"] = latest["status"]
                        v["simplified_status"] = latest["simplified_status"]
                    else:
                        v["status"] = "unknown"
                        v["simplified_status"] = "Pending Assessment"

            return {
                "items": page_vulns,
                "total": int(total),
                "page": page,
                "page_size": page_size,
                "facets": _sql_compute_facets_global(),
            }

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

                # Materialize vulnerability IDs once – avoids SQLite
                # re-evaluating the subquery in every subsequent statement.
                vuln_id_list = list(db.session.execute(
                    db.select(Finding.vulnerability_id)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .where(Observation.scan_id.in_(latest_ids))
                    .distinct()
                ).scalars().all())

                records = list(db.session.execute(
                    db.select(Vulnerability)
                    .where(Vulnerability.id.in_(vuln_id_list))
                    .order_by(Vulnerability.id)
                ).scalars().all()) if vuln_id_list else []

                if records:
                    # Bulk-load metrics per vulnerability
                    metric_rows = db.session.execute(
                        db.select(Metrics)
                        .where(Metrics.vulnerability_id.in_(vuln_id_list))
                    ).scalars().all()
                    metrics_by_vuln: dict[str, list] = {}
                    for m in metric_rows:
                        metrics_by_vuln.setdefault(m.vulnerability_id, []).append(m)

                    # Bulk-load packages per vulnerability
                    pkg_rows = db.session.execute(
                        db.select(Finding.vulnerability_id, Package.name, Package.version)
                        .join(Package, Finding.package_id == Package.id)
                        .where(Finding.vulnerability_id.in_(vuln_id_list))
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
                        .where(Finding.vulnerability_id.in_(vuln_id_list))
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
            if current_scan_ids:
                # Reuse the already-computed latest scan IDs instead of
                # rebuilding the max-timestamp subquery from scratch.
                rows = db.session.execute(
                    db.select(Finding.vulnerability_id, Variant.name)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .join(Scan, Observation.scan_id == Scan.id)
                    .join(Variant, Scan.variant_id == Variant.id)
                    .where(Finding.vulnerability_id.in_(vuln_ids))
                    .where(Observation.scan_id.in_(current_scan_ids))
                    .distinct()
                ).all()
            else:
                # No scope — compute latest scans for all variants
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

            # Bulk-load assessments and enrich each vuln with status/simplified_status/assessments
            assess_rows = db.session.execute(
                db.select(
                    Finding.vulnerability_id,
                    DBAssessment.id,
                    DBAssessment.status,
                    DBAssessment.simplified_status,
                    DBAssessment.status_notes,
                    DBAssessment.justification,
                    DBAssessment.impact_statement,
                    DBAssessment.workaround,
                    DBAssessment.timestamp,
                    DBAssessment.responses,
                    DBAssessment.variant_id,
                    DBAssessment.finding_id,
                    Package.name,
                    Package.version,
                )
                .join(Finding, DBAssessment.finding_id == Finding.id)
                .join(Package, Finding.package_id == Package.id, isouter=True)
                .where(Finding.vulnerability_id.in_(vuln_ids))
                .order_by(Finding.vulnerability_id, DBAssessment.timestamp)
            ).all()

            assessments_by_vuln: dict = {}
            for row in assess_rows:
                vid = str(row.vulnerability_id)
                ts = row.timestamp.isoformat() if row.timestamp else ""
                pkg_str = f"{row.name}@{row.version}" if row.name else ""
                simplified = row.simplified_status or _S2S.get(row.status or "", "Pending Assessment")
                assessments_by_vuln.setdefault(vid, []).append({
                    "id": str(row.id),
                    "vuln_id": vid,
                    "packages": [pkg_str] if pkg_str else [],
                    "variant_id": str(row.variant_id) if row.variant_id else None,
                    "status": row.status or "",
                    "simplified_status": simplified,
                    "status_notes": row.status_notes or "",
                    "justification": row.justification or "",
                    "impact_statement": row.impact_statement or "",
                    "responses": list(row.responses or []),
                    "workaround": row.workaround or "",
                    "timestamp": ts,
                    "last_update": ts,
                })

            for v in vulns:
                vid = v["id"]
                v_assessments = assessments_by_vuln.get(vid, [])
                v["assessments"] = v_assessments
                if v_assessments:
                    latest = v_assessments[-1]
                    v["status"] = latest["status"]
                    v["simplified_status"] = latest["simplified_status"]
                else:
                    v["status"] = "unknown"
                    v["simplified_status"] = "Pending Assessment"

        if request.args.get('format', 'list') == "dict":
            return {v["id"]: v for v in vulns}

        # ---- Server-side pagination (opt-in via ?page=) ----
        page = request.args.get('page', type=int)
        if page is not None:
            page_size = min(max(request.args.get('page_size', 50, type=int), 1), 500)
            page = max(page, 1)

            facets = _compute_facets(vulns)
            filtered = _apply_server_filters(vulns, request.args)

            sort_by = request.args.get('sort_by', 'id')
            sort_dir = request.args.get('sort_dir', 'asc')
            filtered = _apply_server_sort(filtered, sort_by, sort_dir)

            total = len(filtered)
            start = (page - 1) * page_size
            items = filtered[start:start + page_size]
            return {
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size,
                "facets": facets,
            }

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

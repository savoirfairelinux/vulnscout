#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid as _uuid
from datetime import datetime, timezone, timedelta

from flask import request
from sqlalchemy import func

from ..models.vulnerability import Vulnerability
from ..models.finding import Finding
from ..models.observation import Observation
from ..models.package import Package
from ..models.metrics import Metrics as MetricsModel
from ..models.assessment import Assessment, STATUS_TO_SIMPLIFIED
from ..models.scan import Scan
from ..models.variant import Variant
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
from ..extensions import db
from .vulnerabilities import (
    _latest_scan_id_for_variant,
    _latest_scan_ids_for_project,
    _populate_found_by,
    _FORMAT_TO_FOUND_BY,
    _DEDICATED_SCANNER_FORMATS,
)

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_TEXT_TO_INDEX: dict[str, int] = {
    'none': 0, 'unknown': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
}

_SOURCE_DISPLAY_NAMES: dict[str, str] = {
    'openvex': 'OpenVex',
    'local_user_data': 'Local User Data',
    'yocto': 'Yocto',
    'spdx3': 'SPDX3',
    'grype': 'Grype',
    'cyclonedx': 'CycloneDx',
}


def _score_to_severity_index(score) -> int:
    if score is None:
        return 0
    score = float(score)
    if score == 0.0:
        return 0
    if score < 4.0:
        return 1
    if score < 7.0:
        return 2
    if score < 9.0:
        return 3
    return 4


def _severity_text_to_index(text: str | None) -> int:
    return _SEVERITY_TEXT_TO_INDEX.get((text or '').lower(), 0)


# ---------------------------------------------------------------------------
# Time-scale helpers  (mirrors front-end logic)
# ---------------------------------------------------------------------------

def _zeroise_dt(dt: datetime, unit: str) -> datetime:
    """Strip sub-period fields from *dt* according to *unit*."""
    if unit.startswith('month'):
        dt = dt.replace(day=1)
    if unit.startswith('hour'):
        return dt.replace(minute=0, second=0, microsecond=0)
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def _prev_dt(dt: datetime, unit: str) -> datetime:
    """Step back by one *unit*."""
    if unit.startswith('week'):
        return dt - timedelta(weeks=1)
    if unit.startswith('hour'):
        return dt - timedelta(hours=1)
    # days AND months both step back by 1 day; zeroise_date then sets day=1 for months
    return dt - timedelta(days=1)


def _generate_checkpoints(scale: int, unit: str) -> list[datetime]:
    """Return `scale` timezone-aware checkpoint datetimes, oldest first."""
    now = datetime.now(timezone.utc)
    checkpoints: list[datetime] = []
    dt = _zeroise_dt(now, unit)
    while len(checkpoints) < scale:
        checkpoints.insert(0, dt)
        dt = _zeroise_dt(_prev_dt(dt, unit), unit)
    return checkpoints


def _format_checkpoint_label(dt: datetime, unit: str) -> str:
    if unit.startswith('hour'):
        return dt.strftime('%H:00')
    if unit.startswith('month'):
        return dt.strftime("%b '%y")
    return dt.strftime("%-d %b '%y")


# ---------------------------------------------------------------------------
# Evolution algorithm  (direct Python port of the front-end reduce)
# ---------------------------------------------------------------------------

def _compute_evolution(
    assessments_by_vuln: dict[str, list[tuple[datetime, str]]],
    checkpoints: list[datetime],
) -> list[int]:
    """Return count of active vulnerabilities at each checkpoint."""
    nb = len(checkpoints)
    totals = [0] * nb

    for assessments in assessments_by_vuln.values():
        is_active = False
        date_index = 0
        was_active = [False] * nb

        for assess_ts, simplified_status in assessments:
            if assess_ts.tzinfo is None:
                assess_ts = assess_ts.replace(tzinfo=timezone.utc)

            # Advance the checkpoint index past all checkpoints before this assessment
            while (
                date_index < nb - 1
                and assess_ts > checkpoints[date_index + 1]
            ):
                if is_active:
                    was_active[date_index] = True
                date_index += 1

            should_be_active = simplified_status not in ('Not affected', 'Fixed')
            if is_active != should_be_active:
                if should_be_active and assess_ts >= checkpoints[date_index]:
                    was_active[date_index] = True
                is_active = should_be_active

        # Fill remaining checkpoints
        while date_index < nb:
            if is_active:
                was_active[date_index] = True
            date_index += 1

        for i, active in enumerate(was_active):
            if active:
                totals[i] += 1

    return totals


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

def init_app(app):

    @app.route('/api/metrics')
    def get_metrics():
        variant_id_raw = request.args.get('variant_id')
        project_id_raw = request.args.get('project_id')
        time_scale_str = request.args.get('time_scale', '6_months')

        # ── Parse time scale ────────────────────────────────────────────
        parts = time_scale_str.split('_', 1)
        if len(parts) != 2:
            return {"error": "Invalid time_scale"}, 400
        try:
            scale = int(parts[0])
            unit = parts[1]
        except ValueError:
            return {"error": "Invalid time_scale"}, 400
        if scale < 2 or unit not in ('months', 'weeks', 'days', 'hours'):
            return {"error": "Invalid time_scale"}, 400

        # ── Scope resolution ─────────────────────────────────────────────
        current_scan_ids: list = []
        scope_variant = None
        scope_project = None

        if variant_id_raw:
            try:
                scope_variant = _uuid.UUID(variant_id_raw)
            except ValueError:
                return {"error": "Invalid variant_id"}, 400
            latest = _latest_scan_id_for_variant(scope_variant)
            current_scan_ids = [latest] if latest else []
        elif project_id_raw:
            try:
                scope_project = _uuid.UUID(project_id_raw)
            except ValueError:
                return {"error": "Invalid project_id"}, 400
            current_scan_ids = _latest_scan_ids_for_project(scope_project)

        # ── Build the empty-response helper ──────────────────────────────
        def _empty():
            checkpoints = _generate_checkpoints(scale, unit)
            labels = [_format_checkpoint_label(cp, unit) for cp in checkpoints]
            return {
                "vuln_by_severity": [0, 0, 0, 0, 0],
                "vuln_by_status": [0, 0, 0, 0],
                "vuln_evolution": {"labels": labels, "data": [0] * scale},
                "vuln_by_source": {"labels": [], "data": []},
                "top_packages": [],
                "top_vulns": [],
            }

        # ── Scoped vulnerability IDs ─────────────────────────────────────
        if scope_variant is not None or scope_project is not None:
            if not current_scan_ids:
                return _empty()
            vuln_ids: list[str] = list(db.session.execute(
                db.select(Finding.vulnerability_id)
                .join(Observation, Finding.id == Observation.finding_id)
                .where(Observation.scan_id.in_(current_scan_ids))
                .distinct()
            ).scalars().all())
        else:
            vuln_ids = list(db.session.execute(
                db.select(Vulnerability.id)
            ).scalars().all())

        if not vuln_ids:
            return _empty()

        # ── 1. Severity distribution ─────────────────────────────────────
        # Prefer max CVSS score; fall back to the vulnerability's status column
        sev_rows = db.session.execute(
            db.select(
                Vulnerability.id,
                Vulnerability.status,
                func.max(MetricsModel.score).label('max_score'),
            )
            .outerjoin(MetricsModel, MetricsModel.vulnerability_id == Vulnerability.id)
            .where(Vulnerability.id.in_(vuln_ids))
            .group_by(Vulnerability.id, Vulnerability.status)
        ).all()

        severity_counts = [0, 0, 0, 0, 0]
        for _vid, base_sev, max_score in sev_rows:
            if max_score is not None:
                idx = _score_to_severity_index(max_score)
            else:
                idx = _severity_text_to_index(base_sev)
            severity_counts[idx] += 1

        # ── 2. Status distribution + assessment history ─────────────────
        # Lightweight query: only the columns needed for evolution and status aggregation.
        # Full assessment details are fetched separately for top-vulns only.
        slim_assess_rows = db.session.execute(
            db.select(
                Finding.vulnerability_id,
                Assessment.timestamp,
                Assessment.status,
                Assessment.simplified_status,
            )
            .join(Finding, Assessment.finding_id == Finding.id)
            .where(Finding.vulnerability_id.in_(vuln_ids))
            .order_by(Finding.vulnerability_id, Assessment.timestamp)
        ).all()

        # Group: latest status per vuln + evolution data
        latest_sstat_by_vuln: dict[str, str] = {}   # vuln_id -> latest simplified_status
        evolution_by_vuln: dict[str, list[tuple]] = {}  # for evolution chart

        for row in slim_assess_rows:
            vid = row.vulnerability_id
            ts = row.timestamp
            if ts is not None and ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            sstat = row.simplified_status or STATUS_TO_SIMPLIFIED.get(row.status or '', 'Pending Assessment')
            sstat = sstat or 'Pending Assessment'

            # Last assignment wins because rows are ordered by timestamp
            latest_sstat_by_vuln[vid] = sstat
            evolution_by_vuln.setdefault(vid, []).append((ts, sstat))

        latest_status_by_vuln: dict[str, str] = latest_sstat_by_vuln

        status_counts = [0, 0, 0, 0]  # Not affected, Fixed, Pending Assessment, Exploitable
        for vid in vuln_ids:
            sstat = latest_status_by_vuln.get(vid, 'Pending Assessment')
            if sstat == 'Not affected':
                status_counts[0] += 1
            elif sstat == 'Fixed':
                status_counts[1] += 1
            elif sstat == 'Pending Assessment':
                status_counts[2] += 1
            else:
                status_counts[3] += 1

        # ── 3. Evolution data ────────────────────────────────────────────
        checkpoints = _generate_checkpoints(scale, unit)
        labels = [_format_checkpoint_label(cp, unit) for cp in checkpoints]
        evolution_counts = _compute_evolution(evolution_by_vuln, checkpoints)

        # ── 4. Source distribution ────────────────────────────────────────
        source_query = (
            db.select(Finding.vulnerability_id, Finding.package_id, SBOMDocument.format)
            .select_from(Finding)
            .join(SBOMPackage, SBOMPackage.package_id == Finding.package_id)
            .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
            .where(SBOMDocument.format.isnot(None))
            .where(Finding.vulnerability_id.in_(vuln_ids))
        )
        if scope_variant is not None:
            source_query = (
                source_query
                .join(Scan, Scan.id == SBOMDocument.scan_id)
                .where(Scan.variant_id == scope_variant)
            )
        elif scope_project is not None:
            source_query = (
                source_query
                .join(Scan, Scan.id == SBOMDocument.scan_id)
                .join(Variant, Variant.id == Scan.variant_id)
                .where(Variant.project_id == scope_project)
            )

        source_rows = db.session.execute(source_query.distinct()).all()

        pkg_formats: dict[tuple, set] = {}
        for vuln_id, pkg_id, fmt in source_rows:
            key = (vuln_id, str(pkg_id))
            pkg_formats.setdefault(key, set()).add(fmt)

        found_by_by_vuln: dict[str, set] = {}
        for (vuln_id, _), formats in pkg_formats.items():
            dedicated = formats & _DEDICATED_SCANNER_FORMATS
            sources = dedicated if dedicated else formats
            for fmt in sources:
                mapped = _FORMAT_TO_FOUND_BY.get(fmt, fmt)
                found_by_by_vuln.setdefault(vuln_id, set()).add(mapped)

        source_counts: dict[str, int] = {}
        for sources in found_by_by_vuln.values():
            for src in sources:
                source_counts[src] = source_counts.get(src, 0) + 1

        sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)
        source_labels = [_SOURCE_DISPLAY_NAMES.get(s, s) for s, _ in sorted_sources]
        source_data_vals = [count for _, count in sorted_sources]

        # ── 5. Top vulnerable packages ────────────────────────────────────
        if current_scan_ids:
            pkg_vuln_rows = db.session.execute(
                db.select(
                    Package.name, Package.version,
                    func.count(Finding.vulnerability_id.distinct()).label('cnt'),
                )
                .join(Finding, Finding.package_id == Package.id)
                .join(Observation, Finding.id == Observation.finding_id)
                .where(Observation.scan_id.in_(current_scan_ids))
                .group_by(Package.name, Package.version)
                .order_by(func.count(Finding.vulnerability_id.distinct()).desc())
                .limit(5)
            ).all()
        else:
            pkg_vuln_rows = db.session.execute(
                db.select(
                    Package.name, Package.version,
                    func.count(Finding.vulnerability_id.distinct()).label('cnt'),
                )
                .join(Finding, Finding.package_id == Package.id)
                .where(Finding.vulnerability_id.in_(vuln_ids))
                .group_by(Package.name, Package.version)
                .order_by(func.count(Finding.vulnerability_id.distinct()).desc())
                .limit(5)
            ).all()

        top_packages = [
            {"id": idx + 1, "name": name, "version": version or "-", "count": cnt}
            for idx, (name, version, cnt) in enumerate(pkg_vuln_rows)
        ]

        # ── 6. Top unfixed vulnerabilities ────────────────────────────────
        active_vuln_ids = [
            vid for vid in vuln_ids
            if latest_status_by_vuln.get(vid, 'Pending Assessment') not in ('Fixed', 'Not affected')
        ]

        if not active_vuln_ids:
            top_vulns: list = []
        else:
            # Max CVSS per active vuln
            cvss_rows = db.session.execute(
                db.select(
                    MetricsModel.vulnerability_id,
                    func.max(MetricsModel.score).label('max_score'),
                )
                .where(MetricsModel.vulnerability_id.in_(active_vuln_ids))
                .group_by(MetricsModel.vulnerability_id)
            ).all()
            max_cvss: dict[str, float] = {vid: float(s) for vid, s in cvss_rows}

            top5_ids = sorted(active_vuln_ids, key=lambda v: max_cvss.get(v, 0.0), reverse=True)[:5]

            # Fetch vulnerability records with metrics pre-loaded to avoid N+1
            from sqlalchemy.orm import selectinload
            top_records = list(db.session.execute(
                db.select(Vulnerability)
                .options(selectinload(Vulnerability.metrics))
                .where(Vulnerability.id.in_(top5_ids))
            ).scalars().all())
            _populate_found_by(top_records, scope_variant, scope_project)

            # packages_current for top 5
            if current_scan_ids:
                top_pkg_rows = db.session.execute(
                    db.select(Finding.vulnerability_id, Package.name, Package.version)
                    .join(Observation, Finding.id == Observation.finding_id)
                    .join(Package, Finding.package_id == Package.id)
                    .where(Observation.scan_id.in_(current_scan_ids))
                    .where(Finding.vulnerability_id.in_(top5_ids))
                    .distinct()
                ).all()
            else:
                top_pkg_rows = db.session.execute(
                    db.select(Finding.vulnerability_id, Package.name, Package.version)
                    .join(Package, Finding.package_id == Package.id)
                    .where(Finding.vulnerability_id.in_(top5_ids))
                    .distinct()
                ).all()
            pkgs_current: dict[str, list] = {}
            for vid, pname, pver in top_pkg_rows:
                pkgs_current.setdefault(str(vid), []).append(f"{pname}@{pver}")

            # Build response ordered by rank
            records_by_id = {r.id: r for r in top_records}
            top_vulns = []
            for rank_idx, vid in enumerate(top5_ids):
                record = records_by_id.get(vid)
                if not record:
                    continue
                vuln_dict = record.to_dict()
                vuln_dict['packages_current'] = sorted(pkgs_current.get(vid, []))
                vuln_dict['simplified_status'] = latest_status_by_vuln.get(vid, 'Pending Assessment')

                # Fetch full assessment details for this top-5 vuln (modal data)
                top_assess_rows = db.session.execute(
                    db.select(
                        Assessment.id.label('assess_id'),
                        Assessment.source,
                        Assessment.status,
                        Assessment.simplified_status,
                        Assessment.status_notes,
                        Assessment.justification,
                        Assessment.impact_statement,
                        Assessment.responses,
                        Assessment.workaround,
                        Assessment.timestamp,
                        Assessment.variant_id,
                        Package.name.label('pkg_name'),
                        Package.version.label('pkg_version'),
                    )
                    .join(Finding, Assessment.finding_id == Finding.id)
                    .join(Package, Finding.package_id == Package.id)
                    .where(Finding.vulnerability_id == vid)
                    .order_by(Assessment.timestamp)
                ).all()

                assess_dicts = []
                for row in top_assess_rows:
                    ts = row.timestamp
                    ts_str = ts.isoformat() if ts is not None and hasattr(ts, 'isoformat') else (str(ts) if ts else None)
                    sstat = row.simplified_status or STATUS_TO_SIMPLIFIED.get(row.status or '', 'Pending Assessment')
                    assess_dicts.append({
                        "id": str(row.assess_id),
                        "source": row.source or "",
                        "vuln_id": vid,
                        "packages": [f"{row.pkg_name}@{row.pkg_version}"],
                        "variant_id": str(row.variant_id) if row.variant_id else None,
                        "timestamp": ts_str,
                        "last_update": ts_str or "",
                        "status": row.status or "",
                        "simplified_status": sstat or 'Pending Assessment',
                        "status_notes": row.status_notes or "",
                        "justification": row.justification or "",
                        "impact_statement": row.impact_statement or "",
                        "responses": list(row.responses or []),
                        "workaround": row.workaround or "",
                    })
                vuln_dict['assessments'] = assess_dicts
                vuln_dict['variants'] = []

                top_vulns.append({
                    "rank": rank_idx + 1,
                    "cve": vid,
                    "package": ", ".join(sorted(pkgs_current.get(vid, []))),
                    "severity": vuln_dict['severity']['severity'],
                    "max_cvss": max_cvss.get(vid, 0.0),
                    "texts": vuln_dict['texts'],
                    "vuln": vuln_dict,
                })

        return {
            "vuln_by_severity": severity_counts,
            "vuln_by_status": status_counts,
            "vuln_evolution": {"labels": labels, "data": evolution_counts},
            "vuln_by_source": {"labels": source_labels, "data": source_data_vals},
            "top_packages": top_packages,
            "top_vulns": top_vulns,
        }

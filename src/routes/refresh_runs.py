# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only, scoped views and exact-run exports of durable refresh artifacts."""

import csv
import io
import json
from datetime import datetime, timedelta, timezone

from flask import Response, abort, current_app, jsonify, request
from sqlalchemy import ColumnElement, case, exists, func, or_, select, true

from ..extensions import db
from ..helpers.datetime_utils import ensure_utc_iso
from ..helpers.refresh_runs import source_statuses
from ..models.refresh_run import (
    RefreshChange, RefreshRun, RefreshRunScope, RefreshTarget, RefreshTargetLink,
)
from ..models.vulnerability import Vulnerability
from ..models.vulnerability_history import CVSS_FIELD_PREFIX, current_values, equivalent_values

SCOPE_KEYS = ("project_id", "variant_id")
CHANGE_FILTERS = ("source", "field", "kind", "change_type")
SOURCE_ORDER = ("nvd", "epss", "ghsa", "euvd")


def pagination(params: dict) -> tuple[int, int]:
    """Raise ValueError for non-integer values; clamp the rest."""
    return (min(1000, max(1, int(params.get("limit", 100)))), max(0, int(params.get("offset", 0))))


def _scoped(params: dict) -> bool:
    return any(params.get(key) for key in SCOPE_KEYS)


def _link_filter(params: dict) -> list:
    return [getattr(RefreshTargetLink, key) == params[key] for key in SCOPE_KEYS if params.get(key)]


def _initiated_in_scope(run_id, source, params: dict) -> ColumnElement[bool]:
    """A run started from another project must not leak through CVEs shared with the selected one.

    Each source is matched against the scopes that initiated it; runs without
    scope rows are global.
    """
    applicable = [RefreshRunScope.run_id == run_id,
                  or_(RefreshRunScope.source.is_(None), RefreshRunScope.source == source)]
    matching = [or_(getattr(RefreshRunScope, key) == params[key], getattr(RefreshRunScope, key).is_(None))
                for key in SCOPE_KEYS if params.get(key)]
    # Correlate with the enclosing run/target/change rows explicitly, as this is nested two levels deep.
    scopes = exists().where(*applicable).correlate(RefreshRun, RefreshTarget, RefreshChange)
    return or_(~scopes, exists().where(*applicable, *matching).correlate(RefreshRun, RefreshTarget, RefreshChange))


def _target_filter(run_id, params: dict) -> list:
    conditions = [RefreshTarget.run_id == run_id]
    if params.get("vuln_id"):
        conditions.append(RefreshTarget.vuln_id == params["vuln_id"].upper())
    if _scoped(params):
        conditions.append(exists().where(RefreshTargetLink.target_id == RefreshTarget.id, *_link_filter(params)))
        conditions.append(_initiated_in_scope(run_id, RefreshTarget.source, params))
    return conditions


def _change_filter(run_id: str, params: dict) -> list:
    conditions = [RefreshChange.run_id == run_id]
    if params.get("vuln_id"):
        conditions.append(RefreshChange.vuln_id == params["vuln_id"].upper())
    if _scoped(params):
        conditions.append(exists().where(RefreshTargetLink.target_id == RefreshChange.target_id,
                                         *_link_filter(params)))
        conditions.append(_initiated_in_scope(run_id, RefreshChange.source, params))
    conditions += [getattr(RefreshChange, key) == params[key] for key in CHANGE_FILTERS if params.get(key)]
    return conditions


def visible_run(params: dict):
    """Run visibility as a SQL condition correlated with ``RefreshRun``.

    A run is visible when a target matches the filters through its captured
    package links. Without a vulnerability filter, a run whose initiating scope
    matches (for example an empty-target run) is visible too.
    """
    if not (_scoped(params) or params.get("vuln_id")):
        return true()
    visible: ColumnElement[bool] = exists().where(*_target_filter(RefreshRun.run_id, params))
    if _scoped(params) and not params.get("vuln_id"):
        visible = or_(visible, exists().where(
            RefreshRunScope.run_id == RefreshRun.run_id,
            *[getattr(RefreshRunScope, key) == params[key] for key in SCOPE_KEYS if params.get(key)],
        ))
    return visible


def _packages(link: RefreshTargetLink) -> dict:
    return {"package_id": link.package_id, "name": link.name, "version": link.version,
            "package": link.package, "variant_id": link.variant_id, "project_id": link.project_id}


def _links_by_target(target_ids: list[int], params: dict) -> dict[int, list[dict]]:
    links: dict[int, list[dict]] = {}
    for start in range(0, len(target_ids), 500):
        for link in db.session.scalars(
            select(RefreshTargetLink)
            .where(RefreshTargetLink.target_id.in_(target_ids[start:start + 500]), *_link_filter(params))
            .order_by(RefreshTargetLink.id)
        ):
            links.setdefault(link.target_id, []).append(_packages(link))
    return links


def _scope_rows(run_ids: list[str]) -> dict[str, list[RefreshRunScope]]:
    rows: dict[str, list[RefreshRunScope]] = {run_id: [] for run_id in run_ids}
    for row in db.session.scalars(select(RefreshRunScope).where(RefreshRunScope.run_id.in_(run_ids))):
        rows[row.run_id].append(row)
    return rows


def _scoped_sources(rows: list[RefreshRunScope], source_status: dict[str, str], params: dict) -> list[str]:
    """Sources initiated from the requested scope; mirrors ``_initiated_in_scope``."""
    if not _scoped(params):
        return list(source_status)

    def matches(row: RefreshRunScope) -> bool:
        return all(getattr(row, key) in (params[key], None) for key in SCOPE_KEYS if params.get(key))

    return [source for source in source_status
            if not (applicable := [row for row in rows if row.source in (None, source)])
            or any(matches(row) for row in applicable)]


def _scoped_scope(run: RefreshRun, sources: list[str]) -> dict:
    scope = {key: value for key, value in run.scope.items() if key != "refresh_type"}
    by_source = scope.get("source_scopes")
    if by_source:
        scope["source_scopes"] = {source: item for source, item in by_source.items() if source in sources}
        scope["variants"] = [variant for item in scope["source_scopes"].values()
                             for variant in item.get("variants", [])]
    return scope


def metadata(run: RefreshRun, params: dict, scope_rows: list[RefreshRunScope] | None = None) -> dict:
    """Run metadata and summary computed in the database, without change bodies or coverage.

    ``scope_rows`` lets list callers load the scope rows of a whole page at once.
    """
    all_status = source_statuses(run.run_id)
    if scope_rows is None:
        scope_rows = _scope_rows([run.run_id])[run.run_id] if _scoped(params) else []
    visible = _scoped_sources(scope_rows, all_status, params)
    source_status = {source: all_status[source] for source in visible}
    total, changed, first = db.session.execute(
        select(func.count(), func.count(RefreshChange.vuln_id.distinct()),
               func.coalesce(func.sum(case((RefreshChange.kind == "first_enrichment", 1), else_=0)), 0))
        .where(*_change_filter(run.run_id, params))
    ).one()
    refreshed = db.session.scalar(
        select(func.count(RefreshTarget.vuln_id.distinct()))
        .where(*_target_filter(run.run_id, params), RefreshTarget.status == "complete")
    )
    if run.finished_at is None:
        status = "running"
    else:
        unchecked = db.session.scalar(select(exists().where(
            *_target_filter(run.run_id, params), RefreshTarget.status != "complete",
        )))
        status = "complete" if not unchecked and all(
            value == "complete" for value in source_status.values()
        ) else "incomplete"
    return {
        "run_id": run.run_id, "scope": _scoped_scope(run, visible),
        "refresh_type": run.scope.get("refresh_type", "unknown"),
        "sources": list(source_status),
        "source_status": source_status,
        "started_at": ensure_utc_iso(run.started_at), "finished_at": ensure_utc_iso(run.finished_at),
        "status": status,
        "summary": {"refreshed_vulnerabilities": refreshed, "total_changes": total,
                    "changed_vulnerabilities": changed, "first_enrichments": first},
    }


def artifact(run: RefreshRun, params: dict, *, paginate: bool = True) -> dict:
    """Full artifact of a run already known to be visible under ``params``."""
    limit, offset = pagination(params)
    meta = metadata(run, params)
    targets = db.session.execute(
        select(RefreshTarget.id, RefreshTarget.source, RefreshTarget.vuln_id,
               RefreshTarget.status, RefreshTarget.error)
        .where(*_target_filter(run.run_id, params)).order_by(RefreshTarget.id)
    ).all()
    links = _links_by_target([target.id for target in targets], params)
    coverage = [{"source": target.source, "vuln_id": target.vuln_id, "status": target.status,
                 "error": target.error, "packages": links.get(target.id, [])} for target in targets]
    query = select(RefreshChange).where(*_change_filter(run.run_id, params)).order_by(RefreshChange.id)
    if paginate:
        query = query.limit(limit).offset(offset)
    rows = db.session.scalars(query).all()
    change_links = _links_by_target(list({row.target_id for row in rows if row.target_id is not None}), params)
    changes = [{**row.snapshot, "packages": change_links.get(row.target_id, []) if row.target_id else [],
                "change_type": row.change_type} for row in rows]
    total = meta["summary"]["total_changes"]
    return {**meta, "coverage": coverage, "changes": changes, "total": total, "limit": limit, "offset": offset}


def _retention_cutoff() -> datetime:
    days = current_app.config.get("REFRESH_RUN_RETENTION_DAYS", 90)
    return datetime.now(timezone.utc) - timedelta(days=days)


def retained_runs():
    from ..helpers.refresh_runs import reconcile_interrupted_runs
    reconcile_interrupted_runs()
    return db.select(RefreshRun).where(
        RefreshRun.started_at >= _retention_cutoff()
    ).order_by(RefreshRun.started_at.desc(), RefreshRun.run_id.desc())


def find_run(params: dict, run_id: str | None = None) -> RefreshRun | None:
    """Exact run when ``run_id`` is given (never substituted), else the latest visible run."""
    query = retained_runs().where(visible_run(params))
    if run_id is not None:
        query = query.where(RefreshRun.run_id == run_id)
    return db.session.scalars(query.limit(1)).first()


def _cvss_identity(field: str) -> dict | None:
    if not field.startswith(CVSS_FIELD_PREFIX):
        return None
    version, _, rest = field[len(CVSS_FIELD_PREFIX):].partition(":")
    author, _, metric_id = rest.rpartition(":")
    return {"version": version, "author": author, "metric_id": metric_id}


def _entry_key(item) -> str:
    return json.dumps(item, sort_keys=True, default=str)


def _field_indicator(field: str, before, after, changed_at: str, live) -> dict | None:
    """Net effect of one refresh on one field, or ``None`` when it cancelled out.

    ``new`` covers previously absent values and collections that only gained
    entries, ``updated`` covers modified values (the previous value is kept),
    and ``removed`` covers values the provider cleared. ``current`` is false
    once another write replaced the refreshed value, so stale indicators never
    describe live data.
    """
    if equivalent_values(before, after):
        return None
    indicator: dict = {
        "field": field, "before": before, "after": after, "changed_at": changed_at,
        "kind": "first_enrichment" if before is None else "changed",
        "current": equivalent_values(after, live),
        "cvss": _cvss_identity(field),
    }
    removed: list = []
    if isinstance(before, list) or isinstance(after, list):
        old = [item for item in (before if isinstance(before, list) else []) if item is not None]
        new = [item for item in (after if isinstance(after, list) else []) if item is not None]
        old_keys, new_keys = {_entry_key(item) for item in old}, {_entry_key(item) for item in new}
        removed = [item for item in old if _entry_key(item) not in new_keys]
        indicator["added"] = [item for item in new if _entry_key(item) not in old_keys]
        indicator["removed"] = removed
    if before is None:
        indicator["indicator"] = "new"
    elif after is None:
        indicator["indicator"] = "removed"
    elif "added" in indicator and indicator["added"] and not removed:
        indicator["indicator"] = "new"
    else:
        indicator["indicator"] = "updated"
    return indicator


def _run_reference(run: RefreshRun, params: dict, cache: dict[str, dict]) -> dict:
    if run.run_id not in cache:
        meta = metadata(run, params)
        cache[run.run_id] = {key: meta[key] for key in (
            "run_id", "refresh_type", "status", "source_status", "started_at", "finished_at",
        )}
    return cache[run.run_id]


def vulnerability_indicators(vuln: Vulnerability, params: dict) -> dict:
    """Per-source deltas of the latest refresh that successfully checked ``vuln``.

    Each source is resolved independently: its newest retained, in-scope
    target with a ``complete`` outcome is the applicable refresh, including an
    explicit no-change result. Newer failed, skipped, cancelled or pending
    targets never replace those indicators; the newest one is reported as
    ``later_attempt`` instead.
    """
    from ..helpers.refresh_runs import reconcile_interrupted_runs
    reconcile_interrupted_runs()
    scope = {key: params[key] for key in SCOPE_KEYS if params.get(key)}
    rows = db.session.execute(
        select(RefreshTarget, RefreshRun).join(RefreshRun, RefreshRun.run_id == RefreshTarget.run_id)
        .where(*_target_filter(RefreshTarget.run_id, {**scope, "vuln_id": vuln.id}),
               RefreshRun.started_at >= _retention_cutoff())
        .order_by(RefreshRun.started_at.desc(), RefreshRun.run_id.desc())
    ).all()
    attempts: dict[str, list[tuple[RefreshTarget, RefreshRun]]] = {}
    for target, run in rows:
        attempts.setdefault(target.source, []).append((target, run))
    live = current_values(vuln)
    cache: dict[str, dict] = {}
    sources = []
    for source in sorted(attempts, key=lambda name: (
        SOURCE_ORDER.index(name) if name in SOURCE_ORDER else len(SOURCE_ORDER), name,
    )):
        newest_target, newest_run = attempts[source][0]
        entry: dict = {"source": source, "state": "no_baseline", "run": None, "changes": [], "later_attempt": None}
        if newest_target.status != "complete":
            entry["later_attempt"] = {"status": newest_target.status, "error": newest_target.error,
                                      "run": _run_reference(newest_run, scope, cache)}
        applicable = next((run for target, run in attempts[source] if target.status == "complete"), None)
        if applicable is not None:
            by_field: dict[str, list[dict]] = {}
            for change in db.session.scalars(
                select(RefreshChange).where(RefreshChange.run_id == applicable.run_id,
                                            RefreshChange.source == source, RefreshChange.vuln_id == vuln.id)
                .order_by(RefreshChange.id)
            ):
                by_field.setdefault(change.field, []).append(change.snapshot)
            changes = [indicator for field, snapshots in by_field.items() if (indicator := _field_indicator(
                field, snapshots[0]["before"], snapshots[-1]["after"], snapshots[-1]["changed_at"], live.get(field),
            ))]
            entry.update(state="changed" if changes else "no_change", changes=changes,
                         run=_run_reference(applicable, scope, cache))
        sources.append(entry)
    return {"vuln_id": vuln.id, "scope": scope, "sources": sources}


def export_artifact(data: dict, format_: str) -> str:
    if format_ == "json":
        return json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if format_ != "csv":
        raise ValueError("format must be json or csv")
    output = io.StringIO(newline="")
    columns = ["record_type", "run_id", "status", "source", "vuln_id", "field", "kind",
               "change_type", "before", "after", "changed_at", "packages", "metadata"]
    writer = csv.DictWriter(output, columns, quoting=csv.QUOTE_ALL)
    writer.writeheader()

    def safe(value):
        if isinstance(value, (dict, list)) or value is None:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        text = str(value)
        return "'" + text if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else text

    metadata = {key: value for key, value in data.items() if key != "changes"}
    writer.writerow({"record_type": "run", "run_id": safe(data["run_id"]), "status": data["status"],
                     "metadata": safe(metadata)})
    for row in data["changes"]:
        cells = {key: safe(row[key]) for key in columns if key in row}
        for key in ("before", "after"):
            cells[key] = json.dumps(row[key], ensure_ascii=False)
        writer.writerow({**cells, "record_type": "change",
                         "run_id": safe(data["run_id"]), "status": data["status"]})
    return output.getvalue()


def init_app(app):
    @app.get("/api/refresh-runs")
    def list_refresh_runs():
        params = request.args.to_dict()
        try:
            limit, offset = pagination(params)
        except ValueError:
            abort(400, description="Invalid pagination")
        query = retained_runs().where(visible_run(params))
        if params.get("hide_individual") == "true":
            query = query.where(func.coalesce(RefreshRun.scope["refresh_type"].as_string(), "unknown") != "individual")
        total = db.session.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
        page = db.session.scalars(query.limit(limit).offset(offset)).all()
        rows = _scope_rows([run.run_id for run in page]) if _scoped(params) else {}
        runs = [metadata(run, params, rows.get(run.run_id, [])) for run in page]
        return jsonify({"runs": runs, "total": total, "limit": limit, "offset": offset})

    @app.get("/api/refresh-runs/latest", endpoint="get_latest_refresh_run")
    @app.get("/api/refresh-runs/<run_id>", endpoint="get_refresh_run")
    @app.get("/api/refresh-runs/<run_id>/export", endpoint="export_refresh_run")
    def get_refresh_run(run_id=None):
        params = request.args.to_dict()
        export = request.path.endswith("/export")
        format_ = params.get("format", "json")
        try:
            pagination(params)
            if export and format_ not in ("json", "csv"):
                raise ValueError("format must be json or csv")
        except ValueError as exc:
            abort(400, description=str(exc))
        run = find_run(params, run_id)
        if run is None:
            if run_id is None:
                return jsonify(None)
            abort(404, description="Refresh run unavailable, expired, or outside the selected scope")
        data = artifact(run, params, paginate=not export)
        if export:
            return Response(export_artifact(data, format_),
                            mimetype="text/csv" if format_ == "csv" else "application/json",
                            headers={"Content-Disposition": f'attachment; filename="refresh-{run.run_id}.{format_}"'})
        return jsonify(data)

    @app.get("/api/vulnerabilities/<vuln_id>/refresh-indicators")
    def get_vulnerability_refresh_indicators(vuln_id: str):
        """Per-source New/Updated indicators from the latest refresh that checked a vulnerability.

        Derived from persisted refresh deltas only; reading them acknowledges nothing.

        OpenAPI:
        query project_id uuid optional Restrict to refreshes visible in a project.
        query variant_id uuid optional Restrict to refreshes visible in a variant.
        response 200 JsonObject Object with vuln_id, scope and per-source indicator states.
        response 404 Error Vulnerability not found.
        """
        vuln = db.session.get(Vulnerability, vuln_id.upper())
        if vuln is None:
            return {"error": "Vulnerability not found"}, 404
        return jsonify(vulnerability_indicators(vuln, request.args.to_dict()))

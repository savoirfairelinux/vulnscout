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

SCOPE_KEYS = ("project_id", "variant_id")
CHANGE_FILTERS = ("source", "field", "kind", "change_type")


def pagination(params: dict) -> tuple[int, int]:
    """Raise ValueError for non-integer values; clamp the rest."""
    return (min(1000, max(1, int(params.get("limit", 100)))), max(0, int(params.get("offset", 0))))


def _scoped(params: dict) -> bool:
    return any(params.get(key) for key in SCOPE_KEYS)


def _link_filter(params: dict) -> list:
    return [getattr(RefreshTargetLink, key) == params[key] for key in SCOPE_KEYS if params.get(key)]


def _target_filter(run_id, params: dict) -> list:
    conditions = [RefreshTarget.run_id == run_id]
    if params.get("vuln_id"):
        conditions.append(RefreshTarget.vuln_id == params["vuln_id"].upper())
    if _scoped(params):
        conditions.append(exists().where(RefreshTargetLink.target_id == RefreshTarget.id, *_link_filter(params)))
    return conditions


def _change_filter(run_id: str, params: dict) -> list:
    conditions = [RefreshChange.run_id == run_id]
    if params.get("vuln_id"):
        conditions.append(RefreshChange.vuln_id == params["vuln_id"].upper())
    if _scoped(params):
        conditions.append(exists().where(RefreshTargetLink.target_id == RefreshChange.target_id,
                                         *_link_filter(params)))
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


def metadata(run: RefreshRun, params: dict) -> dict:
    """Run metadata and summary computed in the database, without change bodies or coverage."""
    source_status = source_statuses(run.run_id)
    total, changed, first = db.session.execute(
        select(func.count(), func.count(RefreshChange.vuln_id.distinct()),
               func.coalesce(func.sum(case((RefreshChange.kind == "first_enrichment", 1), else_=0)), 0))
        .where(*_change_filter(run.run_id, params))
    ).one()
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
        "run_id": run.run_id, "scope": run.scope, "sources": list(source_status),
        "source_status": source_status,
        "started_at": ensure_utc_iso(run.started_at), "finished_at": ensure_utc_iso(run.finished_at),
        "status": status,
        "summary": {"total_changes": total, "changed_vulnerabilities": changed, "first_enrichments": first},
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


def retained_runs():
    from ..helpers.refresh_runs import reconcile_interrupted_runs
    reconcile_interrupted_runs()
    days = current_app.config.get("REFRESH_RUN_RETENTION_DAYS", 90)
    return db.select(RefreshRun).where(
        RefreshRun.started_at >= datetime.now(timezone.utc) - timedelta(days=days)
    ).order_by(RefreshRun.started_at.desc(), RefreshRun.run_id.desc())


def find_run(params: dict, run_id: str | None = None) -> RefreshRun | None:
    """Exact run when ``run_id`` is given (never substituted), else the latest visible run."""
    query = retained_runs().where(visible_run(params))
    if run_id is not None:
        query = query.where(RefreshRun.run_id == run_id)
    return db.session.scalars(query.limit(1)).first()


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
        total = db.session.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
        runs = [metadata(run, params) for run in db.session.scalars(query.limit(limit).offset(offset))]
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

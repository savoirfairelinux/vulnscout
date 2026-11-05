# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only, scoped views and exact-run exports of durable refresh artifacts."""

import csv
import io
import json
from datetime import datetime, timedelta, timezone

from flask import Response, abort, current_app, jsonify, request
from sqlalchemy import JSON, case, column, func

from ..extensions import db
from ..helpers.datetime_utils import ensure_utc_iso
from ..models.refresh_run import RefreshChange, RefreshRun, RefreshTarget


def _visible(packages: list, params: dict) -> list:
    return [package for package in packages if all(
        not params.get(key) or package[key] == params[key] for key in ("project_id", "variant_id")
    )]


def artifact(run: RefreshRun, params: dict, *, paginate: bool = True, summary: dict | None = None) -> dict | None:
    coverage = []
    for entry in run.coverage:
        packages = _visible(entry["packages"], params)
        if (params.get("project_id") or params.get("variant_id")) and not packages:
            continue
        if params.get("vuln_id") and entry["vuln_id"] != params["vuln_id"].upper():
            continue
        coverage.append({**entry, "packages": packages})
    if not coverage and (params.get("project_id") or params.get("variant_id") or params.get("vuln_id")):
        scope_matches = not params.get("vuln_id") and any(
            all(not params.get(key) or entry.get(key) == params[key] for key in ("project_id", "variant_id"))
            for entry in [run.scope, *run.scope.get("variants", [])]
        )
        if not scope_matches:
            return None
    changes = []
    for change in ([] if summary is not None else db.session.scalars(
        db.select(RefreshChange).where(RefreshChange.run_id == run.run_id).order_by(RefreshChange.id)
    )):
        row = dict(change.snapshot)
        row["packages"] = _visible(row["packages"], params)
        if (params.get("project_id") or params.get("variant_id")) and not row["packages"]:
            continue
        if params.get("vuln_id") and row["vuln_id"] != params["vuln_id"].upper():
            continue
        row["change_type"] = (
            "addition" if row["before"] is None else "removal" if row["after"] is None else "modification"
        )
        if any(params.get(key) and row[key] != params[key]
               for key in ("source", "field", "kind", "change_type")):
            continue
        changes.append(row)
    limit = min(1000, max(1, int(params.get("limit", 100))))
    offset = max(0, int(params.get("offset", 0)))
    status = "running" if run.finished_at is None else (
        "complete" if all(value == "complete" for value in run.source_status.values())
        and all(entry["status"] == "complete" for entry in coverage) else "incomplete"
    )
    return {
        "run_id": run.run_id, "scope": run.scope, "sources": run.sources,
        "source_status": run.source_status,
        "started_at": ensure_utc_iso(run.started_at), "finished_at": ensure_utc_iso(run.finished_at),
        "status": status, "coverage": coverage,
        "summary": summary if summary is not None else {
            "total_changes": len(changes),
            "changed_vulnerabilities": len({row["vuln_id"] for row in changes}),
            "first_enrichments": sum(row["kind"] == "first_enrichment" for row in changes),
        },
        "changes": changes[offset:offset + limit] if paginate else changes,
        "total": summary["total_changes"] if summary is not None else len(changes), "limit": limit, "offset": offset,
    }


def retained_runs():
    from ..helpers.refresh_runs import reconcile_interrupted_runs
    reconcile_interrupted_runs()
    days = current_app.config.get("REFRESH_RUN_RETENTION_DAYS", 90)
    return db.select(RefreshRun).where(
        RefreshRun.started_at >= datetime.now(timezone.utc) - timedelta(days=days)
    ).order_by(RefreshRun.started_at.desc(), RefreshRun.run_id.desc())


def _scope_conditions(value, params):
    return [value[key].as_string() == params[key] for key in ("project_id", "variant_id") if params.get(key)]


def _array_scope_exists(value, params):
    """Correlate immutable JSON package/scope membership on both supported engines."""
    expand = func.json_array_elements if db.engine.dialect.name == "postgresql" else func.json_each
    entries = expand(value).table_valued(column("value", JSON), joins_implicitly=True)
    return db.select(1).select_from(entries).where(*_scope_conditions(entries.c.value, params)).exists()


def _matching_runs(query, params):
    scoped = bool(params.get("project_id") or params.get("variant_id"))
    if not scoped and not params.get("vuln_id"):
        return query
    targets = db.select(1).where(RefreshTarget.run_id == RefreshRun.run_id)
    if params.get("vuln_id"):
        targets = targets.where(RefreshTarget.vuln_id == params["vuln_id"].upper())
    if scoped:
        targets = targets.where(_array_scope_exists(RefreshTarget.packages, params))
    matches = targets.exists()
    if scoped and not params.get("vuln_id"):
        matches = db.or_(
            matches, db.and_(*_scope_conditions(RefreshRun.scope, params)),
            _array_scope_exists(RefreshRun.scope["variants"], params),
        )
    return query.where(matches)


def _summaries(run_ids, params):
    snapshot = RefreshChange.snapshot
    before_missing = snapshot["before"].as_string().is_(None)
    after_missing = snapshot["after"].as_string().is_(None)
    query = db.select(
        RefreshChange.run_id, func.count(),
        func.count(func.distinct(snapshot["vuln_id"].as_string())),
        func.sum(case((snapshot["kind"].as_string() == "first_enrichment", 1), else_=0)),
    ).where(RefreshChange.run_id.in_(run_ids))
    for key in ("vuln_id", "source", "field", "kind"):
        if params.get(key):
            query = query.where(snapshot[key].as_string() == (
                params[key].upper() if key == "vuln_id" else params[key]
            ))
    if params.get("project_id") or params.get("variant_id"):
        query = query.where(_array_scope_exists(snapshot["packages"], params))
    if params.get("change_type"):
        query = query.where(case(
            (before_missing, "addition"), (after_missing, "removal"), else_="modification",
        ) == params["change_type"])
    return {
        row[0]: dict(zip(("total_changes", "changed_vulnerabilities", "first_enrichments"), row[1:]))
        for row in db.session.execute(query.group_by(RefreshChange.run_id))
    }


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
        try:
            params = request.args.to_dict()
            limit = min(1000, max(1, int(params.get("limit", 100))))
            offset = max(0, int(params.get("offset", 0)))
            query = _matching_runs(retained_runs(), params)
            total = db.session.scalar(db.select(func.count()).select_from(query.order_by(None).subquery()))
            page = db.session.scalars(query.limit(limit).offset(offset)).all()
            summaries = _summaries([run.run_id for run in page], params) if page else {}
            empty = {"total_changes": 0, "changed_vulnerabilities": 0, "first_enrichments": 0}
            runs = [artifact(run, params, summary=summaries.get(run.run_id, empty)) for run in page]
            for run in runs:
                run.pop("changes")
            return jsonify({"runs": runs, "total": total,
                            "limit": limit, "offset": offset})
        except ValueError:
            abort(400, description="Invalid pagination")

    @app.get("/api/refresh-runs/latest", endpoint="get_latest_refresh_run")
    @app.get("/api/refresh-runs/<run_id>", endpoint="get_refresh_run")
    @app.get("/api/refresh-runs/<run_id>/export", endpoint="export_refresh_run")
    def get_refresh_run(run_id=None):
        try:
            params = request.args.to_dict()
            query = retained_runs()
            if run_id is not None:
                query = query.where(RefreshRun.run_id == run_id)
            for run in db.session.scalars(query):
                data = artifact(run, params, paginate=not request.path.endswith("/export"))
                if data is not None:
                    if request.path.endswith("/export"):
                        format_ = params.get("format", "json")
                        body = export_artifact(data, format_)
                        return Response(body, mimetype="text/csv" if format_ == "csv" else "application/json",
                                        headers={"Content-Disposition":
                                                 f'attachment; filename="refresh-{run.run_id}.{format_}"'})
                    return jsonify(data)
            abort(404, description="Refresh run unavailable, expired, or outside the selected scope")
        except ValueError as exc:
            abort(400, description=str(exc))

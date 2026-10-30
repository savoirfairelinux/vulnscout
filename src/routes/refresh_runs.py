# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only, scoped views and exact-run exports of durable refresh artifacts."""

import csv
import io
import json
from datetime import datetime, timedelta, timezone

from flask import Response, abort, current_app, jsonify, request

from ..extensions import db
from ..helpers.datetime_utils import ensure_utc_iso
from ..models.refresh_run import RefreshChange, RefreshRun


def _visible(packages: list, params: dict) -> list:
    return [package for package in packages if all(
        not params.get(key) or package[key] == params[key] for key in ("project_id", "variant_id")
    )]


def artifact(run: RefreshRun, params: dict, *, paginate: bool = True) -> dict | None:
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
    for change in db.session.scalars(
        db.select(RefreshChange).where(RefreshChange.run_id == run.run_id).order_by(RefreshChange.id)
    ):
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
        "summary": {
            "total_changes": len(changes),
            "changed_vulnerabilities": len({row["vuln_id"] for row in changes}),
            "first_enrichments": sum(row["kind"] == "first_enrichment" for row in changes),
        },
        "changes": changes[offset:offset + limit] if paginate else changes,
        "total": len(changes), "limit": limit, "offset": offset,
    }


def retained_runs():
    from ..helpers.refresh_runs import reconcile_interrupted_runs
    reconcile_interrupted_runs()
    days = current_app.config.get("REFRESH_RUN_RETENTION_DAYS", 90)
    return db.select(RefreshRun).where(
        RefreshRun.started_at >= datetime.now(timezone.utc) - timedelta(days=days)
    ).order_by(RefreshRun.started_at.desc(), RefreshRun.run_id.desc())


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
            runs = [data for run in db.session.scalars(retained_runs())
                    if (data := artifact(run, params)) is not None]
            for run in runs:
                run.pop("changes")
            return jsonify({"runs": runs[offset:offset + limit], "total": len(runs),
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

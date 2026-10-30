# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Exact-run artifact export and explicit retention cleanup."""

from datetime import datetime, timedelta, timezone

import click
from flask import current_app
from flask.cli import with_appcontext

from ..extensions import db
from ..models.refresh_run import RefreshChange, RefreshRun
from ..routes.refresh_runs import artifact, export_artifact, retained_runs
from ._common import resolve_project, resolve_project_variant
from ._console import Command


@click.command("export-refresh-changes", cls=Command)
@click.option("--run-id", required=True, help="Exact run identity; never selects latest.")
@click.option("--format", "format_", type=click.Choice(["json", "csv"]), default="json")
@click.option("--output", type=click.Path(dir_okay=False), default="-", help="Output file, or - for stdout.")
@click.option("--project", default=None)
@click.option("--variant", default=None)
@with_appcontext
def export_refresh_changes_command(run_id, format_, output, project, variant):
    if variant and not project:
        raise click.UsageError("--variant requires --project.")
    params = {}
    if project:
        project_obj = resolve_project(project)
        params["project_id"] = str(project_obj.id)
        if variant:
            _, variant_obj = resolve_project_variant(project, variant)
            params["variant_id"] = str(variant_obj.id)
    run = db.session.scalar(retained_runs().where(RefreshRun.run_id == run_id))
    data = artifact(run, params, paginate=False) if run is not None else None
    if data is None:
        raise click.ClickException("Exact refresh run unavailable, expired, or outside the selected scope")
    try:
        body = export_artifact(data, format_)
        if output == "-":
            click.echo(body, nl=False)
        else:
            with click.open_file(output, "w", encoding="utf-8", atomic=True) as handle:
                handle.write(body)
    except (OSError, ValueError) as exc:
        raise click.ClickException(f"Refresh artifact export failed: {exc}") from exc


@click.command("prune-refresh-runs", cls=Command)
@with_appcontext
def prune_refresh_runs_command():
    """Remove expired runs and their snapshots; defaults to 90 days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=current_app.config.get("REFRESH_RUN_RETENTION_DAYS", 90))
    ids = db.select(RefreshRun.run_id).where(RefreshRun.started_at < cutoff)
    db.session.execute(db.delete(RefreshChange).where(RefreshChange.run_id.in_(ids)))
    result = db.session.execute(db.delete(RefreshRun).where(RefreshRun.started_at < cutoff))
    db.session.commit()
    click.echo(f"Removed {result.rowcount} expired refresh runs.")

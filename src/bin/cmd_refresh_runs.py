# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Exact-run artifact export and explicit retention cleanup."""

from datetime import datetime, timedelta, timezone
from typing import cast

import click
from flask import current_app
from flask.cli import with_appcontext
from sqlalchemy.engine import CursorResult

from ..extensions import db
from ..models.refresh_run import (
    RefreshChange, RefreshRun, RefreshRunScope, RefreshRunSource, RefreshTarget, RefreshTargetLink,
)
from ..routes.refresh_runs import artifact, export_artifact, find_run
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
    # A supplied but empty name must never widen the export to every scope.
    if project is not None and not project.strip():
        raise click.UsageError("--project must not be empty.")
    if variant is not None and not variant.strip():
        raise click.UsageError("--variant must not be empty.")
    if variant is not None and project is None:
        raise click.UsageError("--variant requires --project.")
    params = {}
    if project is not None:
        project_obj = resolve_project(project)
        params["project_id"] = str(project_obj.id)
        if variant is not None:
            _, variant_obj = resolve_project_variant(project, variant)
            params["variant_id"] = str(variant_obj.id)
    run = find_run(params, run_id)
    if run is None:
        raise click.ClickException("Exact refresh run unavailable, expired, or outside the selected scope")
    data = artifact(run, params, paginate=False)
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
    target_ids = db.select(RefreshTarget.id).where(RefreshTarget.run_id.in_(ids))
    db.session.execute(db.delete(RefreshChange).where(RefreshChange.run_id.in_(ids)))
    db.session.execute(db.delete(RefreshTargetLink).where(RefreshTargetLink.target_id.in_(target_ids)))
    for model in (RefreshTarget, RefreshRunSource, RefreshRunScope):
        db.session.execute(db.delete(model).where(model.run_id.in_(ids)))
    result = cast(CursorResult, db.session.execute(db.delete(RefreshRun).where(RefreshRun.started_at < cutoff)))
    db.session.commit()
    click.echo(f"Removed {result.rowcount} expired refresh runs.")

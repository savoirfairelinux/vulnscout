# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""AI context import/export CLI commands:
``flask export-context`` and ``flask import-context``."""

import json as _json

import click
from flask.cli import with_appcontext

from ..extensions import db
from ..helpers.context_io import (
    build_export_document,
    collect_entries,
    extract_entries,
    import_entries,
)
from ._common import resolve_project, resolve_project_variant


@click.command("export-context")
@click.option("--output", "-o", default="./context-export.json", show_default=True,
              help="File to write the exported context to.")
@click.option("--project", "-p", default=None,
              help="Project name. Restricts the export to a single project's variants.")
@click.option("--variant", "-v", default=None,
              help="Variant name. Requires --project; restricts the export to a single variant.")
@with_appcontext
def export_context_command(output: str, project: str | None, variant: str | None) -> None:
    """Export AI assessment context as a versioned JSON document."""
    if variant and not project:
        click.echo("Error: --variant requires --project.", err=True)
        raise SystemExit(1)

    if project and variant:
        project_obj, variant_obj = resolve_project_variant(project, variant, create=False)
        projects = collect_entries(project_obj.id, variant_obj.id)
    elif project:
        project_obj = resolve_project(project)
        projects = [
            group for group in collect_entries()
            if group["project_name"] == project_obj.name
        ]
    else:
        projects = collect_entries()

    document = build_export_document(projects)
    with open(output, "w") as fh:
        _json.dump(document, fh, indent=2)

    count = sum(len(group["variants"]) for group in projects)
    click.echo(f"Context exported: {output} ({count} entr{'y' if count == 1 else 'ies'})")


@click.command("import-context")
@click.argument("file_path")
@with_appcontext
def import_context_command(file_path: str) -> None:
    """Import AI assessment context from a JSON file.

    Accepts either the versioned export envelope or a bare array of entries.
    Existing context for each matching project/variant is overwritten. Entries
    whose project or variant does not exist are ignored; entries missing
    mandatory fields fail.
    """
    try:
        with open(file_path) as fh:
            data = _json.load(fh)
    except FileNotFoundError:
        click.echo(f"Error: file not found: {file_path}", err=True)
        raise SystemExit(1)
    except (ValueError, OSError):
        click.echo("Error: invalid JSON file.", err=True)
        raise SystemExit(1)

    try:
        entries = extract_entries(data)
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    result = import_entries(entries)

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        click.echo(f"Error: failed to import context: {exc}", err=True)
        raise SystemExit(1)

    imported = result["imported"]
    ignored = result["ignored"]
    failed = result["failed"]

    for item in ignored:
        click.echo(f"  Ignored {_label(item)}: {item.get('reason', '')}", err=True)
    for item in failed:
        click.echo(f"  Failed {_label(item)}: {item.get('reason', '')}", err=True)

    click.echo(
        f"Imported {len(imported)} context entr{'y' if len(imported) == 1 else 'ies'}"
        f" ({len(ignored)} ignored, {len(failed)} failed)"
    )


def _label(item: dict) -> str:
    project = item.get("project_name") or "?"
    variant = item.get("variant_name") or "?"
    return f"{project}/{variant}"

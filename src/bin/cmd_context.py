# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""AI context CLI commands: ``flask export-context``, ``flask import-context`` and
``flask ai-context-attach|ai-context-list|ai-context-detach`` for attached host folders."""

import json as _json

import click
from ._console import Command, echo
from flask.cli import with_appcontext

from ..controllers import host_mounts
from ..controllers.host_mounts import HostMountConflict
from ..extensions import db
from ..helpers.host_mounts import HostHelperError, HostHelperUnavailable
from ..helpers.context_io import (
    build_export_document,
    collect_entries,
    extract_entries,
    import_entries,
    retarget_entries,
)
from ._common import resolve_project, resolve_project_variant


@click.command("export-context", cls=Command)
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
        echo("Error: --variant requires --project.", err=True, role="error")
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
    echo(f"Context exported: {output} ({count} entr{'y' if count == 1 else 'ies'})", role="success")


@click.command("import-context", cls=Command)
@click.argument("file_path")
@click.option("--project", "-p", default=None,
              help="Import every entry into this project, keeping its variant names.")
@click.option("--variant", "-v", default=None,
              help="Requires --project; import the file's single entry into this variant.")
@with_appcontext
def import_context_command(file_path: str, project: str | None, variant: str | None) -> None:
    """Import AI assessment context from a JSON file.

    Accepts either the versioned export envelope or a bare array of entries.
    Each successful entry replaces the project description shared by all its
    variants. It also replaces the matching variant's context, except that an
    unmarked entry with only Context text preserves System and STRIDE.
    Unknown projects or variants and entries marked as never configured are
    ignored; entries missing mandatory fields fail. --project/--variant retarget
    the file's entries and must name an existing project/variant.
    """
    if variant and not project:
        echo("Error: --variant requires --project.", err=True, role="error")
        raise SystemExit(1)

    try:
        with open(file_path) as fh:
            data = _json.load(fh)
    except FileNotFoundError:
        echo(f"Error: file not found: {file_path}", err=True, role="error")
        raise SystemExit(1)
    except (ValueError, OSError):
        echo("Error: invalid JSON file.", err=True, role="error")
        raise SystemExit(1)

    try:
        entries = extract_entries(data)
        if project:
            if variant:
                resolve_project_variant(project, variant, create=False)
            else:
                resolve_project(project)
            entries = retarget_entries(entries, project, variant)
    except ValueError as exc:
        echo(f"Error: {exc}", err=True, role="error")
        raise SystemExit(1)

    result = import_entries(entries)

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        echo(f"Error: failed to import context: {exc}", err=True, role="error")
        raise SystemExit(1)

    imported = result["imported"]
    ignored = result["ignored"]
    failed = result["failed"]

    for item in ignored:
        echo(f"  Ignored {_label(item)}: {item.get('reason', '')}", err=True, role="warning")
    for item in failed:
        echo(f"  Failed {_label(item)}: {item.get('reason', '')}", err=True, role="error")

    echo(
        f"Imported {len(imported)} context entr{'y' if len(imported) == 1 else 'ies'}"
        f" ({len(ignored)} ignored, {len(failed)} failed)",
        role="error" if failed else "warning" if ignored else "success",
    )

    if failed:
        raise SystemExit(1)


def _label(item: dict) -> str:
    project = item.get("project_name") or "?"
    variant = item.get("variant_name") or "?"
    return f"{project}/{variant}"


_SCOPE_OPTIONS = (
    click.option("--project", "-p", default="default", show_default=True, help="Project name."),
    click.option("--variant", "-v", default="default", show_default=True, help="Variant name."),
)


def _scoped(command):
    for option in reversed(_SCOPE_OPTIONS):
        command = option(command)
    return command


@click.command("ai-context-attach", cls=Command)
@click.argument("mappings", nargs=-1, required=True)
@click.option("--host-permit", hidden=True)
@_scoped
@with_appcontext
def ai_context_attach_command(mappings: tuple[str, ...], project: str, variant: str, host_permit: str | None) -> None:
    """Attach host folders to a variant's AI context as ALIAS=HOST_PATH pairs.

    Run this through the host launcher so it can authorize each exact folder.
    The host helper serves the files read-only.
    """
    pairs = []
    for mapping in mappings:
        alias, separator, path = mapping.partition("=")
        if not separator or not alias or not path:
            echo(f"Error: expected ALIAS=HOST_PATH, got '{mapping}'.", err=True, role="error")
            raise SystemExit(1)
        pairs.append((alias, path))
    if not host_permit:
        echo("Error: attach folders with './vulnscout ai-context attach' on the host.", err=True, role="error")
        raise SystemExit(1)
    _, variant_obj = resolve_project_variant(project, variant, create=False)
    failed = False
    for alias, path in pairs:
        try:
            mount, created, warning = host_mounts.attach(variant_obj.id, alias, path, host_permit=host_permit)
        except (HostMountConflict, ValueError) as exc:
            echo(f"Error: {alias}: {exc}", err=True, role="error")
            failed = True
            continue
        except HostHelperUnavailable as exc:
            echo(f"Error: {exc.message}", err=True, role="error")
            raise SystemExit(1)
        except HostHelperError as exc:
            echo(f"Error: {alias}: {exc.message}", err=True, role="error")
            failed = True
            continue
        verb = "Attached" if created else "Already attached"
        echo(f"{verb} {mount['alias']} -> {mount['host_path']} ({project}/{variant}); "
             f"agents use file_id {mount['file_id']}", role="success")
        if warning:
            echo(f"Warning: {alias}: {warning}", err=True, role="warning")
    if failed:
        raise SystemExit(1)


@click.command("ai-context-list", cls=Command)
@_scoped
@click.option("--json", "as_json", is_flag=True, help="Print the attachments as JSON.")
@click.option("--variant-id-only", is_flag=True, hidden=True)
@with_appcontext
def ai_context_list_command(project: str, variant: str, as_json: bool, variant_id_only: bool) -> None:
    """List the host folders attached to a variant, with their availability."""
    _, variant_obj = resolve_project_variant(project, variant, create=False)
    if variant_id_only:
        click.echo(str(variant_obj.id))
        return
    helper_state, rows = host_mounts.list_mounts(variant_obj.id)
    if as_json:
        click.echo(_json.dumps({"helper": helper_state, "mounts": rows}, indent=2))
        return
    if not helper_state["available"] and rows:
        echo(f"Warning: {helper_state['message']}", err=True, role="warning")
    if not rows:
        echo(f"No host folders attached to {project}/{variant}.")
        return
    width = max(len(row["alias"]) for row in rows)
    for row in rows:
        line = f"{row['alias']:<{width}}  {row['status']:<11}  {row['host_path']}"
        if row["status"] != "available" and row["message"]:
            line += f"  ({row['message']})"
        echo(line, role="success" if row["status"] == "available" else "warning")


@click.command("ai-context-detach", cls=Command)
@click.argument("aliases", nargs=-1, required=True)
@_scoped
@with_appcontext
def ai_context_detach_command(aliases: tuple[str, ...], project: str, variant: str) -> None:
    """Detach host folders from a variant's AI context by alias."""
    _, variant_obj = resolve_project_variant(project, variant, create=False)
    failed = False
    for alias in aliases:
        try:
            existed, warning = host_mounts.detach(variant_obj.id, alias)
        except ValueError as exc:
            echo(f"Error: {alias}: {exc}", err=True, role="error")
            failed = True
            continue
        if not existed:
            echo(f"Error: no folder is attached as '{alias}' to {project}/{variant}.", err=True, role="error")
            failed = True
            continue
        echo(f"Detached {alias} from {project}/{variant}", role="success")
        if warning:
            echo(f"Warning: helper registry not updated: {warning}", err=True, role="warning")
    if failed:
        raise SystemExit(1)

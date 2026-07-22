# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""VulnScout JSON and OpenVEX custom-assessment import/export commands."""

import click
import json as _json
import os
from flask.cli import with_appcontext
from ..helpers.assessment_io import (
    is_openvex_doc,
    build_variant_by_name_map,
    build_openvex_doc,
    sanitize_variant_name,
    import_statements,
    build_custom_data_export,
    import_custom_data,
)
from ..models.assessment import Assessment as DBAssessment
from ..models.variant import Variant as DBVariant
from datetime import datetime as _dt, timezone as _tz
from ._common import get_default_author, resolve_project, resolve_project_variant

_JSON_SUFFIX = ".json"


def _load_json_file(file_path: str) -> dict:
    if not os.path.isfile(file_path):
        raise click.ClickException(f"File not found: {file_path}")
    if not file_path.endswith(_JSON_SUFFIX):
        raise click.ClickException("Unsupported file type. Please provide a .json file.")
    try:
        with open(file_path) as file:
            data = _json.load(file)
    except Exception as error:
        raise click.ClickException("Invalid JSON file.") from error
    if not isinstance(data, dict):
        raise click.ClickException("Invalid JSON file.")
    return data


def _print_custom_data_import_result(result: dict) -> None:
    if result.get("status") != "success":
        for error in result.get("errors", []):
            click.echo(f"  {error}", err=True)
        raise click.ClickException("Failed to import VulnScout JSON data.")
    for error in result.get("errors", []):
        click.echo(f"  Warning: {error}", err=True)
    click.echo(
        f"Imported {result['assessments_imported']} assessments"
        f" ({result['assessments_skipped']} skipped as duplicates),"
        f" {result['cvss_imported']} CVSS,"
        f" {result['time_estimates_imported']} time estimates"
    )


@click.command("export-custom-vulnscout-data")
@click.option("--output-dir", default="/scan/outputs", show_default=True,
              help="Directory where the exported file is written.")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", default=None,
              help="Variant name. If empty, all project variants are exported.")
@with_appcontext
def export_custom_vulnscout_data_command(output_dir: str, project: str, variant: str | None) -> None:
    """Export custom VulnScout JSON data for one or all project variants."""
    project_obj = resolve_project(project)
    if variant:
        _, variant_obj = resolve_project_variant(project, variant, create=False)
        variant_ids = [variant_obj.id]
        filename_label = sanitize_variant_name(variant_obj.name)
    else:
        variant_ids = [project_variant.id for project_variant in DBVariant.get_by_project(project_obj.id)]
        filename_label = "all"

    data = build_custom_data_export(variant_ids)
    if not data["assessments"] and not data["cvss"] and not data["time_estimates"]:
        raise click.ClickException("No custom VulnScout data to export.")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"custom_vulnscout_data_{filename_label}{_JSON_SUFFIX}")
    with open(output_path, "w") as file:
        _json.dump(data, file, indent=2)
    click.echo(f"Custom VulnScout data exported: {output_path}")


@click.command("import-custom-vulnscout-data")
@click.argument("file_path")
@click.option("--project", "-p", required=True, help="Project name.")
@with_appcontext
def import_custom_vulnscout_data_command(file_path: str, project: str) -> None:
    """Import custom VulnScout JSON data using its embedded variant metadata."""
    project_obj = resolve_project(project)
    data = _load_json_file(file_path)
    if "version" not in data or is_openvex_doc(data):
        raise click.ClickException("Not a valid VulnScout JSON data file.")

    variant_by_name = build_variant_by_name_map(project_obj.id)
    _print_custom_data_import_result(import_custom_data(data, variant_by_name))


@click.command("export-custom-openvex-assessments")
@click.option("--output-dir", default="/scan/outputs", show_default=True,
              help="Directory where the exported file is written.")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", required=True, help="Variant name to export.")
@with_appcontext
def export_custom_openvex_assessments_command(output_dir: str, project: str, variant: str) -> None:
    """Export custom assessments for one variant as an OpenVEX JSON file."""
    _, variant_obj = resolve_project_variant(project, variant, create=False)
    handmade = DBAssessment.get_by_origin([variant_obj.id])
    if not handmade:
        raise click.ClickException("No custom assessments to export.")

    author = get_default_author()
    document = build_openvex_doc(handmade, author, _dt.now(_tz.utc).isoformat())
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(
        output_dir,
        f"custom_openvex_{sanitize_variant_name(variant_obj.name)}{_JSON_SUFFIX}",
    )
    with open(output_path, "w") as file:
        _json.dump(document, file, indent=2)
    click.echo(f"Custom OpenVEX assessments exported: {output_path}")


@click.command("import-custom-openvex-assessments")
@click.argument("file_path")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", required=True, help="Variant name to import into.")
@with_appcontext
def import_custom_openvex_assessments_command(file_path: str, project: str, variant: str) -> None:
    """Import one OpenVEX JSON document into the specified variant."""
    _, variant_obj = resolve_project_variant(project, variant, create=False)
    data = _load_json_file(file_path)
    if not is_openvex_doc(data):
        raise click.ClickException("Not a valid OpenVEX document.")

    total_created, total_errors, total_skipped = import_statements(
        data["statements"], variant_obj.id
    )
    for error in total_errors:
        click.echo(f"  Warning: {error}", err=True)
    click.echo(
        f"Imported {len(total_created)} OpenVEX assessments"
        f" ({total_skipped} skipped as duplicates)"
    )

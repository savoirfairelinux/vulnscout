# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""VulnScout JSON and OpenVEX custom-assessment import/export commands."""

import click
from ._console import Command, echo
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
    custom_data_version,
    import_custom_data,
    reconcile_review_export,
)
from ..models.assessment import Assessment as DBAssessment
from ..models.variant import Variant as DBVariant
from datetime import datetime as _dt, timezone as _tz
from ._common import get_default_author, resolve_project, resolve_project_variant

_JSON_SUFFIX = ".json"


_PROJECT_MARKER = "x-vulnscout-project"


def _is_project_export(file_path: str, project_name: str) -> bool:
    try:
        return _load_json_file(file_path).get(_PROJECT_MARKER) == project_name
    except click.ClickException:
        return False


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
            echo(f"  {error}", err=True, role="error")
        raise click.ClickException("Failed to import VulnScout JSON data.")
    for error in result.get("errors", []):
        echo(f"  Warning: {error}", err=True, role="warning")
    echo(
        f"Imported {result['assessments_imported']} assessments"
        f" ({result['assessments_skipped']} skipped as duplicates),"
        f" {result['ai_assessments_imported']} AI assessments"
        f" ({result['ai_assessments_skipped']} skipped as duplicates),"
        f" {result['cvss_imported']} CVSS,"
        f" {result['time_estimates_imported']} time estimates", role="warning"
    )


@click.command("export-custom-vulnscout-data", cls=Command)
@click.option("--output-dir", default="/scan/outputs", show_default=True,
              help="Directory where the exported file is written.")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", default=None,
              help="Variant name. If empty, all project variants are exported.")
@click.option("--amend", is_flag=True,
              help="Update the existing output file while preserving stable review ordering.")
@with_appcontext
def export_custom_vulnscout_data_command(output_dir: str, project: str, variant: str | None, amend: bool) -> None:
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
    if (
        not data["assessments"]
        and not data["ai_assessments"]
        and not data["cvss"]
        and not data["time_estimates"]
    ):
        raise click.ClickException("No custom VulnScout data to export.")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"custom_vulnscout_data_{filename_label}{_JSON_SUFFIX}")
    if amend:
        data = reconcile_review_export(_load_json_file(output_path), data)
    with open(output_path, "w") as file:
        _json.dump(data, file, indent=2)
    echo(f"Custom VulnScout data exported: {output_path}", role="success")


@click.command("import-custom-vulnscout-data", cls=Command)
@click.argument("file_path")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option(
    "--use-original-timestamps/--use-current-timestamps",
    default=False,
    help="Choose whether to preserve assessment timestamps from the file.",
)
@with_appcontext
def import_custom_vulnscout_data_command(
    file_path: str,
    project: str,
    use_original_timestamps: bool,
) -> None:
    """Import custom VulnScout JSON data using its embedded variant metadata."""
    project_obj = resolve_project(project)
    data = _load_json_file(file_path)
    if "version" not in data or is_openvex_doc(data):
        raise click.ClickException("Not a valid VulnScout JSON data file.")
    try:
        custom_data_version(data)
    except ValueError as error:
        raise click.ClickException(str(error)) from error

    variant_by_name = build_variant_by_name_map(project_obj.id)
    _print_custom_data_import_result(import_custom_data(
        data,
        variant_by_name,
        use_original_timestamps=use_original_timestamps,
    ))


@click.command("export-custom-openvex-assessments", cls=Command)
@click.option("--output-dir", default="/scan/outputs", show_default=True,
              help="Directory where the exported file is written.")
@click.option("--project", "-p", default="default", show_default=True, help="Project name.")
@click.option("--variant", "-v", default=None,
              help="Variant name to export. If empty, each project variant is exported to its own file.")
@click.option("--amend", is_flag=True,
              help="Update the existing output file while preserving stable review ordering.")
@with_appcontext
def export_custom_openvex_assessments_command(
    output_dir: str, project: str, variant: str | None, amend: bool,
) -> None:
    """Export custom assessments as OpenVEX JSON, one file per variant."""
    if variant:
        project_obj, variant_obj = resolve_project_variant(project, variant, create=False)
        variants = [variant_obj]
    else:
        project_obj = resolve_project(project)
        variants = list(DBVariant.get_by_project(project_obj.id))

    paths = {
        variant_obj.id: os.path.join(
            output_dir, f"custom_openvex_{sanitize_variant_name(variant_obj.name)}{_JSON_SUFFIX}")
        for variant_obj in variants
    }
    if len(set(paths.values())) != len(paths):
        raise click.ClickException(
            "Variant names map to the same output file name; export them one at a time with --variant.")

    author = get_default_author()
    now_iso = _dt.now(_tz.utc).isoformat()
    # An OpenVEX product carries no variant identity, so each variant gets its own document;
    # merging them would mix conflicting statements for the same package and CVE.
    exports = []
    for variant_obj in variants:
        handmade = DBAssessment.get_by_origin([variant_obj.id])
        if handmade:
            exports.append((variant_obj, handmade))
    if not exports:
        raise click.ClickException("No custom assessments to export.")

    os.makedirs(output_dir, exist_ok=True)
    if not variant:
        # A variant without custom assessments must not keep a stale export that a restore would
        # resurrect. Output directories can be shared by projects, so only remove files marked as ours.
        exported_ids = {variant_obj.id for variant_obj, _ in exports}
        for variant_obj in variants:
            stale_path = paths[variant_obj.id]
            if variant_obj.id not in exported_ids and _is_project_export(stale_path, project_obj.name):
                os.remove(stale_path)
                echo(f"Removed stale export: {stale_path}", role="success")
    for variant_obj, handmade in exports:
        document = build_openvex_doc(handmade, author, now_iso, variant_ids=[variant_obj.id])
        output_path = paths[variant_obj.id]
        if amend:
            document = reconcile_review_export(_load_json_file(output_path), document)
        document[_PROJECT_MARKER] = project_obj.name
        with open(output_path, "w") as file:
            _json.dump(document, file, indent=2)
        echo(f"Custom OpenVEX assessments exported: {output_path}", role="success")


@click.command("import-custom-openvex-assessments", cls=Command)
@click.argument("file_path")
@click.option("--project", "-p", default="default", show_default=True, help="Project name.")
@click.option("--variant", "-v", default=None,
              help="Variant name to import into. If empty, the project's only variant is used.")
@click.option(
    "--use-original-timestamps/--use-current-timestamps",
    default=True,
    help="Choose whether to preserve assessment timestamps from the file.",
)
@with_appcontext
def import_custom_openvex_assessments_command(
    file_path: str,
    project: str,
    variant: str | None,
    use_original_timestamps: bool,
) -> None:
    """Import one OpenVEX JSON document into a variant of the project."""
    if variant:
        _, variant_obj = resolve_project_variant(project, variant, create=False)
    else:
        project_obj = resolve_project(project)
        variants = DBVariant.get_by_project(project_obj.id)
        if len(variants) != 1:
            names = ", ".join(project_variant.name for project_variant in variants) or "none"
            raise click.ClickException(
                f"project '{project}' has {len(variants)} variants ({names}); choose one with --variant."
            )
        variant_obj = variants[0]
    data = _load_json_file(file_path)
    if not is_openvex_doc(data):
        raise click.ClickException("Not a valid OpenVEX document.")

    total_created, total_errors, total_skipped = import_statements(
        data["statements"],
        variant_obj.id,
        use_original_timestamps=use_original_timestamps,
    )
    for error in total_errors:
        echo(f"  Warning: {error}", err=True, role="warning")
    echo(
        f"Imported {len(total_created)} OpenVEX assessments"
        f" ({total_skipped} skipped as duplicates)", role="warning"
    )

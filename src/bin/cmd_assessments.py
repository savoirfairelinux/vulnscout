# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Custom assessment import/export commands:
``flask export-custom-assessments`` and ``flask import-custom-assessments``."""

import uuid
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
    import_directory,
    import_custom_data,
)
from ..models.assessment import Assessment as DBAssessment
from ..models.variant import Variant as DBVariant
from datetime import datetime as _dt, timezone as _tz
from ._common import get_default_author, resolve_project, resolve_project_variant

_JSON_SUFFIX = ".json"


@click.command("export-custom-assessments")
@click.option("--output-dir", default="/scan/outputs", show_default=True,
              help="Directory where the exported file is written.")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", default=None,
              help="Variant name. If empty, all variants will be exported.")
@with_appcontext
def export_custom_assessments_command(output_dir: str, project: str, variant: str | None) -> None:
    """Export handmade (custom) assessments as OpenVEX file(s)."""

    author = get_default_author()
    now_iso = _dt.now(_tz.utc).isoformat()

    project_obj = resolve_project(project)

    variants: list[DBVariant]
    if variant:
        _, variant_obj = resolve_project_variant(project, variant, create=False)
        variants = [variant_obj]
    else:
        variants = DBVariant.get_by_project(project_obj.id)

    handmade = DBAssessment.get_by_origin([v.id for v in variants])
    if not handmade:
        click.echo("No custom assessments to export.", err=True)
        raise SystemExit(1)

    os.makedirs(output_dir, exist_ok=True)
    vuln_cache: dict = {}

    def _write_doc(assessments, filename):
        doc = build_openvex_doc(assessments, author, now_iso, vuln_cache)
        out_path = os.path.join(output_dir, filename)
        with open(out_path, "w") as fh:
            _json.dump(doc, fh, indent=2)
        return out_path

    if variant is None:
        by_variant: dict[uuid.UUID, list[DBAssessment]] = {}
        for assess in handmade:
            if assess.variant_id is not None:
                by_variant.setdefault(assess.variant_id, []).append(assess)

        for variant_id, assessments in by_variant.items():
            variant_for_assessment = DBVariant.get_by_id(variant_id)
            assert variant_for_assessment
            filename = sanitize_variant_name(variant_for_assessment.name) + _JSON_SUFFIX
            out_path = _write_doc(assessments, filename)
            click.echo(f"Custom assessments exported: {out_path}")
    else:
        assert variant_obj
        filename = sanitize_variant_name(variant_obj.name) + _JSON_SUFFIX
        out_path = _write_doc(handmade, filename)
        click.echo(f"Custom assessments exported: {out_path}")


@click.command("import-custom-assessments")
@click.argument("file_path")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", default=None, help="Variant name. Defaults to the file name.")
@with_appcontext
def import_custom_assessments_command(file_path: str, project: str, variant: str | None) -> None:
    """Import custom assessments from a .json file or directory of OpenVEX files."""
    if not os.path.isfile(file_path) and not os.path.isdir(file_path):
        click.echo(f"Error: file not found: {file_path}", err=True)
        raise SystemExit(1)

    project_obj = resolve_project(project)

    variant_obj: DBVariant | None = None
    if variant:
        _, variant_obj = resolve_project_variant(project, variant, create=False)

    variant_by_name = build_variant_by_name_map(project_obj.id)
    basename = os.path.basename(file_path)
    total_created: list[dict]
    total_errors: list[dict]
    total_skipped: int
    variant_files_found: int = 0

    if os.path.isdir(file_path):
        if variant:
            click.echo("Error: cannot use the --variant argument with a directory of custom assessments.")
            raise SystemExit(1)

        try:
            total_created, total_errors, total_skipped, variant_files_found = (
                import_directory(file_path, variant_by_name)
            )
        except ValueError as exc:
            click.echo(f"Error: {exc}", err=True)
            raise SystemExit(1)

        if variant_files_found == 0 and not total_created:
            click.echo(
                "Error: no valid OpenVEX files matching known "
                "variants found in directory.", err=True
            )
            for err in total_errors:
                click.echo(f"  {err}", err=True)
            raise SystemExit(1)

    elif file_path.endswith(_JSON_SUFFIX):
        try:
            with open(file_path) as fh:
                data = _json.load(fh)
        except Exception:
            click.echo("Error: invalid JSON file.", err=True)
            raise SystemExit(1)

        # Custom-data export format (web "export custom data" button):
        # {version, assessments, cvss, time_estimates}. Routed to the
        # dedicated importer; the embedded per-item variant is used unless
        # --variant forces a target.
        if isinstance(data, dict) and "version" in data and not is_openvex_doc(data):
            result = import_custom_data(
                data, variant_by_name,
                variant_obj.id if variant_obj is not None else None,
            )
            if result.get("status") != "success":
                click.echo("Error: failed to import custom-data file.", err=True)
                for err in result.get("errors", []):
                    click.echo(f"  {err}", err=True)
                raise SystemExit(1)
            for err in result.get("errors", []):
                click.echo(f"  Warning: {err}", err=True)
            click.echo(
                f"Imported {result['assessments_imported']} assessments"
                f" ({result['assessments_skipped']} skipped as duplicates),"
                f" {result['cvss_imported']} CVSS,"
                f" {result['time_estimates_imported']} time estimates"
            )
            return

        # OpenVEX single-document format: requires a variant (from --variant
        # or the filename matching an existing variant name).
        if variant:
            assert variant_obj
        else:
            variant_name = basename[:-len(_JSON_SUFFIX)]
            variant_obj = variant_by_name.get(variant_name)
            if variant_obj is None:
                click.echo(
                    f"Error: no variant found matching filename "
                    f"'{variant_name}'. The JSON filename must "
                    f"correspond to an existing variant name. "
                    "Hint: use --variant to specify another name.",
                    err=True,
                )
                raise SystemExit(1)

        if not is_openvex_doc(data):
            click.echo("Error: not a valid OpenVEX document.", err=True)
            raise SystemExit(1)

        total_created, total_errors, total_skipped = import_statements(
            data["statements"], variant_obj.id
        )
    else:
        click.echo(
            "Error: unsupported file type. "
            "Please provide a .json file or directory.",
            err=True,
        )
        raise SystemExit(1)

    for err in total_errors:
        click.echo(f"  Warning: {err}", err=True)

    click.echo(
        f"Imported {len(total_created)} assessments"
        f" ({total_skipped} skipped as duplicates)"
    )

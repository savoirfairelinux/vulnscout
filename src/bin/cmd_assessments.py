# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Custom assessment import/export commands:
``flask export-custom-assessments`` and ``flask import-custom-assessments``."""

import click
import os
from flask.cli import with_appcontext


@click.command("export-custom-assessments")
@click.option("--output-dir", default="/scan/outputs", show_default=True,
              help="Directory where the exported tar.gz is written.")
@with_appcontext
def export_custom_assessments_command(output_dir: str) -> None:
    """Export handmade (custom) assessments as a tar.gz of OpenVEX files."""
    from ..helpers.assessment_io import build_openvex_archive
    from ..models.assessment import Assessment as DBAssessment
    from ..models.variant import Variant as DBVariant

    handmade = DBAssessment.get_handmade()
    if not handmade:
        click.echo("No custom assessments to export.", err=True)
        raise SystemExit(1)

    author = os.getenv("AUTHOR_NAME", "Savoir-faire Linux")
    variant_names = {str(v.id): v.name for v in DBVariant.get_all()}

    archive_bytes = build_openvex_archive(handmade, variant_names, author)
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "custom_assessments.tar.gz")
    with open(out_path, "wb") as fh:
        fh.write(archive_bytes)
    click.echo(f"Custom assessments exported: {out_path}")


@click.command("import-custom-assessments")
@click.argument("file_path")
@with_appcontext
def import_custom_assessments_command(file_path: str) -> None:
    """Import custom assessments from a .json or .tar.gz OpenVEX file."""
    import json as _json
    from ..helpers.assessment_io import (
        is_openvex_doc,
        import_statements as _import_openvex_statements,
        build_variant_by_name_map,
        import_archive_bytes,
    )

    if not os.path.isfile(file_path):
        click.echo(f"Error: file not found: {file_path}", err=True)
        raise SystemExit(1)

    variant_by_name = build_variant_by_name_map()
    basename = os.path.basename(file_path)
    total_created: list[dict] = []
    total_errors: list[dict] = []
    total_skipped = 0

    if file_path.endswith(".tar.gz") or file_path.endswith(".tgz"):
        try:
            with open(file_path, "rb") as fh:
                archive_bytes = fh.read()
            total_created, total_errors, total_skipped, found = import_archive_bytes(
                archive_bytes, variant_by_name
            )
        except ValueError:
            click.echo("Error: unable to open tar.gz archive.", err=True)
            raise SystemExit(1)

        if found == 0 and not total_created:
            click.echo(
                "Error: no valid OpenVEX files matching known "
                "variants found in archive.", err=True
            )
            for err in total_errors:
                click.echo(f"  {err}", err=True)
            raise SystemExit(1)

    elif file_path.endswith(".json"):
        variant_name = basename[: -len(".json")]
        variant = variant_by_name.get(variant_name)
        if variant is None:
            click.echo(
                f"Error: no variant found matching filename "
                f"'{variant_name}'. The JSON filename must "
                f"correspond to an existing variant name.",
                err=True,
            )
            raise SystemExit(1)

        try:
            with open(file_path) as fh:
                data = _json.load(fh)
        except Exception:
            click.echo("Error: invalid JSON file.", err=True)
            raise SystemExit(1)

        if not is_openvex_doc(data):
            click.echo("Error: not a valid OpenVEX document.", err=True)
            raise SystemExit(1)

        total_created, total_errors, total_skipped = _import_openvex_statements(
            data["statements"], variant.id
        )
    else:
        click.echo(
            "Error: unsupported file type. "
            "Please provide a .json or .tar.gz file.",
            err=True,
        )
        raise SystemExit(1)

    for err in total_errors:
        click.echo(f"  Warning: {err}", err=True)

    click.echo(
        f"Imported {len(total_created)} assessments"
        f" ({total_skipped} skipped as duplicates)"
    )

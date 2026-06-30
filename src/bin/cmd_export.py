# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""SBOM export and report generation commands: ``flask export`` and ``flask report``."""

from __future__ import annotations

from ..controllers import ControllersCache
from ..controllers.projects import ProjectController
from ..models.variant import Variant as DBVariant
from ..views.spdx import SPDX
from ..views.spdx3 import SPDX3
from ..views.cyclonedx import CycloneDx
from ..views.openvex import OpenVex
from ..views.templates import Templates
from .cmd_process import evaluate_condition
from ._common import get_default_author
from ..helpers.export_scope import compute_export_scope
from datetime import date as _date
import click
import json
import os
import uuid
from flask.cli import with_appcontext


@click.command("export")
@click.option("--format", "export_format", default="spdx3",
              type=click.Choice(["spdx2", "spdx3", "cdx14", "cdx15", "cdx16", "openvex"], case_sensitive=False),
              show_default=True, help="Output format.")
@click.option("--output-dir", default="/scan/outputs", show_default=True,
              help="Directory where the exported file is written.")
@click.option("--project", "-p", default=None,
              help="Project name. When set, the export is scoped to this project.")
@click.option("--variant", "-v", default=None,
              help="Variant name. When omitted, all variants of the project are exported.")
@click.option("--variant-id", "variant_id", default=None,
              help="Variant UUID. Takes precedence over --project/--variant and "
                   "resolves the variant unambiguously (use when variant names "
                   "are not unique within a project).")
@with_appcontext
def export_command(
    export_format: str,
    output_dir: str,
    project: str | None,
    variant: str | None,
    variant_id: str | None,
) -> None:
    """Export the current project data as an SBOM (SPDX, CycloneDX, or OpenVEX)."""
    # Resolve the optional project/variant scope so the export only contains
    # the packages/vulnerabilities/assessments of the selected variant (or all
    # variants of the project when only --project is given).  A missing
    # project/variant is non-fatal: we warn and fall back to a global export so
    # existing pipelines keep working.
    scope = None
    if variant_id:
        # Exact-UUID scoping (used by the Grype trigger).  Avoids the ambiguity
        # of resolving a variant by name when several variants share the same
        # name within a project.
        try:
            vid = uuid.UUID(str(variant_id))
        except (ValueError, TypeError):
            click.echo(f"Warning: invalid variant id '{variant_id}'; exporting all data.", err=True)
        else:
            if DBVariant.get_by_id(vid) is None:
                click.echo(f"Warning: variant id '{variant_id}' not found; exporting all data.", err=True)
            else:
                scope = compute_export_scope(variant_id=vid)
    elif project:
        project_obj = ProjectController.get_by_name(project)
        if project_obj is None:
            click.echo(f"Warning: project '{project}' not found; exporting all data.", err=True)
        elif variant:
            variant_obj = DBVariant.get_by_name_and_project(variant, project_obj.id)
            if variant_obj is None:
                click.echo(
                    f"Warning: variant '{variant}' not found in project '{project}'; "
                    f"exporting the whole project.", err=True)
                scope = compute_export_scope(project_id=project_obj.id)
            else:
                scope = compute_export_scope(variant_id=variant_obj.id)
        else:
            scope = compute_export_scope(project_id=project_obj.id)

    ctrls = ControllersCache(scope=scope)
    ctrls.packages._preload_cache()
    author = get_default_author()

    os.makedirs(output_dir, exist_ok=True)
    fmt = export_format.lower()

    try:
        if fmt == "spdx2":
            spdx = SPDX(ctrls)
            content = spdx.output_as_json(author=author)
            out_path = os.path.join(output_dir, "sbom_spdx_v2_3.spdx.json")
            with open(out_path, "w") as fh:
                fh.write(content)
        elif fmt == "spdx3":
            spdx3 = SPDX3(ctrls)
            content = spdx3.output_as_json(author)
            out_path = os.path.join(output_dir, "sbom_spdx_v3_0.spdx.json")
            with open(out_path, "w") as fh:
                fh.write(content)
        elif fmt in ("cdx14", "cdx15", "cdx16"):
            version_map = {"cdx14": 4, "cdx15": 5, "cdx16": 6}
            cdx = CycloneDx(ctrls)
            content = cdx.output_as_json(version_map[fmt], author)
            ver = fmt[3:5]  # '14' → '1_4'
            out_path = os.path.join(output_dir, f"sbom_cyclonedx_v{ver[0]}_{ver[1]}.cdx.json")
            with open(out_path, "w") as fh:
                fh.write(content)
        elif fmt == "openvex":
            opvx = OpenVex(ctrls)
            content = json.dumps(opvx.to_dict(True, author), indent=2)
            out_path = os.path.join(output_dir, "openvex.json")
            with open(out_path, "w") as fh:
                fh.write(content)
        click.echo(f"Export written: {out_path}")
    except Exception as e:
        click.echo(f"Error: could not export '{export_format}': {e}", err=True)
        raise SystemExit(1)


@click.command("report")
@click.argument("template_name")
@click.option("--output-dir", default="/scan/outputs", show_default=True,
              help="Directory where generated reports are written.")
@click.option("--format", "output_format", default=None,
              help="Output format override: pdf or html (default: use template extension).")
@with_appcontext
def report_command(template_name: str, output_dir: str, output_format: str | None) -> None:
    """Render TEMPLATE_NAME and write the result to OUTPUT_DIR.

    Also honours the GENERATE_DOCUMENTS env var (comma-separated list) when
    invoked; TEMPLATE_NAME is always generated regardless.
    """
    controllers = ControllersCache()
    templ = Templates(controllers)

    # Reuse failed_vulns from flask process if available, otherwise evaluate now
    match_condition = os.getenv("MATCH_CONDITION", "")
    failed_vulns: list | None = None
    if match_condition:
        cache_path = "/tmp/vulnscout_matched_vulns.json"
        if os.path.exists(cache_path):
            try:
                with open(cache_path) as _f:
                    failed_vulns = json.load(_f)
            except Exception:
                pass  # TODO log error somewhere?

        if failed_vulns is None:
            failed_vulns = evaluate_condition(controllers.vulnerabilities, controllers.assessments, match_condition)

    metadata = {
        "author": get_default_author(),
        "client_name": os.getenv("CLIENT_NAME", ""),
        "export_date": _date.today().isoformat(),
        "ignore_before": "1970-01-01T00:00",
        "only_epss_greater": 0.0,
        "scan_date": "unknown date",
        "failed_vulns": failed_vulns or [],
        "match_condition": match_condition,
    }

    # Collect all templates to generate (deduplicated)
    to_generate = [template_name]
    extra = os.getenv("GENERATE_DOCUMENTS", "")
    if extra:
        for t in extra.split(","):
            t = t.strip()
            if t and t not in to_generate:
                to_generate.append(t)

    os.makedirs(output_dir, exist_ok=True)

    for tmpl in to_generate:
        # Always use the bare filename — Jinja2 FileSystemLoader does not
        # accept absolute or relative paths, only names within its search dirs.
        tmpl = os.path.basename(tmpl)
        try:
            content = templ.render(tmpl, **metadata)
            fmt = output_format
            if fmt is None and tmpl.endswith(".adoc"):
                fmt = "adoc"  # keep as adoc by default

            if fmt == "pdf" and tmpl.endswith(".adoc"):
                data = templ.adoc_to_pdf(content)
                out_path = os.path.join(output_dir, tmpl + ".pdf")
                with open(out_path, "wb") as fh:
                    fh.write(data)
            elif fmt == "html" and tmpl.endswith(".adoc"):
                data = templ.adoc_to_html(content)
                out_path = os.path.join(output_dir, tmpl + ".html")
                with open(out_path, "wb") as fh:
                    fh.write(data)
            else:
                out_path = os.path.join(output_dir, tmpl)
                with open(out_path, "w") as fh:
                    fh.write(content)

            click.echo(f"Report written: {out_path}")
        except Exception as e:
            click.echo(f"Warning: could not generate '{tmpl}': {e}", err=True)

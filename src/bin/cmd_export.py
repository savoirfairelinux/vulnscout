# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""SBOM export and report generation commands: ``flask export`` and ``flask report``."""

from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController
from ..controllers.scans import ScanController
from ..controllers.sbom_documents import SBOMDocumentController
from .cmd_process import evaluate_condition
import click
import json
from flask.cli import with_appcontext


@click.command("export")
@click.option("--format", "export_format", default="spdx3",
              type=click.Choice(["spdx2", "spdx3", "cdx14", "cdx15", "cdx16", "openvex"], case_sensitive=False),
              show_default=True, help="Output format.")
@click.option("--output-dir", default="/scan/outputs", show_default=True,
              help="Directory where the exported file is written.")
@with_appcontext
def export_command(export_format: str, output_dir: str) -> None:
    """Export the current project data as an SBOM (SPDX, CycloneDX, or OpenVEX)."""
    from ..controllers.packages import PackagesController
    from ..controllers.vulnerabilities import VulnerabilitiesController
    from ..controllers.assessments import AssessmentsController
    from ..views.spdx import SPDX
    from ..views.spdx3 import SPDX3
    from ..views.cyclonedx import CycloneDx
    from ..views.openvex import OpenVex
    import os as _os
    import json as _json

    pkgCtrl = PackagesController()
    pkgCtrl._preload_cache()
    vulnCtrl = VulnerabilitiesController(pkgCtrl)
    assessCtrl = AssessmentsController(pkgCtrl, vulnCtrl)
    ctrls = {"packages": pkgCtrl, "vulnerabilities": vulnCtrl, "assessments": assessCtrl}
    author = _os.getenv("AUTHOR_NAME", "Savoir-faire Linux")

    _os.makedirs(output_dir, exist_ok=True)
    fmt = export_format.lower()

    try:
        if fmt == "spdx2":
            spdx = SPDX(ctrls)
            content = spdx.output_as_json(author)
            out_path = _os.path.join(output_dir, "sbom_spdx_v2_3.spdx.json")
            with open(out_path, "w") as fh:
                fh.write(content)
        elif fmt == "spdx3":
            spdx3 = SPDX3(ctrls)
            content = spdx3.output_as_json(author)
            out_path = _os.path.join(output_dir, "sbom_spdx_v3_0.spdx.json")
            with open(out_path, "w") as fh:
                fh.write(content)
        elif fmt in ("cdx14", "cdx15", "cdx16"):
            version_map = {"cdx14": 4, "cdx15": 5, "cdx16": 6}
            cdx = CycloneDx(ctrls)
            content = cdx.output_as_json(version_map[fmt], author)
            ver = fmt[3:5]  # '14' → '1_4'
            out_path = _os.path.join(output_dir, f"sbom_cyclonedx_v{ver[0]}_{ver[1]}.cdx.json")
            with open(out_path, "w") as fh:
                fh.write(content)
        elif fmt == "openvex":
            opvx = OpenVex(ctrls)
            content = _json.dumps(opvx.to_dict(True, author), indent=2)
            out_path = _os.path.join(output_dir, "openvex.json")
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
    from datetime import date as _date
    from ..controllers.packages import PackagesController
    from ..controllers.vulnerabilities import VulnerabilitiesController
    from ..controllers.assessments import AssessmentsController
    from ..views.templates import Templates
    import os as _os

    pkgCtrl = PackagesController()
    vulnCtrl = VulnerabilitiesController(pkgCtrl)
    assessCtrl = AssessmentsController(pkgCtrl, vulnCtrl)
    vulnCtrl = VulnerabilitiesController.from_dict(pkgCtrl, vulnCtrl.to_dict())

    controllers = {
        "packages": pkgCtrl,
        "vulnerabilities": vulnCtrl,
        "assessments": assessCtrl,
        "projects": ProjectController(),
        "variants": VariantController(),
        "scans": ScanController(),
        "sbom_documents": SBOMDocumentController(),
    }
    templ = Templates(controllers)

    # Reuse failed_vulns from flask process if available, otherwise evaluate now
    match_condition = _os.getenv("MATCH_CONDITION", "")
    failed_vulns: list = []
    if match_condition:
        cache_path = "/tmp/vulnscout_matched_vulns.json"
        if _os.path.exists(cache_path):
            try:
                with open(cache_path) as _f:
                    failed_vulns = json.load(_f)
            except Exception:
                failed_vulns = evaluate_condition(controllers, match_condition)
        else:
            failed_vulns = evaluate_condition(controllers, match_condition)

    metadata = {
        "author": _os.getenv("AUTHOR_NAME", "Savoir-faire Linux"),
        "client_name": _os.getenv("CLIENT_NAME", ""),
        "export_date": _date.today().isoformat(),
        "ignore_before": "1970-01-01T00:00",
        "only_epss_greater": 0.0,
        "scan_date": "unknown date",
        "failed_vulns": failed_vulns,
        "match_condition": match_condition,
    }

    # Collect all templates to generate (deduplicated)
    to_generate = [template_name]
    extra = _os.getenv("GENERATE_DOCUMENTS", "")
    if extra:
        for t in extra.split(","):
            t = t.strip()
            if t and t not in to_generate:
                to_generate.append(t)

    _os.makedirs(output_dir, exist_ok=True)

    for tmpl in to_generate:
        # Always use the bare filename — Jinja2 FileSystemLoader does not
        # accept absolute or relative paths, only names within its search dirs.
        tmpl = _os.path.basename(tmpl)
        try:
            content = templ.render(tmpl, **metadata)
            fmt = output_format
            if fmt is None and tmpl.endswith(".adoc"):
                fmt = "adoc"  # keep as adoc by default

            if fmt == "pdf" and tmpl.endswith(".adoc"):
                data = templ.adoc_to_pdf(content)
                out_path = _os.path.join(output_dir, tmpl + ".pdf")
                with open(out_path, "wb") as fh:
                    fh.write(data)
            elif fmt == "html" and tmpl.endswith(".adoc"):
                data = templ.adoc_to_html(content)
                out_path = _os.path.join(output_dir, tmpl + ".html")
                with open(out_path, "wb") as fh:
                    fh.write(data)
            else:
                out_path = _os.path.join(output_dir, tmpl)
                with open(out_path, "w") as fh:
                    fh.write(content)

            click.echo(f"Report written: {out_path}")
        except Exception as e:
            click.echo(f"Warning: could not generate '{tmpl}': {e}", err=True)

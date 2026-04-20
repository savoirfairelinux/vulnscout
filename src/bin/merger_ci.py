#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This python job aggregates packages, vulnerabilities and assessments from
# source files, enriches them with VEX info and persists everything to the
# database.  Output SBOM files are still generated for downstream consumption
# but packages / vulnerabilities / assessments are no longer written to
# intermediate JSON files — the DB is the single source of truth.
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..views.cyclonedx import CycloneDx
from ..views.spdx import SPDX
from ..views.fast_spdx import FastSPDX
from ..views.fast_spdx3 import FastSPDX3
from ..views.openvex import OpenVex
from ..views.yocto_vulns import YoctoVulns
from ..views.grype_vulns import GrypeVulns
from ..views.templates import Templates
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController
from ..controllers.conditions_parser import ConditionParser
from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController
from ..controllers.scans import ScanController
from ..controllers.sbom_documents import SBOMDocumentController
from ..models.sbom_document import SBOMDocument
from ..models.scan import Scan as ScanModel
from ..models.finding import Finding as FindingModel
from ..models.observation import Observation
from ..models.project import Project as ProjectModel
from ..helpers.verbose import verbose
from ..helpers.env_vars import get_bool_env
from ..extensions import batch_session, db as _db
import click
import json
import os
import typing
import uuid
from flask.cli import with_appcontext
from sqlalchemy import and_, exists

DEFAULT_VARIANT_NAME = "default"


def _ts_key(ts) -> str:
    """Normalise a timestamp (str or datetime) to an ISO string for comparison."""
    if ts is None:
        return ""
    if isinstance(ts, str):
        return ts
    try:
        return ts.isoformat()
    except Exception:
        return str(ts)


def post_treatment(controllers, documents=None):
    """Enrich vulnerabilities with EPSS scores."""

    controllers["vulnerabilities"].fetch_epss_scores()


def evaluate_condition(controllers, condition):
    """Evaluate a condition and return the list of vulnerability IDs that trigger it."""
    parser = ConditionParser()
    failed_vulns = []
    for (vuln_id, vuln) in controllers["vulnerabilities"].vulnerabilities.items():
        data = {
            "id": vuln_id,
            "cvss": vuln.severity_max_score or vuln.severity_min_score or False,
            "cvss_min": vuln.severity_min_score or vuln.severity_max_score or False,
            "epss": vuln.epss["score"] or False,
            "effort": False if vuln.effort["likely"] is None else vuln.effort["likely"].total_seconds,
            "effort_min": False if vuln.effort["optimistic"] is None else vuln.effort["optimistic"].total_seconds,
            "effort_max": False if vuln.effort["pessimistic"] is None else vuln.effort["pessimistic"].total_seconds,
            "fixed": False,
            "ignored": False,
            "affected": False,
            "pending": True,
            "new": True
        }

        last_assessment = None
        for assessment in controllers["assessments"].gets_by_vuln(vuln_id):
            if last_assessment is None or _ts_key(last_assessment.timestamp) < _ts_key(assessment.timestamp):
                last_assessment = assessment
        if last_assessment:
            data["fixed"] = last_assessment.status in ["fixed", "resolved", "resolved_with_pedigree"]
            data["ignored"] = last_assessment.status in ["not_affected", "false_positive"]
            data["affected"] = last_assessment.status in ["affected", "exploitable"]
            data["pending"] = last_assessment.status in ["under_investigation", "in_triage"]
            data["new"] = False
        if parser.evaluate(condition, data):
            failed_vulns.append(vuln_id)
            print(f"Vulnerability triggered fail condition: {vuln_id}")  # output in stdout to be catched by the CI
    return failed_vulns


def read_inputs(controllers, scan_id=None):
    """Parse all SBOM documents registered in the DB.

    When *scan_id* is provided only the documents that belong to that scan
    are parsed.  This prevents reprocessing older scans' assessment files
    under the wrong variant when multiple scans/variants exist in the DB.
    """
    cdx = CycloneDx(controllers)
    spdx = SPDX(controllers)
    fastspdx3 = FastSPDX3(controllers)
    fastspdx = FastSPDX(controllers)
    openvex = OpenVex(controllers)
    yocto = YoctoVulns(controllers)
    grype = GrypeVulns(controllers)
    templates = Templates(controllers)

    use_fastspdx = get_bool_env('IGNORE_PARSING_ERRORS', False)
    if use_fastspdx:
        verbose("merger_ci: Using FastSPDX parser")

    pkgCtrl = controllers["packages"]
    docs = SBOMDocument.get_by_scan(scan_id) if scan_id is not None else SBOMDocument.get_all()

    for doc in docs:
        pkgCtrl.set_sbom_document(doc.id)
        try:
            verbose(f"merger_ci: Reading {doc.path} (format={doc.format!r})")
            with open(doc.path, "r") as f:
                data = json.load(f)

            # Prefer the explicit format stored at registration time (set by
            # scan.sh via the --spdx / --cdx / --openvex / --yocto-cve / --grype
            # options) and fall back to content-sniffing only when it is absent.
            fmt = doc.format  # 'spdx', 'cdx', 'openvex', 'yocto_cve_check', 'grype', or None

            if fmt == "spdx" or (
                fmt is None and (
                    fastspdx3.could_parse_spdx(data) or "spdxVersion" in data or doc.source_name.endswith(".spdx.json")
                )
            ):
                if fastspdx3.could_parse_spdx(data):
                    fastspdx3.parse_from_dict(data)
                elif use_fastspdx:
                    fastspdx.parse_from_dict(data)
                else:
                    spdx.load_from_file(doc.path)
                    spdx.parse_and_merge()
            elif fmt == "cdx" or (
                fmt is None and (
                    data.get("bomFormat") == "CycloneDX"
                    or doc.source_name.endswith(".cdx.json")
                )
            ):
                cdx.load_from_dict(data)
                cdx.parse_and_merge()
            elif fmt == "openvex" or (fmt is None and "statements" in data):
                openvex.load_from_dict(data)
            elif fmt == "yocto_cve_check" or (fmt is None and "package" in data and "matches" not in data):
                yocto.load_from_dict(data)
            elif fmt == "grype" or (fmt is None and "matches" in data):
                grype.load_from_dict(data)
            else:
                print(f"Warning: unknown format for {doc.path}, skipping")
        except FileNotFoundError:
            pass  # File was already merged into the DB and cleaned up — expected.
        except Exception as e:
            if not use_fastspdx:
                print(f"Error parsing {doc.path}: {e}")
                print("Hint: set IGNORE_PARSING_ERRORS=true to ignore this error")
                raise e
            else:
                print(f"Ignored: Error parsing {doc.path}: {e}")
        finally:
            pkgCtrl.set_sbom_document(None)

    return {
        "cdx": cdx,
        "templates": templates
    }


@click.command("merge")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", default=None,
              help=f"Variant name (defaults to '{DEFAULT_VARIANT_NAME}').")
@click.option("--spdx", "spdx_inputs", multiple=True, type=click.Path(exists=True),
              help="SPDX SBOM file (may be repeated).")
@click.option("--cdx", "cdx_inputs", multiple=True, type=click.Path(exists=True),
              help="CycloneDX SBOM file (may be repeated).")
@click.option("--openvex", "openvex_inputs", multiple=True, type=click.Path(exists=True),
              help="OpenVEX file (may be repeated).")
@click.option("--yocto-cve", "yocto_cve_inputs", multiple=True, type=click.Path(exists=True),
              help="Yocto CVE-check JSON file (may be repeated).")
@click.option("--grype", "grype_inputs", multiple=True, type=click.Path(exists=True),
              help="Grype vulnerability JSON file (may be repeated).")
@with_appcontext
def create_project_context(
    project: str,
    variant: str | None,
    spdx_inputs: tuple,
    cdx_inputs: tuple,
    openvex_inputs: tuple,
    yocto_cve_inputs: tuple,
    grype_inputs: tuple,
) -> None:
    """Register SBOM inputs into the database under a named project/variant scan.

    Use --spdx, --cdx, --openvex, --yocto-cve and --grype to pass files with
    their explicit format so that parsing is unambiguous.  Each option may be
    repeated for multiple files of the same format.
    When no variant is given, inputs go into a scan under the 'default' variant.
    """
    variant_name = variant or DEFAULT_VARIANT_NAME

    project_obj = ProjectController.get_or_create(project)
    variant_obj = VariantController.get_or_create(variant_name, project_obj.id)

    # Determine scan type: if there are any SBOM inputs (spdx, cdx, yocto_cve)
    # or openvex, it's an "sbom" scan.  Grype-only → "tool" scan.
    has_sbom_inputs = bool(spdx_inputs or cdx_inputs or openvex_inputs or yocto_cve_inputs)
    scan_type = "sbom" if has_sbom_inputs else "tool"
    scan_description = "empty description"
    scan_source = "grype" if (not has_sbom_inputs and grype_inputs) else None

    scan = ScanController.create(scan_description, variant_obj.id, scan_type=scan_type,
                                 scan_source=scan_source)
    click.echo(f"project='{project}' variant='{variant_name}' scan={scan.id} type={scan_type}")

    format_groups: list[tuple[tuple, str]] = [
        (spdx_inputs, "spdx"),
        (cdx_inputs, "cdx"),
        (openvex_inputs, "openvex"),
        (yocto_cve_inputs, "yocto_cve_check"),
        (grype_inputs, "grype"),
    ]
    for files, fmt in format_groups:
        for sbom_file in files:
            abs_path = os.path.abspath(sbom_file)
            SBOMDocumentController.create(abs_path, os.path.basename(sbom_file), scan.id, format=fmt)
            click.echo(f"  + [{fmt}] {sbom_file}")


@click.command("process")
@with_appcontext
def process_command() -> None:
    """Parse all SBOM inputs, persist results to the DB and generate output files."""
    _run_main()


def _run_main() -> dict:
    """Core processing logic (usable both from the CLI command and directly)."""
    pkgCtrl = PackagesController()
    # pkgCtrl._preload_cache()  # bulk-load pkg UUIDs + findings into cache; eliminates per-vuln SELECT queries
    vulnCtrl = VulnerabilitiesController(pkgCtrl)
    assessCtrl = AssessmentsController(pkgCtrl, vulnCtrl)
    latest_scan = ScanModel.get_latest()
    if latest_scan:
        assessCtrl.current_variant_id = latest_scan.variant_id
    controllers = {
        "packages": pkgCtrl,
        "vulnerabilities": vulnCtrl,
        "assessments": assessCtrl
    }

    # Wrap all ingestion + post-treatment inside batch_session so that the
    # hundreds/thousands of individual model commit() calls are deferred to a
    # single SQLite transaction at the end of the block.
    with batch_session():
        # Disable SAVEPOINTs during bulk ingestion for better performance
        vulnCtrl.use_savepoints = False
        assessCtrl.use_savepoints = False

        scan_id = latest_scan.id if latest_scan else None
        read_inputs(controllers, scan_id=scan_id)
        verbose("merger_ci: Finished reading inputs")

    # ← single COMMIT happens here
    verbose("merger_ci: DB commit done")

    # In interactive (serve) mode the webapp background thread handles all
    # enrichment after the loading screen clears.  Running it here too would
    # block the shell from writing the __END_OF_SCAN_SCRIPT__ marker, keeping
    # the frontend stuck at Step 1.
    # In batch / CI mode (INTERACTIVE_MODE != "true") we run it here so that
    # EPSS scores are available for --match-condition evaluation.
    interactive_mode = get_bool_env("INTERACTIVE_MODE", False)
    if not interactive_mode:
        verbose("merger_ci: Starting post-treatment (EPSS enrichment)")
        post_treatment(controllers)
        verbose("merger_ci: Post-treatment done")
    else:
        verbose("merger_ci: Skipping CLI enrichment in interactive mode (webapp background thread will handle it)")

    match_condition = os.getenv("MATCH_CONDITION", "")
    failed_vulns = []
    if match_condition:
        verbose("merger_ci: Start evaluating conditions")
        failed_vulns = evaluate_condition(controllers, match_condition)
        verbose("merger_ci: Finished evaluating conditions")
        # Cache result so flask report can reuse it without re-evaluating
        try:
            with open("/tmp/vulnscout_matched_vulns.json", "w") as _f:
                json.dump(failed_vulns, _f)
        except Exception:
            pass

    verbose("merger_ci: Start exporting results")
    verbose("merger_ci: Finished exporting results")

    # Populate the observations table: link findings to the scan they were
    # discovered in.  Only findings whose package appears in one of this scan's
    # SBOM documents are eligible — linking ALL global findings would break
    # variant-scoped filtering when multiple scans/variants exist in the DB.
    verbose("merger_ci: Populating observations table")
    try:
        from ..models.sbom_package import SBOMPackage as SBOMPkg
        from ..models.sbom_document import SBOMDocument as SBOMDoc

        latest_scan = ScanModel.get_latest()
        if latest_scan:
            # 1. Collect package_ids referenced by this scan's SBOM documents
            package_ids_in_scan = list(_db.session.execute(
                _db.select(SBOMPkg.package_id)
                .join(SBOMDoc, SBOMPkg.sbom_document_id == SBOMDoc.id)
                .where(SBOMDoc.scan_id == latest_scan.id)
                .distinct()
            ).scalars().all())

            # 2. Collect vuln IDs that were actually encountered in this run's
            #    input files (populated by VulnerabilitiesController.add()).
            encountered_vuln_ids = list(vulnCtrl._encountered_this_run)

            if package_ids_in_scan and encountered_vuln_ids:
                # 3. Find findings for (packages in scan) × (vulns in this run)
                #    that are not yet observed in this scan.
                new_finding_ids = list(_db.session.execute(
                    _db.select(FindingModel.id)
                    .where(FindingModel.package_id.in_(package_ids_in_scan))
                    .where(FindingModel.vulnerability_id.in_(encountered_vuln_ids))
                    .where(
                        ~exists(
                            _db.select(1).select_from(Observation).where(
                                and_(
                                    Observation.finding_id == FindingModel.id,
                                    Observation.scan_id == latest_scan.id
                                )
                            )
                        )
                    )
                ).scalars().all())

                if new_finding_ids:
                    new_observations = [
                        Observation(finding_id=fid, scan_id=latest_scan.id)
                        for fid in new_finding_ids
                    ]
                    with batch_session():
                        _db.session.bulk_save_objects(new_observations)
                    verbose(f"merger_ci: Observations created for scan {latest_scan.id} ({len(new_observations)} new)")
            else:
                verbose(
                    "merger_ci: No packages or no vulnerabilities encountered this run"
                    " — skipping observation creation."
                )
        else:
            print("Warning: no scan found in DB — skipping observation creation.")
    except Exception as e:
        print(f"Warning: could not populate observations table: {e}")

    verbose("merger_ci: Processing complete")

    if len(failed_vulns) > 0:
        raise SystemExit(2)

    return controllers


def init_app(app) -> None:
    """Register the ``flask merge``, ``flask process``, ``flask report`` and ``flask export`` commands with *app*."""
    app.cli.add_command(create_project_context)
    app.cli.add_command(process_command)
    app.cli.add_command(report_command)
    app.cli.add_command(export_command)
    app.cli.add_command(export_custom_assessments_command)
    app.cli.add_command(import_custom_assessments_command)
    app.cli.add_command(list_projects_command)
    app.cli.add_command(list_scans_command)
    app.cli.add_command(delete_scan_command)


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


@click.command("export-custom-assessments")
@click.option("--output-dir", default="/scan/outputs", show_default=True,
              help="Directory where the exported tar.gz is written.")
@with_appcontext
def export_custom_assessments_command(output_dir: str) -> None:
    """Export handmade (custom) assessments as a tar.gz of OpenVEX files."""
    import io
    import tarfile
    import uuid as _uuid
    import json as _json
    from datetime import datetime as _dt, timezone as _tz
    from collections import defaultdict
    from ..models.assessment import (
        Assessment as DBAssessment,
    )
    from ..models.variant import Variant as DBVariant
    from ..models.vulnerability import Vulnerability as DBVuln

    handmade = DBAssessment.get_handmade()
    if not handmade:
        click.echo("No custom assessments to export.", err=True)
        raise SystemExit(1)

    author = os.getenv("AUTHOR_NAME", "Savoir-faire Linux")
    now_iso = _dt.now(_tz.utc).isoformat()

    variant_names: dict[str, str] = {}
    for v in DBVariant.get_all():
        variant_names[str(v.id)] = v.name

    vuln_cache: dict[str, DBVuln | None] = {}

    def _get_vuln(vuln_id: str):
        if vuln_id not in vuln_cache:
            vuln_cache[vuln_id] = DBVuln.get_by_id(vuln_id)
        return vuln_cache[vuln_id]

    by_variant: dict[str | None, list] = defaultdict(list)
    for assess in handmade:
        vid = str(assess.variant_id) if assess.variant_id else None
        by_variant[vid].append(assess)

    os.makedirs(output_dir, exist_ok=True)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for vid, assessments in by_variant.items():
            filename = (
                variant_names.get(vid, "unassigned")
                if vid else "unassigned"
            ) + ".json"
            filename = filename.replace("/", "_").replace("\\", "_")

            statements = []
            for assess in assessments:
                stmt = assess.to_openvex_dict()
                if stmt is None:
                    continue

                vuln_obj = (
                    _get_vuln(assess.vuln_id)
                    if assess.vuln_id else None
                )
                description = ""
                aliases: list[str] = []
                vuln_url = ""
                if vuln_obj:
                    desc = vuln_obj.texts.get("description", "")
                    yocto_desc = vuln_obj.texts.get(
                        "yocto description", ""
                    )
                    description = desc or yocto_desc or ""
                    aliases = list(vuln_obj.aliases or [])
                    urls = (
                        list(vuln_obj.urls) if vuln_obj.urls
                        else list(vuln_obj.links or [])
                    )
                    vuln_url = urls[0] if urls else ""
                    if (
                        not vuln_url
                        and assess.vuln_id.startswith("CVE-")
                    ):
                        vuln_url = (
                            "https://nvd.nist.gov/vuln/detail/"
                            + assess.vuln_id
                        )
                    elif (
                        not vuln_url
                        and assess.vuln_id.startswith("GHSA-")
                    ):
                        vuln_url = (
                            "https://github.com/advisories/"
                            + assess.vuln_id
                        )

                stmt["vulnerability"] = {
                    "name": assess.vuln_id,
                    "description": description,
                    "aliases": aliases,
                    "@id": vuln_url,
                }

                products = []
                for pkg_str in assess.packages:
                    if "@" in pkg_str:
                        name, version = pkg_str.rsplit("@", 1)
                    else:
                        name, version = pkg_str, ""
                    products.append({
                        "@id": pkg_str,
                        "identifiers": {
                            "cpe23": (
                                "cpe:2.3:*:*:"
                                f"{name}:{version}"
                                ":*:*:*:*:*:*:*"
                            ),
                            "purl": f"pkg:generic/{name}@{version}",
                        }
                    })
                stmt["products"] = products
                stmt.setdefault("action_statement_timestamp", "")
                stmt["scanners"] = list({
                    assess.source or "local_user_data",
                    assess.origin or "local_user_data",
                })
                statements.append(stmt)

            doc = {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "@id": (
                    "https://savoirfairelinux.com/sbom/openvex/"
                    + str(_uuid.uuid4())
                ),
                "author": author,
                "timestamp": now_iso,
                "version": 1,
                "statements": statements,
            }

            json_bytes = _json.dumps(doc, indent=2).encode("utf-8")
            info = tarfile.TarInfo(name=filename)
            info.size = len(json_bytes)
            tar.addfile(info, io.BytesIO(json_bytes))

    out_path = os.path.join(output_dir, "custom_assessments.tar.gz")
    with open(out_path, "wb") as fh:
        fh.write(buf.getvalue())
    click.echo(f"Custom assessments exported: {out_path}")


@click.command("import-custom-assessments")
@click.argument("file_path")
@with_appcontext
def import_custom_assessments_command(file_path: str) -> None:
    """Import custom assessments from a .json or .tar.gz OpenVEX file."""
    import tarfile
    import json as _json
    from ..extensions import db as _db
    from ..models.assessment import (
        Assessment as DBAssessment,
        STATUS_TO_SIMPLIFIED,
    )
    from ..models.variant import Variant as DBVariant
    from ..models.vulnerability import Vulnerability as DBVuln
    from ..models.package import Package
    from ..models.finding import Finding

    if not os.path.isfile(file_path):
        click.echo(f"Error: file not found: {file_path}", err=True)
        raise SystemExit(1)

    all_variants = DBVariant.get_all()
    variant_by_name: dict[str, "DBVariant"] = {}
    for v in all_variants:
        sanitised = v.name.replace("/", "_").replace("\\", "_")
        variant_by_name[sanitised] = v
        variant_by_name[v.name] = v

    def _is_openvex(doc: dict) -> bool:
        ctx = doc.get("@context", "")
        return "openvex" in ctx and isinstance(
            doc.get("statements"), list
        )

    def _import_statements(
        statements: list, variant_id
    ) -> tuple[list, list, int]:
        created: list[dict] = []
        errors: list[dict] = []
        skipped = 0
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            vuln_obj = stmt.get("vulnerability", {})
            vuln_name = (
                vuln_obj.get("name")
                if isinstance(vuln_obj, dict) else None
            )
            if not vuln_name:
                errors.append({
                    "error": "Missing vulnerability name",
                    "statement": str(stmt)[:200],
                })
                continue
            status = stmt.get("status")
            if not status:
                errors.append({
                    "vuln_id": vuln_name,
                    "error": "Missing status",
                })
                continue

            products = stmt.get("products", [])
            pkg_ids = []
            for prod in products:
                if isinstance(prod, dict) and "@id" in prod:
                    pkg_ids.append(prod["@id"])
                elif isinstance(prod, str):
                    pkg_ids.append(prod)
            if not pkg_ids:
                errors.append({
                    "vuln_id": vuln_name,
                    "error": "No products/packages found",
                })
                continue

            justification = stmt.get("justification", "")
            impact_statement = stmt.get("impact_statement", "")
            status_notes = stmt.get("status_notes", "")
            workaround = stmt.get("action_statement", "")

            for pkg_string_id in pkg_ids:
                try:
                    if "@" in pkg_string_id:
                        name, version = pkg_string_id.rsplit(
                            "@", 1
                        )
                    else:
                        name, version = pkg_string_id, ""
                    db_pkg = Package.find_or_create(name, version)
                    DBVuln.get_or_create(vuln_name)
                    finding = Finding.get_or_create(
                        db_pkg.id, vuln_name
                    )

                    existing = _db.session.execute(
                        _db.select(DBAssessment).where(
                            DBAssessment.finding_id == finding.id,
                            DBAssessment.variant_id == variant_id,
                            DBAssessment.status == status,
                            DBAssessment.justification
                            == justification,
                            DBAssessment.impact_statement
                            == impact_statement,
                            DBAssessment.status_notes
                            == status_notes,
                            DBAssessment.workaround == workaround,
                        )
                    ).scalar_one_or_none()
                    if existing is not None:
                        skipped += 1
                        continue

                    db_a = DBAssessment.create(
                        status=status,
                        simplified_status=(
                            STATUS_TO_SIMPLIFIED.get(
                                status, "Pending Assessment"
                            )
                        ),
                        finding_id=finding.id,
                        variant_id=variant_id,
                        origin="custom",
                        status_notes=status_notes,
                        justification=justification,
                        impact_statement=impact_statement,
                        workaround=workaround,
                        responses=[],
                        commit=True,
                    )
                    created.append(db_a.to_dict())
                except Exception as e:
                    errors.append({
                        "vuln_id": vuln_name,
                        "package": pkg_string_id,
                        "error": str(e),
                    })
        return created, errors, skipped

    basename = os.path.basename(file_path)
    total_created: list[dict] = []
    total_errors: list[dict] = []
    total_skipped = 0

    if file_path.endswith(".tar.gz") or file_path.endswith(".tgz"):
        try:
            tar = tarfile.open(file_path, mode='r:gz')
        except Exception:
            click.echo(
                "Error: unable to open tar.gz archive.", err=True
            )
            raise SystemExit(1)

        variant_files_found = 0
        for member in tar.getmembers():
            if not member.isfile() or not member.name.endswith(
                ".json"
            ):
                continue
            base = os.path.basename(member.name)
            variant_name = base[:-len(".json")]
            variant = variant_by_name.get(variant_name)
            if variant is None:
                total_errors.append({
                    "file": member.name,
                    "error": (
                        f"No variant found matching name "
                        f"'{variant_name}'"
                    ),
                })
                continue

            f = tar.extractfile(member)
            if f is None:
                continue
            try:
                doc = _json.load(f)
            except Exception:
                total_errors.append({
                    "file": member.name,
                    "error": "Invalid JSON",
                })
                continue

            if not _is_openvex(doc):
                total_errors.append({
                    "file": member.name,
                    "error": "Not a valid OpenVEX document",
                })
                continue

            variant_files_found += 1
            c, e, s = _import_statements(
                doc["statements"], variant.id
            )
            total_created.extend(c)
            total_errors.extend(e)
            total_skipped += s

        tar.close()

        if variant_files_found == 0 and not total_created:
            click.echo(
                "Error: no valid OpenVEX files matching known "
                "variants found in archive.", err=True
            )
            for err in total_errors:
                click.echo(f"  {err}", err=True)
            raise SystemExit(1)

    elif file_path.endswith(".json"):
        variant_name = basename[:-len(".json")]
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

        if not _is_openvex(data):
            click.echo(
                "Error: not a valid OpenVEX document.", err=True
            )
            raise SystemExit(1)

        c, e, s = _import_statements(
            data["statements"], variant.id
        )
        total_created.extend(c)
        total_errors.extend(e)
        total_skipped += s
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


_T = typing.TypeVar("_T")


def _echo_object_list(
    json_format: bool,
    objects: list[_T],
    pretty_format: typing.Callable[[_T], str],
    to_dict: typing.Callable[[_T], dict],
):
    if json_format:
        # cannot use a generator here since the json library cannot dump an
        # array "lazily"
        click.echo_via_pager(json.dumps(
            [to_dict(obj) for obj in objects],
            indent=4)
        )
    else:
        click.echo_via_pager(pretty_format(obj) for obj in objects)


@click.command("list-projects")
@click.option("--json", "json_format", is_flag=True)
@with_appcontext
def list_projects_command(json_format: bool):
    def _format_project_pretty(project: ProjectModel) -> str:
        variants_string = ", ".join(v.name for v in project.variants)
        return (f"{project.name} ({project.id}), "
                f"{len(project.variants)} variants: {variants_string}\n")

    projects = ProjectController.get_all()
    _echo_object_list(json_format, projects, _format_project_pretty, ProjectModel.to_dict)


@click.command("list-scans")
@click.option("--json", "json_format", is_flag=True)
@with_appcontext
def list_scans_command(json_format: bool = False):
    def _format_scan_pretty(scan: ScanModel) -> str:
        return (f"{scan.id} ({scan.description}) at {scan.timestamp}, "
                f"project {scan.variant.project.name}, "
                f"variant {scan.variant.name}, "
                f"{len(scan.sbom_documents)} SBOMs, "
                f"{len(scan.observations)} observations\n")

    scans = ScanController.get_all()
    _echo_object_list(json_format, scans, _format_scan_pretty, ScanModel.to_dict)


@click.command("delete-scan")
@click.argument("scan-id", type=click.UUID)
@with_appcontext
def delete_scan_command(scan_id: uuid.UUID):
    ScanController.delete(scan_id)
    click.echo(f"Successfully deleted scan {scan_id}")


def main() -> dict:
    """Entry-point for direct invocation (``python -m src.bin.merger_ci``).

    Returns the controllers dict so callers can inspect in-memory state.
    Prefer running via ``flask --app bin.webapp process`` in production so that
    the DB session is properly initialised.
    """
    return _run_main()


if __name__ == "__main__":
    main()

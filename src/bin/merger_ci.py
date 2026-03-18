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
from ..views.spdx3 import SPDX3
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
from ..helpers.verbose import verbose
import click
import json
import os
from datetime import date, datetime, timezone
from typing import Any
from flask.cli import with_appcontext
from sqlalchemy import and_, not_, exists

DEFAULT_VARIANT_NAME = "default"

def post_treatment(controllers, files):
    """Enrich vulnerabilities with EPSS scores and NVD published dates."""
    # 1. fetch EPSS
    controllers["vulnerabilities"].fetch_epss_scores()

    # 2. fetch published dates from NVD
    controllers["vulnerabilities"].fetch_published_dates()


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

        def _ts_key(ts):
            """Normalise a timestamp (str or datetime) to an ISO string for comparison."""
            if ts is None:
                return ""
            if isinstance(ts, str):
                return ts
            try:
                return ts.isoformat()
            except Exception:
                return str(ts)

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


def read_inputs(controllers):
    """Parse all SBOM documents registered in the DB."""
    cdx = CycloneDx(controllers)
    spdx = SPDX(controllers)
    fastspdx3 = FastSPDX3(controllers)
    fastspdx = FastSPDX(controllers)
    openvex = OpenVex(controllers)
    yocto = YoctoVulns(controllers)
    grype = GrypeVulns(controllers)
    templates = Templates(controllers)

    use_fastspdx = os.getenv('IGNORE_PARSING_ERRORS', 'false') == 'true'
    if use_fastspdx:
        verbose("merger_ci: Using FastSPDX parser")

    pkgCtrl = controllers["packages"]
    docs = SBOMDocument.get_all()

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

            if fmt == "spdx" or (fmt is None and (fastspdx3.could_parse_spdx(data) or "spdxVersion" in data or doc.source_name.endswith(".spdx.json"))):
                if fastspdx3.could_parse_spdx(data):
                    fastspdx3.parse_from_dict(data)
                elif use_fastspdx:
                    fastspdx.parse_from_dict(data)
                else:
                    spdx.load_from_file(doc.path)
                    spdx.parse_and_merge()
            elif fmt == "cdx" or (fmt is None and (data.get("bomFormat") == "CycloneDX" or doc.source_name.endswith(".cdx.json"))):
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
            print(f"Error: registered SBOM document not found on disk: {doc.path}")
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
    scan = ScanController.create("default", variant_obj.id)
    click.echo(f"project='{project}' variant='{variant_name}' scan={scan.id}")

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


def _profile_with_pyspy(output: str, format: str) -> None:
    """Attach py-spy to the current PID and record until the returned handle is closed."""
    pid = os.getpid()
    cmd = [
        "py-spy", "record",
        "--pid", str(pid),
        "--output", output,
        "--format", format,
        "--subprocesses",
    ]
    try:
        proc = subprocess.Popen(cmd)
    except FileNotFoundError:
        click.echo(
            "Warning: py-spy not found — install it with: pip install py-spy\n"
            "Continuing without profiling.",
            err=True,
        )
        return None
    return proc


@click.command("process")
@click.option(
    "--profile",
    "profile_output",
    default=None,
    metavar="FILE",
    help="Record a py-spy flamegraph to FILE (e.g. profile.svg).",
)
@click.option(
    "--profile-format",
    default="flamegraph",
    show_default=True,
    type=click.Choice(["flamegraph", "speedscope", "raw"], case_sensitive=False),
    help="Output format for --profile.",
)
@with_appcontext
def process_command(profile_output: str | None, profile_format: str) -> None:
    """Parse all SBOM inputs, persist results to the DB and generate output files."""
    if profile_output:
        click.echo(f"Profiling with py-spy → {profile_output} (format={profile_format})")
        pyspy_proc = _profile_with_pyspy(profile_output, profile_format)
    else:
        pyspy_proc = None

    try:
        _run_main()
    finally:
        if pyspy_proc is not None:
            pyspy_proc.terminate()
            pyspy_proc.wait()
            click.echo(f"Profile saved to {profile_output}")


def _run_main() -> dict:
    """Core processing logic (usable both from the CLI command and directly)."""
    from ..extensions import batch_session, db as _db

    pkgCtrl = PackagesController()
    # pkgCtrl._preload_cache()  # bulk-load pkg UUIDs + findings into cache; eliminates per-vuln SELECT queries
    vulnCtrl = VulnerabilitiesController(pkgCtrl)
    assessCtrl = AssessmentsController(pkgCtrl, vulnCtrl)
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
        
        files = read_inputs(controllers)
        verbose("merger_ci: Finished reading inputs")

        verbose("merger_ci: Start Post-treatment")
        post_treatment(controllers, files)
        verbose("merger_ci: Finished post-treatment")
    # ← single COMMIT happens here
    verbose("merger_ci: DB commit done")

    fail_condition = os.getenv("FAIL_CONDITION", "")
    failed_vulns = []
    if fail_condition:
        verbose("merger_ci: Start evaluating conditions")
        failed_vulns = evaluate_condition(controllers, fail_condition)
        verbose("merger_ci: Finished evaluating conditions")

    verbose("merger_ci: Start exporting results")
    verbose("merger_ci: Finished exporting results")

    # Populate the observations table: link every finding to the current scan.
    verbose("merger_ci: Populating observations table")
    try:
        latest_scan = ScanModel.get_latest()
        if latest_scan:          
            # Find findings without observations for this scan
            new_finding_ids = list(_db.session.execute(
                _db.select(FindingModel.id).where(
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
            
            # Create observations in batches to reduce memory usage
            if new_finding_ids:
                new_observations = [
                    Observation(finding_id=fid, scan_id=latest_scan.id)
                    for fid in new_finding_ids
                ]
                with batch_session():
                    _db.session.bulk_save_objects(new_observations)
                # ← single COMMIT for all observations
                verbose(f"merger_ci: Observations created for scan {latest_scan.id} ({len(new_observations)} new)")
        else:
            print("Warning: no scan found in DB — skipping observation creation.")
    except Exception as e:
        print(f"Warning: could not populate observations table: {e}")

    verbose("merger_ci: Processing complete")

    if len(failed_vulns) > 0:
        raise SystemExit(2)

    return controllers


def init_app(app) -> None:
    """Register the ``flask merge`` and ``flask process`` commands with *app*."""
    app.cli.add_command(create_project_context)
    app.cli.add_command(process_command)


def main() -> dict:
    """Entry-point for direct invocation (``python -m src.bin.merger_ci``).

    Returns the controllers dict so callers can inspect in-memory state.
    Prefer running via ``flask --app bin.webapp process`` in production so that
    the DB session is properly initialised.
    """
    return _run_main()


if __name__ == "__main__":
    main()
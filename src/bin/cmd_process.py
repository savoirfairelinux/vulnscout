# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""SBOM ingestion & processing commands: ``flask merge`` and ``flask process``."""

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
from ..helpers.verbose import verbose
from ..helpers.env_vars import get_bool_env
from ..extensions import batch_session, db as _db
import click
import json
import os
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

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""SBOM ingestion & processing commands: ``flask merge`` and ``flask process``."""

from __future__ import annotations

from ..views.cyclonedx import CycloneDx
from ..views.spdx import SPDX
from ..views.fast_spdx import FastSPDX
from ..views.fast_spdx3 import FastSPDX3
from ..views.openvex import OpenVex
from ..views.yocto_vulns import YoctoVulns
from ..views.yocto_vex import YoctoVex
from ..views.grype_vulns import GrypeVulns
from ..views.templates import Templates
from ..controllers import ControllersCache, ConditionParser, ScanController, SBOMDocumentController
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage as SBOMPkg
from ..models.scan import Scan as ScanModel
from ..models.finding import Finding as FindingModel
from ..models.observation import Observation
from ..helpers.env_vars import get_bool_env
from ..extensions import batch_session, db as _db
import click
from ._console import Command, echo, print_message, verbose, warn
import json
import os
from itertools import chain
from typing import Callable, Iterable, TYPE_CHECKING
from flask.cli import with_appcontext
from sqlalchemy import and_, exists
from sqlalchemy.exc import SQLAlchemyError
from ._common import DEFAULT_VARIANT_NAME, resolve_project, resolve_project_variant
from ..controllers.projects import ProjectController
from ..helpers.export_scope import compute_export_scope
from ..helpers.jsonld_groups import is_zephyr_jsonld, record_jsonld_groups
from ..controllers.operation_registry import new_queue_id

if TYPE_CHECKING:
    from ..controllers.packages import PackagesController
    from ..controllers.vulnerabilities import VulnerabilitiesController
    from ..controllers.assessments import AssessmentsController


def _is_yocto_vex(data: dict) -> bool:
    """Return True when JSON content looks like a yocto-vex file rather than a
    plain yocto cve-check file.

    yocto-vex and yocto cve-check share the same top-level shape
    (``version``/``package``/``issue``).  The distinguishing fields are
    package-level ``cpes`` and issue-level ``patch-file`` / ``detail``.
    """
    for pkg in data.get("package", []):
        if pkg.get("cpes"):
            return True
        for issue in pkg.get("issue", []):
            if "patch-file" in issue or "detail" in issue:
                return True
    return False


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


def post_treatment(controllers: ControllersCache, documents=None, reporter=None):
    """Enrich vulnerabilities with EPSS scores."""
    from ..controllers.progress_reporter import NULL_REPORTER
    return controllers.vulnerabilities.fetch_epss_scores(reporter or NULL_REPORTER)


REFRESH_SOURCES = ("epss", "nvd", "euvd", "ghsa")


def _refresh_source(controllers: ControllersCache, source: str) -> bool:
    if source == "epss":
        result = post_treatment(controllers)
    elif source in {"nvd", "ghsa"}:
        result = controllers.vulnerabilities.fetch_nvd_data()
    else:
        result = controllers.vulnerabilities.fetch_euvd_data()
    return result is None or result.completed


def refresh_vulnerability_sources(
    controllers: ControllersCache,
    vulnerability_ids: Iterable[str],
    refresh_sources: Iterable[str] = REFRESH_SOURCES,
    on_source_start: Callable[[str, int, int], None] | None = None,
) -> list[str]:
    """Refresh selected providers for the supplied vulnerabilities."""
    vuln_ctrl = controllers.vulnerabilities
    all_vulnerabilities = vuln_ctrl.vulnerabilities
    selected_vulnerability_ids = tuple(vulnerability_ids)
    selected_sources = set(refresh_sources)
    applicable_sources = [
        source
        for source in REFRESH_SOURCES
        if source in selected_sources
        and any(
            vuln_id.startswith("GHSA-" if source == "ghsa" else "CVE-")
            and vuln_id in all_vulnerabilities
            for vuln_id in selected_vulnerability_ids
        )
    ]
    failed_sources: list[str] = []
    try:
        for step, source in enumerate(applicable_sources, start=1):
            prefix = "GHSA-" if source == "ghsa" else "CVE-"
            vuln_ctrl.vulnerabilities = {
                vuln_id: all_vulnerabilities[vuln_id]
                for vuln_id in selected_vulnerability_ids
                if vuln_id.startswith(prefix) and vuln_id in all_vulnerabilities
            }
            label = source.upper()
            if on_source_start is not None:
                on_source_start(label, step, len(applicable_sources))
            try:
                if not _refresh_source(controllers, source):
                    failed_sources.append(label)
            except Exception as exc:
                failed_sources.append(label)
                verbose(f"{label} enrichment failed: {exc}")
    finally:
        vuln_ctrl.vulnerabilities = all_vulnerabilities
    return failed_sources


def evaluate_condition(
    vulnerabilitiesCtrl: VulnerabilitiesController,
    assessmentsCtrl: AssessmentsController,
    condition,
):
    """Evaluate a condition and return the list of vulnerability IDs that trigger it."""
    parser = ConditionParser()
    failed_vulns = []
    for (vuln_id, vuln) in vulnerabilitiesCtrl.vulnerabilities.items():
        data = {
            "id": vuln_id,
            "cvss": vuln.severity_max_score or vuln.severity_min_score or False,
            "cvss_min": vuln.severity_min_score or vuln.severity_max_score or False,
            "epss": vuln.epss["score"] or False,
            "effort": False if vuln.effort["likely"] is None else vuln.effort["likely"].total_seconds,
            "effort_min": False if vuln.effort["optimistic"] is None else vuln.effort["optimistic"].total_seconds,
            "effort_max": False if vuln.effort["pessimistic"] is None else vuln.effort["pessimistic"].total_seconds,
            "known_exploitable": bool(vuln.euvd_known_exploited),
            "fixed": False,
            "ignored": False,
            "affected": False,
            "pending": True,
            "new": True
        }

        last_assessment = None
        for assessment in assessmentsCtrl.gets_by_vuln(vuln_id):
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
            # Keep this message on stdout for CI consumers.
            print_message(f"Vulnerability triggered fail condition: {vuln_id}", role="error")
    return failed_vulns


def read_inputs(controllers: ControllersCache, scan_id=None):
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
    yocto_vex = YoctoVex(controllers)
    grype = GrypeVulns(controllers)
    templates = Templates(controllers)

    use_fastspdx = get_bool_env('IGNORE_PARSING_ERRORS', False)
    if use_fastspdx:
        verbose("merger_ci: Using FastSPDX parser")

    pkgCtrl: PackagesController = controllers.packages
    docs = SBOMDocument.get_by_scan(scan_id) if scan_id is not None else SBOMDocument.get_all()
    jsonld_documents = []
    file_documents = []
    detached_cdx_documents: list[SBOMDocument] = []
    detached_cdx_refs: dict[SBOMDocument, dict[str, str]] = {}

    for doc in chain(docs, detached_cdx_documents):
        document_path = doc.path
        pkgCtrl.current_sbom_document = doc
        try:
            verbose(f"merger_ci: Reading {doc.path} (format={doc.format!r})")
            with open(doc.path, "r") as f:
                data = json.load(f)

            # Prefer the explicit format stored at registration time (set by
            # scan.sh via the --spdx / --cdx / --openvex / --yocto-cve / --yocto-vex / --grype
            # options) and fall back to content-sniffing only when it is absent.
            fmt = doc.format  # 'spdx', 'cdx', 'openvex', 'yocto_cve_check', 'yocto_vex', 'grype', or None

            if fmt == "spdx" or (
                fmt is None and (
                    fastspdx3.could_parse_spdx(data) or "spdxVersion" in data or doc.source_name.endswith(".spdx.json")
                )
            ):
                if fastspdx3.could_parse_spdx(data):
                    fastspdx3.parse_from_dict(data)
                    file_documents.append(
                        (doc, data, dict(fastspdx3._document_refs),
                         fastspdx3._namespace_map(data.get('@graph', [])))
                    )
                    if is_zephyr_jsonld(data):
                        jsonld_documents.append(
                            (doc, data, dict(fastspdx3._document_refs),
                             fastspdx3._namespace_map(data.get('@graph', [])))
                        )
                    else:
                        doc.jsonld_groups = None
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
                document_cdx = cdx
                if doc in detached_cdx_refs:
                    document_cdx = CycloneDx(controllers)
                    document_cdx.ref_dict = detached_cdx_refs.pop(doc)
                    document_cdx._document_refs = {
                        ref: package for ref, package in document_cdx.ref_dict.items() if ref.startswith("urn:cdx:")
                    }
                document_cdx.load_from_dict(data)
                if document_cdx is cdx:
                    cdx.merge_components_into_controller()
                    pkgCtrl.add_dependencies(cdx._document_refs, cdx._dependency_edges)
                    if (getattr(cdx, "sbom", None) is not None
                            and any(affect.ref.startswith("urn:cdx:") and affect.ref not in cdx.bom_link_refs
                                    for vulnerability in cdx.sbom.vulnerabilities for affect in vulnerability.affects)):
                        detached_cdx_documents.append(doc)
                        # URN-shaped local fallbacks must belong to this document,
                        # not another inventory in the accumulated local index.
                        detached_cdx_refs[doc] = {
                            affect.ref: cdx.ref_dict[affect.ref]
                            for vulnerability in cdx.sbom.vulnerabilities for affect in vulnerability.affects
                            if affect.ref in cdx.ref_dict
                            and (not affect.ref.startswith("urn:cdx:") or affect.ref in cdx._document_refs)
                        }
                        continue
                elif getattr(document_cdx, "sbom", None) is not None:
                    document_cdx.bom_link_refs = {
                        affect.ref: cdx.bom_link_refs[affect.ref]
                        for vulnerability in document_cdx.sbom.vulnerabilities for affect in vulnerability.affects
                        if affect.ref.startswith("urn:cdx:") and affect.ref in cdx.bom_link_refs
                    }
                document_cdx.merge_vulnerabilities_into_controller()
            elif fmt == "openvex" or (fmt is None and "statements" in data):
                openvex.load_from_dict(data)
            elif fmt == "yocto_vex" or (
                fmt is None
                and "package" in data
                and "matches" not in data
                and _is_yocto_vex(data)
            ):
                yocto_vex.load_from_dict(data)
            elif fmt == "yocto_cve_check" or (fmt is None and "package" in data and "matches" not in data):
                yocto.load_from_dict(data)
            elif fmt == "grype" or (fmt is None and "matches" in data):
                grype.load_from_dict(data)
            else:
                print_message(f"Warning: unknown format for {doc.path}, skipping", role="warning")
                continue
            doc.dependencies_recorded = True
        except FileNotFoundError:
            pass  # File was already merged into the DB and cleaned up — expected.
        except SQLAlchemyError as e:
            _db.session.rollback()
            print_message(f"Error importing {document_path}: {e}", role="error")
            raise
        except Exception as e:
            if not use_fastspdx:
                print_message(f"Error parsing {document_path}: {e}", role="error")
                print_message("Hint: set IGNORE_PARSING_ERRORS=true to ignore this error", role="error")
                raise
            else:
                print_message(f"Ignored: Error parsing {document_path}: {e}", role="warning")
        finally:
            pkgCtrl.current_sbom_document = None
    pkgCtrl.flush_spdx_dependencies()
    pkgCtrl.flush_spdx_sources()
    # Companion documents resolve only inside their own scan.
    for current_scan_id in {document.scan_id for document, *_ in jsonld_documents}:
        record_jsonld_groups(
            [entry for entry in jsonld_documents if entry[0].scan_id == current_scan_id], pkgCtrl,
        )
    from ..helpers.jsonld_storage import consolidate_jsonld_packages

    with _db.session.begin_nested():
        consolidated = consolidate_jsonld_packages(_db.session())
    if consolidated:
        pkgCtrl._cache.clear()
        pkgCtrl._db_id_cache.clear()
        pkgCtrl._finding_cache.clear()
        original_ids = {
            member["id"] for document, *_ in jsonld_documents
            for group in document.jsonld_groups or [] if group.get("canonical_package_id")
            for member in group["members"]
        }
        from ..models import Assessment, Vulnerability

        vulnCtrl = controllers.vulnerabilities
        assessCtrl = controllers.assessments
        for vulnerability in vulnCtrl.vulnerabilities.values():
            if original_ids.intersection(vulnerability.packages):
                record = _db.session.get(Vulnerability, vulnerability.id)
                if record is not None:
                    vulnerability.packages = sorted({finding.package.string_id for finding in record.findings})
                    vulnerability._persisted_packages = set(vulnerability.packages)
                    record.packages = list(vulnerability.packages)
        assessCtrl._by_vuln_pkg.clear()
        assessCtrl._db_queried_vuln_pkg.clear()
        assessCtrl._db_queried_pkgs.clear()
        for key, assessment in assessCtrl.assessments.items():
            if original_ids.intersection(assessment.packages):
                stored = _db.session.get(Assessment, assessment.id)
                if stored is not None:
                    assessment.packages = stored.packages
            for package_id in assessment.packages:
                assessCtrl._by_vuln_pkg.setdefault((assessment.vuln_id, package_id), []).append(key)
    from ..helpers.sbom_files import record_source_files

    for current_scan_id in {document.scan_id for document, *_ in file_documents}:
        record_source_files([entry for entry in file_documents if entry[0].scan_id == current_scan_id])
    _db.session.commit()

    return {
        "cdx": cdx,
        "templates": templates
    }


@click.command("merge", cls=Command)
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
@click.option("--yocto-vex", "yocto_vex_inputs", multiple=True, type=click.Path(exists=True),
              help="Yocto VEX JSON file (may be repeated).")
@click.option("--grype", "grype_inputs", multiple=True, type=click.Path(exists=True),
              help="Grype vulnerability JSON file (may be repeated).")
@click.option("--run-id", default=None,
              help="Group tool scans from the same invocation under this run ID (ignored for SBOM imports).")
@with_appcontext
def create_project_context(
    project: str,
    variant: str | None,
    spdx_inputs: tuple,
    cdx_inputs: tuple,
    openvex_inputs: tuple,
    yocto_cve_inputs: tuple,
    yocto_vex_inputs: tuple,
    grype_inputs: tuple,
    run_id: str | None,
) -> None:
    """Register SBOM inputs into the database under a named project/variant scan.

    Use --spdx, --cdx, --openvex, --yocto-cve, --yocto-vex and --grype to pass
    files with their explicit format so that parsing is unambiguous.  Each
    option may be repeated for multiple files of the same format.
    When no variant is given, inputs go into a scan under the 'default' variant.
    """
    variant_name = variant or DEFAULT_VARIANT_NAME

    project_obj, variant_obj = resolve_project_variant(project, variant, create=True)

    # Determine scan type: if there are any SBOM inputs (spdx, cdx, yocto_cve)
    # or openvex, it's an "sbom" scan.  Grype-only → "tool" scan.
    has_sbom_inputs = bool(spdx_inputs or cdx_inputs or openvex_inputs or yocto_cve_inputs or yocto_vex_inputs)
    scan_type = "sbom" if has_sbom_inputs else "tool"
    scan_description = "empty description"
    scan_source = "grype" if (not has_sbom_inputs and grype_inputs) else None

    scan = ScanController.create(scan_description, variant_obj.id, scan_type=scan_type,
                                 scan_source=scan_source,
                                 run_id=(run_id or new_queue_id()) if scan_type == "tool" else None)
    echo(f"project='{project}' variant='{variant_name}' scan={scan.id} type={scan_type}", role="info")

    format_groups: list[tuple[tuple, str]] = [
        (spdx_inputs, "spdx"),
        (cdx_inputs, "cdx"),
        (openvex_inputs, "openvex"),
        (yocto_cve_inputs, "yocto_cve_check"),
        (yocto_vex_inputs, "yocto_vex"),
        (grype_inputs, "grype"),
    ]
    for files, fmt in format_groups:
        for sbom_file in files:
            abs_path = os.path.abspath(sbom_file)
            SBOMDocumentController.create(abs_path, os.path.basename(sbom_file), scan.id, format=fmt)
            echo(f"  + [{fmt}] {sbom_file}", role="info")


@click.command("process", cls=Command)
@click.option(
    "--refresh-vulnerability-data",
    is_flag=True,
    help="Refresh stored EPSS, NVD, EUVD, and GHSA data.",
)
@click.option("--project", "project_name", default=None, help="Evaluate conditions in this project.")
@click.option("--variant", "variant_name", default=None, help="Evaluate conditions in this project variant.")
@with_appcontext
def process_command(
    refresh_vulnerability_data: bool,
    project_name: str | None,
    variant_name: str | None,
) -> None:
    """Parse all SBOM inputs, persist results to the DB and generate output files."""
    _run_main(
        refresh_vulnerability_data=refresh_vulnerability_data,
        project_name=project_name,
        variant_name=variant_name,
    )


@click.command("refresh-vulnerability-data", cls=Command)
@click.option("--project", "project_name", default=None, help="Refresh vulnerabilities in this project only.")
@click.option("--variant", "variant_name", default=None, help="Refresh vulnerabilities in this project variant only.")
@with_appcontext
def refresh_vulnerability_data_command(project_name: str | None, variant_name: str | None) -> None:
    """Refresh vulnerability data already stored in the database."""
    scope = None
    if variant_name and not project_name:
        raise click.UsageError("--variant requires --project.")
    if project_name:
        project = ProjectController.get_by_name(project_name)
        if project is None:
            raise click.ClickException(f"project not found: {project_name}")
        if variant_name:
            _, variant = resolve_project_variant(project_name, variant_name)
            scope = compute_export_scope(variant_id=variant.id)
        else:
            scope = compute_export_scope(project_id=project.id)

    controllers = ControllersCache(scope=scope)
    failed_sources = refresh_vulnerability_sources(
        controllers,
        controllers.vulnerabilities.vulnerabilities,
        on_source_start=lambda label, step, total: echo(
            f"Refreshing {label} data (step {step} of {total})...", role="info"
        ),
    )
    if failed_sources:
        unique_failed = list(dict.fromkeys(failed_sources))
        raise click.ClickException(
            f"{', '.join(unique_failed)} vulnerability-data refresh failed."
        )
    echo("Vulnerability data refresh complete.", role="success")


def populate_observations(scan, vulnCtrl, log_prefix: str = "merger_ci") -> None:
    """Link findings discovered in *scan* to that scan's observations row.

    Only findings whose package appears in one of *scan*'s SBOM documents are
    eligible — linking ALL global findings would break variant-scoped filtering
    when multiple scans/variants exist in the DB.

    *vulnCtrl* is used to retrieve the set of vulnerability IDs encountered in
    the current ingestion run (``vulnCtrl._encountered_this_run``).
    """
    verbose(f"{log_prefix}: Populating observations table")
    try:
        if not scan:
            print_message("Warning: no scan provided — skipping observation creation.", role="warning")
            return

        # 1. Collect package_ids referenced by this scan's SBOM documents
        package_ids_in_scan = list(_db.session.execute(
            _db.select(SBOMPkg.package_id)
            .join(SBOMDocument, SBOMPkg.sbom_document_id == SBOMDocument.id)
            .where(SBOMDocument.scan_id == scan.id)
            .distinct()
        ).scalars().all())

        # 2. Collect vuln IDs encountered in this run
        encountered_vuln_ids = list(vulnCtrl._encountered_this_run)

        if not package_ids_in_scan or not encountered_vuln_ids:
            verbose(
                f"{log_prefix}: No packages or no vulnerabilities encountered"
                " — skipping observation creation."
            )
            return

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
                            Observation.scan_id == scan.id
                        )
                    )
                )
            )
        ).scalars().all())

        if new_finding_ids:
            new_observations = [
                Observation(finding_id=fid, scan_id=scan.id)
                for fid in new_finding_ids
            ]
            with batch_session():
                _db.session.bulk_save_objects(new_observations)
            verbose(f"{log_prefix}: Observations created for scan {scan.id} ({len(new_observations)} new)")
    except Exception as e:
        print_message(f"Warning: could not populate observations table: {e}", role="warning")


def _condition_scope(project_name: str | None, variant_name: str | None):
    project = project_name or "default"
    if project_name is not None and variant_name is None:
        project_obj = resolve_project(project)
        return compute_export_scope(project_id=project_obj.id)

    _, variant_obj = resolve_project_variant(project, variant_name)
    return compute_export_scope(variant_id=variant_obj.id)


def _evaluate_condition_in_scope(scope, condition: str) -> list[str]:
    matched_vulns: list[str] = []
    for variant_id in sorted(scope.variant_ids, key=str):
        variant_controllers = ControllersCache(
            scope=compute_export_scope(variant_id=variant_id)
        )
        matched_vulns.extend(evaluate_condition(
            variant_controllers.vulnerabilities,
            variant_controllers.assessments,
            condition,
        ))
    return list(dict.fromkeys(matched_vulns))


def _run_main(
    refresh_vulnerability_data: bool = False,
    project_name: str | None = None,
    variant_name: str | None = None,
) -> ControllersCache:
    """Core processing logic (usable both from the CLI command and directly)."""
    controllers = ControllersCache()
    vulnCtrl: VulnerabilitiesController = controllers.vulnerabilities
    assessCtrl: AssessmentsController = controllers.assessments
    latest_scan = ScanModel.get_latest()
    if latest_scan:
        assessCtrl.current_variant_id = latest_scan.variant_id
        vulnCtrl.current_variant_id = latest_scan.variant_id
    else:
        # Assessments are stored against (variant, finding) targets, and the
        # variant comes from the scan being ingested. Without one, every
        # parsed assessment is dropped -- warn once here rather than leaving
        # the user to infer it from the per-assessment messages.
        warn(
            "merger_ci: no scan found, so there is no variant to attach"
            " assessments to -- parsed assessments will not be stored"
        )

    # Wrap ingestion inside batch_session so that the
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

    match_condition = os.getenv("MATCH_CONDITION", "")

    observations_populated = False
    if refresh_vulnerability_data:
        populate_observations(latest_scan, vulnCtrl)
        observations_populated = True
        failed_sources = refresh_vulnerability_sources(
            controllers,
            vulnCtrl._encountered_this_run,
            on_source_start=lambda label, step, total: echo(
                f"Refreshing {label} data (step {step} of {total})...", role="info"
            ),
        )
        if failed_sources:
            unique_failed = list(dict.fromkeys(failed_sources))
            raise click.ClickException(
                f"{', '.join(unique_failed)} vulnerability-data refresh failed."
            )
        echo("Vulnerability data refresh complete.", role="success")

    failed_vulns = []
    if match_condition:
        verbose("merger_ci: Start evaluating conditions")
        failed_vulns = _evaluate_condition_in_scope(
            _condition_scope(project_name, variant_name),
            match_condition,
        )
        verbose("merger_ci: Finished evaluating conditions")
        # Cache result so flask report can reuse it without re-evaluating
        try:
            with open("/tmp/vulnscout_matched_vulns.json", "w") as _f:
                json.dump(failed_vulns, _f)
        except Exception:
            pass

    verbose("merger_ci: Start exporting results")
    verbose("merger_ci: Finished exporting results")

    if not observations_populated:
        latest_scan = ScanModel.get_latest()
        populate_observations(latest_scan, vulnCtrl)

    verbose("merger_ci: Processing complete")

    if len(failed_vulns) > 0:
        raise SystemExit(2)

    return controllers

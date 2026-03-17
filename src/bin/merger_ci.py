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

from ..views.grype_vulns import GrypeVulns
from ..views.yocto_vulns import YoctoVulns
from ..views.openvex import OpenVex
from ..views.time_estimates import TimeEstimates
from ..views.cyclonedx import CycloneDx
from ..views.spdx import SPDX
from ..views.spdx3 import SPDX3
from ..views.fast_spdx import FastSPDX
from ..views.fast_spdx3 import FastSPDX3
from ..views.templates import Templates
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController
from ..controllers.conditions_parser import ConditionParser
from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController
from ..controllers.scans import ScanController
from ..controllers.sbom_documents import SBOMDocumentController
from ..models.assessment import Assessment
from ..models.sbom_document import SBOMDocument
from ..models.scan import Scan as ScanModel
from ..models.finding import Finding as FindingModel
from ..models.observation import Observation
from ..helpers.verbose import verbose
import click
import glob
import json
import os
from datetime import date, datetime, timezone
from typing import Any
from flask.cli import with_appcontext

DEFAULT_VARIANT_NAME = "default"

CDX_PATH = "/scan/tmp/merged.cdx.json"
OPENVEX_PATH = "/scan/tmp/merged.openvex.json"
SPDX_FOLDER = "/scan/tmp/spdx"
GRYPE_CDX_PATH = "/scan/tmp/vulns-cdx.grype.json"
GRYPE_SPDX_PATH = "/scan/tmp/vulns-spdx.grype.json"
YOCTO_FOLDER = "/scan/tmp/yocto_cve_check"
LOCAL_USER_DATABASE_PATH = "/scan/outputs/openvex.json"
TIME_ESTIMATES_PATH = "/scan/outputs/time_estimates.json"

OUTPUT_CDX_PATH = "/scan/outputs/sbom.cdx.json"
OUTPUT_SPDX_PATH = "/scan/outputs/sbom.spdx.json"
OUTPUT_SPDX3_PATH = "/scan/outputs/sbom.spdx3.json"


def is_items_only_openvex(scanners: list[str]) -> bool:
    """Return True if only openvex scanners are found."""
    for scanner in scanners:
        if "openvex" not in scanner:
            return False
    return True


def expire_vuln(vuln_id, packages):
    """Expire a vulnerability."""
    expired = Assessment.new_dto(vuln_id, packages)
    expired.set_status("not_affected")
    expired.set_justification("component_not_present")
    expired.set_not_affected_reason("Vulnerable component removed, marking as expired")
    expired.set_status_notes("Vulnerability no longer present in analysis, marking as expired")
    return expired


def revert_expiration_vuln(vuln_id, packages, previous_assessment):
    """Expire a vulnerability."""
    state = Assessment.new_dto(vuln_id, packages)
    if previous_assessment is None:
        state.set_status("under_investigation")
        state.set_status_notes("Vulnerability was expired but is found again by scanners, setting it in default state")
    else:
        state.set_status(previous_assessment.status)
        state.set_justification(previous_assessment.justification)
        state.set_not_affected_reason(previous_assessment.impact_statement)
        state.set_status_notes(
            "Vulnerability was expired but is found again by scanners, setting it back to previous state"
        )
    return state


def post_treatment(controllers, files):
    """Do some actions on data after collect and aggregation."""
    # 1. fetch EPSS
    controllers["vulnerabilities"].fetch_epss_scores()

    # 2. fetch published dates from NVD
    controllers["vulnerabilities"].fetch_published_dates()

    # 3. Mark all vulnerabilities not present in analysis anymore as expired (but still in openvex)
    for (vuln_id, vuln) in controllers["vulnerabilities"].vulnerabilities.items():
        assessments = controllers["assessments"].gets_by_vuln(vuln_id)
        already_expired = False
        is_last_assessment_an_expiration = False
        last_assessment_before_expiration = None
        need_expiration = False
        for assessment in assessments:
            is_last_assessment_an_expiration = False
            if assessment.status in ["affected", "exploitable", "under_investigation", "in_triage"]:
                need_expiration = True
                last_assessment_before_expiration = assessment
            else:
                need_expiration = False
                if "marking as expired" in assessment.status_notes:
                    already_expired = True
                    is_last_assessment_an_expiration = True
                else:
                    last_assessment_before_expiration = assessment

        if is_items_only_openvex(vuln.found_by) and need_expiration and not already_expired:
            controllers["assessments"].add(expire_vuln(vuln_id, vuln.packages))

        elif is_last_assessment_an_expiration and not is_items_only_openvex(vuln.found_by):
            controllers["assessments"].add(
                revert_expiration_vuln(vuln_id, vuln.packages, last_assessment_before_expiration)
            )


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
    """Read from well-known files to grab vulnerabilities."""
    scanGrype = GrypeVulns(controllers)
    scanYocto = YoctoVulns(controllers)
    local_database = OpenVex(controllers)
    openvex = OpenVex(controllers)
    timeEstimates = TimeEstimates(controllers)
    cdx = CycloneDx(controllers)
    spdx = SPDX(controllers)
    fastspdx3 = FastSPDX3(controllers)
    fastspdx = FastSPDX(controllers)
    templates = Templates(controllers)

    verbose(f"merger_ci: Reading {os.getenv('LOCAL_USER_DATABASE_PATH', LOCAL_USER_DATABASE_PATH)}")
    try:
        with open(os.getenv("LOCAL_USER_DATABASE_PATH", LOCAL_USER_DATABASE_PATH), "r") as f:
            local_database.load_from_dict(json.loads(f.read()), ["local_user_data"])
    except FileNotFoundError:
        print("Warning: Did not find local user database file, which is used to store history of analysis."
              + " This is normal at first start but not in later analysis")
    except Exception as e:
        if os.getenv('IGNORE_PARSING_ERRORS', 'false') != 'true':
            print(f"Error parsing OpenVEX file: {e}")
            print("Hint: set IGNORE_PARSING_ERRORS=true to ignore this error")
            raise e
        else:
            print(f"Ignored: Error parsing OpenVEX file: {e}")

    verbose(f"merger_ci: Reading {os.getenv('CDX_PATH', CDX_PATH)}")
    error_cdx_not_found_displayed = False
    try:
        with open(os.getenv("CDX_PATH", CDX_PATH), "r") as f:
            cdx.load_from_dict(json.loads(f.read()))
            cdx.parse_and_merge()
    except FileNotFoundError:
        print("Warning: Did not find CycloneDX files. If you intended to scan CycloneDX files,"
              + " this mean there was an issue when collecting them.")
        error_cdx_not_found_displayed = True

    verbose(f"merger_ci: Reading {os.getenv('OPENVEX_PATH', OPENVEX_PATH)}")
    try:
        with open(os.getenv("OPENVEX_PATH", OPENVEX_PATH), "r") as f:
            openvex.load_from_dict(json.loads(f.read()))
    except FileNotFoundError:
        print("Warning: Did not find OpenVEX files. If you intended to scan OpenVEX files,"
              + " this mean there was an issue when collecting them.")

    verbose(f"merger_ci: Reading {os.getenv('GRYPE_CDX_PATH', GRYPE_CDX_PATH)}")
    try:
        with open(os.getenv("GRYPE_CDX_PATH", GRYPE_CDX_PATH), "r") as f:
            scanGrype.load_from_dict(json.loads(f.read()))
    except FileNotFoundError:
        if not error_cdx_not_found_displayed:
            print("Warning: Did not find Grype analysis of CDX files. If you intended to scan"
                  + " CycloneDX files, this mean there was an issue when analysing them.")

    use_fastspdx = False
    if os.getenv('IGNORE_PARSING_ERRORS', 'false') == 'true':
        use_fastspdx = True
        verbose("spdx_merge: Using FastSPDX parser")

    pkgCtrl = controllers["packages"]

    # First try to read the merged SPDX file (created by spdx_merge.py)
    verbose("merger_ci: Merged SPDX file not found, reading individual files")
    for file in glob.glob(f"{os.getenv('SPDX_FOLDER', SPDX_FOLDER)}/*.spdx.json"):
        abs_path = os.path.abspath(file)
        try:
            doc = SBOMDocument.get_by_path(abs_path)
            if doc:
                pkgCtrl.set_sbom_document(doc.id)
        except Exception:
            pass
        try:
            verbose(f"merger_ci: Reading {file}")
            with open(file, "r") as f:
                data = json.load(f)
                if fastspdx3.could_parse_spdx(data):
                    fastspdx3.parse_from_dict(data)
                elif use_fastspdx:
                    fastspdx.parse_from_dict(data)
                else:
                    spdx.load_from_file(file)
                    spdx.parse_and_merge()
        except Exception as e:
            if os.getenv('IGNORE_PARSING_ERRORS', 'false') != 'true':
                print(f"Error parsing SPDX file: {file} {e}")
                print("Hint: set IGNORE_PARSING_ERRORS=true to ignore this error")
                raise e
            else:
                print(f"Ignored: Error parsing SPDX file: {file} {e}")
        finally:
            pkgCtrl.set_sbom_document(None)

    verbose(f"merger_ci: Reading {os.getenv('GRYPE_SPDX_PATH', GRYPE_SPDX_PATH)}")
    try:
        with open(os.getenv("GRYPE_SPDX_PATH", GRYPE_SPDX_PATH), "r") as f:
            scanGrype.load_from_dict(json.loads(f.read()))
    except FileNotFoundError:
        print("Warning: Did not find Grype analysis of SPDX files. If you intended to scan"
              + " SPDX files, this mean there was an issue when analysing them.")

    for file in glob.glob(f"{os.getenv('YOCTO_FOLDER', YOCTO_FOLDER)}/*.json"):
        abs_path = os.path.abspath(file)
        try:
            doc = SBOMDocument.get_by_path(abs_path)
            if doc:
                pkgCtrl.set_sbom_document(doc.id)
        except Exception:
            pass
        try:
            verbose(f"merger_ci: Reading {file}")
            with open(file, "r") as f:
                scanYocto.load_from_dict(json.loads(f.read()))
        finally:
            pkgCtrl.set_sbom_document(None)

    verbose(f"merger_ci: Reading {os.getenv('TIME_ESTIMATES_PATH', TIME_ESTIMATES_PATH)}")
    try:
        with open(os.getenv("TIME_ESTIMATES_PATH", TIME_ESTIMATES_PATH), "r") as f:
            timeEstimates.load_from_dict(json.loads(f.read()))
    except FileNotFoundError:
        pass
    except Exception as e:
        if os.getenv('IGNORE_PARSING_ERRORS', 'false') != 'true':
            print(f"Error parsing time_estimates.json file: {e}")
            print("Hint: set IGNORE_PARSING_ERRORS=true to ignore this error")
            raise e
        else:
            print(f"Ignored: Error parsing time_estimates.json file: {e}")

    return {
        "openvex": openvex,
        "time_estimates": timeEstimates,
        "cdx": cdx,
        "templates": templates
    }


def output_results(controllers, files, failed: bool = False, failed_vulns=None):
    """Output the results to files."""

    fail_condition = os.getenv("FAIL_CONDITION", "")
    list_docs = [d.strip() for d in os.getenv("GENERATE_DOCUMENTS", "").split(",") if d.strip()]

    if not fail_condition:
        spdx = SPDX(controllers)  # regenerate, don't re-use reader SPDX to avoid validation errors
        spdx3 = SPDX3(controllers)

        verbose(f"merger_ci: Exporting {os.getenv('LOCAL_USER_DATABASE_PATH', LOCAL_USER_DATABASE_PATH)}")
        with open(os.getenv("LOCAL_USER_DATABASE_PATH", LOCAL_USER_DATABASE_PATH), "w") as f:
            f.write(json.dumps(files["openvex"].to_dict(), indent=2))

        verbose(f"merger_ci: Exporting {os.getenv('OUTPUT_CDX_PATH', OUTPUT_CDX_PATH)}")
        with open(os.getenv("OUTPUT_CDX_PATH", OUTPUT_CDX_PATH), "w") as f:
            f.write(files["cdx"].output_as_json())

        verbose(f"merger_ci: Exporting {os.getenv('OUTPUT_SPDX_PATH', OUTPUT_SPDX_PATH)}")
        with open(os.getenv("OUTPUT_SPDX_PATH", OUTPUT_SPDX_PATH), "w") as f:
            f.write(spdx.output_as_json())

        verbose(f"merger_ci: Exporting {os.getenv('OUTPUT_SPDX3_PATH', OUTPUT_SPDX3_PATH)}")
        with open(os.getenv("OUTPUT_SPDX3_PATH", OUTPUT_SPDX3_PATH), "w") as f:
            f.write(spdx3.output_as_json())

        verbose(f"merger_ci: Exporting {os.getenv('TIME_ESTIMATES_PATH', TIME_ESTIMATES_PATH)}")
        with open(os.getenv("TIME_ESTIMATES_PATH", TIME_ESTIMATES_PATH), "w") as f:
            f.write(json.dumps(files["time_estimates"].to_dict(), indent=2))

        # packages / vulnerabilities / assessments are now served from the DB;
        # no intermediate JSON files are written for those.

        if "match_condition.adoc" in list_docs:
            list_docs.remove("match_condition.adoc")
    else:
        if "match_condition.adoc" in list_docs:
            list_docs = ["match_condition.adoc"]
        else:
            list_docs = []

    metadata: dict[str, Any] = {
        "author": os.getenv('AUTHOR_NAME', 'Savoir-faire Linux'),
        "export_date": date.today().isoformat()
    }
    if os.getenv('DEBUG_SKIP_SCAN', '') != 'true':
        metadata["scan_date"] = datetime.now(timezone.utc).strftime("%Y-%m-%d at %H:%M (UTC)")
    if failed:
        metadata["failed_vulns"] = failed_vulns or []
    for doc in list_docs:
        if not doc:
            continue
        try:
            doc = doc.strip()
            verbose(f"merger_ci: Generating report from template {doc}")
            content = files["templates"].render(doc, **metadata)
            with open(f"/scan/outputs/{doc}", "w") as f:
                f.write(content)
        except Exception as e:
            print(f"Warning: failed to generate document from {doc}: {e}")


@click.command("merge")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", default=None,
              help=f"Variant name (defaults to '{DEFAULT_VARIANT_NAME}').")
@click.argument("sbom_inputs", nargs=-1, type=click.Path(exists=True))
@with_appcontext
def create_project_context(project: str, variant: str | None, sbom_inputs: tuple) -> None:
    """Merge SBOM inputs into the database under a named project/variant scan.

    SBOM_INPUTS is one or more paths to SBOM files.
    When no variant is given, inputs go into a scan under the 'default' variant.
    """
    variant_name = variant or DEFAULT_VARIANT_NAME

    project_obj = ProjectController.get_or_create(project)
    variant_obj = VariantController.get_or_create(variant_name, project_obj.id)
    scan = ScanController.create("default", variant_obj.id)
    click.echo(f"project='{project}' variant='{variant_name}' scan={scan.id}")

    for sbom_file in sbom_inputs:
        abs_path = os.path.abspath(sbom_file)
        SBOMDocumentController.create(abs_path, os.path.basename(sbom_file), scan.id)
        click.echo(f"  + {sbom_file}")


@click.command("process")
@with_appcontext
def process_command() -> None:
    """Parse all SBOM inputs, persist results to the DB and generate output files."""
    _run_main()


def _run_main() -> dict:
    """Core processing logic (usable both from the CLI command and directly)."""
    from ..extensions import batch_session, db as _db
    import time as _time

    pkgCtrl = PackagesController()
    vulnCtrl = VulnerabilitiesController(pkgCtrl)
    assessCtrl = AssessmentsController(pkgCtrl, vulnCtrl)
    controllers = {
        "packages": pkgCtrl,
        "vulnerabilities": vulnCtrl,
        "assessments": assessCtrl
    }

    _t0 = _time.monotonic()

    # Wrap all ingestion + post-treatment inside batch_session so that the
    # hundreds/thousands of individual model commit() calls are deferred to a
    # single SQLite transaction at the end of the block.
    with batch_session():
        files = read_inputs(controllers)
        verbose(f"merger_ci: Finished reading inputs ({_time.monotonic() - _t0:.1f}s)")

        _t1 = _time.monotonic()
        verbose("merger_ci: Start Post-treatment")
        post_treatment(controllers, files)
        verbose(f"merger_ci: Finished post-treatment ({_time.monotonic() - _t1:.1f}s)")
    # ← single COMMIT happens here
    verbose(f"merger_ci: DB commit done ({_time.monotonic() - _t0:.1f}s total)")

    fail_condition = os.getenv("FAIL_CONDITION", "")
    failed_vulns = []
    if fail_condition:
        _t2 = _time.monotonic()
        verbose("merger_ci: Start evaluating conditions")
        failed_vulns = evaluate_condition(controllers, fail_condition)
        verbose(f"merger_ci: Finished evaluating conditions ({_time.monotonic() - _t2:.1f}s)")

    _t3 = _time.monotonic()
    verbose("merger_ci: Start exporting results")
    output_results(controllers, files, failed=len(failed_vulns) > 0, failed_vulns=failed_vulns)
    verbose(f"merger_ci: Finished exporting results ({_time.monotonic() - _t3:.1f}s)")

    # Populate the observations table: link every finding to the current scan.
    _t4 = _time.monotonic()
    verbose("merger_ci: Populating observations table")
    try:
        latest_scan = ScanModel.get_latest()
        if latest_scan:
            findings = list(_db.session.execute(_db.select(FindingModel)).scalars().all())
            existing_pairs = {
                (obs.finding_id, obs.scan_id)
                for obs in Observation.get_by_scan(latest_scan.id)
            }
            with batch_session():
                for finding in findings:
                    if (finding.id, latest_scan.id) not in existing_pairs:
                        try:
                            Observation.create(finding.id, latest_scan.id)
                        except Exception:
                            pass
            # ← single COMMIT for all observations
            verbose(f"merger_ci: Observations created for scan {latest_scan.id} ({_time.monotonic() - _t4:.1f}s)")
        else:
            print("Warning: no scan found in DB — skipping observation creation.")
    except Exception as e:
        print(f"Warning: could not populate observations table: {e}")

    verbose(f"merger_ci: Total processing time: {_time.monotonic() - _t0:.1f}s")

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

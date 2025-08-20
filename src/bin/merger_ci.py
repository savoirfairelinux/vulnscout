#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This python job is to aggregate packages, vulnerabilities and assessments from
# sources files, aggregate them, enrich them with VEX info and output them to files.
# Outputs files will be used by web API later. (see scan.sh)
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..views.grype_vulns import GrypeVulns
from ..views.yocto_vulns import YoctoVulns
from ..views.openvex import OpenVex
from ..views.time_estimates import TimeEstimates
from ..views.cyclonedx import CycloneDx
from ..views.spdx import SPDX
from ..views.fast_spdx import FastSPDX
from ..views.fast_spdx3 import FastSPDX3
from ..views.templates import Templates
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController
from ..controllers.conditions_parser import ConditionParser
from ..models.assessment import VulnAssessment
from ..helpers.verbose import verbose
from .set_status import SetStatus
import glob
import orjson
import os
from datetime import date, datetime, timezone

CDX_PATH = "/scan/tmp/merged.cdx.json"
SPDX_FOLDER = "/scan/tmp/spdx"
GRYPE_CDX_PATH = "/scan/tmp/vulns-cdx.grype.json"
GRYPE_SPDX_PATH = "/scan/tmp/vulns-spdx.grype.json"
YOCTO_FOLDER = "/scan/tmp/yocto_cve_check"
OPENVEX_PATH = "/scan/outputs/openvex.json"
TIME_ESTIMATES_PATH = "/scan/outputs/time_estimates.json"

OUTPUT_PATH = "/scan/tmp/vulns-merged.json"
OUTPUT_PKG_PATH = "/scan/tmp/packages-merged.json"
OUTPUT_VULN_PATH = "/scan/tmp/vulnerabilities-merged.json"
OUTPUT_ASSESSEMENT_PATH = "/scan/tmp/assessments-merged.json"
OUTPUT_CDX_PATH = "/scan/outputs/sbom.cdx.json"
OUTPUT_SPDX_PATH = "/scan/outputs/sbom.spdx.json"


def is_items_only_openvex(scanners: list[str]) -> bool:
    """Return True if only openvex scanners are found."""
    for scanner in scanners:
        if "openvex" not in scanner:
            return False
    return True


def expire_vuln(vuln_id, packages):
    """Expire a vulnerability."""
    expired = VulnAssessment(vuln_id, packages)
    expired.set_status("not_affected")
    expired.set_justification("component_not_present")
    expired.set_not_affected_reason("Vulnerable component removed, marking as expired")
    expired.set_status_notes("Vulnerability no longer present in analysis, marking as expired")
    return expired


def revert_expiration_vuln(vuln_id, packages, previous_assessment):
    """Expire a vulnerability."""
    state = VulnAssessment(vuln_id, packages)
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


def post_treatment(controllers, status):
    """Do some actions on data after collect and aggregation."""
    # 1. fetch EPSS
    status.set_status("7", "Fetching EPSS scores", "0")
    controllers["vulnerabilities"].fetch_epss_scores()
    status.set_status("7", "Fetching EPSS scores", "100")

    # 2. Mark all vulnerabilities not present in analysis anymore as expired (but still in openvex)
    vulns = list(controllers["vulnerabilities"].vulnerabilities.items())
    total_vulns = len(vulns) or 1

    for idx, (vuln_id, vuln) in enumerate(vulns, start=1):
        status.set_status(
            "7",
            f"Processing vulnerability {idx} of {total_vulns}",
            f"{idx / total_vulns * 100:.1f}"
        )

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

    status.set_status("7", "Finished processing vulnerabilities", "100")


def evaluate_condition(controllers, condition):
    """Evaluate a condition and exit if it's True."""
    parser = ConditionParser()
    have_failed = False
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
            if last_assessment is None or last_assessment.timestamp < assessment.timestamp:
                last_assessment = assessment
        if last_assessment:
            data["fixed"] = last_assessment.status in ["fixed", "resolved", "resolved_with_pedigree"]
            data["ignored"] = last_assessment.status in ["not_affected", "false_positive"]
            data["affected"] = last_assessment.status in ["affected", "exploitable"]
            data["pending"] = last_assessment.status in ["under_investigation", "in_triage"]
            data["new"] = False
        if parser.evaluate(condition, data):
            have_failed = True
            print(f"Vulnerability triggered fail condition: {vuln_id}")  # output in stdout to be catched by the CI
    if have_failed:
        exit(2)


def read_inputs(controllers, status):
    """Read from well-known files to grab vulnerabilities with per-category progress."""
    scanGrype = GrypeVulns(controllers)
    scanYocto = YoctoVulns(controllers)
    openvex = OpenVex(controllers)
    timeEstimates = TimeEstimates(controllers)
    cdx = CycloneDx(controllers)
    spdx = SPDX(controllers)
    fastspdx3 = FastSPDX3(controllers)
    fastspdx = FastSPDX(controllers)
    templates = Templates(controllers)

    def update_progress(current, total):
        return f"{current / total * 100}" if total else "100"

    # --- OpenVEX ---
    verbose(f"merger_ci: Reading {os.getenv('OPENVEX_PATH', OPENVEX_PATH)}")
    status.set_status("7", "Reading OpenVEX file", "0")
    try:
        vex_path = os.getenv("OPENVEX_PATH", OPENVEX_PATH)
        if os.path.exists(vex_path):
            with open(os.getenv("OPENVEX_PATH", OPENVEX_PATH), "rb") as f:
                openvex.load_from_dict(orjson.loads(f.read()))
    except FileNotFoundError:
        print("Warning: Did not find OpenVEX file. Normal on first start.")
    except Exception as e:
        if os.getenv('IGNORE_PARSING_ERRORS', 'false') != 'true':
            print(f"Error parsing OpenVEX file: {e}")
            raise e
        else:
            print(f"Ignored: Error parsing OpenVEX file: {e}")
    status.set_status("7", "Reading OpenVEX file", "100")

    # --- CycloneDX ---
    cdx_input = os.getenv('CDX_PATH', CDX_PATH)
    if os.path.isfile(cdx_input):
        cdx_files = [cdx_input]
    else:
        cdx_files = glob.glob(f"{cdx_input}/*.json")
    total_cdx_files = len(cdx_files) or 1
    for idx, file in enumerate(cdx_files, start=1):
        verbose(f"merger_ci: Reading {file}")
        status.set_status(
            "7",
            f"Reading CycloneDX file {idx} of {total_cdx_files}",
            update_progress(idx, total_cdx_files)
        )
        try:
            with open(file, "rb") as f:
                cdx.load_from_dict(orjson.loads(f.read()))
        except Exception as e:
            if os.getenv('IGNORE_PARSING_ERRORS', 'false') != 'true':
                print(f"Error parsing CycloneDX file: {file} {e}")
                raise e
            else:
                print(f"Ignored: Error parsing CycloneDX file: {file} {e}")
    cdx.parse_and_merge()
    status.set_status("7", "Reading CycloneDX files", "100")

    # --- Grype CycloneDX ---
    verbose(f"merger_ci: Reading {os.getenv('GRYPE_CDX_PATH', GRYPE_CDX_PATH)}")
    status.set_status("7", "Reading Grype CycloneDX analysis", "0")
    try:
        with open(os.getenv("GRYPE_CDX_PATH", GRYPE_CDX_PATH), "rb") as f:
            scanGrype.load_from_dict(orjson.loads(f.read()))
    except FileNotFoundError:
        print("Warning: Did not find Grype analysis of CDX files.")
    status.set_status("7", "Reading Grype CycloneDX analysis", "100")

    # --- SPDX files ---
    use_fastspdx = os.getenv('IGNORE_PARSING_ERRORS', 'false') == 'true'
    spdx_files = glob.glob(f"{os.getenv('SPDX_FOLDER', SPDX_FOLDER)}/*.spdx.json")
    total_spdx_files = len(spdx_files)
    for idx, file in enumerate(spdx_files, start=1):
        verbose(f"merger_ci: Reading {file}")
        status.set_status(
            "7",
            f"Reading SPDX file {idx} of {total_spdx_files}",
            update_progress(idx, total_spdx_files)
        )
        try:
            with open(file, "rb") as f:
                data = orjson.loads(f.read())
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
                raise e
            else:
                print(f"Ignored: Error parsing SPDX file: {file} {e}")

    # --- Grype SPDX ---
    verbose(f"merger_ci: Reading {os.getenv('GRYPE_SPDX_PATH', GRYPE_SPDX_PATH)}")
    status.set_status("7", "Reading Grype SPDX analysis", "0")
    try:
        with open(os.getenv("GRYPE_SPDX_PATH", GRYPE_SPDX_PATH), "rb") as f:
            scanGrype.load_from_dict(orjson.loads(f.read()))
    except FileNotFoundError:
        print("Warning: Did not find Grype analysis of SPDX files.")
    status.set_status("7", "Reading Grype SPDX analysis", "100")

    # --- Yocto files ---
    yocto_files = glob.glob(f"{os.getenv('YOCTO_FOLDER', YOCTO_FOLDER)}/*.json")
    total_yocto_files = len(yocto_files)
    for idx, file in enumerate(yocto_files, start=1):
        verbose(f"merger_ci: Reading {file}")
        status.set_status(
            "7",
            f"Reading Yocto file {idx} of {total_yocto_files}",
            update_progress(idx, total_yocto_files)
        )
        with open(file, "rb") as f:
            scanYocto.load_from_dict(orjson.loads(f.read()))
    status.set_status("7", "Reading Yocto files", "100")

    # --- Time estimates ---
    verbose(f"merger_ci: Reading {os.getenv('TIME_ESTIMATES_PATH', TIME_ESTIMATES_PATH)}")
    status.set_status("7", "Reading time estimates file", "0")
    try:
        with open(os.getenv("TIME_ESTIMATES_PATH", TIME_ESTIMATES_PATH), "rb") as f:
            timeEstimates.load_from_dict(orjson.loads(f.read()))
    except FileNotFoundError:
        pass
    except Exception as e:
        if os.getenv('IGNORE_PARSING_ERRORS', 'false') != 'true':
            print(f"Error parsing time_estimates.json file: {e}")
            raise e
        else:
            print(f"Ignored: Error parsing time_estimates.json file: {e}")
    status.set_status("7", "Reading time estimates file", "100")

    return {
        "openvex": openvex,
        "time_estimates": timeEstimates,
        "cdx": cdx,
        "templates": templates
    }


def output_results(controllers, files, status):
    """Output the results to files with progress updates."""
    spdx = SPDX(controllers)  # regenerate, don't re-use reader SPDX to avoid validation errors

    # --- Step 1: Export main data ---
    status.set_status("7", "Exporting main data", "0")
    output = {
        "packages": controllers["packages"].to_dict(),
        "vulnerabilities": controllers["vulnerabilities"].to_dict(),
        "assessments": controllers["assessments"].to_dict()
    }

    file_steps = [
        ("OUTPUT_PATH", output),
        ("OUTPUT_PKG_PATH", output["packages"]),
        ("OUTPUT_VULN_PATH", output["vulnerabilities"]),
        ("OUTPUT_ASSESSEMENT_PATH", output["assessments"])
    ]

    total_files = len(file_steps)
    for idx, (env_var, data) in enumerate(file_steps, start=1):
        path = os.getenv(env_var, globals().get(env_var))
        verbose(f"merger_ci: Exporting {path}")
        status.set_status(
            "7",
            f"Exporting {idx} of {total_files}: {path}",
            f"{idx / total_files * 100:.1f}"
        )
        with open(path, "wb") as f:
            f.write(orjson.dumps(data))

    # --- Step 2: Export OpenVEX ---
    openvex_path = os.getenv("OPENVEX_PATH", OPENVEX_PATH)
    verbose(f"merger_ci: Exporting {openvex_path}")
    status.set_status("7", "Exporting OpenVEX file", "0")
    with open(openvex_path, "wb") as f:
        f.write(orjson.dumps(files["openvex"].to_dict(), option=orjson.OPT_INDENT_2))
    status.set_status("7", "Exporting OpenVEX file", "100")

    # --- Step 3: Export CycloneDX ---
    cdx_path = os.getenv("OUTPUT_CDX_PATH", OUTPUT_CDX_PATH)
    verbose(f"merger_ci: Exporting {cdx_path}")
    status.set_status("7", "Exporting CycloneDX file", "0")
    with open(cdx_path, "w") as f:
        f.write(files["cdx"].output_as_json())
    status.set_status("7", "Exporting CycloneDX file", "100")

    # --- Step 4: Export SPDX ---
    spdx_path = os.getenv("OUTPUT_SPDX_PATH", OUTPUT_SPDX_PATH)
    verbose(f"merger_ci: Exporting {spdx_path}")
    status.set_status("7", "Exporting SPDX file", "0")
    with open(spdx_path, "w") as f:
        f.write(spdx.output_as_json())
    status.set_status("7", "Exporting SPDX file", "100")

    # --- Step 5: Export time estimates ---
    time_path = os.getenv("TIME_ESTIMATES_PATH", TIME_ESTIMATES_PATH)
    verbose(f"merger_ci: Exporting {time_path}")
    status.set_status("7", "Exporting time estimates", "0")
    with open(time_path, "wb") as f:
        f.write(orjson.dumps(files["time_estimates"].to_dict(), option=orjson.OPT_INDENT_2))
    status.set_status("7", "Exporting time estimates", "100")

    # --- Step 6: Generate documents from templates ---
    list_docs = os.getenv("GENERATE_DOCUMENTS", "").split(",")
    metadata = {
        "author": os.getenv('COMPANY_NAME', 'Savoir-faire Linux'),
        "export_date": date.today().isoformat()
    }
    if os.getenv('DEBUG_SKIP_SCAN', '') != 'true':
        metadata["scan_date"] = datetime.now(timezone.utc).strftime("%Y-%m-%d at %H:%M (UTC)")

    total_docs = len([d for d in list_docs if d.strip()])
    for idx, doc in enumerate(list_docs, start=1):
        doc = doc.strip()
        if not doc:
            continue
        try:
            verbose(f"merger_ci: Generating report from template {doc}")
            status.set_status(
                "7",
                f"Generating document {idx} of {total_docs}: {doc}",
                f"{idx / total_docs * 100:.1f}"
            )
            content = files["templates"].render(doc, **metadata)
            with open(f"/scan/outputs/{doc}", "w") as f:
                f.write(content)
        except Exception as e:
            print(f"Warning: failed to generate document from {doc}: {e}")

    status.set_status("7", "Finished exporting all results", "100")


def main():
    base_dir = os.getenv("BASE_DIR", "/scan")
    status = SetStatus(base_dir)

    pkgCtrl = PackagesController()
    vulnCtrl = VulnerabilitiesController(pkgCtrl)
    assessCtrl = AssessmentsController(pkgCtrl, vulnCtrl)
    controllers = {
        "packages": pkgCtrl,
        "vulnerabilities": vulnCtrl,
        "assessments": assessCtrl
    }

    files = read_inputs(controllers, status)
    verbose("merger_ci: Finished reading inputs")

    verbose("merger_ci: Start Post-treatment")
    post_treatment(controllers, status)
    verbose("merger_ci: Finished post-treatment")

    if os.getenv("FAIL_CONDITION", "") != "":
        verbose("merger_ci: Start evaluating conditions")
        evaluate_condition(controllers, os.getenv("FAIL_CONDITION"))
        verbose("merger_ci: Finished evaluating conditions")

    verbose("merger_ci: Start exporting results")
    output_results(controllers, files, status)
    verbose("merger_ci: Finished exporting results")


if __name__ == "__main__":
    main()

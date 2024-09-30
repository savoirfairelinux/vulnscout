#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This python job is to aggregate packages, vulnerabilities and assessments from
# sources files, aggregate them, enrich them with VEX info and output them to files.
# Outputs files will be used by web API later. (see scan.sh)
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.

from ..views.grype_vulns import GrypeVulns
from ..views.yocto_vulns import YoctoVulns
from ..views.openvex import OpenVex
from ..views.time_estimates import TimeEstimates
from ..views.cyclonedx import CycloneDx
from ..views.templates import Templates
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController
from ..controllers.conditions_parser import ConditionParser
import glob
import json
import os

CDX_PATH = "/scan/tmp/merged.cdx.json"
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


def post_treatment(controllers, files):
    """Do some actions on data after collect and aggregation."""
    controllers["vulnerabilities"].fetch_epss_scores()


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


def read_inputs(controllers):
    """Read from well-known files to grab vulnerabilities."""
    scanGrype = GrypeVulns(controllers)
    scanYocto = YoctoVulns(controllers)
    openvex = OpenVex(controllers)
    timeEstimates = TimeEstimates(controllers)
    cdx = CycloneDx(controllers)
    templates = Templates(controllers)

    try:
        with open(os.getenv("OPENVEX_PATH", OPENVEX_PATH), "r") as f:
            openvex.load_from_dict(json.loads(f.read()))
    except FileNotFoundError:
        print("Warning: Did not find openvex file, which is used to store history of analysis."
              + " This is normal at first start but not in later analysis")
    except Exception as e:
        if os.getenv('IGNORE_PARSING_ERRORS', 'false') != 'true':
            print(f"Error parsing OpenVEX file: {e}")
            print("Hint: set IGNORE_PARSING_ERRORS=true to ignore this error")
            raise e
        else:
            print(f"Ignored: Error parsing OpenVEX file: {e}")

    error_cdx_not_found_displayed = False
    try:
        with open(os.getenv("CDX_PATH", CDX_PATH), "r") as f:
            cdx.load_from_dict(json.loads(f.read()))
            cdx.parse_and_merge()
    except FileNotFoundError:
        print("Warning: Did not find CycloneDX files. If you intended to scan CycloneDX files,"
              + " this mean there was an issue when collecting them.")
        error_cdx_not_found_displayed = True

    try:
        with open(os.getenv("GRYPE_CDX_PATH", GRYPE_CDX_PATH), "r") as f:
            scanGrype.load_from_dict(json.loads(f.read()))
    except FileNotFoundError:
        if not error_cdx_not_found_displayed:
            print("Warning: Did not find Grype analysis of CDX files. If you intended to scan"
                  + " CycloneDX files, this mean there was an issue when analysing them.")

    with open(os.getenv("GRYPE_SPDX_PATH", GRYPE_SPDX_PATH), "r") as f:
        scanGrype.load_from_dict(json.loads(f.read()))

    for file in glob.glob(f"{os.getenv('YOCTO_FOLDER', YOCTO_FOLDER)}/*.json"):
        with open(file, "r") as f:
            scanYocto.load_from_dict(json.loads(f.read()))

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


def output_results(controllers, files):
    """Output the results to files."""
    output = {
        "packages": controllers["packages"].to_dict(),
        "vulnerabilities": controllers["vulnerabilities"].to_dict(),
        "assessments": controllers["assessments"].to_dict()
    }
    with open(os.getenv("OUTPUT_PATH", OUTPUT_PATH), "w") as f:
        f.write(json.dumps(output))
    with open(os.getenv("OUTPUT_PKG_PATH", OUTPUT_PKG_PATH), "w") as f:
        f.write(json.dumps(output["packages"]))
    with open(os.getenv("OUTPUT_VULN_PATH", OUTPUT_VULN_PATH), "w") as f:
        f.write(json.dumps(output["vulnerabilities"]))
    with open(os.getenv("OUTPUT_ASSESSEMENT_PATH", OUTPUT_ASSESSEMENT_PATH), "w") as f:
        f.write(json.dumps(output["assessments"]))

    with open(os.getenv("OPENVEX_PATH", OPENVEX_PATH), "w") as f:
        f.write(json.dumps(files["openvex"].to_dict(), indent=2))
    with open(os.getenv("OUTPUT_CDX_PATH", OUTPUT_CDX_PATH), "w") as f:
        f.write(files["cdx"].output_as_json())
    with open(os.getenv("TIME_ESTIMATES_PATH", TIME_ESTIMATES_PATH), "w") as f:
        f.write(json.dumps(files["time_estimates"].to_dict(), indent=2))

    list_docs = os.getenv("GENERATE_DOCUMENTS", "").split(",")
    for doc in list_docs:
        if not doc:
            continue
        try:
            doc = doc.strip()
            content = files["templates"].render(doc)
            with open(f"/scan/outputs/{doc}", "w") as f:
                f.write(content)
        except Exception as e:
            print(f"Warning: failed to generate document from {doc}: {e}")


def main():
    pkgCtrl = PackagesController()
    vulnCtrl = VulnerabilitiesController(pkgCtrl)
    assessCtrl = AssessmentsController(pkgCtrl, vulnCtrl)
    controllers = {
        "packages": pkgCtrl,
        "vulnerabilities": vulnCtrl,
        "assessments": assessCtrl
    }

    files = read_inputs(controllers)
    post_treatment(controllers, files)
    if os.getenv("FAIL_CONDITION", "") != "":
        evaluate_condition(controllers, os.getenv("FAIL_CONDITION"))
    output_results(controllers, files)


if __name__ == "__main__":
    main()

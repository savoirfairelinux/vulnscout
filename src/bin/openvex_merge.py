#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This Python job reads a bunch of OpenVEX files and merges them into one.
# Output files can then be used by merger_ci.py later.
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..views.openvex import OpenVex
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController
from ..helpers.verbose import verbose
import glob
import os
import json

INPUT_OPENVEX_FOLDER = "/scan/tmp/openvex"
OUTPUT_OPENVEX_FILE = "/scan/outputs/sbom.openvex.json"

def read_inputs(controllers):
    """Read OpenVEX files from folder and merge them into controllers."""
    openvex = OpenVex(controllers)

    for file in glob.glob(f"{os.getenv('INPUT_OPENVEX_FOLDER', INPUT_OPENVEX_FOLDER)}/*openvex*.json"):
        try:
            verbose(f"openvex_merge: Merging {file}")
            with open(file, "r") as f:
                data = json.load(f)
                openvex.load_from_dict(data)
        except Exception as e:
            if os.getenv('IGNORE_PARSING_ERRORS', 'false') != 'true':
                print(f"Error parsing OpenVEX file: {file} {e}")
                print("Hint: set IGNORE_PARSING_ERRORS=true to ignore this error")
                raise e
            else:
                print(f"Ignored: Error parsing OpenVEX file: {file} {e}")

def output_results(controllers):
    """Output the merged OpenVEX results to a single file."""
    openvex = OpenVex(controllers)

    verbose(f"openvex_merge: Writing {os.getenv('OUTPUT_OPENVEX_FILE', OUTPUT_OPENVEX_FILE)}")
    with open(os.getenv("OUTPUT_OPENVEX_FILE", OUTPUT_OPENVEX_FILE), "w") as f:
        json.dump(openvex.to_dict(), f, indent=2)

def main():
    pkg_ctrl = PackagesController()
    vuln_ctrl = VulnerabilitiesController(pkg_ctrl)
    assess_ctrl = AssessmentsController(pkg_ctrl, vuln_ctrl)
    controllers = {
        "packages": pkg_ctrl,
        "vulnerabilities": vuln_ctrl,
        "assessments": assess_ctrl
    }

    read_inputs(controllers)
    output_results(controllers)


if __name__ == "__main__":
    main()

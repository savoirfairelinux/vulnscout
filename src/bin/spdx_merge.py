#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This python job is to read a bunch of SPDX files and merge them in one
# Outputs files will be used by merger_ci.py later. (see scan.sh)
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.

from ..views.spdx import SPDX
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController
import glob
import os

INPUT_SPDX_FOLDER = "/scan/tmp/spdx"
OUTPUT_SPDX_FILE = "/scan/outputs/sbom.spdx.json"


def read_inputs(controllers):
    """Read from folder."""
    spdx = SPDX(controllers)

    for file in glob.glob(f"{os.getenv('INPUT_SPDX_FOLDER', INPUT_SPDX_FOLDER)}/*.spdx.json"):
        try:
            spdx.load_from_file(file)
            spdx.parse_and_merge()
        except Exception as e:
            if os.getenv('IGNORE_PARSING_ERRORS', 'false') != 'true':
                print(f"Error parsing SPDX file: {file} {e}")
                print("Hint: set IGNORE_PARSING_ERRORS=true to ignore this error")
                raise e
            else:
                print(f"Ignored: Error parsing SPDX file: {file} {e}")


def output_results(controllers):
    """Output the results to files."""
    spdx = SPDX(controllers)

    with open(os.getenv("OUTPUT_SPDX_FILE", OUTPUT_SPDX_FILE), "w") as f:
        f.write(spdx.output_as_json())


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

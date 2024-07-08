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
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController
import glob
import json
import os

GRYPE_CDX_PATH = "/scan/tmp/vulns-cdx.grype.json"
GRYPE_SPDX_PATH = "/scan/tmp/vulns-spdx.grype.json"
YOCTO_FOLDER = "/scan/tmp/yocto_cve_check"
OPENVEX_PATH = "/scan/outputs/openvex.json"

OUTPUT_PATH = "/scan/tmp/vulns-merged.json"
OUTPUT_PKG_PATH = "/scan/tmp/packages-merged.json"
OUTPUT_VULN_PATH = "/scan/tmp/vulnerabilities-merged.json"
OUTPUT_ASSESSEMENT_PATH = "/scan/tmp/assessments-merged.json"


def post_treatment(controllers, files):
    """Merge the vulnerabilities by vuln id."""
    pass


def read_inputs(controllers):
    """Read from well-known files to grab vulnerabilities."""
    scanGrype = GrypeVulns(controllers)
    scanYocto = YoctoVulns(controllers)
    openvex = OpenVex(controllers)

    try:
        with open(os.getenv("OPENVEX_PATH", OPENVEX_PATH), "r") as f:
            openvex.load_from_dict(json.loads(f.read()))
    except FileNotFoundError:
        pass
    except Exception as e:
        if os.getenv('IGNORE_PARSING_ERRORS', 'false') != 'true':
            print(f"Error parsing OpenVEX file: {e}")
            print("Hint: set IGNORE_PARSING_ERRORS=true to ignore this error")
            raise e
        else:
            print(f"Ignored: Error parsing OpenVEX file: {e}")

    with open(os.getenv("GRYPE_CDX_PATH", GRYPE_CDX_PATH), "r") as f:
        scanGrype.load_from_dict(json.loads(f.read()))
    with open(os.getenv("GRYPE_SPDX_PATH", GRYPE_SPDX_PATH), "r") as f:
        scanGrype.load_from_dict(json.loads(f.read()))

    for file in glob.glob(f"{os.getenv('YOCTO_FOLDER', YOCTO_FOLDER)}/*.json"):
        with open(file, "r") as f:
            scanYocto.load_from_dict(json.loads(f.read()))

    return {
        "openvex": openvex
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
    output_results(controllers, files)


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import os as _os

_DATA_DIR = _os.path.dirname(_os.path.abspath(__file__))

_EMPTY_OPENVEX = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://openvex.dev/docs/example/vex-empty-test",
    "author": "Tests",
    "timestamp": "2024-01-01T00:00:00Z",
    "version": 1,
    "statements": [],
}


def write_demo_files(files):
    """Write files with an real-life example issued fron cairo vulnerability."""

    if "CDX_PATH" in files:
        with open(_os.path.join(_DATA_DIR, "input_cdx.json"), "r") as f:
            files["CDX_PATH"].write_text(f.read())

    if "SPDX_PATH" in files:
        with open(_os.path.join(_DATA_DIR, "input_spdx.json"), "r") as f:
            files["SPDX_PATH"].write_text(f.read())

    if "GRYPE_CDX_PATH" in files:
        with open(_os.path.join(_DATA_DIR, "grype_cdx.json"), "r") as f:
            files["GRYPE_CDX_PATH"].write_text(f.read())

    if "GRYPE_SPDX_PATH" in files:
        with open(_os.path.join(_DATA_DIR, "grype_spdx.json"), "r") as f:
            files["GRYPE_SPDX_PATH"].write_text(f.read())

    if "YOCTO_CVE_CHECKER" in files:
        with open(_os.path.join(_DATA_DIR, "yocto.json"), "r") as f:
            files["YOCTO_CVE_CHECKER"].write_text(f.read())

    if "YOCTO_VEX" in files:
        files["YOCTO_VEX"].write_text(json.dumps({
            "version": "1",
            "package": [
                {
                    "name": "openssl",
                    "version": "3.0.2",
                    "layer": "meta",
                    "cpes": ["cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"],
                    "products": [
                        {"product": "openssl", "cvesInRecord": "Yes"}
                    ],
                    "issue": [
                        {
                            "id": "CVE-2022-0778",
                            "summary": "Infinite loop in BN_mod_sqrt()",
                            "scorev3": "7.5",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                            "detail": "fixed-version: Fixed in 3.0.3",
                            "patch-file": "/patches/CVE-2022-0778.patch",
                            "status": "Patched",
                            "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778"
                        }
                    ]
                }
            ]
        }))

    if "TIME_ESTIMATES_PATH" in files:
        with open(_os.path.join(_DATA_DIR, "time_estimates.json"), "r") as f:
            files["TIME_ESTIMATES_PATH"].write_text(f.read())

    if "LOCAL_USER_DATABASE_PATH" in files:
        files["LOCAL_USER_DATABASE_PATH"].write_text(json.dumps(_EMPTY_OPENVEX))

    return files

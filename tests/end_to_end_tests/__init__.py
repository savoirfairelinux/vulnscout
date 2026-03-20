# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json

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
        with open("end_to_end_tests/input_cdx.json", "r") as f:
            files["CDX_PATH"].write_text(f.read())

    if "SPDX_PATH" in files:
        with open("end_to_end_tests/input_spdx.json", "r") as f:
            files["SPDX_PATH"].write_text(f.read())

    if "GRYPE_CDX_PATH" in files:
        with open("end_to_end_tests/grype_cdx.json", "r") as f:
            files["GRYPE_CDX_PATH"].write_text(f.read())

    if "GRYPE_SPDX_PATH" in files:
        with open("end_to_end_tests/grype_spdx.json", "r") as f:
            files["GRYPE_SPDX_PATH"].write_text(f.read())

    if "YOCTO_CVE_CHECKER" in files:
        with open("end_to_end_tests/yocto.json", "r") as f:
            files["YOCTO_CVE_CHECKER"].write_text(f.read())

    if "TIME_ESTIMATES_PATH" in files:
        with open("end_to_end_tests/time_estimates.json", "r") as f:
            files["TIME_ESTIMATES_PATH"].write_text(f.read())

    if "LOCAL_USER_DATABASE_PATH" in files:
        files["LOCAL_USER_DATABASE_PATH"].write_text(json.dumps(_EMPTY_OPENVEX))

    return files

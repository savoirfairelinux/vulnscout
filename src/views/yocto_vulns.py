# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models import Package
from .yocto_base import YoctoBase


class YoctoVulns(YoctoBase):
    """Parser for the Yocto cve-check JSON format."""

    _SOURCE_TAG = "yocto_cve_check"
    _PATCHED_LABEL = "Yocto reported vulnerability as Patched"
    _IGNORED_LABEL = "Yocto reported vulnerability as Ignored"
    _SBOM_KEY = "Yocto Description"

    def _build_package(self, pkg: dict) -> Package:
        package = Package(pkg["name"], pkg["version"], [], [])
        package.generate_generic_cpe()
        package.generate_generic_purl()
        return package

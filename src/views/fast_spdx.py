# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.package import Package


class FastSPDX ():
    """
    SPDX class to handle SPDX SBOM and parse it.
    Also support output to SPDX SBOM format.
    """

    def __init__(self, controllers):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]
        self.sbom = None

    def get_field(self, obj: dict, field: list[str]):
        """Get field from dict or return None."""
        for f in field:
            if f in obj:
                return obj[f]
        return None

    def check_spdx_version(self):
        """Check if the SPDX version is supported."""
        self.version = self.get_field(self.sbom, ["spdxVersion", "SPDXVersion", "spdxversion"])
        if self.version != "SPDX-2.3" and self.version != "SPDX-2.2":
            raise ValueError("Unsupported SPDX version")

    def merge_packages(self):
        """Merge packages from SPDX SBOM."""
        if not self.get_field(self.sbom, ["packages", "Packages"]):
            return

        for pkg in self.get_field(self.sbom, ["packages", "Packages"]):
            name = self.get_field(pkg, ["name", "Name", "packageName", "PackageName"])
            if name is None:
                continue
            version = self.get_field(pkg, ["version", "Version", "packageVersion", "PackageVersion", "versionInfo"])
            primary_package_purpose = self.get_field(pkg, ["primaryPackagePurpose", "PrimaryPackagePurpose"])

            package = Package(name, version or "", [], [])
            cpe_type = "a"
            if primary_package_purpose == "OPERATING-SYSTEM" or primary_package_purpose == "OPERATING_SYSTEM":
                cpe_type = "o"
            if primary_package_purpose == "DEVICE":
                cpe_type = "h"
            package.add_cpe(f"cpe:2.3:{cpe_type}:*:{name}:{version or '*'}:*:*:*:*:*:*:*")
            package.generate_generic_cpe()
            package.generate_generic_purl()

            self.packagesCtrl.add(package)

    def parse_from_dict(self, spdx: dict):
        """Read data from SPDX json parsed format."""
        self.sbom = spdx
        self.check_spdx_version()
        self.merge_packages()

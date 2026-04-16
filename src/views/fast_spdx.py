# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.package import Package
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController


class FastSPDX ():
    """
    SPDX class to handle SPDX SBOM and parse it.
    Also support output to SPDX SBOM format.
    """

    def __init__(self, controllers):
        self.packagesCtrl: PackagesController = controllers["packages"]
        self.vulnerabilitiesCtrl: VulnerabilitiesController = controllers["vulnerabilities"]
        self.assessmentsCtrl: AssessmentsController = controllers["assessments"]

    def _check_spdx_version(self, sbom: dict):
        """Check if the SPDX version is supported."""
        self.version = _get_field(sbom, ["spdxVersion", "SPDXVersion", "spdxversion"])
        if self.version not in ("SPDX-2.3", "SPDX-2.2"):
            raise ValueError("Unsupported SPDX version")

    def _merge_packages(self, sbom: dict):
        """Merge packages from SPDX SBOM."""
        for pkg in _get_field(sbom, ["packages", "Packages"]) or []:
            parsed_package = self._parse_package(pkg)
            if parsed_package:
                self.packagesCtrl.add(parsed_package)

    def _parse_package(self, pkg: dict) -> Package | None:
        name = _get_field(pkg, ["name", "Name", "packageName", "PackageName"])
        if name is None:
            return None
        version = _get_field(pkg, ["version", "Version", "packageVersion", "PackageVersion", "versionInfo"])
        primary_package_purpose = _get_field(pkg, ["primaryPackagePurpose", "PrimaryPackagePurpose"])
        licences = _get_field(pkg, ["licenseDeclared", "LicenseDeclared"])

        package = Package(name, version or "", [], [], licences or "")
        cpe_type = "a"
        if primary_package_purpose == "OPERATING-SYSTEM" or primary_package_purpose == "OPERATING_SYSTEM":
            cpe_type = "o"
        if primary_package_purpose == "DEVICE":
            cpe_type = "h"
        package.add_cpe(f"cpe:2.3:{cpe_type}:*:{name}:{version or '*'}:*:*:*:*:*:*:*")

        for external_ref in _get_field(pkg, ["externalRefs"]) or []:
            if _get_field(external_ref, ["referenceType"]) == "purl":
                purl = _get_field(external_ref, ["referenceLocator"])
                assert isinstance(purl, str)
                package.add_purl(purl)

        package.generate_generic_cpe()
        package.generate_generic_purl()

        return package

    def parse_from_dict(self, spdx: dict):
        """Read data from SPDX json parsed format."""
        self._check_spdx_version(spdx)
        self._merge_packages(spdx)


def _get_field(obj: dict, field: list[str]):
    """Get field from dict or return None."""
    for f in field:
        if f in obj:
            return obj[f]
    return None

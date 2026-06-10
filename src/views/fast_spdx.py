# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.package import Package
from ..controllers.packages import PackagesController
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.assessments import AssessmentsController
from typing import Any


class FastSPDX ():
    """
    SPDX class to handle SPDX SBOM and parse it.
    Also support output to SPDX SBOM format.
    """

    def __init__(self, controllers: Any) -> None:
        self.packagesCtrl: PackagesController = controllers["packages"]
        self.vulnerabilitiesCtrl: VulnerabilitiesController = controllers["vulnerabilities"]
        self.assessmentsCtrl: AssessmentsController = controllers["assessments"]

    def _check_spdx_version(self, sbom: dict) -> None:
        """Check if the SPDX version is supported."""
        self.version = _get_field(sbom, ["spdxVersion", "SPDXVersion", "spdxversion"])
        if self.version not in ("SPDX-2.3", "SPDX-2.2"):
            raise ValueError("Unsupported SPDX version")

    def _merge_packages(self, sbom: dict) -> None:
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
        licences = _get_field(pkg, ["licenseDeclared", "LicenseDeclared"])

        package = Package(name, version or "", [], [], licences or "")

        for external_ref in _get_field(pkg, ["externalRefs"]) or []:
            ref_type = _get_field(external_ref, ["referenceType"])
            if ref_type == "purl":
                purl = _get_field(external_ref, ["referenceLocator"])
                assert isinstance(purl, str)
                package.add_purl(purl)
            elif ref_type == "cpe23Type":
                cpe = _get_field(external_ref, ["referenceLocator"])
                if isinstance(cpe, str):
                    package.add_cpe(cpe)

        package.generate_generic_cpe()
        package.generate_generic_purl()

        return package

    def parse_from_dict(self, spdx: dict) -> None:
        """Read data from SPDX json parsed format."""
        self._check_spdx_version(spdx)
        self._merge_packages(spdx)


def _get_field(obj: dict, field: list[str]) -> Any:
    """Get field from dict or return None."""
    for f in field:
        if f in obj:
            return obj[f]
    return None

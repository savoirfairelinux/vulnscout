# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.package import Package
from ..controllers import ControllersCache, VulnerabilitiesController, PackagesController, AssessmentsController

_SPDX2_DEPENDENCY_OF = frozenset({
    "DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "DEV_DEPENDENCY_OF",
    "OPTIONAL_DEPENDENCY_OF", "PROVIDED_DEPENDENCY_OF", "TEST_DEPENDENCY_OF",
})


def spdx2_dependency_edge(source, kind, target) -> tuple[str, str] | None:
    """Return the ``(dependent, dependency)`` pair of an SPDX 2 dependency relationship."""
    if not isinstance(source, str) or not isinstance(target, str):
        return None
    if kind == "DEPENDS_ON":
        return source, target
    if kind in _SPDX2_DEPENDENCY_OF:
        return target, source
    return None


class FastSPDX ():
    """
    SPDX class to handle SPDX SBOM and parse it.
    Also support output to SPDX SBOM format.
    """

    def __init__(self, controllers: ControllersCache):
        self.packagesCtrl: PackagesController = controllers.packages
        self.vulnerabilitiesCtrl: VulnerabilitiesController = controllers.vulnerabilities
        self.assessmentsCtrl: AssessmentsController = controllers.assessments
        self._document_refs: dict[str, str] = {}

    def _check_spdx_version(self, sbom: dict):
        """Check if the SPDX version is supported."""
        self.version = _get_field(sbom, ["spdxVersion", "SPDXVersion", "spdxversion"])
        if self.version not in ("SPDX-2.3", "SPDX-2.2"):
            raise ValueError("Unsupported SPDX version")

    def _merge_packages(self, sbom: dict):
        """Merge packages from SPDX SBOM."""
        self._document_refs = {}
        for pkg in _get_field(sbom, ["packages", "Packages"]) or []:
            parsed_package = self._parse_package(pkg)
            if parsed_package:
                self.packagesCtrl.add(parsed_package)
                spdx_id = _get_field(pkg, ["SPDXID", "spdxId"])
                if isinstance(spdx_id, str):
                    self._document_refs[spdx_id] = parsed_package.string_id

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
                if isinstance(purl, str):
                    package.add_purl(purl)
            elif ref_type in ("cpe23Type", "http://spdx.org/rdf/references/cpe23Type"):
                cpe = _get_field(external_ref, ["referenceLocator"])
                if isinstance(cpe, str):
                    package.add_cpe(cpe)

        package.generate_generic_cpe()
        package.generate_generic_purl()

        return package

    def parse_from_dict(self, spdx: dict):
        """Read data from SPDX json parsed format."""
        self._check_spdx_version(spdx)
        self._merge_packages(spdx)
        edges = set()
        for relation in _get_field(spdx, ["relationships", "Relationships"]) or []:
            if not isinstance(relation, dict):
                continue
            edge = spdx2_dependency_edge(relation.get("spdxElementId"), relation.get("relationshipType"),
                                         relation.get("relatedSpdxElement"))
            if edge:
                edges.add(edge)
        external_documents = {
            ref["externalDocumentId"]: ref["spdxDocument"]
            for ref in _get_field(spdx, ["externalDocumentRefs"]) or []
            if isinstance(ref, dict) and isinstance(ref.get("externalDocumentId"), str)
            and isinstance(ref.get("spdxDocument"), str)
        }
        namespace = _get_field(spdx, ["documentNamespace"])
        self.packagesCtrl.add_spdx_dependencies(namespace if isinstance(namespace, str) else None,
                                                self._document_refs, external_documents, edges)


def _get_field(obj: dict, field: list[str]):
    """Get field from dict or return None."""
    for f in field:
        if f in obj:
            return obj[f]
    return None

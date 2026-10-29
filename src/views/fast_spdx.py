# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.package import Package
from ..helpers.package_versions import git_revision_from_url
from ..controllers import ControllersCache, VulnerabilitiesController, PackagesController, AssessmentsController

_SPDX2_DEPENDENCY_OF = frozenset({
    "DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "DEV_DEPENDENCY_OF",
    "OPTIONAL_DEPENDENCY_OF", "PROVIDED_DEPENDENCY_OF", "TEST_DEPENDENCY_OF",
})
SPDX2_SYNTHETIC_SOURCE_COMMENT = "VulnScout: synthetic Git source provenance (not an inventory component)."


def spdx2_dependency_edge(source, kind, target) -> tuple[str, str] | None:
    """Return the ``(dependent, dependency)`` pair of an SPDX 2 dependency relationship."""
    if not isinstance(source, str) or not isinstance(target, str):
        return None
    if kind == "DEPENDS_ON":
        return source, target
    if kind in _SPDX2_DEPENDENCY_OF:
        return target, source
    return None


def spdx2_dependency_scope(kind: str) -> str:
    """Only explicit lifecycle qualifiers imply a scope, not generic dependency types."""
    return {
        "BUILD_DEPENDENCY_OF": "build", "RUNTIME_DEPENDENCY_OF": "runtime",
        "DEV_DEPENDENCY_OF": "development", "TEST_DEPENDENCY_OF": "test",
    }.get(kind, "")


def spdx2_provenance_only_sources(sbom: dict) -> set[str]:
    """Exclude only explicitly marked Git source nodes used exclusively as provenance."""
    packages = {
        ref: package
        for package in _get_field(sbom, ["packages", "Packages"]) or []
        if isinstance(package, dict)
        for ref in [_get_field(package, ["SPDXID", "spdxId"])]
        if isinstance(ref, str)
    }
    candidates = {
        ref for ref, package in packages.items()
        if package.get("comment") == SPDX2_SYNTHETIC_SOURCE_COMMENT
        and package.get("primaryPackagePurpose") == "SOURCE"
        and not _get_field(package, ["version", "Version", "packageVersion", "PackageVersion", "versionInfo"])
        and isinstance(package.get("downloadLocation"), str)
        and git_revision_from_url(package["downloadLocation"]) is not None
    }
    referenced: set[str] = set()
    independent: set[str] = set()
    for relation in _get_field(sbom, ["relationships", "Relationships"]) or []:
        if not isinstance(relation, dict):
            continue
        source, target = relation.get("spdxElementId"), relation.get("relatedSpdxElement")
        if isinstance(source, str) and source in candidates:
            independent.add(source)
        if not isinstance(target, str) or target not in candidates:
            continue
        if (relation.get("relationshipType") == "GENERATED_FROM"
                and isinstance(source, str) and source in packages and source not in candidates):
            referenced.add(target)
        else:
            independent.add(target)
    return referenced - independent


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
        provenance_sources = spdx2_provenance_only_sources(sbom)
        for pkg in _get_field(sbom, ["packages", "Packages"]) or []:
            if _get_field(pkg, ["SPDXID", "spdxId"]) in provenance_sources:
                continue
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
        download = _get_field(pkg, ["downloadLocation"])
        if isinstance(download, str):
            package.add_source_url(download)

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
        derivations = set()
        inputs = set()
        for relation in _get_field(spdx, ["relationships", "Relationships"]) or []:
            if not isinstance(relation, dict):
                continue
            edge = spdx2_dependency_edge(relation.get("spdxElementId"), relation.get("relationshipType"),
                                         relation.get("relatedSpdxElement"))
            if edge:
                kind = relation["relationshipType"]
                edges.add((*edge, kind, spdx2_dependency_scope(kind)))
            source, target = relation.get("spdxElementId"), relation.get("relatedSpdxElement")
            if isinstance(source, str) and isinstance(target, str):
                if relation.get("relationshipType") == "GENERATED_FROM":
                    derivations.add((source, target))
                elif relation.get("relationshipType") == "BUILD_DEPENDENCY_OF":
                    inputs.add((target, source))
        external_documents = {
            ref["externalDocumentId"]: ref["spdxDocument"]
            for ref in _get_field(spdx, ["externalDocumentRefs"]) or []
            if isinstance(ref, dict) and isinstance(ref.get("externalDocumentId"), str)
            and isinstance(ref.get("spdxDocument"), str)
        }
        namespace = _get_field(spdx, ["documentNamespace"])
        self.packagesCtrl.add_spdx_dependencies(namespace if isinstance(namespace, str) else None,
                                                self._document_refs, external_documents, edges)
        urls = {
            ref: url
            for package in _get_field(spdx, ["packages", "Packages"]) or []
            for ref, url in [(_get_field(package, ["SPDXID", "spdxId"]),
                              _get_field(package, ["downloadLocation"]))]
            if isinstance(ref, str) and isinstance(url, str)
        }
        self.packagesCtrl.add_spdx_sources(
            namespace if isinstance(namespace, str) else None,
            self._document_refs, external_documents, urls, derivations, inputs,
        )


def _get_field(obj: dict, field: list[str]):
    """Get field from dict or return None."""
    for f in field:
        if f in obj:
            return obj[f]
    return None

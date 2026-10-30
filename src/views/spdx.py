# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.package import Package
from ..helpers.verbose import verbose
from ..controllers import ControllersCache, PackagesController, VulnerabilitiesController, AssessmentsController
from .fast_spdx import SPDX2_SYNTHETIC_SOURCE_COMMENT, spdx2_dependency_edge, spdx2_provenance_only_sources
from ..helpers.export_files import file_metadata, SPDX2_INVENTORY_PREFIX, SPDX2_ASSOCIATION_COMMENT

from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
from spdx_tools.spdx.parser.jsonlikedict.file_parser import FileParser
from spdx_tools.spdx.model.file import File as SpdxFile
from spdx_tools.spdx.jsonschema.document_converter import DocumentConverter
from spdx_tools.spdx.writer.json.json_writer import write_document_to_stream as write_document_to_json_stream
from spdx_tools.spdx.writer.xml.xml_writer import write_document_to_stream as write_document_to_xml_stream
from spdx_tools.spdx.model.package import (
    PackagePurpose,
    Package as SpdxPackage,
    ExternalPackageRef,
    ExternalPackageRefCategory
)
from spdx_tools.spdx.model.document import Document, CreationInfo
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.spdx_none import SpdxNone
from spdx_tools.spdx.validation.file_validator import validate_file
from uuid_extensions import uuid7
from datetime import datetime, timezone
from io import StringIO
from os import getenv
import json
import re


def _normalize_spdx_dict(doc_dict: dict) -> None:
    """Normalize an SPDX JSON dict to fix known spdx_tools parser compat issues.

    The spdx_tools Version class only accepts "X.Y" format, but real-world SPDX
    files may use three-part semver for licenseListVersion (e.g. "3.28.0").
    This trims such values to "X.Y" so the parser does not reject the document.
    """
    creation_info = doc_dict.get("creationInfo") or {}
    license_list_version = creation_info.get("licenseListVersion", "")
    if re.match(r"^\d+\.\d+\.\d", license_list_version):
        major, minor = license_list_version.split(".")[:2]
        creation_info["licenseListVersion"] = f"{major}.{minor}"


class _RecordedFileParser(FileParser):
    def parse_file(self, file_dict: dict):
        name, spdx_id = file_dict.get("fileName"), file_dict.get("SPDXID")
        if (not isinstance(name, str) or not isinstance(spdx_id, str)
                or (file_dict.get("checksums") is not None and file_dict["checksums"] != [])):
            return super().parse_file(file_dict)
        # File inventories can be recorded without hashing the source tree.
        # Keep raw properties in the inventory recorder; do not invent a hash
        # merely to satisfy spdx-tools' mandatory constructor argument.
        return SpdxFile(
            name=name, spdx_id=spdx_id, checksums=[],
            comment=file_dict.get("comment"),
        )


def _recorded_file_parser() -> JsonLikeDictParser:
    parser = JsonLikeDictParser()
    parser.file_parser = _RecordedFileParser()
    return parser


_ACTOR_TYPE_LABELS = {
    ActorType.ORGANIZATION: "Organization",
    ActorType.PERSON: "Person",
    ActorType.TOOL: "Tool",
}


class _SPDXDocumentConverter(DocumentConverter):
    def __init__(self):
        super().__init__()
        self.recorded_files: list[dict] = []
        self.recorded_relationships: list[dict] = []
        self.recorded_annotations: list[dict] = []

    def convert(self, instance: Document, document: Document | None = None) -> dict:
        result = super().convert(instance, document)
        if self.recorded_files:
            result.setdefault("files", []).extend(self.recorded_files)
            result.setdefault("relationships", []).extend(self.recorded_relationships)
        if self.recorded_annotations:
            result.setdefault("annotations", []).extend(self.recorded_annotations)
        # spdx-tools emits enum names instead of SPDX's hyphenated JSON/XML values.
        for package in result.get("packages", []):
            if package.get("primaryPackagePurpose") == "OPERATING_SYSTEM":
                package["primaryPackagePurpose"] = "OPERATING-SYSTEM"
            for reference in package.get("externalRefs", []):
                if reference.get("referenceCategory") in {"PACKAGE_MANAGER", "PERSISTENT_ID"}:
                    reference["referenceCategory"] = reference["referenceCategory"].replace("_", "-")
        return result


class SPDX:
    """
    SPDX class to handle SPDX SBOM and parse it.
    Also support output to SPDX SBOM format.
    """

    def __init__(self, controllers: ControllersCache):
        self.packagesCtrl: PackagesController = controllers.packages
        self.vulnerabilitiesCtrl: VulnerabilitiesController = controllers.vulnerabilities
        self.assessmentsCtrl: AssessmentsController = controllers.assessments
        self.ref_dict: dict[str, str] = {}
        self.pkg_to_ref: dict[str, str] = {}
        self._document_refs: dict[str, str] = {}

    def load_from_dict(self, spdx: dict):
        """Read data from SPDX json parsed format."""
        parser = _recorded_file_parser()
        from copy import deepcopy
        normalized = deepcopy(spdx)
        _normalize_spdx_dict(normalized)
        self.sbom = parser.parse(normalized)

    def load_from_file(self, spdx_file: str):
        """Read data from SPDX file, detecting format automatically."""
        try:
            try_reading = parse_file(spdx_file)
        except SPDXParsingError as original_err:
            # Fallback: pre-process JSON to fix known compat issues (e.g. 3-part licenseListVersion)
            try:
                with open(spdx_file) as f:
                    doc_dict = json.load(f)
                _normalize_spdx_dict(doc_dict)
                try_reading = _recorded_file_parser().parse(doc_dict)
            except Exception:
                raise original_err
        if try_reading:
            self.sbom = try_reading
        else:
            raise Exception("Invalid SPDX file")

    def merge_components_into_controller(self):
        """
        Internal method.
        Merge components from SBOM into controller.
        """
        self._document_refs = {}
        provenance_sources = spdx2_provenance_only_sources({
            "packages": [
                {"SPDXID": package.spdx_id,
                 "primaryPackagePurpose": (
                     package.primary_package_purpose.name if package.primary_package_purpose else None
                 ),
                 "versionInfo": package.version, "downloadLocation": package.download_location,
                 "comment": package.comment}
                for package in self.sbom.packages
            ],
            "relationships": [
                {"spdxElementId": relation.spdx_element_id, "relationshipType": relation.relationship_type.name,
                 "relatedSpdxElement": relation.related_spdx_element_id}
                for relation in self.sbom.relationships
            ],
        })
        for package in self.sbom.packages:
            if package.spdx_id in provenance_sources:
                continue
            supplier = ""
            try:
                if package.supplier is not None and not isinstance(package.supplier, SpdxNoAssertion):
                    actor = package.supplier
                    actor_label = _ACTOR_TYPE_LABELS.get(actor.actor_type, actor.actor_type.name.capitalize())
                    supplier = f"{actor_label}: {actor.name}"
                    if actor.email:
                        supplier += f" ({actor.email})"
            except Exception:
                verbose(f"[SPDX.merge_components] failed to read supplier for {package.name!r}")

            pkg = Package(package.name, package.version or "", [], [], "", supplier=supplier)
            if isinstance(package.download_location, str):
                pkg.add_source_url(package.download_location)
            license_declared = package.license_declared
            if license_declared is not None:
                license_str = str(license_declared)
                pkg.licences = license_str

            for external_ref in package.external_references:
                if external_ref.reference_type == "purl":
                    pkg.add_purl(external_ref.locator)
                elif external_ref.reference_type in ("cpe23Type", "http://spdx.org/rdf/references/cpe23Type"):
                    pkg.add_cpe(external_ref.locator)

            pkg.generate_generic_cpe()
            pkg.generate_generic_purl()

            if package.spdx_id:
                self.ref_dict[package.spdx_id] = pkg.string_id
                self.pkg_to_ref[pkg.string_id] = package.spdx_id
                self._document_refs[package.spdx_id] = pkg.string_id

            self.packagesCtrl.add(pkg)

    def parse_and_merge(self):
        """Parse the SBOM and merge it into the controller."""
        self.merge_components_into_controller()
        edges = set()
        derivations = set()
        inputs = set()
        for relation in self.sbom.relationships:
            edge = spdx2_dependency_edge(relation.spdx_element_id, relation.relationship_type.name,
                                         relation.related_spdx_element_id)
            if edge:
                edges.add(edge)
            source, target = relation.spdx_element_id, relation.related_spdx_element_id
            if isinstance(target, str):
                if relation.relationship_type == RelationshipType.GENERATED_FROM:
                    derivations.add((source, target))
                elif relation.relationship_type == RelationshipType.BUILD_DEPENDENCY_OF:
                    inputs.add((target, source))
        creation_info = self.sbom.creation_info
        external_documents = {ref.document_ref_id: ref.document_uri for ref in creation_info.external_document_refs}
        self.packagesCtrl.add_spdx_dependencies(creation_info.document_namespace, self._document_refs,
                                                external_documents, edges)
        urls = {package.spdx_id: package.download_location for package in self.sbom.packages
                if isinstance(package.download_location, str)}
        self.packagesCtrl.add_spdx_sources(
            creation_info.document_namespace, self._document_refs, external_documents, urls, derivations, inputs,
        )

    def register_components(self, with_cpe=False):
        """
        Internal method.
        Copy components from controller into SBOM.
        """
        for pkg in self.packagesCtrl:
            if pkg.string_id not in self.pkg_to_ref:
                newid = f"SPDXRef-{uuid7(as_type='str')}"
                self.pkg_to_ref[pkg.string_id] = newid
                self.ref_dict[newid] = pkg.string_id
                package = SpdxPackage(
                    name=pkg.name,
                    spdx_id=self.pkg_to_ref[pkg.string_id],
                    primary_package_purpose=PackagePurpose.APPLICATION,
                    download_location=SpdxNoAssertion(),
                    files_analyzed=False
                )
                if pkg.version:
                    package.version = pkg.version
                for purl in pkg.purl or []:
                    package.external_references.append(ExternalPackageRef(
                        category=ExternalPackageRefCategory.PACKAGE_MANAGER, reference_type="purl", locator=purl,
                    ))
                for cpe in pkg.cpe:
                    cpe_type = cpe.split(":")[2]
                    if cpe_type == "o":
                        package.primary_package_purpose = PackagePurpose.OPERATING_SYSTEM
                    if cpe_type == "h":
                        package.primary_package_purpose = PackagePurpose.DEVICE
                    if with_cpe:
                        # Add CPE as external reference
                        package.external_references.append(
                            ExternalPackageRef(
                                category=ExternalPackageRefCategory.SECURITY,
                                reference_type="cpe23Type",
                                locator=cpe
                            )
                        )

                self.sbom.packages = self.sbom.packages + [package]
                for url in pkg.source_urls or []:
                    source_id = f"SPDXRef-{uuid7(as_type='str')}"
                    self.sbom.packages.append(SpdxPackage(
                        name=f"{pkg.name}-source", spdx_id=source_id,
                        primary_package_purpose=PackagePurpose.SOURCE,
                        download_location=url, files_analyzed=False,
                        comment=SPDX2_SYNTHETIC_SOURCE_COMMENT,
                    ))
                    self.sbom.relationships.append(Relationship(
                        spdx_element_id=package.spdx_id, relationship_type=RelationshipType.GENERATED_FROM,
                        related_spdx_element_id=source_id,
                    ))
                self.sbom.relationships = self.sbom.relationships + [
                    Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, newid)
                ]

    def register_dependencies(self):
        """Copy dependency edges between registered components into SBOM."""
        existing = {
            (relation.spdx_element_id, relation.related_spdx_element_id)
            for relation in self.sbom.relationships
            if relation.relationship_type == RelationshipType.DEPENDS_ON
        }
        for source, target in sorted(self.packagesCtrl.dependency_edges()):
            edge = (self.pkg_to_ref[source], self.pkg_to_ref[target])
            if edge not in existing:
                existing.add(edge)
                self.sbom.relationships.append(Relationship(edge[0], RelationshipType.DEPENDS_ON, edge[1]))

    def create_shell_document(self, author=None):
        if "sbom" not in self.__dict__ or not self.sbom:
            self.sbom = Document(
                creation_info=CreationInfo(
                    spdx_version="SPDX-2.3",
                    data_license="CC0-1.0",
                    spdx_id="SPDXRef-DOCUMENT",
                    name=f"{getenv('PRODUCT_NAME', 'PRODUCT_NAME')}-{getenv('PRODUCT_VERSION', '1.0.0')}",
                    document_namespace=getenv('DOCUMENT_URL')
                    or f"https://spdx.org/spdxdocs/{uuid7(as_type='str')}.spdx.json",
                    creators=[
                        Actor(
                            actor_type=ActorType.ORGANIZATION,
                            name=author if author is not None else "Savoir-faire Linux",
                            email=getenv('CONTACT_EMAIL', None)
                        ),
                        Actor(
                            actor_type=ActorType.TOOL,
                            name="VulnScout"
                        )
                    ],
                    created=datetime.now(timezone.utc)
                ),
                packages=[]
            )

    def _output_generic(self, writer, validate=True, author=None, with_cpe=True) -> str:
        self.create_shell_document(author)
        self.register_components(with_cpe=with_cpe)
        self.register_dependencies()

        if len(self.sbom.relationships) == 0:
            self.sbom.relationships = [Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, SpdxNone())]

        stream = StringIO()
        converter = _SPDXDocumentConverter()
        annotated_files: list[dict] = []
        annotated_relationships: list[dict] = []
        for record in self.packagesCtrl.recorded_files():
            ref = f"SPDXRef-File-{uuid7(as_type='str')}"
            file = {
                "SPDXID": ref, "fileName": record["path"], **file_metadata(record, spdx3=False),
            }
            try:
                parsed = FileParser().parse_file(file)
                native = parsed is not None and not validate_file(parsed, "SPDX-2.3")
            except (SPDXParsingError, TypeError, ValueError):
                native = False
            destination = converter.recorded_files if native else annotated_files
            relationships = converter.recorded_relationships if native else annotated_relationships
            destination.append(file)
            relationships.extend({
                "spdxElementId": self.pkg_to_ref[owner], "relationshipType": "OTHER",
                "relatedSpdxElement": ref,
                "comment": SPDX2_ASSOCIATION_COMMENT,
            } for owner in record["packages"] if owner in self.pkg_to_ref)
        if annotated_files:
            converter.recorded_annotations.append({
                "annotationDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "annotationType": "OTHER", "annotator": "Tool: VulnScout",
                "comment": SPDX2_INVENTORY_PREFIX + json.dumps({
                    "files": annotated_files, "relationships": annotated_relationships,
                }, sort_keys=True),
            })
        # CPE validation may fail because the SPDX spec expects special characters in package
        # names to be escaped, but our CPE strings may contain unescaped special characters
        if with_cpe:
            writer(self.sbom, stream, validate=False, converter=converter)
        else:
            writer(self.sbom, stream, validate=validate, converter=converter)
        return stream.getvalue()

    def output_as_json(self, validate=True, author=None, with_cpe=False) -> str:
        """Output the SBOM to JSON format."""
        return self._output_generic(write_document_to_json_stream, validate=validate, author=author, with_cpe=with_cpe)

    def output_as_xml(self, validate=True, author=None, with_cpe=False) -> str:
        """Output the SBOM to XML format."""
        return self._output_generic(write_document_to_xml_stream, validate=validate, author=author, with_cpe=with_cpe)

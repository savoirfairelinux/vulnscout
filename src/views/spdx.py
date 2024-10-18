# -*- coding: utf-8 -*-
from ..models.package import Package
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
from spdx_tools.spdx.writer.json.json_writer import write_document_to_stream
from spdx_tools.spdx.model.package import PackagePurpose, Package as SpdxPackage
from spdx_tools.spdx.model.document import Document, CreationInfo
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.spdx_none import SpdxNone
from uuid_extensions import uuid7
from datetime import datetime, timezone
from io import StringIO
from os import getenv


class SPDX:
    """
    SPDX class to handle SPDX SBOM and parse it.
    Also support output to SPDX SBOM format.
    """

    def __init__(self, controllers):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]
        self.ref_dict = {}
        self.pkg_to_ref = {}

    def load_from_dict(self, spdx: dict):
        """Read data from SPDX json parsed format."""
        parser = JsonLikeDictParser()
        self.sbom = parser.parse(spdx)

    def load_from_file(self, spdx_file: str):
        """Read data from SPDX file, detecting format automaticaly."""
        try_reading = parse_file(spdx_file)
        if try_reading:
            self.sbom = try_reading
        else:
            raise Exception("Invalid SPDX file")

    def merge_components_into_controller(self):
        """
        Internal method.
        Merge components from SBOM into controller.
        """
        for package in self.sbom.packages:
            pkg = Package(package.name, package.version or "", [], [])
            cpe_type = "a"
            if package.primary_package_purpose == PackagePurpose.OPERATING_SYSTEM:
                cpe_type = "o"
            if package.primary_package_purpose == PackagePurpose.DEVICE:
                cpe_type = "h"
            pkg.add_cpe(f"cpe:2.3:{cpe_type}:*:{package.name}:{package.version or '*'}:*:*:*:*:*:*:*")
            pkg.generate_generic_cpe()
            pkg.generate_generic_purl()

            if package.spdx_id:
                self.ref_dict[package.spdx_id] = pkg.id
                self.pkg_to_ref[pkg.id] = package.spdx_id

            self.packagesCtrl.add(pkg)

    def parse_and_merge(self):
        """Parse the SBOM and merge it into the controller."""
        self.merge_components_into_controller()

    def register_components(self):
        """
        Internal method.
        Copy components from controller into SBOM.
        """
        for pkg in self.packagesCtrl:
            if pkg.id not in self.pkg_to_ref:
                newid = f"SPDXRef-{uuid7(as_type='str')}"
                self.pkg_to_ref[pkg.id] = newid
                self.ref_dict[newid] = pkg.id
                package = SpdxPackage(
                    name=pkg.name,
                    spdx_id=self.pkg_to_ref[pkg.id],
                    primary_package_purpose=PackagePurpose.APPLICATION,
                    download_location=SpdxNoAssertion(),
                    files_analyzed=False
                )
                if pkg.version:
                    package.version = pkg.version
                for cpe in pkg.cpe:
                    cpe_type = cpe.split(":")[2]
                    if cpe_type == "o":
                        package.primary_package_purpose = PackagePurpose.OPERATING_SYSTEM
                    if cpe_type == "h":
                        package.primary_package_purpose = PackagePurpose.DEVICE

                self.sbom.packages = self.sbom.packages + [package]
                self.sbom.relationships = self.sbom.relationships + [
                    Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, newid)
                ]

    def output_as_json(self, validate=True, author=None) -> str:
        """Output the SBOM to JSON format."""
        if "sbom" not in self.__dict__ or not self.sbom:
            self.sbom = Document(
                creation_info=CreationInfo(
                    spdx_version="SPDX-2.3",
                    data_license="CC0-1.0",
                    spdx_id="SPDXRef-DOCUMENT",
                    name=f"{getenv('PRODUCT_NAME', 'PRODUCT_NAME')}-{getenv('PRODUCT_VERSION', '1.0.0')}",
                    document_namespace=getenv(
                        'DOCUMENT_URL',
                        f"https://spdx.org/spdxdocs/{uuid7(as_type='str')}.spdx.json"
                    ),
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
        self.register_components()

        if len(self.sbom.relationships) == 0:
            self.sbom.relationships = [Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, SpdxNone())]

        stream = StringIO()
        write_document_to_stream(self.sbom, stream, validate=validate)
        # Replace is here until patch are applied upstream: https://github.com/spdx/tools-python/pull/828
        return stream.getvalue().replace("OPERATING_SYSTEM", "OPERATING-SYSTEM")

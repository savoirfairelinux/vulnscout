# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import uuid


def generate_spdx_namespace() -> str:
    """Generate SPDX namespace UUID-based for SPDX 3.0 specv3 documents."""
    ns_uuid = os.getenv("SPDX_DOCUMENT_UUID", str(uuid.uuid4()))
    return f"https://spdx.org/spdxdocs/{ns_uuid}.spdx.json-specv3"


class SPDX3:
    def __init__(self, controllers: Dict[str, Any]):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.pkg_to_ref: Dict[str, str] = {}
        self.vuln_to_ref: Dict[str, str] = {}
        self.namespace = generate_spdx_namespace()
        self._creation_info_ref: Optional[str] = None
        self._id_counter = 0  # sequential counter for gnrtdX IDs

    def _next_spdx_ref(self) -> str:
        """Return next sequential SPDXRef-gnrtdX string."""
        self._id_counter += 1
        return f"{self.namespace}/SPDXRef-gnrtd{self._id_counter}"

    def _get_spdx_id(self, obj_id: str, mapping: Dict[str, str]) -> str:
        if obj_id not in mapping:
            mapping[obj_id] = self._next_spdx_ref()
        return mapping[obj_id]

    def _make_external_identifiers(self, pairs: List[tuple[str, Any]]) -> List[Dict[str, str]]:
        return [
            {"type": "ExternalIdentifier", "externalIdentifierType": t, "identifier": v}
            for t, v in pairs if v
        ]

    def create_document_structure(self, author: str = "Savoir-faire Linux") -> Dict[str, Any]:
        """Create the base SPDX 3.0 document structure."""

        document_id = f"{self.namespace}#SPDXRef-Document"

        # Create creation info with blank node ID
        creation_info = {
            "@id": "_:creationInfo_0",
            "type": "CreationInfo",
            "specVersion": "3.0.1",
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "createdBy": [
                "https://vulnscout.io/spdx/Organization_SavoirFaireLinux",
                "https://vulnscout.io/spdx/Tool_VulnScout"
            ],
            "createdUsing": [
                "https://vulnscout.io/spdx/Tool_VulnScout"
            ]
        }

        # Cache creation info reference for reuse
        self._creation_info_ref = str(creation_info["@id"])

        # Create the SPDX document node
        spdx_document = {
            "type": "SpdxDocument",
            "spdxId": document_id,
            "name": "PRODUCT_NAME-1.0.0",
            "dataLicense": "http://spdx.org/licenses/CC0-1.0",
            "rootElement": [],
            "creationInfo": self._creation_info_ref
        }

        return {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [creation_info, spdx_document]
        }

    def generate_package_element(self, pkg) -> Dict[str, Any]:
        """Generate SPDX 3.0 package element from Package object."""

        spdx_id = self._get_spdx_id(pkg.id, self.pkg_to_ref)

        element = {
            "type": "software_Package",
            "spdxId": spdx_id,
            "name": pkg.name,
        }

        if pkg.version:
            element["software_packageVersion"] = pkg.version

        # Create external identifiers using helper method
        external_ids = self._make_external_identifiers(
            [("cpe23", cpe) for cpe in (pkg.cpe or [])] + [("purl", purl) for purl in (pkg.purl or [])]
        )
        if external_ids:
            element["externalIdentifier"] = external_ids

        element["software_primaryPurpose"] = "application"

        element["creationInfo"] = "_:creationInfo_0"

        return element

    def generate_vulnerability_element(self, vuln_id: str, vuln) -> Dict[str, Any]:
        """Generate SPDX 3.0 vulnerability element."""

        spdx_id = self._get_spdx_id(vuln_id, self.vuln_to_ref)

        # Create external identifiers using helper method
        external_identifiers = self._make_external_identifiers(
            [("cve", vuln_id)] + [("securityAdvisory", url) for url in (vuln.urls or [])]
        )

        element = {
            "type": "security_Vulnerability",
            "spdxId": spdx_id,
            "externalIdentifier": external_identifiers
        }

        return element

    def generate_relationship(self, from_ref: str, to_refs: List[str], relationship_type: str) -> Dict[str, Any]:
        """Generate SPDX 3.0 relationship element."""

        # Generate deterministic ID based on relationship content
        relationship_id = self._next_spdx_ref()

        return {
            "type": "Relationship",
            "spdxId": relationship_id,
            "from": from_ref,
            "relationshipType": relationship_type,
            "to": to_refs
        }

    def output_as_json(self, author: str = "Savoir-faire Linux") -> str:
        spdx_doc = self.create_document_structure(author)
        graph = spdx_doc["@graph"]

        elements_to_add = []
        relationships_to_add = []

        for pkg in self.packagesCtrl:
            pkg_element = self.generate_package_element(pkg)
            elements_to_add.append(pkg_element)

        for vuln_id, vuln in self.vulnerabilitiesCtrl.vulnerabilities.items():
            vuln_element = self.generate_vulnerability_element(vuln_id, vuln)
            elements_to_add.append(vuln_element)

        graph.extend(elements_to_add)

        document_node = next((item for item in graph if item.get("type") == "SpdxDocument"), None)
        if document_node and elements_to_add:
            root_elements = [element["spdxId"] for element in elements_to_add]
            # Create single relationship describing all elements
            rel = self.generate_relationship(document_node["spdxId"], root_elements, "describes")
            rel["creationInfo"] = self._creation_info_ref
            relationships_to_add.append(rel)
            document_node["rootElement"] = root_elements

        for vuln_id, vuln in self.vulnerabilitiesCtrl.vulnerabilities.items():
            vuln_ref = self.vuln_to_ref.get(vuln_id)
            if not vuln_ref:
                continue
            if hasattr(vuln, "packages"):
                for pkg_id in vuln.packages:
                    pkg_ref = self.pkg_to_ref.get(pkg_id)
                    if pkg_ref:
                        rel = self.generate_relationship(vuln_ref, [pkg_ref], "affects")
                        rel["creationInfo"] = self._creation_info_ref
                        relationships_to_add.append(rel)

        graph.extend(relationships_to_add)
        return json.dumps(spdx_doc, indent=2)

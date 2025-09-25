# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom.minidom import parseString
import uuid


def uuid7(as_type='str'):
    if as_type == 'str':
        return str(uuid.uuid4())
    return uuid.uuid4()


class SPDX3:
    """
    Class to generate SPDX 3.0 SBOM output.
    """

    def __init__(self, controllers: Dict[str, Any]):
        """
        Initialize the SPDX3 generator with controllers for packages, vulnerabilities, and assessments.

        Args:
            controllers: Dictionary containing controllers for packages, vulnerabilities, and assessments
        """
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]

        self.pkg_to_ref: Dict[str, str] = {}
        self.vuln_to_ref: Dict[str, str] = {}

    def generate_package_element(self, pkg) -> Dict[str, Any]:
        """Generate SPDX 3.0 package element from Package object."""

        # Generate unique SPDX ID if not already present in the object
        if pkg.id not in self.pkg_to_ref:
            self.pkg_to_ref[pkg.id] = f"pkg-{uuid7(as_type='str')}"

        spdx_id = self.pkg_to_ref[pkg.id]

        element = {
            "type": "software_Package",
            "spdxId": spdx_id,
            "name": pkg.name,
            "software_primaryPurpose": "application"
        }

        if pkg.version:
            element["versionInfo"] = pkg.version

        # Add external identifiers for CPEs and PURLs
        external_ids = []

        for cpe in pkg.cpe:
            external_ids.append({
                "externalIdentifierType": "cpe23",
                "identifier": cpe
            })

        for purl in pkg.purl:
            external_ids.append({
                "externalIdentifierType": "purl",
                "identifier": purl
            })

        if external_ids:
            element["externalIdentifier"] = external_ids

        return element

    def generate_vulnerability_element(self, vuln_id: str, vuln) -> Dict[str, Any]:
        """Generate SPDX 3.0 vulnerability element."""

        if vuln_id not in self.vuln_to_ref:
            self.vuln_to_ref[vuln_id] = f"vuln-{uuid7(as_type='str')}"

        spdx_id = self.vuln_to_ref[vuln_id]

        # Create external identifiers list starting with CVE
        external_identifiers: List[Dict[str, str]] = [{
            "externalIdentifierType": "cve",
            "identifier": vuln_id
        }]

        # Add URLs as additional identifiers
        for url in vuln.urls:
            external_identifiers.append({
                "externalIdentifierType": "other",
                "identifier": url
            })

        element = {
            "type": "security_Vulnerability",
            "spdxId": spdx_id,
            "externalIdentifier": external_identifiers
        }

        return element

    def generate_relationship(self, from_ref: str, to_refs: List[str], relationship_type: str) -> Dict[str, Any]:
        """Generate SPDX 3.0 relationship element."""
        return {
            "type": "Relationship",
            "spdxId": f"rel-{uuid7(as_type='str')}",
            "from": from_ref,
            "relationshipType": relationship_type,
            "to": to_refs
        }

    def generate_vex_assessment(self, assessment) -> Optional[Dict[str, Any]]:
        """Generate SPDX 3.0 VEX assessment relationship from VulnAssessment."""

        vuln_ref = self.vuln_to_ref.get(assessment.vuln_id)
        if not vuln_ref:
            return None

        # Get package refs for this assessment
        pkg_refs = []
        for pkg_id in assessment.packages:
            pkg_ref = self.pkg_to_ref.get(pkg_id)
            if pkg_ref:
                pkg_refs.append(pkg_ref)

        if not pkg_refs:
            return None

        # Map VulnScout status to SPDX 3.0 VEX relationship types
        status_map = {
            "not_affected": ("security_VexNotAffectedVulnAssessmentRelationship", "doesNotAffect"),
            "false_positive": ("security_VexNotAffectedVulnAssessmentRelationship", "doesNotAffect"),
            "affected": ("security_VexAffectedVulnAssessmentRelationship", "affects"),
            "exploitable": ("security_VexAffectedVulnAssessmentRelationship", "affects"),
            "fixed": ("security_VexFixedVulnAssessmentRelationship", "fixedIn"),
            "resolved": ("security_VexFixedVulnAssessmentRelationship", "fixedIn"),
            "resolved_with_pedigree": ("security_VexFixedVulnAssessmentRelationship", "fixedIn")
        }

        vex_type, relationship_type = status_map.get(
            assessment.status,
            ("security_VexAffectedVulnAssessmentRelationship", "affects")
        )

        element = {
            "type": vex_type,
            "spdxId": f"vex-{uuid7(as_type='str')}",
            "from": vuln_ref,
            "relationshipType": relationship_type,
            "to": pkg_refs
        }

        # Add justification if available
        justification_map = {
            "vulnerable_code_not_present": "vulnerableCodeNotPresent",
            "component_not_present": "componentNotPresent",
            "vulnerable_code_not_in_execute_path": "vulnerableCodeNotInExecutePath",
            "vulnerable_code_cannot_be_controlled_by_adversary": "vulnerableCodeCannotBeControlledByAdversary",
            "inline_mitigations_already_exist": "inlineMitigationsAlreadyExist"
        }

        if assessment.justification and assessment.justification in justification_map:
            element["security_justificationType"] = justification_map[assessment.justification]

        if assessment.impact_statement:
            element["security_impactStatement"] = assessment.impact_statement

        if assessment.status_notes:
            element["security_statusNotes"] = assessment.status_notes

        return element

    def create_document_structure(self, author: str = "Savoir-faire Linux") -> Dict[str, Any]:
        """Create the base SPDX 3.0 document structure."""

        document_id = f"doc-{uuid7(as_type='str')}"
        namespace = os.getenv('DOCUMENT_URL', f"https://spdx.org/spdxdocs/{uuid7(as_type='str')}.spdx3.json")

        creation_info = {
            "type": "CreationInfo",
            "spdxId": f"creationinfo-{uuid7(as_type='str')}",
            "specVersion": "3.0.1",
            "dataLicense": "CC0-1.0",
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": [f"Organization: {author}", "Tool: VulnScout"]
        }

        document = {
            "type": "SpdxDocument",
            "spdxId": document_id,
            "name": f"{os.getenv('PRODUCT_NAME', 'PRODUCT_NAME')}-{os.getenv('PRODUCT_VERSION', '1.0.0')}",
            "namespaceMap": {
                "": namespace
            },
            "creationInfo": creation_info.get("spdxId")
        }

        return {
            "@context": "https://raw.githubusercontent.com/spdx/spdx-3-model/main/model/spdx-context.jsonld",
            "@graph": [creation_info, document],
            "spdxId": document_id
        }

    def output_as_json(self, author: str = "Savoir-faire Linux") -> str:
        """Generate SPDX 3.0 JSON output."""

        # Create base document structure
        spdx_doc = self.create_document_structure(author)

        # Generate package elements
        for pkg in self.packagesCtrl:
            pkg_element = self.generate_package_element(pkg)
            spdx_doc["@graph"].append(pkg_element)

        # Generate vulnerability elements and package-vulnerability relationships
        for vuln_id, vuln in self.vulnerabilitiesCtrl.vulnerabilities.items():
            vuln_element = self.generate_vulnerability_element(vuln_id, vuln)
            spdx_doc["@graph"].append(vuln_element)

            # Create relationships between packages and vulnerabilities
            vuln_ref = self.vuln_to_ref[vuln_id]
            affected_pkg_refs = []

            for pkg_id in vuln.packages:
                if pkg_id in self.pkg_to_ref:
                    affected_pkg_refs.append(self.pkg_to_ref[pkg_id])

            if affected_pkg_refs:
                for pkg_ref in affected_pkg_refs:
                    relationship = self.generate_relationship(
                        pkg_ref,
                        [vuln_ref],
                        "hasAssociatedVulnerability"
                    )
                    spdx_doc["@graph"].append(relationship)

        # Generate VEX assessments
        for assessment_key, assessment in self.assessmentsCtrl.assessments.items():
            vex_element = self.generate_vex_assessment(assessment)
            if vex_element:
                spdx_doc["@graph"].append(vex_element)

        # Add document relationships (describes packages)
        document_id = spdx_doc["spdxId"]
        pkg_refs = list(self.pkg_to_ref.values())

        if pkg_refs:
            doc_relationship = self.generate_relationship(
                document_id,
                pkg_refs,
                "describes"
            )
            spdx_doc["@graph"].append(doc_relationship)

        return json.dumps(spdx_doc, indent=2)

    def dict_to_xml_element(self, data: Dict[str, Any], parent_name: str = "element", namespace_prefix: str = "spdx") -> Element:
        """Convert dictionary to XML element with SPDX 3.0 specific handling."""
        
        # Map SPDX 3.0 types to proper XML element names
        type_mapping = {
            "software_Package": f"{namespace_prefix}:software_Package",
            "security_Vulnerability": f"{namespace_prefix}:security_Vulnerability", 
            "security_VexNotAffectedVulnAssessmentRelationship": f"{namespace_prefix}:security_VexNotAffectedVulnAssessmentRelationship",
            "security_VexAffectedVulnAssessmentRelationship": f"{namespace_prefix}:security_VexAffectedVulnAssessmentRelationship",
            "security_VexFixedVulnAssessmentRelationship": f"{namespace_prefix}:security_VexFixedVulnAssessmentRelationship",
            "Relationship": f"{namespace_prefix}:Relationship",
            "SpdxDocument": f"{namespace_prefix}:SpdxDocument",
            "CreationInfo": f"{namespace_prefix}:CreationInfo"
        }
        
        # Handle SPDX type mapping
        if "type" in data and data["type"] in type_mapping:
            element_name = type_mapping[data["type"]]
        else:
            element_name = f"{namespace_prefix}:{parent_name}" if namespace_prefix and not parent_name.startswith(namespace_prefix) else parent_name
            
        element = Element(element_name)

        for key, value in data.items():
            if key.startswith("@"):
                # Handle attributes (like @context, @graph)
                continue
            elif key == "type":
                # Skip type as it's already handled in element name
                continue
            elif key == "spdxId":
                # Handle spdxId as rdf:about attribute
                element.set("rdf:about", f"#{value}")
                continue
            elif key in ["from", "to"] and isinstance(value, (str, list)):
                # Handle relationship references
                if isinstance(value, str):
                    ref_elem = SubElement(element, f"{namespace_prefix}:{key}")
                    ref_elem.set("rdf:resource", f"#{value}")
                else:  # list
                    for ref_value in value:
                        ref_elem = SubElement(element, f"{namespace_prefix}:{key}")
                        ref_elem.set("rdf:resource", f"#{ref_value}")
                continue
            elif isinstance(value, dict):
                child = self.dict_to_xml_element(value, key, namespace_prefix)
                element.append(child)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        child = self.dict_to_xml_element(item, key.rstrip('s'), namespace_prefix)
                        element.append(child)
                    else:
                        child = Element(f"{namespace_prefix}:{key.rstrip('s')}")
                        child.text = str(item)
                        element.append(child)
            else:
                child = Element(f"{namespace_prefix}:{key}")
                child.text = str(value)
                element.append(child)

        return element



    def output_as_xml(self, author: str = "Savoir-faire Linux") -> str:
        """Generate SPDX 3.0 XML output using unified data structure approach."""
        
        # Generate the same JSON structure but convert to XML
        json_doc = json.loads(self.output_as_json(author))
        
        # Create root element with namespaces
        root = Element("rdf:RDF")
        root.set("xmlns:spdx", "https://spdx.org/rdf/3.0.1/terms/")
        root.set("xmlns:rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#")
        root.set("xmlns:rdfs", "http://www.w3.org/2000/01/rdf-schema#")
        
        # Convert each item in @graph to XML element
        for item in json_doc.get("@graph", []):
            xml_element = self.dict_to_xml_element(item, item.get("type", "element"))
            root.append(xml_element)
        
        # Convert to string with pretty formatting
        rough_string = tostring(root, encoding='unicode')
        reparsed = parseString(rough_string)
        return reparsed.toprettyxml(indent="  ", encoding=None)

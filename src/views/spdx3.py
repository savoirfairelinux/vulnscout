# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom.minidom import parseString
import uuid

def uuid7(as_type='str'):
    if as_type == 'str':
        return str(uuid.uuid4())
    return uuid.uuid4()


class SPDX3:
    """
    SPDX3 class to generate SPDX 3.0 SBOM output.
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
        self.pkg_to_ref = {}
        self.vuln_to_ref = {}

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
        
        element = {
            "type": "security_Vulnerability",
            "spdxId": spdx_id,
            "externalIdentifier": [{
                "externalIdentifierType": "cve",
                "identifier": vuln_id
            }]
        }
        
        # Add URLs as additional identifiers
        for url in vuln.urls:
            element["externalIdentifier"].append({
                "externalIdentifierType": "other",
                "identifier": url
            })
        
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
        
        vex_type, relationship_type = status_map.get(assessment.status, 
            ("security_VexAffectedVulnAssessmentRelationship", "affects"))
        
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

    def _dict_to_xml_element(self, data: Dict[str, Any], parent_name: str = "element") -> Element:
        """Convert dictionary to XML element."""
        element = Element(parent_name)
        
        for key, value in data.items():
            if key.startswith("@"):
                # Handle attributes (like @context, @graph)
                continue
            elif isinstance(value, dict):
                child = self._dict_to_xml_element(value, key)
                element.append(child)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        child = self._dict_to_xml_element(item, key.rstrip('s'))  # Remove plural 's'
                        element.append(child)
                    else:
                        child = Element(key.rstrip('s'))
                        child.text = str(item)
                        element.append(child)
            else:
                child = Element(key)
                child.text = str(value)
                element.append(child)
        
        return element

    def _create_xml_document_structure(self, author: str = "Savoir-faire Linux") -> Element:
        """Create the base SPDX 3.0 XML document structure."""
        
        document_id = f"doc-{uuid7(as_type='str')}"
        namespace = os.getenv('DOCUMENT_URL', f"https://spdx.org/spdxdocs/{uuid7(as_type='str')}.spdx3.xml")
        
        # Create root element with namespaces
        root = Element("spdx:SpdxDocument")
        root.set("xmlns:spdx", "https://spdx.org/rdf/3.0.1/terms/")
        root.set("xmlns:rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#")
        root.set("xmlns:rdfs", "http://www.w3.org/2000/01/rdf-schema#")
        root.set("rdf:about", f"#{document_id}")
        
        # Add document name
        name_elem = SubElement(root, "spdx:name")
        name_elem.text = f"{os.getenv('PRODUCT_NAME', 'PRODUCT_NAME')}-{os.getenv('PRODUCT_VERSION', '1.0.0')}"
        
        # Add namespace map
        namespace_elem = SubElement(root, "spdx:namespaceMap")
        namespace_elem.text = namespace
        
        # Add creation info
        creation_info_id = f"creationinfo-{uuid7(as_type='str')}"
        creation_info_elem = SubElement(root, "spdx:creationInfo")
        creation_info_ref = SubElement(creation_info_elem, "spdx:CreationInfo")
        creation_info_ref.set("rdf:about", f"#{creation_info_id}")
        
        # Add creation info details
        spec_version_elem = SubElement(creation_info_ref, "spdx:specVersion")
        spec_version_elem.text = "3.0.1"
        
        data_license_elem = SubElement(creation_info_ref, "spdx:dataLicense")
        data_license_elem.text = "CC0-1.0"
        
        created_elem = SubElement(creation_info_ref, "spdx:created")
        created_elem.text = datetime.now(timezone.utc).isoformat()
        
        # Add creators
        creator_org_elem = SubElement(creation_info_ref, "spdx:creators")
        creator_org_elem.text = f"Organization: {author}"
        
        creator_tool_elem = SubElement(creation_info_ref, "spdx:creators")
        creator_tool_elem.text = "Tool: VulnScout"
        
        return root, document_id

    def _add_xml_package_element(self, root: Element, pkg) -> None:
        """Add package element to XML structure."""
        
        # Generate unique SPDX ID if not already mapped
        if pkg.id not in self.pkg_to_ref:
            self.pkg_to_ref[pkg.id] = f"pkg-{uuid7(as_type='str')}"
        
        spdx_id = self.pkg_to_ref[pkg.id]
        
        # Create package element
        pkg_elem = SubElement(root, "spdx:software_Package")
        pkg_elem.set("rdf:about", f"#{spdx_id}")
        
        # Add package name
        name_elem = SubElement(pkg_elem, "spdx:name")
        name_elem.text = pkg.name
        
        # Add version info if available
        if pkg.version:
            version_elem = SubElement(pkg_elem, "spdx:versionInfo")
            version_elem.text = pkg.version
        
        # Add primary purpose
        purpose_elem = SubElement(pkg_elem, "spdx:software_primaryPurpose")
        purpose_elem.text = "application"
        
        # Add external identifiers for CPEs and PURLs
        for cpe in pkg.cpe:
            ext_id_elem = SubElement(pkg_elem, "spdx:externalIdentifier")
            ext_id_ref = SubElement(ext_id_elem, "spdx:ExternalIdentifier")
            
            type_elem = SubElement(ext_id_ref, "spdx:externalIdentifierType")
            type_elem.text = "cpe23"
            
            id_elem = SubElement(ext_id_ref, "spdx:identifier")
            id_elem.text = cpe
        
        for purl in pkg.purl:
            ext_id_elem = SubElement(pkg_elem, "spdx:externalIdentifier")
            ext_id_ref = SubElement(ext_id_elem, "spdx:ExternalIdentifier")
            
            type_elem = SubElement(ext_id_ref, "spdx:externalIdentifierType")
            type_elem.text = "purl"
            
            id_elem = SubElement(ext_id_ref, "spdx:identifier")
            id_elem.text = purl

    def _add_xml_vulnerability_element(self, root: Element, vuln_id: str, vuln) -> None:
        """Add vulnerability element to XML structure."""
        
        if vuln_id not in self.vuln_to_ref:
            self.vuln_to_ref[vuln_id] = f"vuln-{uuid7(as_type='str')}"
        
        spdx_id = self.vuln_to_ref[vuln_id]
        
        # Create vulnerability element
        vuln_elem = SubElement(root, "spdx:security_Vulnerability")
        vuln_elem.set("rdf:about", f"#{spdx_id}")
        
        # Add CVE identifier
        ext_id_elem = SubElement(vuln_elem, "spdx:externalIdentifier")
        ext_id_ref = SubElement(ext_id_elem, "spdx:ExternalIdentifier")
        
        type_elem = SubElement(ext_id_ref, "spdx:externalIdentifierType")
        type_elem.text = "cve"
        
        id_elem = SubElement(ext_id_ref, "spdx:identifier")
        id_elem.text = vuln_id
        
        # Add URLs as additional identifiers
        for url in vuln.urls:
            ext_id_elem = SubElement(vuln_elem, "spdx:externalIdentifier")
            ext_id_ref = SubElement(ext_id_elem, "spdx:ExternalIdentifier")
            
            type_elem = SubElement(ext_id_ref, "spdx:externalIdentifierType")
            type_elem.text = "other"
            
            id_elem = SubElement(ext_id_ref, "spdx:identifier")
            id_elem.text = url

    def _add_xml_relationship(self, root: Element, from_ref: str, to_refs: List[str], relationship_type: str) -> None:
        """Add relationship element to XML structure."""
        
        rel_id = f"rel-{uuid7(as_type='str')}"
        rel_elem = SubElement(root, "spdx:Relationship")
        rel_elem.set("rdf:about", f"#{rel_id}")
        
        # Add from reference
        from_elem = SubElement(rel_elem, "spdx:from")
        from_elem.set("rdf:resource", f"#{from_ref}")
        
        # Add relationship type
        type_elem = SubElement(rel_elem, "spdx:relationshipType")
        type_elem.text = relationship_type
        
        # Add to references
        for to_ref in to_refs:
            to_elem = SubElement(rel_elem, "spdx:to")
            to_elem.set("rdf:resource", f"#{to_ref}")

    def _add_xml_vex_assessment(self, root: Element, assessment) -> None:
        """Add VEX assessment relationship to XML structure."""
        
        vuln_ref = self.vuln_to_ref.get(assessment.vuln_id)
        if not vuln_ref:
            return
        
        # Get package refs for this assessment
        pkg_refs = []
        for pkg_id in assessment.packages:
            pkg_ref = self.pkg_to_ref.get(pkg_id)
            if pkg_ref:
                pkg_refs.append(pkg_ref)
        
        if not pkg_refs:
            return
        
        # Map VulnScout status to SPDX 3.0 VEX relationship types
        status_map = {
            "not_affected": ("spdx:security_VexNotAffectedVulnAssessmentRelationship", "doesNotAffect"),
            "false_positive": ("spdx:security_VexNotAffectedVulnAssessmentRelationship", "doesNotAffect"),
            "affected": ("spdx:security_VexAffectedVulnAssessmentRelationship", "affects"),
            "exploitable": ("spdx:security_VexAffectedVulnAssessmentRelationship", "affects"),
            "fixed": ("spdx:security_VexFixedVulnAssessmentRelationship", "fixedIn"),
            "resolved": ("spdx:security_VexFixedVulnAssessmentRelationship", "fixedIn"),
            "resolved_with_pedigree": ("spdx:security_VexFixedVulnAssessmentRelationship", "fixedIn")
        }
        
        vex_type, relationship_type = status_map.get(assessment.status, 
            ("spdx:security_VexAffectedVulnAssessmentRelationship", "affects"))
        
        vex_id = f"vex-{uuid7(as_type='str')}"
        vex_elem = SubElement(root, vex_type.split(":")[-1])
        vex_elem.set("rdf:about", f"#{vex_id}")
        
        # Add from reference (vulnerability)
        from_elem = SubElement(vex_elem, "spdx:from")
        from_elem.set("rdf:resource", f"#{vuln_ref}")
        
        # Add relationship type
        type_elem = SubElement(vex_elem, "spdx:relationshipType")
        type_elem.text = relationship_type
        
        # Add to references (packages)
        for pkg_ref in pkg_refs:
            to_elem = SubElement(vex_elem, "spdx:to")
            to_elem.set("rdf:resource", f"#{pkg_ref}")
        
        # Add justification if available
        justification_map = {
            "vulnerable_code_not_present": "vulnerableCodeNotPresent",
            "component_not_present": "componentNotPresent",
            "vulnerable_code_not_in_execute_path": "vulnerableCodeNotInExecutePath",
            "vulnerable_code_cannot_be_controlled_by_adversary": "vulnerableCodeCannotBeControlledByAdversary",
            "inline_mitigations_already_exist": "inlineMitigationsAlreadyExist"
        }
        
        if assessment.justification and assessment.justification in justification_map:
            just_elem = SubElement(vex_elem, "spdx:security_justificationType")
            just_elem.text = justification_map[assessment.justification]
        
        if assessment.impact_statement:
            impact_elem = SubElement(vex_elem, "spdx:security_impactStatement")
            impact_elem.text = assessment.impact_statement
        
        if assessment.status_notes:
            notes_elem = SubElement(vex_elem, "spdx:security_statusNotes")
            notes_elem.text = assessment.status_notes

    def output_as_xml(self, author: str = "Savoir-faire Linux") -> str:
        """Generate SPDX 3.0 XML output."""
        
        # Create base document structure
        root, document_id = self._create_xml_document_structure(author)
        
        # Generate package elements
        for pkg in self.packagesCtrl:
            self._add_xml_package_element(root, pkg)
        
        # Generate vulnerability elements and package-vulnerability relationships
        for vuln_id, vuln in self.vulnerabilitiesCtrl.vulnerabilities.items():
            self._add_xml_vulnerability_element(root, vuln_id, vuln)
            
            # Create relationships between packages and vulnerabilities
            vuln_ref = self.vuln_to_ref[vuln_id]
            affected_pkg_refs = []
            
            for pkg_id in vuln.packages:
                if pkg_id in self.pkg_to_ref:
                    affected_pkg_refs.append(self.pkg_to_ref[pkg_id])
            
            if affected_pkg_refs:
                for pkg_ref in affected_pkg_refs:
                    self._add_xml_relationship(
                        root, pkg_ref, [vuln_ref], "hasAssociatedVulnerability"
                    )
        
        # Generate VEX assessments
        for assessment_key, assessment in self.assessmentsCtrl.assessments.items():
            self._add_xml_vex_assessment(root, assessment)
        
        # Add document relationships (describes packages)
        pkg_refs = list(self.pkg_to_ref.values())
        
        if pkg_refs:
            self._add_xml_relationship(
                root, document_id, pkg_refs, "describes"
            )
        
        # Convert to string with pretty formatting
        rough_string = tostring(root, encoding='unicode')
        reparsed = parseString(rough_string)
        return reparsed.toprettyxml(indent="  ", encoding=None)

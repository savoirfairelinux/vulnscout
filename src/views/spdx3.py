# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def safe_spdx_id(text: str) -> str:
    """Convert text to safe SPDX ID format by replacing unsafe characters."""
    return text.replace('@', '-').replace(':', '-').replace('/', '-').replace(' ', '-')


def generate_spdx_namespace() -> str:
    """Generate SPDX namespace from environment or use default."""
    return os.getenv('SPDX_NAMESPACE', 'https://vulnscout.example.org')


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
        self.namespace = generate_spdx_namespace()
        self._creation_info_ref = None

    def _generate_package_spdx_id(self, pkg_id: str) -> str:
        """Generate deterministic SPDX ID for package using existing package.id"""
        safe_id = safe_spdx_id(pkg_id)
        return f"{self.namespace}#SPDXRef-Package-{safe_id}"

    def _generate_vulnerability_spdx_id(self, vuln_id: str) -> str:
        """Generate deterministic SPDX ID for vulnerability using existing vuln.id"""
        safe_id = safe_spdx_id(vuln_id)
        return f"{self.namespace}#SPDXRef-Vulnerability-{safe_id}"

    def _generate_assessment_spdx_id(self, assessment_id: str) -> str:
        """Generate deterministic SPDX ID for VEX assessment using existing assessment.id"""
        return f"{self.namespace}#SPDXRef-VexAssessment-{assessment_id}"

    def _generate_relationship_spdx_id(self, from_ref: str, to_ref: str, relationship_type: str) -> str:
        """Generate deterministic SPDX ID for relationship based on content"""
        content_hash = hash(f"{from_ref}-{to_ref}-{relationship_type}")
        return f"{self.namespace}#SPDXRef-Relationship-{abs(content_hash) % 1000000000000}"

    def _generate_creation_info_spdx_id(self) -> str:
        """Generate deterministic SPDX ID for creation info"""
        return f"{self.namespace}#SPDXRef-CreationInfo"

    def generate_package_element(self, pkg) -> Dict[str, Any]:
        """Generate SPDX 3.0 package element from Package object."""

        # Generate deterministic SPDX ID using the existing package.id
        if pkg.id not in self.pkg_to_ref:
            self.pkg_to_ref[pkg.id] = self._generate_package_spdx_id(pkg.id)

        spdx_id = self.pkg_to_ref[pkg.id]

        element = {
            "type": "software_Package",
            "spdxId": spdx_id,
            "name": pkg.name,
            "software_primaryPurpose": "application"
        }

        if pkg.version:
            element["software_packageVersion"] = pkg.version

        # Add external identifiers for CPEs and PURLs
        external_ids = []

        for cpe in pkg.cpe:
            external_ids.append({
                "type": "ExternalIdentifier",
                "externalIdentifierType": "cpe23",
                "identifier": cpe
            })

        for purl in pkg.purl:
            external_ids.append({
                "type": "ExternalIdentifier", 
                "externalIdentifierType": "purl",
                "identifier": purl
            })

        if external_ids:
            element["externalIdentifier"] = external_ids

        return element

    def generate_vulnerability_element(self, vuln_id: str, vuln) -> Dict[str, Any]:
        """Generate SPDX 3.0 vulnerability element."""

        if vuln_id not in self.vuln_to_ref:
            self.vuln_to_ref[vuln_id] = self._generate_vulnerability_spdx_id(vuln_id)

        spdx_id = self.vuln_to_ref[vuln_id]

        # Create external identifiers list starting with CVE
        external_identifiers: List[Dict[str, str]] = [{
            "type": "ExternalIdentifier",
            "externalIdentifierType": "cve",
            "identifier": vuln_id
        }]

        # Add URLs as additional identifiers
        for url in vuln.urls:
            external_identifiers.append({
                "type": "ExternalIdentifier",
                "externalIdentifierType": "securityAdvisory",
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
        # Generate deterministic ID based on relationship content
        to_refs_str = "-".join(sorted(to_refs))  # Sort for consistency
        relationship_id = self._generate_relationship_spdx_id(from_ref, to_refs_str, relationship_type)
        
        return {
            "type": "Relationship",
            "spdxId": relationship_id,
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
            "spdxId": self._generate_assessment_spdx_id(assessment.id),
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

        document_id = f"{self.namespace}#SPDXRef-Document"

        creation_info = {
            "type": "CreationInfo",
            "spdxId": self._generate_creation_info_spdx_id(),
            "specVersion": "3.0.1",
            "dataLicense": "CC0-1.0",
            "created": datetime.now(timezone.utc).isoformat(),
            "createdBy": [f"Organization: {author}", "Tool: VulnScout"]
        }

        # Cache creation info reference for reuse
        self._creation_info_ref = creation_info["spdxId"]

        document = {
            "type": "SpdxDocument",
            "spdxId": document_id,
            "name": f"{os.getenv('PRODUCT_NAME', 'PRODUCT_NAME')}-{os.getenv('PRODUCT_VERSION', '1.0.0')}",
            "creationInfo": self._creation_info_ref,
            "profileConformance": ["core", "software", "security"]
        }

        return {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [creation_info, document],
            "spdxId": document_id
        }

    def output_as_json(self, author: str = "Savoir-faire Linux") -> str:
        """Generate SPDX 3.0 JSON output with optimized performance."""

        # Create base document structure
        spdx_doc = self.create_document_structure(author)
        graph = spdx_doc["@graph"]
        
        # Single pass: Generate all elements with creation info pre-added
        elements_to_add = []
        relationships_to_add = []
        
        # Process packages
        for pkg in self.packagesCtrl:
            pkg_element = self.generate_package_element(pkg)
            pkg_element["creationInfo"] = self._creation_info_ref
            elements_to_add.append(pkg_element)

        # Process vulnerabilities and their relationships
        for vuln_id, vuln in self.vulnerabilitiesCtrl.vulnerabilities.items():
            # Generate vulnerability element
            vuln_element = self.generate_vulnerability_element(vuln_id, vuln)
            vuln_element["creationInfo"] = self._creation_info_ref
            elements_to_add.append(vuln_element)

            # Generate package-vulnerability relationships efficiently
            vuln_ref = self.vuln_to_ref[vuln_id]
            for pkg_id in vuln.packages:
                pkg_ref = self.pkg_to_ref.get(pkg_id)
                if pkg_ref:
                    relationship = self.generate_relationship(
                        pkg_ref,
                        [vuln_ref],
                        "hasAssociatedVulnerability"
                    )
                    relationship["creationInfo"] = self._creation_info_ref
                    relationships_to_add.append(relationship)

        # Process VEX assessments
        for assessment in self.assessmentsCtrl.assessments.values():
            vex_element = self.generate_vex_assessment(assessment)
            if vex_element:
                vex_element["creationInfo"] = self._creation_info_ref
                elements_to_add.append(vex_element)

        # Add all elements and relationships to graph at once
        graph.extend(elements_to_add)
        graph.extend(relationships_to_add)

        # Build element references list efficiently
        element_refs = [item["spdxId"] for item in elements_to_add + relationships_to_add]
        
        # Update the SpdxDocument with element list
        for item in graph:
            if item.get("type") == "SpdxDocument":
                item["element"] = element_refs
                # Find first package as root element
                package_refs = [ref for ref, item in zip(element_refs, elements_to_add) 
                              if item.get("type") == "software_Package"]
                if package_refs:
                    item["rootElement"] = [package_refs[0]]
                break

        return json.dumps(spdx_doc, indent=2)

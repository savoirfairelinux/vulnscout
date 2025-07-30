# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from typing import Dict, List, Optional, Any
import logging
import re
from ..models.package import Package
from ..models.vulnerability import Vulnerability
from ..models.assessment import VulnAssessment


class FastSPDX3:
    """
    FastSPDX3 class to handle SPDX 3.0 SBOM and parse it.
    Uses a lightweight approach similar to FastSPDX for parsing SPDX 3.0 files.
    """

    logger = logging.getLogger(__name__)

    # Types of VEX assessment relationships in SPDX 3.0
    ASSESSMENT_TYPES = {
        'security_VexNotAffectedVulnAssessmentRelationship',
        'security_VexAffectedVulnAssessmentRelationship',
        'security_VexFixedVulnAssessmentRelationship',
    }

    # Map from SPDX VEX justification types to internal representation
    JUSTIFICATION_MAP = {
        "vulnerableCodeNotPresent": "vulnerable_code_not_present",
        "componentNotPresent": "component_not_present",
        "vulnerableCodeNotInExecutePath": "vulnerable_code_not_in_execute_path",
        "vulnerableCodeCannotBeControlledByAdversary": "vulnerable_code_cannot_be_controlled_by_adversary",
        "inlineMitigationsAlreadyExist": "inline_mitigations_already_exist",
    }

    def __init__(self, controllers: Dict[str, Any]):
        """
        Initialize the FastSPDX3 parser with controllers for packages, vulnerabilities, and assessments.

        Args:
            controllers: Dictionary containing controllers for packages, vulnerabilities, and assessments
        """
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]
        self.uri_to_package: Dict[str, str] = {}

    def find_spdx_version(self, spdx: Dict[str, Any]) -> Optional[str]:
        """
        Find the SPDX version from the document.
        """
        for item in spdx.get("@graph", []):
            if item.get("@type") == "CreationInfo" or item.get("type") == "CreationInfo":
                version = item.get("specVersion")
                if version:
                    return version

        return None

    def could_parse_spdx(self, spdx: Dict[str, Any]) -> bool:
        """
        Check if this parser can handle the SPDX document (version 3.x).

        Args:
            spdx: SPDX document dictionary

        Returns:
            True if the document version starts with "3", False otherwise
        """
        version = self.find_spdx_version(spdx)
        return bool(version and version.startswith("3"))

    def merge_components_into_controller(self, components_dict: Dict[str, Any]):
        """
        Extract package information from components objects and create Package objects.
        """
        if not isinstance(components_dict, dict):
            return

        graph = components_dict.get("@graph", [])
        if not isinstance(graph, list):
            self.logger.warning("@graph is not a list")
            return

        if not graph:
            self.logger.warning("No @graph found in SPDX document")
            return

        for component in graph:
            if not isinstance(component, dict):
                continue
            if component.get('type') != 'software_Package':
                continue
            primary_purpose = component.get('software_primaryPurpose', '').lower()
            if primary_purpose in {'source', 'development', 'documentation'}:
                continue

            package = self._convert_to_package(component)
            if not package:
                continue

            # Store mapping from URI to package ID
            spdx_id = component.get('spdxId')
            if spdx_id:
                self.uri_to_package[spdx_id] = package.id

            self.packagesCtrl.add(package)

    def _convert_to_package(self, pkg_element: Dict[str, Any]) -> Optional[Package]:
        """
        Convert an SPDX 3.0 package dictionary to a VulnScout Package object.
        """

        def extract_value(fields: List[str]) -> Optional[str]:
            for f in fields:
                value = pkg_element.get(f)
                if isinstance(value, str):
                    return value
            return None

        name = extract_value(["name", "Name", "packageName", "PackageName"])
        version = extract_value(["versionInfo", "version", "software_packageVersion", "packageVersion"])

        if not name or not version:
            return None

        pkg = Package(name, version, [], [])

        cpes = self.extract_cpes(pkg_element)
        for cpe in cpes:
            pkg.add_cpe(cpe)
        pkg.generate_generic_cpe()

        purl = self.extract_purl(pkg_element)
        if purl:
            pkg.add_purl(purl)
        pkg.generate_generic_purl()

        return pkg

    def extract_purl(self, element: Dict[str, Any]) -> Optional[str]:
        """
        Extract Package URL (PURL) from SPDX element.
        """
        if 'packageUrl' in element:
            return element['packageUrl']

        if 'software_packageUrl' in element:
            return element['software_packageUrl']
        return None

    def extract_cpes(self, element: Dict[str, Any]) -> List[str]:
        """
        Extract CPE identifiers from an SPDX element.
        """
        external_identifiers = element.get('externalIdentifier')
        if not isinstance(external_identifiers, list):
            return []

        cpe_identifiers = []

        for ext_id in external_identifiers:
            if not isinstance(ext_id, dict):
                continue
            ext_id_type = ext_id.get('externalIdentifierType', '')
            if ext_id_type == 'cpe23' or ext_id_type == 'cpe22':
                cpe_id = ext_id.get('identifier')
                if cpe_id:
                    cpe_identifiers.append(cpe_id)

        return cpe_identifiers

    def merge_vulnerabilities_into_controller(self, vuln_dict: Dict[str, Any]):
        """
        Extract Vulnerability objects from SPDX graph elements.
        """
        if not isinstance(vuln_dict, dict):
            self.logger.warning("Invalid SPDX document format")
            return

        graph = vuln_dict.get("@graph", [])
        if not isinstance(graph, list):
            self.logger.warning("@graph is not a list")
            return

        if not graph:
            return

        self._extract_explicit_vulnerabilities(graph)

        self._process_package_vulnerability_relationships(graph)

        self._remove_vulnerabilities_without_packages()

    def _remove_vulnerabilities_without_packages(self):
        """
        Remove vulnerabilities that don't have any packages.
        """
        vulnerabilities_to_remove = []

        for vuln in self.vulnerabilitiesCtrl.vulnerabilities.values():
            if not vuln.packages:
                vulnerabilities_to_remove.append(vuln.id)

        for vuln_id in vulnerabilities_to_remove:
            self.vulnerabilitiesCtrl.remove(vuln_id)

    def _extract_explicit_vulnerabilities(self, graph: List[Dict]):
        """
        Extract vulnerabilities explicitly defined as security_Vulnerability elements.

        Structure example:
        {
            "type": "security_Vulnerability",
            "externalIdentifier": [
                {
                    "externalIdentifierType": "cve",
                    "identifier": "CVE-2023-XXXX",
                    "identifierLocator": ["https://..."]
                }
            ]
        }
        """
        for element in graph:
            if not isinstance(element, dict):
                continue
            if element.get('type') != 'security_Vulnerability':
                continue

            ext_ids = element.get('externalIdentifier', [])
            if not isinstance(ext_ids, list):
                continue
            for ext_id in ext_ids:
                if not isinstance(ext_id, dict):
                    continue
                if ext_id.get('externalIdentifierType') != 'cve':
                    continue

                cve_id = ext_id.get('identifier')
                if not cve_id:
                    continue

                locators = ext_id.get('identifierLocator', [])
                if not isinstance(locators, list):
                    locators = []
                datasource = locators[0] if locators else "unknown"

                vulnerability = Vulnerability(cve_id, ["yocto"], datasource, "unknown")

                # Add remaining locators as URLs
                for locator in locators[1:]:
                    if isinstance(locator, str):
                        vulnerability.add_url(locator)

                self.vulnerabilitiesCtrl.add(vulnerability)

    def _process_package_vulnerability_relationships(self, graph: List[Dict]):
        """
        Process relationships that link packages to vulnerabilities, to update the Vulnerability objects.

        Example structure:
        {
            "type": "Relationship",
            "spdxId": "...",
            "from": "package_uri",
            "relationshipType": "hasAssociatedVulnerability",
            "to": ["vulnerability_uri1", "vulnerability_uri2"]
        }
        """
        for element in graph:
            if not isinstance(element, dict):
                continue
            if element.get('type') != 'Relationship':
                continue

            if element.get('relationshipType') != 'hasAssociatedVulnerability':
                continue

            package_uri = element.get('from')
            if not package_uri:
                continue

            vulnerability_uris = element.get('to', [])
            if not isinstance(vulnerability_uris, list) or not vulnerability_uris:
                continue

            # Get package ID from URI mapping
            package_id = self.uri_to_package.get(package_uri)
            if not package_id:
                self.logger.warning(f"Package URI {package_uri} not found in package mapping")
                continue

            for vuln_uri in vulnerability_uris:
                cve_id = self._extract_cve_id(vuln_uri)
                if not cve_id:
                    continue

                vulnerability = self.vulnerabilitiesCtrl.get(cve_id)
                if vulnerability:
                    vulnerability.add_package(package_id)

    CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,}\b')

    def _extract_cve_id(self, text: str) -> Optional[str]:
        """Extract CVE ID from text string if present."""
        if not text:
            return None

        match = self.CVE_PATTERN.search(text)
        if match:
            return match.group(0)

        return None

    def is_vex_relationship(self, rel: Dict[str, Any]) -> bool:
        """
        Check if a relationship element is a VEX relationship.
        """
        rel_type = rel.get("type", "")
        return rel_type in self.ASSESSMENT_TYPES

    def process_vex_relationships(self, spdx_dict: Dict[str, Any]):
        """
        Process VEX relationships from the SPDX document to create vulnerability assessments.
        """
        if not isinstance(spdx_dict, dict):
            self.logger.warning("Invalid SPDX document format")
            return

        graph = spdx_dict.get("@graph", [])
        if not isinstance(graph, list):
            self.logger.warning("@graph is not a list")
            return

        if not graph:
            return

        for rel in graph:
            if not isinstance(rel, dict):
                continue
            if not self.is_vex_relationship(rel):
                continue

            assessment = self._parse_vex_relationship(rel)
            if assessment:
                self.assessmentsCtrl.add(assessment)

    def _parse_vex_relationship(self, element: Dict[str, Any]) -> Optional[VulnAssessment]:
        """
        Extract relevant information from VulnAssessmentRelationship element.
        """
        if 'from' not in element or 'to' not in element:
            return None

        from_value = element.get('from', '')  # vulnerability uri
        to_values = element.get('to', [])     # package uri
        if not isinstance(to_values, list):
            return None
        vuln_id = self._extract_cve_id(from_value)
        package_uri = to_values[0] if to_values else None

        if not vuln_id or not package_uri:
            return None

        package_id = self.uri_to_package.get(package_uri)
        if not package_id:
            self.logger.warning(f"Package URI {package_uri} not found in package mapping for assessment")
            return None

        assessment = VulnAssessment(vuln_id, [package_id])

        # Set status based on relationship type
        relationship_type = element.get('relationshipType', '')
        if relationship_type == 'doesNotAffect':
            assessment.set_status('not_affected')
        elif relationship_type == 'affects':
            assessment.set_status('affected')
        elif relationship_type == "fixedIn":
            assessment.set_status('fixed')

        raw_justification = element.get('security_justificationType')

        if raw_justification and raw_justification in self.JUSTIFICATION_MAP:
            assessment.set_justification(self.JUSTIFICATION_MAP[raw_justification])

        if element.get('security_impactStatement'):
            assessment.impact_statement = element.get("security_impactStatement", "")

        return assessment

    def _remove_vulnerabilities_without_assessments(self):
        """
        Remove vulnerabilities that don't have any assessments.
        Because report generation fails for vulnerabilities without assessments.
        """
        vulnerabilities_to_remove = []

        for vuln in self.vulnerabilitiesCtrl.vulnerabilities.values():
            assessments = self.assessmentsCtrl.gets_by_vuln(vuln.id)
            if not assessments:
                vulnerabilities_to_remove.append(vuln.id)

        for vuln_id in vulnerabilities_to_remove:
            self.vulnerabilitiesCtrl.remove(vuln_id)

    def parse_controllers_from_dict(self, spdx: Dict[str, Any]):
        """
        Parse only packages from SPDX 3 document.
        """
        self.merge_components_into_controller(spdx)

    def parse_from_dict(self, spdx: Dict[str, Any]):
        """
        Read data from SPDX 3 format and populate controllers.
        """
        self.merge_components_into_controller(spdx)
        self.merge_vulnerabilities_into_controller(spdx)
        self.process_vex_relationships(spdx)
        self._remove_vulnerabilities_without_assessments()

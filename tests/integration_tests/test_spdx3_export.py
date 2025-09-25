# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import json
import xml.etree.ElementTree as ET
from src.views.spdx3 import SPDX3
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from src.models.assessment import VulnAssessment
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController


@pytest.fixture
def spdx3_exporter():
    """Create SPDX3 exporter with empty controllers."""
    controllers = {
        "packages": PackagesController(),
        "vulnerabilities": VulnerabilitiesController(PackagesController()),
        "assessments": AssessmentsController(PackagesController(), VulnerabilitiesController(PackagesController()))
    }
    # Update vulnerability controller to use the same package controller
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    controllers["assessments"] = AssessmentsController(controllers["packages"], controllers["vulnerabilities"])
    return SPDX3(controllers)


@pytest.fixture
def populated_spdx3_exporter():
    """Create SPDX3 exporter with sample data."""
    controllers = {
        "packages": PackagesController(),
        "vulnerabilities": VulnerabilitiesController(PackagesController()),
        "assessments": AssessmentsController(PackagesController(), VulnerabilitiesController(PackagesController()))
    }
    # Update controllers to use the same package controller
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    controllers["assessments"] = AssessmentsController(controllers["packages"], controllers["vulnerabilities"])
    
    exporter = SPDX3(controllers)
    
    # Add test packages
    pkg1 = Package("openssl", "3.0.0", [], [])
    pkg1.add_cpe("cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*")
    pkg1.add_purl("pkg:deb/debian/openssl@3.0.0")
    exporter.packagesCtrl.add(pkg1)
    
    pkg2 = Package("nginx", "1.20.1", [], [])
    pkg2.add_cpe("cpe:2.3:a:nginx:nginx:1.20.1:*:*:*:*:*:*:*")
    exporter.packagesCtrl.add(pkg2)
    
    # Add test vulnerabilities
    vuln1 = Vulnerability("CVE-2023-1234", ["test-scanner"], "test-datasource", "test-namespace")
    vuln1.add_package(pkg1.id)
    vuln1.add_url("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234")
    exporter.vulnerabilitiesCtrl.add(vuln1)
    
    vuln2 = Vulnerability("CVE-2023-5678", ["test-scanner"], "test-datasource", "test-namespace") 
    vuln2.add_package(pkg2.id)
    exporter.vulnerabilitiesCtrl.add(vuln2)
    
    # Add test assessments
    assessment1 = VulnAssessment("CVE-2023-1234", [pkg1.id])
    assessment1.set_status("not_affected")
    assessment1.set_justification("vulnerable_code_not_present")
    assessment1.set_not_affected_reason("Vulnerable code is not present in this version")
    assessment1.set_status_notes("Manual review confirmed no vulnerable code")
    exporter.assessmentsCtrl.add(assessment1)
    
    assessment2 = VulnAssessment("CVE-2023-5678", [pkg2.id])
    assessment2.set_status("fixed") 
    assessment2.set_not_affected_reason("Security patch applied")
    exporter.assessmentsCtrl.add(assessment2)
    
    return exporter


class TestSPDX3JSONExport:
    """Test SPDX3 JSON export functionality."""
    
    def test_export_empty_document(self, spdx3_exporter):
        """Test exporting empty SPDX3 document."""
        output = json.loads(spdx3_exporter.output_as_json("Test Author"))
        
        # Check document structure
        assert output["@context"] == "https://raw.githubusercontent.com/spdx/spdx-3-model/main/model/spdx-context.jsonld"
        assert "@graph" in output
        assert "spdxId" in output
        assert output["spdxId"].startswith("doc-")
        
        # Check creation info and document are present
        graph_types = [item["type"] for item in output["@graph"]]
        assert "CreationInfo" in graph_types
        assert "SpdxDocument" in graph_types
        
        # Find creation info
        creation_info = next(item for item in output["@graph"] if item["type"] == "CreationInfo")
        assert creation_info["specVersion"] == "3.0.1"
        assert creation_info["dataLicense"] == "CC0-1.0"
        assert "created" in creation_info
        assert "Organization: Test Author" in creation_info["creators"]
        assert "Tool: VulnScout" in creation_info["creators"]
        
        # Find document
        document = next(item for item in output["@graph"] if item["type"] == "SpdxDocument")
        assert "name" in document
        assert "namespaceMap" in document
        assert document["creationInfo"] == creation_info["spdxId"]
    
    def test_export_packages_only(self, spdx3_exporter):
        """Test exporting SPDX3 document with packages only."""
        # Add test packages
        pkg1 = Package("curl", "7.88.1", [], [])
        pkg1.add_cpe("cpe:2.3:a:haxx:curl:7.88.1:*:*:*:*:*:*:*")
        pkg1.add_purl("pkg:deb/debian/curl@7.88.1")
        spdx3_exporter.packagesCtrl.add(pkg1)
        
        pkg2 = Package("libssl", "3.0.0", [], [])
        pkg2.add_cpe("cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*")
        spdx3_exporter.packagesCtrl.add(pkg2)
        
        output = json.loads(spdx3_exporter.output_as_json())
        
        # Find packages in graph
        packages = [item for item in output["@graph"] if item["type"] == "software_Package"]
        assert len(packages) == 2
        
        # Check first package
        curl_pkg = next(pkg for pkg in packages if pkg["name"] == "curl")
        assert curl_pkg["versionInfo"] == "7.88.1" 
        assert curl_pkg["software_primaryPurpose"] == "application"
        assert "spdxId" in curl_pkg
        
        # Check external identifiers
        ext_ids = curl_pkg["externalIdentifier"]
        cpe_ids = [eid for eid in ext_ids if eid["externalIdentifierType"] == "cpe23"]
        purl_ids = [eid for eid in ext_ids if eid["externalIdentifierType"] == "purl"]
        assert len(cpe_ids) == 1
        assert len(purl_ids) == 1
        assert cpe_ids[0]["identifier"] == "cpe:2.3:a:haxx:curl:7.88.1:*:*:*:*:*:*:*"
        assert purl_ids[0]["identifier"] == "pkg:deb/debian/curl@7.88.1"
        
        # Check document describes packages relationship
        relationships = [item for item in output["@graph"] if item["type"] == "Relationship"]
        describes_rel = next(rel for rel in relationships if rel["relationshipType"] == "describes")
        assert describes_rel["from"] == output["spdxId"]
        assert len(describes_rel["to"]) == 2
    
    def test_export_vulnerabilities_and_relationships(self, populated_spdx3_exporter):
        """Test exporting vulnerabilities and package-vulnerability relationships."""
        output = json.loads(populated_spdx3_exporter.output_as_json())
        
        # Find vulnerabilities in graph
        vulnerabilities = [item for item in output["@graph"] if item["type"] == "security_Vulnerability"]
        assert len(vulnerabilities) == 2
        
        # Check vulnerability structure
        cve_1234 = next(v for v in vulnerabilities if any(
            eid["identifier"] == "CVE-2023-1234" for eid in v["externalIdentifier"]
        ))
        assert "spdxId" in cve_1234
        
        # Check external identifiers
        ext_ids = cve_1234["externalIdentifier"]
        cve_id = next(eid for eid in ext_ids if eid["externalIdentifierType"] == "cve")
        assert cve_id["identifier"] == "CVE-2023-1234"
        
        # Check package-vulnerability relationships
        relationships = [item for item in output["@graph"] if item["type"] == "Relationship" 
                        and item["relationshipType"] == "hasAssociatedVulnerability"]
        assert len(relationships) == 2  # One for each vulnerability
    
    def test_export_vex_assessments(self, populated_spdx3_exporter):
        """Test exporting VEX assessments."""
        output = json.loads(populated_spdx3_exporter.output_as_json())
        
        # Find VEX assessments in graph
        vex_assessments = [item for item in output["@graph"] if item["type"].startswith("security_Vex")]
        assert len(vex_assessments) == 2
        
        # Check not_affected assessment
        not_affected = next(v for v in vex_assessments 
                           if v["type"] == "security_VexNotAffectedVulnAssessmentRelationship")
        assert not_affected["relationshipType"] == "doesNotAffect"
        assert not_affected["security_justificationType"] == "vulnerableCodeNotPresent"
        assert "Vulnerable code is not present" in not_affected["security_impactStatement"]
        assert "Manual review confirmed" in not_affected["security_statusNotes"]
        
        # Check fixed assessment
        fixed = next(v for v in vex_assessments 
                    if v["type"] == "security_VexFixedVulnAssessmentRelationship")
        assert fixed["relationshipType"] == "fixedIn"
        assert "Security patch applied" in fixed["security_impactStatement"]
    
    def test_export_with_custom_author(self, spdx3_exporter):
        """Test export with custom author name."""
        output = json.loads(spdx3_exporter.output_as_json("Custom Organization"))
        
        creation_info = next(item for item in output["@graph"] if item["type"] == "CreationInfo")
        assert "Organization: Custom Organization" in creation_info["creators"]
        assert "Tool: VulnScout" in creation_info["creators"]
    
    def test_uuid_generation_consistency(self, spdx3_exporter):
        """Test that UUID generation is consistent within a document."""
        pkg = Package("test-pkg", "1.0.0", [], [])
        spdx3_exporter.packagesCtrl.add(pkg)
        
        # Export twice and check IDs are consistent
        output1 = json.loads(spdx3_exporter.output_as_json())
        output2 = json.loads(spdx3_exporter.output_as_json())
        
        pkg1 = next(item for item in output1["@graph"] if item["type"] == "software_Package")
        pkg2 = next(item for item in output2["@graph"] if item["type"] == "software_Package") 
        
        assert pkg1["spdxId"] == pkg2["spdxId"]


class TestSPDX3XMLExport:
    """Test SPDX3 XML export functionality."""
    
    def test_export_empty_document_xml(self, spdx3_exporter):
        """Test exporting empty SPDX3 document as XML."""
        xml_output = spdx3_exporter.output_as_xml("Test Author")
        
        # Parse XML and check structure
        root = ET.fromstring(xml_output)
        # XML namespace handling creates tags like {namespace}localname
        assert root.tag.endswith("}SpdxDocument") or root.tag == "spdx:SpdxDocument"
        
        # Check that XML is well-formed and contains expected structure
        # The root should be an SPDX document with namespaces
        assert root is not None
        # Check for namespace declarations or SPDX-related attributes
        all_text = xml_output.lower()
        spdx_in_content = "spdx" in all_text
        xmlns_in_content = "xmlns" in all_text
        assert spdx_in_content or xmlns_in_content
        
        # Check document name (handle namespaced elements)
        name_elems = root.findall(".//*")
        name_elem_found = any("name" in elem.tag for elem in name_elems)
        assert name_elem_found
        
        # Check creation info (handle namespaced elements)
        creation_info_found = any("CreationInfo" in elem.tag for elem in name_elems)
        assert creation_info_found
    
    def test_export_packages_xml(self, spdx3_exporter):
        """Test exporting packages as XML."""
        pkg = Package("apache", "2.4.41", [], [])
        pkg.add_cpe("cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*")
        pkg.add_purl("pkg:deb/debian/apache2@2.4.41")
        spdx3_exporter.packagesCtrl.add(pkg)
        
        xml_output = spdx3_exporter.output_as_xml()
        root = ET.fromstring(xml_output)
        
        # Find package elements (handle namespaced elements)
        all_elements = root.findall(".//*")
        packages = [elem for elem in all_elements if "software_Package" in elem.tag]
        assert len(packages) == 1
        
        package = packages[0]
        # Find name and version in subelements
        subelems = package.findall(".//*")
        name_elem = next((elem for elem in subelems if "name" in elem.tag), None)
        assert name_elem is not None
        assert name_elem.text == "apache"
        
        version_elem = next((elem for elem in subelems if "versionInfo" in elem.tag), None)
        assert version_elem is not None
        assert version_elem.text == "2.4.41"
    
    def test_export_vulnerabilities_xml(self, populated_spdx3_exporter):
        """Test exporting vulnerabilities as XML.""" 
        xml_output = populated_spdx3_exporter.output_as_xml()
        root = ET.fromstring(xml_output)
        
        # Find vulnerability elements (handle namespaced elements)
        all_elements = root.findall(".//*")
        vulnerabilities = [elem for elem in all_elements if "security_Vulnerability" in elem.tag]
        assert len(vulnerabilities) == 2
        
        # Check external identifiers
        for vuln in vulnerabilities:
            subelems = vuln.findall(".//*")
            ext_ids = [elem for elem in subelems if "ExternalIdentifier" in elem.tag]
            assert len(ext_ids) >= 1  # At least CVE identifier
    
    def test_export_vex_assessments_xml(self, populated_spdx3_exporter):
        """Test exporting VEX assessments as XML."""
        xml_output = populated_spdx3_exporter.output_as_xml()
        root = ET.fromstring(xml_output)
        
        # Find VEX assessment elements (handle namespaced elements)
        all_elements = root.findall(".//*")
        vex_elements = [elem for elem in all_elements if "Vex" in elem.tag and "VulnAssessmentRelationship" in elem.tag]
        
        assert len(vex_elements) == 2
        
        # Check relationship types are present
        for vex in vex_elements:
            subelems = vex.findall(".//*")
            rel_type = next((elem for elem in subelems if "relationshipType" in elem.tag), None)
            assert rel_type is not None
            assert rel_type.text in ["doesNotAffect", "fixedIn"]


class TestSPDX3ElementGeneration:
    """Test individual SPDX3 element generation methods."""
    
    def test_generate_package_element(self, spdx3_exporter):
        """Test package element generation."""
        pkg = Package("test-lib", "2.1.0", [], [])
        pkg.add_cpe("cpe:2.3:a:test:test-lib:2.1.0:*:*:*:*:*:*:*")
        
        element = spdx3_exporter.generate_package_element(pkg)
        
        assert element["type"] == "software_Package"
        assert element["name"] == "test-lib"
        assert element["versionInfo"] == "2.1.0"
        assert element["software_primaryPurpose"] == "application"
        assert "spdxId" in element
        
        # Check external identifiers
        ext_ids = element["externalIdentifier"]
        assert len(ext_ids) == 1
        assert ext_ids[0]["externalIdentifierType"] == "cpe23"
        assert ext_ids[0]["identifier"] == "cpe:2.3:a:test:test-lib:2.1.0:*:*:*:*:*:*:*"
    
    def test_generate_vulnerability_element(self, spdx3_exporter):
        """Test vulnerability element generation."""
        vuln = Vulnerability("CVE-2024-9999", ["test-scanner"], "test-datasource", "test-namespace")
        vuln.add_url("https://example.com/vuln")
        
        element = spdx3_exporter.generate_vulnerability_element("CVE-2024-9999", vuln)
        
        assert element["type"] == "security_Vulnerability"
        assert "spdxId" in element
        
        ext_ids = element["externalIdentifier"]
        assert len(ext_ids) == 2  # CVE + URL
        
        cve_id = next(eid for eid in ext_ids if eid["externalIdentifierType"] == "cve")
        assert cve_id["identifier"] == "CVE-2024-9999"
        
        url_id = next(eid for eid in ext_ids if eid["externalIdentifierType"] == "other")
        assert url_id["identifier"] == "https://example.com/vuln"
    
    def test_generate_vex_assessment_mapping(self, spdx3_exporter):
        """Test VEX assessment status mapping.""" 
        pkg = Package("test-pkg", "1.0", [], [])
        spdx3_exporter.packagesCtrl.add(pkg)
        
        # Test different status mappings
        test_cases = [
            ("not_affected", "security_VexNotAffectedVulnAssessmentRelationship", "doesNotAffect"),
            ("false_positive", "security_VexNotAffectedVulnAssessmentRelationship", "doesNotAffect"),
            ("affected", "security_VexAffectedVulnAssessmentRelationship", "affects"),
            ("exploitable", "security_VexAffectedVulnAssessmentRelationship", "affects"),
            ("fixed", "security_VexFixedVulnAssessmentRelationship", "fixedIn"),
            ("resolved", "security_VexFixedVulnAssessmentRelationship", "fixedIn"),
        ]
        
        for status, expected_type, expected_rel in test_cases:
            assessment = VulnAssessment("CVE-2024-TEST", [pkg.id])
            assessment.set_status(status)
            
            # Add vuln and package to refs
            spdx3_exporter.vuln_to_ref["CVE-2024-TEST"] = "test-vuln"
            spdx3_exporter.pkg_to_ref[pkg.id] = "test-pkg"
            
            element = spdx3_exporter.generate_vex_assessment(assessment)
            
            assert element["type"] == expected_type
            assert element["relationshipType"] == expected_rel
    
    def test_generate_relationship(self, spdx3_exporter):
        """Test relationship generation."""
        relationship = spdx3_exporter.generate_relationship("from-ref", ["to-ref-1", "to-ref-2"], "testRelation")
        
        assert relationship["type"] == "Relationship"
        assert relationship["from"] == "from-ref"
        assert relationship["to"] == ["to-ref-1", "to-ref-2"]
        assert relationship["relationshipType"] == "testRelation"
        assert "spdxId" in relationship
    
    def test_justification_mapping(self, spdx3_exporter):
        """Test VEX justification mapping."""
        pkg = Package("test-pkg", "1.0", [], [])
        spdx3_exporter.packagesCtrl.add(pkg)
        
        assessment = VulnAssessment("CVE-2024-TEST", [pkg.id])
        assessment.set_status("not_affected")
        assessment.set_justification("vulnerable_code_not_present")
        assessment.set_not_affected_reason("Test impact statement")
        assessment.set_status_notes("Test notes")
        
        # Set up refs
        spdx3_exporter.vuln_to_ref["CVE-2024-TEST"] = "test-vuln"
        spdx3_exporter.pkg_to_ref[pkg.id] = "test-pkg"
        
        element = spdx3_exporter.generate_vex_assessment(assessment)
        
        assert element["security_justificationType"] == "vulnerableCodeNotPresent"
        assert element["security_impactStatement"] == "Test impact statement"
        assert element["security_statusNotes"] == "Test notes"


class TestSPDX3DocumentStructure:
    """Test SPDX3 document structure creation."""
    
    def test_create_document_structure(self, spdx3_exporter):
        """Test document structure creation."""
        doc = spdx3_exporter.create_document_structure("Test Org")
        
        assert "@context" in doc
        assert "@graph" in doc
        assert "spdxId" in doc
        
        # Check creation info
        creation_info = next(item for item in doc["@graph"] if item["type"] == "CreationInfo")
        assert creation_info["specVersion"] == "3.0.1"
        assert creation_info["dataLicense"] == "CC0-1.0"
        assert "Organization: Test Org" in creation_info["creators"]
        
        # Check document
        document = next(item for item in doc["@graph"] if item["type"] == "SpdxDocument")
        assert document["creationInfo"] == creation_info["spdxId"]
        assert "namespaceMap" in document
    
    def test_package_without_version(self, spdx3_exporter):
        """Test package generation without version."""
        pkg = Package("no-version-pkg", "unknown", [], [])
        pkg.version = None  # Simulate a package without version after creation
        element = spdx3_exporter.generate_package_element(pkg)
        
        assert element["name"] == "no-version-pkg"
        assert "versionInfo" not in element
    
    def test_package_without_external_identifiers(self, spdx3_exporter):
        """Test package generation without CPE/PURL."""
        pkg = Package("simple-pkg", "1.0", [], [])
        element = spdx3_exporter.generate_package_element(pkg)
        
        assert element["name"] == "simple-pkg"
        assert "externalIdentifier" not in element
    
    def test_vulnerability_without_urls(self, spdx3_exporter):
        """Test vulnerability generation without URLs."""
        vuln = Vulnerability("CVE-2024-0000", ["test-scanner"], "test-datasource", "test-namespace")
        element = spdx3_exporter.generate_vulnerability_element("CVE-2024-0000", vuln)
        
        ext_ids = element["externalIdentifier"] 
        assert len(ext_ids) == 1  # Only CVE identifier
        assert ext_ids[0]["externalIdentifierType"] == "cve"

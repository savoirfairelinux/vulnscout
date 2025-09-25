# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import os
import json
import xml.etree.ElementTree as ET
from src.views.spdx3 import SPDX3, uuid7
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from src.models.assessment import VulnAssessment
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController
from unittest.mock import patch


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


class TestUUID7Function:
    """Test the uuid7 helper function."""
    
    def test_uuid7_str_format(self):
        """Test UUID7 string format generation."""
        uuid_str = uuid7(as_type='str')
        assert isinstance(uuid_str, str)
        assert len(uuid_str) == 36  # Standard UUID string length
        assert uuid_str.count('-') == 4  # UUIDs have 4 hyphens
    
    def test_uuid7_uuid_format(self):
        """Test UUID7 UUID object format generation."""
        import uuid as uuid_module
        uuid_obj = uuid7(as_type='uuid')
        assert isinstance(uuid_obj, uuid_module.UUID)
    
    def test_uuid7_default_format(self):
        """Test UUID7 default format is string."""
        uuid_default = uuid7()
        assert isinstance(uuid_default, str)


class TestSPDX3EdgeCases:
    """Test SPDX3 edge cases and error handling."""
    
    def test_generate_vex_assessment_missing_vuln_ref(self, spdx3_exporter):
        """Test generate_vex_assessment with missing vulnerability reference."""
        pkg = Package("test-pkg", "1.0", [], [])
        spdx3_exporter.packagesCtrl.add(pkg)
        spdx3_exporter.pkg_to_ref[pkg.id] = "test-pkg"
        
        assessment = VulnAssessment("CVE-2024-MISSING", [pkg.id])
        assessment.set_status("not_affected")
        
        # Vuln ref is missing
        vex_element = spdx3_exporter.generate_vex_assessment(assessment)
        assert vex_element is None
    
    def test_generate_vex_assessment_missing_pkg_ref(self, spdx3_exporter):
        """Test generate_vex_assessment with missing package reference."""
        assessment = VulnAssessment("CVE-2024-TEST", ["missing-pkg-id"])
        assessment.set_status("affected")
        
        # Add vuln ref but not package ref
        spdx3_exporter.vuln_to_ref["CVE-2024-TEST"] = "test-vuln"
        
        vex_element = spdx3_exporter.generate_vex_assessment(assessment)
        assert vex_element is None
    
    def test_generate_vex_assessment_unknown_status(self, spdx3_exporter):
        """Test generate_vex_assessment with unknown status."""
        pkg = Package("test-pkg", "1.0", [], [])
        spdx3_exporter.packagesCtrl.add(pkg)
        
        assessment = VulnAssessment("CVE-2024-TEST", [pkg.id])
        assessment.status = "unknown_status"  # Set invalid status directly
        
        # Set up refs
        spdx3_exporter.vuln_to_ref["CVE-2024-TEST"] = "test-vuln"
        spdx3_exporter.pkg_to_ref[pkg.id] = "test-pkg"
        
        element = spdx3_exporter.generate_vex_assessment(assessment)
        
        # Should default to affected relationship
        assert element["type"] == "security_VexAffectedVulnAssessmentRelationship"
        assert element["relationshipType"] == "affects"
    
    def test_generate_vex_assessment_unknown_justification(self, spdx3_exporter):
        """Test generate_vex_assessment with unknown justification."""
        pkg = Package("test-pkg", "1.0", [], [])
        spdx3_exporter.packagesCtrl.add(pkg)
        
        assessment = VulnAssessment("CVE-2024-TEST", [pkg.id])
        assessment.set_status("not_affected")
        assessment.justification = "unknown_justification"  # Set invalid justification directly
        
        # Set up refs
        spdx3_exporter.vuln_to_ref["CVE-2024-TEST"] = "test-vuln"
        spdx3_exporter.pkg_to_ref[pkg.id] = "test-pkg"
        
        element = spdx3_exporter.generate_vex_assessment(assessment)
        
        # Should not include justification type
        assert "security_justificationType" not in element


class TestSPDX3XMLSpecificFeatures:
    """Test SPDX3 XML-specific export features."""
    
    def test_dict_to_xml_element_basics(self, spdx3_exporter):
        """Test basic dict_to_xml_element conversion."""
        data = {
            "type": "TestType",
            "spdxId": "test-id",
            "name": "Test Name",
            "value": "Test Value"
        }
        
        element = spdx3_exporter.dict_to_xml_element(data, parent_name="TestType")
        
        assert element.tag == "spdx:element" or element.tag == "spdx:TestType"
        assert element.get("rdf:about") == "#test-id"
        
        name_elem = element.find("spdx:name")
        assert name_elem is not None
        assert name_elem.text == "Test Name"
        
        value_elem = element.find("spdx:value")
        assert value_elem is not None
        assert value_elem.text == "Test Value"
    
    def test_dict_to_xml_element_nested(self, spdx3_exporter):
        """Test dict_to_xml_element with nested structures."""
        data = {
            "type": "ParentType",
            "spdxId": "parent-id",
            "name": "Parent",
            "child": {
                "name": "Child",
                "value": 123
            }
        }
        
        element = spdx3_exporter.dict_to_xml_element(data)
        
        child_elem = element.find("spdx:child")
        assert child_elem is not None
        
        child_name = child_elem.find("spdx:name")
        assert child_name is not None
        assert child_name.text == "Child"
        
        child_value = child_elem.find("spdx:value")
        assert child_value is not None
        assert child_value.text == "123"
    
    def test_dict_to_xml_element_lists(self, spdx3_exporter):
        """Test dict_to_xml_element with list values."""
        data = {
            "type": "TestType",
            "spdxId": "test-id",
            "strings": ["a", "b", "c"],
            "objects": [
                {"name": "Obj1", "value": 1},
                {"name": "Obj2", "value": 2}
            ]
        }
        
        element = spdx3_exporter.dict_to_xml_element(data)
        
        # Check string list items
        string_elems = element.findall("spdx:string")
        assert len(string_elems) == 3
        assert [e.text for e in string_elems] == ["a", "b", "c"]
        
        # Check object list items
        object_elems = element.findall("spdx:object")
        assert len(object_elems) == 2
        
        obj1 = object_elems[0]
        assert obj1.find("spdx:name").text == "Obj1"
        assert obj1.find("spdx:value").text == "1"
        
        obj2 = object_elems[1]
        assert obj2.find("spdx:name").text == "Obj2"
        assert obj2.find("spdx:value").text == "2"
    
    def test_dict_to_xml_element_custom_namespace(self, spdx3_exporter):
        """Test dict_to_xml_element with custom namespace."""
        data = {
            "type": "TestType",
            "name": "Test"
        }
        
        element = spdx3_exporter.dict_to_xml_element(data, parent_name="TestType", namespace_prefix="custom")
        
        assert element.tag == "custom:element" or element.tag == "custom:TestType"
        
        name_elem = element.find("custom:name")
        assert name_elem is not None
        assert name_elem.text == "Test"
    
    def test_xml_output_fallback_approach(self, spdx3_exporter):
        """Test XML output fallback approach when SpdxDocument is not found."""
        # Mock output_as_json to return a document without SpdxDocument
        with patch.object(spdx3_exporter, 'output_as_json') as mock_json:
            mock_json.return_value = json.dumps({
                "@context": "test-context",
                "@graph": [
                    {"type": "CreationInfo", "spdxId": "creation-id"},
                    {"type": "OtherType", "spdxId": "other-id"}
                ]
            })
            
            xml_output = spdx3_exporter.output_as_xml()
            
            # Should use fallback approach with RDF root
            root = ET.fromstring(xml_output)
            # XML namespaces can appear in the tag, so check if it contains RDF
            assert "RDF" in root.tag
            
            # Check that the SPDX namespace is defined somewhere in the XML output
            # ElementTree handles namespaces differently, so we can't use root.get() directly
            assert "xmlns:spdx=\"https://spdx.org/rdf/3.0.1/terms/\"" in xml_output


class TestSPDX3EnvironmentVariables:
    """Test SPDX3 environment variable handling."""
    
    @patch.dict(os.environ, {"DOCUMENT_URL": "https://custom-namespace.org/doc1"})
    def test_custom_document_namespace(self, spdx3_exporter):
        """Test using custom document namespace from environment variable."""
        doc = spdx3_exporter.create_document_structure()
        
        document = next(item for item in doc["@graph"] if item["type"] == "SpdxDocument")
        assert document["namespaceMap"][""] == "https://custom-namespace.org/doc1"
    
    @patch.dict(os.environ, {
        "PRODUCT_NAME": "CustomProduct", 
        "PRODUCT_VERSION": "2.0.0"
    })
    def test_custom_product_info(self, spdx3_exporter):
        """Test using custom product info from environment variables."""
        doc = spdx3_exporter.create_document_structure()
        
        document = next(item for item in doc["@graph"] if item["type"] == "SpdxDocument")
        assert document["name"] == "CustomProduct-2.0.0"
    
    @patch.dict(os.environ, {
        "PRODUCT_NAME": "CustomProduct", 
        "PRODUCT_VERSION": ""
    })
    def test_missing_product_version(self, spdx3_exporter):
        """Test handling missing product version in environment variables."""
        doc = spdx3_exporter.create_document_structure()
        
        document = next(item for item in doc["@graph"] if item["type"] == "SpdxDocument")
        # The format should be CustomProduct-<some_version>
        # We only check the CustomProduct- prefix since the default version might vary
        assert document["name"].startswith("CustomProduct-")


class TestSPDX3ComplexRelationships:
    """Test complex relationship scenarios in SPDX3 export."""
    
    def test_multiple_packages_for_vulnerability(self, spdx3_exporter):
        """Test multiple packages affected by the same vulnerability."""
        # Create packages
        pkg1 = Package("pkg1", "1.0", [], [])
        pkg2 = Package("pkg2", "1.0", [], [])
        pkg3 = Package("pkg3", "1.0", [], [])
        spdx3_exporter.packagesCtrl.add(pkg1)
        spdx3_exporter.packagesCtrl.add(pkg2)
        spdx3_exporter.packagesCtrl.add(pkg3)
        
        # Create vulnerability affecting multiple packages
        vuln = Vulnerability("CVE-2024-MULTI", ["test-scanner"], "test-datasource", "test-namespace")
        vuln.add_package(pkg1.id)
        vuln.add_package(pkg2.id)
        vuln.add_package(pkg3.id)
        spdx3_exporter.vulnerabilitiesCtrl.add(vuln)
        
        # Export and check relationships
        output = json.loads(spdx3_exporter.output_as_json())
        
        # Find relationships for this vulnerability
        vuln_ref = None
        for item in output["@graph"]:
            if item["type"] == "security_Vulnerability":
                for ext_id in item["externalIdentifier"]:
                    if ext_id["identifier"] == "CVE-2024-MULTI":
                        vuln_ref = item["spdxId"]
                        break
        
        assert vuln_ref is not None
        
        # Check relationships
        relationships = [item for item in output["@graph"] if item["type"] == "Relationship"
                        and item["relationshipType"] == "hasAssociatedVulnerability"
                        and vuln_ref in item["to"]]
        
        # Should have 3 relationships (one for each package)
        assert len(relationships) == 3
    
    def test_multiple_vulnerabilities_for_package(self, spdx3_exporter):
        """Test multiple vulnerabilities affecting the same package."""
        # Create package
        pkg = Package("multi-vuln-pkg", "1.0", [], [])
        spdx3_exporter.packagesCtrl.add(pkg)
        
        # Create multiple vulnerabilities affecting the same package
        for i in range(1, 4):
            vuln_id = f"CVE-2024-{1000+i}"
            vuln = Vulnerability(vuln_id, ["test-scanner"], "test-datasource", "test-namespace")
            vuln.add_package(pkg.id)
            spdx3_exporter.vulnerabilitiesCtrl.add(vuln)
        
        # Export and check relationships
        output = json.loads(spdx3_exporter.output_as_json())
        
        # Find package reference
        pkg_ref = None
        for item in output["@graph"]:
            if item["type"] == "software_Package" and item["name"] == "multi-vuln-pkg":
                pkg_ref = item["spdxId"]
                break
        
        assert pkg_ref is not None
        
        # Check relationships
        relationships = [item for item in output["@graph"] if item["type"] == "Relationship"
                        and item["relationshipType"] == "hasAssociatedVulnerability"
                        and item["from"] == pkg_ref]
        
        # Should have 3 relationships (one for each vulnerability)
        assert len(relationships) == 3
    
    def test_multiple_assessments_for_vulnerability(self, spdx3_exporter):
        """Test multiple assessments for the same vulnerability on different packages."""
        # Create packages
        pkg1 = Package("pkg-affected", "1.0", [], [])
        pkg2 = Package("pkg-not-affected", "2.0", [], [])
        spdx3_exporter.packagesCtrl.add(pkg1)
        spdx3_exporter.packagesCtrl.add(pkg2)
        
        # Create vulnerability
        vuln_id = "CVE-2024-MULTI-ASSESSMENT"
        vuln = Vulnerability(vuln_id, ["test-scanner"], "test-datasource", "test-namespace")
        vuln.add_package(pkg1.id)
        vuln.add_package(pkg2.id)
        spdx3_exporter.vulnerabilitiesCtrl.add(vuln)
        
        # Create different assessments for the same vulnerability
        assessment1 = VulnAssessment(vuln_id, [pkg1.id])
        assessment1.set_status("affected")
        assessment1.set_status_notes("Package is affected")
        
        assessment2 = VulnAssessment(vuln_id, [pkg2.id])
        assessment2.set_status("not_affected")
        assessment2.set_justification("vulnerable_code_not_present")
        assessment2.set_status_notes("Package is not affected")
        
        # Add assessments
        spdx3_exporter.assessmentsCtrl.add(assessment1)
        spdx3_exporter.assessmentsCtrl.add(assessment2)
        
        # Export and check VEX elements
        output = json.loads(spdx3_exporter.output_as_json())
        
        # Find VEX elements
        vex_elements = [item for item in output["@graph"] if "security_Vex" in item["type"]]
        
        # Should have 2 VEX assessments
        assert len(vex_elements) == 2
        
        # One should be affected, one not affected
        affected_vex = next(v for v in vex_elements if v["type"] == "security_VexAffectedVulnAssessmentRelationship")
        not_affected_vex = next(v for v in vex_elements if v["type"] == "security_VexNotAffectedVulnAssessmentRelationship")
        
        assert "Package is affected" in affected_vex.get("security_statusNotes", "")
        assert "Package is not affected" in not_affected_vex.get("security_statusNotes", "")


if __name__ == "__main__":
    pytest.main(["-v", "test_spdx3_edge_cases.py"])

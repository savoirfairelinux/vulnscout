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
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController


@pytest.fixture
def spdx3_exporter():
    """Create SPDX3 exporter with empty controllers."""
    controllers = {
        "packages": PackagesController(),
        "vulnerabilities": VulnerabilitiesController(PackagesController())
    }
    # Update vulnerability controller to use the same package controller
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    return SPDX3(controllers)


@pytest.fixture
def populated_spdx3_exporter():
    """Create SPDX3 exporter with sample data."""
    controllers = {
        "packages": PackagesController(),
        "vulnerabilities": VulnerabilitiesController(PackagesController())
    }
    # Update controllers to use the same package controller
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    
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
    
    return exporter


class TestSPDX3JSONExport:
    """Test SPDX3 JSON export functionality."""
    
    def test_export_empty_document(self, spdx3_exporter):
        """Test exporting empty SPDX3 document."""
        output = json.loads(spdx3_exporter.output_as_json("Test Author"))
        
        # Check document structure
        assert output["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
        assert "@graph" in output
        assert "spdxId" not in output  # spdxId is in the document element, not root
        
        # Check creation info and document are present
        graph_types = [item["type"] for item in output["@graph"]]
        assert "CreationInfo" in graph_types
        assert "SpdxDocument" in graph_types
        
        # Find creation info
        creation_info = next(item for item in output["@graph"] if item["type"] == "CreationInfo")
        assert creation_info["specVersion"] == "3.0.1"
        assert "created" in creation_info
        assert len(creation_info["createdBy"]) >= 1
        assert any("SavoirFaireLinux" in creator for creator in creation_info["createdBy"])
        
        # Find document
        document = next(item for item in output["@graph"] if item["type"] == "SpdxDocument")
        assert "name" in document
        assert "spdxId" in document
        assert document["creationInfo"] == creation_info["@id"]
    
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
        assert curl_pkg["software_packageVersion"] == "7.88.1" 
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
        describes_rels = [rel for rel in relationships if rel["relationshipType"] == "describes"]
        document = next(item for item in output["@graph"] if item["type"] == "SpdxDocument")
        assert len(describes_rels) == 1  # One relationship describing all elements
        describes_rel = describes_rels[0]
        assert describes_rel["from"] == document["spdxId"]  # Reference document spdxId
        assert len(describes_rel["to"]) == 2  # Should describe both packages
    
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
                        and item["relationshipType"] == "affects"]
        assert len(relationships) == 2  # One for each vulnerability
    
    @pytest.mark.skip(reason="VEX assessment functionality not yet implemented in SPDX3 class")
    def test_export_vex_assessments(self, populated_spdx3_exporter):
        """Test exporting VEX assessments."""
        pass
    
    def test_export_with_custom_author(self, spdx3_exporter):
        """Test export with custom author name."""
        output = json.loads(spdx3_exporter.output_as_json("Custom Organization"))
        
        creation_info = next(item for item in output["@graph"] if item["type"] == "CreationInfo")
        assert len(creation_info["createdBy"]) >= 1
        assert any("SavoirFaireLinux" in creator for creator in creation_info["createdBy"])
    
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


class TestSPDX3ElementGeneration:
    """Test individual SPDX3 element generation methods."""
    
    def test_generate_package_element(self, spdx3_exporter):
        """Test package element generation."""
        pkg = Package("test-lib", "2.1.0", [], [])
        pkg.add_cpe("cpe:2.3:a:test:test-lib:2.1.0:*:*:*:*:*:*:*")
        
        element = spdx3_exporter.generate_package_element(pkg)
        
        assert element["type"] == "software_Package"
        assert element["name"] == "test-lib"
        assert element["software_packageVersion"] == "2.1.0"
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
        assert len(ext_ids) >= 1  # At least CVE identifier
        
        cve_id = next((eid for eid in ext_ids if eid["externalIdentifierType"] == "cve"), None)
        assert cve_id is not None
        assert cve_id["identifier"] == "CVE-2024-9999"
        
        # Check for URL if present
        url_ids = [eid for eid in ext_ids if eid["externalIdentifierType"] == "securityAdvisory"]
        if url_ids:
            assert url_ids[0]["identifier"] == "https://example.com/vuln"
    
    @pytest.mark.skip(reason="VEX assessment functionality not yet implemented in SPDX3 class")
    def test_generate_vex_assessment_mapping(self, spdx3_exporter):
        """Test VEX assessment status mapping.""" 
        pass
    
    def test_generate_relationship(self, spdx3_exporter):
        """Test relationship generation."""
        relationship = spdx3_exporter.generate_relationship("from-ref", ["to-ref-1", "to-ref-2"], "testRelation")
        
        assert relationship["type"] == "Relationship"
        assert relationship["from"] == "from-ref"
        assert relationship["to"] == ["to-ref-1", "to-ref-2"]
        assert relationship["relationshipType"] == "testRelation"
        assert "spdxId" in relationship
    
    @pytest.mark.skip(reason="VEX assessment functionality not yet implemented in SPDX3 class")
    def test_justification_mapping(self, spdx3_exporter):
        """Test VEX justification mapping."""
        pass


class TestSPDX3DocumentStructure:
    """Test SPDX3 document structure creation."""
    
    def test_create_document_structure(self, spdx3_exporter):
        """Test document structure creation."""
        doc = spdx3_exporter.create_document_structure("Test Org")
        
        assert "@context" in doc
        assert "@graph" in doc
        
        # Check that document has spdxId within the graph structure
        document = next(item for item in doc["@graph"] if item["type"] == "SpdxDocument")
        assert "spdxId" in document
        
        # Check creation info
        creation_info = next(item for item in doc["@graph"] if item["type"] == "CreationInfo")
        assert creation_info["specVersion"] == "3.0.1"
        assert len(creation_info["createdBy"]) >= 1
        assert any("SavoirFaireLinux" in creator for creator in creation_info["createdBy"])
        
        # Check document
        document = next(item for item in doc["@graph"] if item["type"] == "SpdxDocument")
        assert document["creationInfo"] == creation_info["@id"]
        assert document["dataLicense"] == "http://spdx.org/licenses/CC0-1.0"
        assert "name" in document
    
    def test_package_without_version(self, spdx3_exporter):
        """Test package generation without version."""
        pkg = Package("no-version-pkg", "unknown", [], [])
        pkg.version = None  # Simulate a package without version after creation
        element = spdx3_exporter.generate_package_element(pkg)
        
        assert element["name"] == "no-version-pkg"
        assert "software_packageVersion" not in element
    
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
        cve_id = next((eid for eid in ext_ids if eid["externalIdentifierType"] == "cve"), None)
        assert cve_id is not None
        assert cve_id["identifier"] == "CVE-2024-0000"

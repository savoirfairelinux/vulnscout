# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import json
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET
from jsonschema import Draft202012Validator, FormatChecker
from src.views.spdx3 import SPDX3
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from src.controllers import ControllersCache
from src.bin.cmd_process import read_inputs
from src.extensions import db
from src.helpers.export_scope import ExportScope
from src.models.assessment import Assessment
from src.models.finding import Finding
from src.models.project import Project
from src.models.sbom_document import SBOMDocument
from src.models.scan import Scan
from src.models.variant import Variant


@pytest.fixture
def spdx3_exporter():
    """Create SPDX3 exporter with empty controllers."""
    return SPDX3(ControllersCache())


@pytest.fixture
def populated_spdx3_exporter(spdx3_exporter):
    """Create SPDX3 exporter with sample data."""
    # Add test packages
    pkg1 = Package("openssl", "3.0.0", [], [])
    pkg1.add_cpe("cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*")
    pkg1.add_purl("pkg:deb/debian/openssl@3.0.0")
    spdx3_exporter.packagesCtrl.add(pkg1)

    pkg2 = Package("nginx", "1.20.1", [], [])
    pkg2.add_cpe("cpe:2.3:a:nginx:nginx:1.20.1:*:*:*:*:*:*:*")
    spdx3_exporter.packagesCtrl.add(pkg2)

    # Add test vulnerabilities
    vuln1 = Vulnerability("CVE-2023-1234", ["test-scanner"], "test-datasource", "test-namespace")
    vuln1.add_package(pkg1.string_id)
    vuln1.add_url("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234")
    spdx3_exporter.vulnerabilitiesCtrl.add(vuln1)

    vuln2 = Vulnerability("CVE-2023-5678", ["test-scanner"], "test-datasource", "test-namespace")
    vuln2.add_package(pkg2.string_id)
    spdx3_exporter.vulnerabilitiesCtrl.add(vuln2)

    return spdx3_exporter


def test_spdx3_export_roundtrips_source_urls_without_importing_source_nodes(spdx3_exporter):
    from src.views.fast_spdx3 import FastSPDX3

    urls = [f"git+https://example.org/source-{i}.git@{str(i) * 40}" for i in (1, 2)]
    spdx3_exporter.packagesCtrl.add(Package("libc6", "2.41", source_urls=urls))
    document = json.loads(spdx3_exporter.output_as_json())
    builds = [item for item in document["@graph"] if item.get("type") == "build_Build"]
    assert len(builds) == 1
    assert builds[0]["build_buildType"]
    schema_path = Path(__file__).parents[1] / "schemas/spdx/spdx-json-schema-3.0.1.json"
    schema = json.loads(schema_path.read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
    assert sorted(item["software_downloadLocation"] for item in document["@graph"]
                  if item.get("software_primaryPurpose") == "source") == urls
    controllers = ControllersCache()
    FastSPDX3(controllers).parse_from_dict(document)
    assert len(controllers.packages) == 1
    restored = controllers.packages.get("libc6@2.41")
    assert sorted(restored.source_urls) == urls
    assert restored.version_info["revision_conflict"]


@pytest.mark.parametrize("input_status,status,vex_type,relationship_type", [
    ("not_affected", "not_affected", "NotAffected", "doesNotAffect"),
    ("affected", "affected", "Affected", "affects"),
    ("fixed", "fixed", "Fixed", "fixedIn"),
    ("under_investigation", "under_investigation", "UnderInvestigation", "underInvestigationFor"),
    ("exploitable", "affected", "Affected", "affects"),
    ("false_positive", "not_affected", "NotAffected", "doesNotAffect"),
])
def test_assessments_roundtrip_to_another_variant(tmp_path, input_status, status, vex_type, relationship_type):
    project = Project.create("roundtrip")
    source = Variant.create("source", project.id)
    destination = Variant.create("destination", project.id)
    packages = [Package.create(name, "1.0") for name in ("first", "second")]
    Vulnerability.get_or_create("CVE-2026-1234")
    timestamp = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
    for package in packages:
        finding = Finding.get_or_create(package.id, "CVE-2026-1234")
        Assessment.create(
            targets=[(source.id, finding.id)], origin="custom", status="fixed",
            timestamp=datetime(2026, 11, 11, tzinfo=timezone.utc),
        )
        Assessment.create(
            targets=[(source.id, finding.id)], origin="custom", status=input_status,
            justification="vulnerable_code_not_present" if status == "not_affected" else "",
            impact_statement="Disabled in this build" if status == "not_affected" else "Impact reviewed",
            workaround="Upgrade this package" if status == "affected" else "",
            status_notes="Reviewed against the shipped configuration", timestamp=timestamp,
        )
        Assessment.create(
            targets=[(source.id, finding.id)], origin="ai", status="not_affected",
            timestamp=datetime(2026, 11, 13, tzinfo=timezone.utc),
        )
    scope = ExportScope(package_ids={p.id for p in packages}, variant_ids={source.id})
    export_controllers = ControllersCache(scope=scope)
    export_controllers.packages._preload_cache()
    document = json.loads(SPDX3(export_controllers).output_as_json())
    schema_path = Path(__file__).parents[1] / "schemas/spdx/spdx-json-schema-3.0.1.json"
    Draft202012Validator(json.loads(schema_path.read_text()), format_checker=FormatChecker()).validate(document)
    relationships = [item for item in document["@graph"] if item.get("type", "").startswith("security_Vex")]
    assert len(relationships) == 2
    assert {rel["type"] for rel in relationships} == {f"security_Vex{vex_type}VulnAssessmentRelationship"}
    assert {rel["relationshipType"] for rel in relationships} == {relationship_type}
    assert all("CVE-" not in rel["from"] for rel in relationships)
    assert not any(item["type"] == "Relationship" and item["relationshipType"] == "affects"
                   for item in document["@graph"])

    sbom_path = tmp_path / "export.spdx.json"
    sbom_path.write_text(json.dumps(document))
    scan = Scan.create("reimport", destination.id, scan_type="sbom")
    SBOMDocument.create(str(sbom_path), sbom_path.name, scan.id, format="spdx")
    controllers = ControllersCache()
    controllers.assessments.current_variant_id = destination.id
    read_inputs(controllers, scan_id=scan.id)
    read_inputs(controllers, scan_id=scan.id)
    db.session.commit()
    db.session.expire_all()
    for package in packages:
        finding = Finding.get_by_package_and_vulnerability(package.string_id, "CVE-2026-1234")
        restored, = Assessment.get_by_finding_and_variant(finding.id, destination.id)
        assert restored.status == status
        assert restored.origin == "sbom"
        assert restored.status_notes == "Reviewed against the shipped configuration"
        assert restored.timestamp.replace(tzinfo=timezone.utc) == timestamp
        assert restored.impact_statement == ("Disabled in this build" if status == "not_affected" else "Impact reviewed")
        if status == "not_affected":
            assert restored.justification == "vulnerable_code_not_present"
            assert restored.impact_statement == "Disabled in this build"
        elif status == "affected":
            assert restored.workaround == "Upgrade this package"
        assert len(Assessment.get_by_finding_and_variant(finding.id, source.id)) == 3
    restored_vulnerability = controllers.vulnerabilities.get("CVE-2026-1234")
    assert set(restored_vulnerability.packages) == {p.string_id for p in packages}


def test_assessment_export_filters_exact_variant_package_targets():
    project = Project.create("scope")
    source = Variant.create("source", project.id)
    outside = Variant.create("outside", project.id)
    packages = [Package.create(name, "1.0") for name in ("first", "second", "third")]
    Vulnerability.get_or_create("CVE-2026-1234")
    findings = [Finding.get_or_create(p.id, "CVE-2026-1234") for p in packages]
    Assessment.create(
        targets=[(source.id, findings[0].id), (outside.id, findings[1].id)],
        origin="custom", status="not_affected", justification="component_not_present",
    )
    Assessment.create(targets=[(source.id, findings[1].id)], origin="custom", status="affected")
    Assessment.create(targets=[(outside.id, findings[2].id)], origin="custom", status="fixed")
    scope = ExportScope(package_ids={p.id for p in packages}, variant_ids={source.id})
    export_controllers = ControllersCache(scope=scope)
    export_controllers.packages._preload_cache()
    document = json.loads(SPDX3(export_controllers).output_as_json())
    package_names = {item["spdxId"]: item["name"] for item in document["@graph"]
                     if item["type"] == "software_Package"}
    relationships = [item for item in document["@graph"] if item.get("type", "").startswith("security_Vex")]
    assert {(package_names[rel["to"][0]], rel["relationshipType"]) for rel in relationships} == {
        ("first", "doesNotAffect"), ("second", "affects"),
    }


@pytest.mark.parametrize("scoped", [True, False], ids=["project", "global"])
@pytest.mark.parametrize("first_status,second_status,expected_status,expected_relationship", [
    ("affected", "not_affected", "affected", "affects"),
    ("under_investigation", "fixed", "under_investigation", "underInvestigationFor"),
    ("fixed", "not_affected", "under_investigation", "underInvestigationFor"),
    ("not_affected", "not_affected", "not_affected", "doesNotAffect"),
])
def test_consolidated_export_uses_current_variant_verdicts_conservatively(
    scoped, first_status, second_status, expected_status, expected_relationship,
):
    from src.views.fast_spdx3 import FastSPDX3

    project = Project.create("consolidated")
    first = Variant.create("first", project.id)
    second = Variant.create("second", project.id)
    destination = Variant.create("destination", project.id)
    package = Package.create("shared", "1.0")
    Vulnerability.get_or_create("CVE-2026-1234")
    finding = Finding.get_or_create(package.id, "CVE-2026-1234")
    Assessment.create(
        targets=[(first.id, finding.id), (second.id, finding.id)], origin="custom", status="affected",
        timestamp=datetime(2026, 11, 10, tzinfo=timezone.utc),
    )
    for variant, status, day in ((first, first_status, 11), (second, second_status, 12)):
        Assessment.create(
            targets=[(variant.id, finding.id)], origin="custom", status=status,
            justification="vulnerable_code_not_present" if status == "not_affected" else "",
            status_notes=f"Reviewed {variant.name}", workaround="Apply the patch" if status == "affected" else "",
            impact_statement=f"Reason from {variant.name}",
            timestamp=datetime(2026, 11, day, tzinfo=timezone.utc),
        )
    original_statuses = {str(assessment.id): assessment.status for assessment in Assessment.get_all()}
    scope = ExportScope(package_ids={package.id}, variant_ids={first.id, second.id}) if scoped else None
    controllers = ControllersCache(scope=scope)
    controllers.packages._preload_cache()
    document = json.loads(SPDX3(controllers).output_as_json())
    schema_path = Path(__file__).parents[1] / "schemas/spdx/spdx-json-schema-3.0.1.json"
    Draft202012Validator(json.loads(schema_path.read_text()), format_checker=FormatChecker()).validate(document)
    relationship, = [item for item in document["@graph"] if item.get("type", "").startswith("security_Vex")]
    assert relationship["relationshipType"] == expected_relationship
    if first_status != second_status:
        assert "Consolidated" in relationship["security_statusNotes"]
        assert first_status in relationship["security_statusNotes"]
        assert second_status in relationship["security_statusNotes"]
    if expected_status not in {first_status, second_status}:
        assert "description" not in relationship
        assert "security_impactStatement" not in relationship
        assert "security_justificationType" not in relationship
        assert "security_actionStatement" not in relationship
    elif first_status != second_status:
        assert relationship["description"] == "Reason from first"
    assert {str(assessment.id): assessment.status for assessment in Assessment.get_all()} == original_statuses

    controllers = ControllersCache()
    controllers.assessments.current_variant_id = destination.id
    FastSPDX3(controllers).parse_from_dict(document)
    db.session.commit()
    db.session.expire_all()
    restored, = Assessment.get_by_finding_and_variant(finding.id, destination.id)
    assert restored.status == expected_status
    for variant, status in ((first, first_status), (second, second_status)):
        controllers = ControllersCache(scope=ExportScope(package_ids={package.id}, variant_ids={variant.id}))
        controllers.packages._preload_cache()
        document = json.loads(SPDX3(controllers).output_as_json())
        relationship, = [item for item in document["@graph"] if item.get("type", "").startswith("security_Vex")]
        parser = FastSPDX3(ControllersCache())
        parser.merge_components_into_controller(document)
        parser.merge_vulnerabilities_into_controller(document)
        assert parser._parse_vex_relationship(relationship).status == status


def test_ingestion_export_replaces_the_current_variants_old_verdict():
    project = Project.create("ingestion")
    variant = Variant.create("current", project.id)
    package = Package.create("shared", "1.0")
    Vulnerability.get_or_create("CVE-2026-1234")
    finding = Finding.get_or_create(package.id, "CVE-2026-1234")
    Assessment.create(
        targets=[(variant.id, finding.id)], origin="sbom", status="affected",
        timestamp=datetime(2026, 11, 10, tzinfo=timezone.utc),
    )
    controllers = ControllersCache()
    controllers.assessments.current_variant_id = variant.id
    current = Assessment.new_dto("CVE-2026-1234", [package.string_id])
    current.set_status("fixed")
    current.timestamp = datetime(2026, 11, 12, tzinfo=timezone.utc)
    controllers.assessments.add(current)

    document = json.loads(SPDX3(controllers).output_as_json())
    relationship, = [item for item in document["@graph"] if item.get("type", "").startswith("security_Vex")]
    assert relationship["relationshipType"] == "fixedIn"


def test_description_and_reasoning_roundtrip_to_a_fresh_database(tmp_path):
    description = "A bounds check is missing.\nUntrusted input can reach the vulnerable parser."
    notes = "Reviewed the shipped configuration.\nThe optional parser is disabled."
    reasoning = "The vulnerable code is not compiled:\n- CONFIG_OPTIONAL_PARSER is unset."
    project = Project.create("source")
    source = Variant.create("source", project.id)
    package = Package.create("parser", "1.0")
    Vulnerability.create_record("CVE-2026-1234", description=description)
    finding = Finding.get_or_create(package.id, "CVE-2026-1234")
    Assessment.create(
        targets=[(source.id, finding.id)], origin="custom", status="not_affected",
        justification="vulnerable_code_not_present", impact_statement=reasoning, status_notes=notes,
    )
    scope = ExportScope(package_ids={package.id}, variant_ids={source.id})
    controllers = ControllersCache(scope=scope)
    controllers.packages._preload_cache()
    sbom_path = tmp_path / "export.spdx.json"
    sbom_path.write_text(SPDX3(controllers).output_as_json())
    schema_path = Path(__file__).parents[1] / "schemas/spdx/spdx-json-schema-3.0.1.json"
    Draft202012Validator(json.loads(schema_path.read_text()), format_checker=FormatChecker()).validate(
        json.loads(sbom_path.read_text())
    )

    db.session.remove()
    db.drop_all()
    db.create_all()
    project = Project.create("destination")
    destination = Variant.create("destination", project.id)
    scan = Scan.create("reimport", destination.id, scan_type="sbom")
    SBOMDocument.create(str(sbom_path), sbom_path.name, scan.id, format="spdx")
    controllers = ControllersCache()
    controllers.assessments.current_variant_id = destination.id
    read_inputs(controllers, scan_id=scan.id)
    db.session.expire_all()

    restored_vulnerability = Vulnerability.get_by_id("CVE-2026-1234")
    assert restored_vulnerability.description == description
    finding = Finding.get_by_package_and_vulnerability("parser@1.0", "CVE-2026-1234")
    assessment, = Assessment.get_by_finding_and_variant(finding.id, destination.id)
    assert assessment.status == "not_affected"
    assert assessment.justification == "vulnerable_code_not_present"
    assert assessment.status_notes == notes
    assert assessment.impact_statement == reasoning


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
        purl_ids = [eid for eid in ext_ids if eid["externalIdentifierType"] == "packageUrl"]
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
        url_ids = [eid for eid in ext_ids if eid["externalIdentifierType"] == "securityOther"]
        if url_ids:
            assert url_ids[0]["identifier"] == "https://example.com/vuln"

    def test_generate_relationship(self, spdx3_exporter):
        """Test relationship generation."""
        relationship = spdx3_exporter.generate_relationship("from-ref", ["to-ref-1", "to-ref-2"], "testRelation")

        assert relationship["type"] == "Relationship"
        assert relationship["from"] == "from-ref"
        assert relationship["to"] == ["to-ref-1", "to-ref-2"]
        assert relationship["relationshipType"] == "testRelation"
        assert "spdxId" in relationship


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

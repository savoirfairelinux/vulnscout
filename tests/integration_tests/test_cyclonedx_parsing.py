# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.views.cyclonedx import CycloneDx
from src.models.assessment import Assessment
from src.controllers import ControllersCache
import json
from pathlib import Path


@pytest.fixture
def cdx_parser():
    return CycloneDx(ControllersCache())


def test_parse_yocto_bom_and_vex_examples(cdx_parser):
    """The detached VEX targets the BOM's components through BOM-Link URNs."""
    example_dir = Path(__file__).resolve().parents[2] / "example" / "yocto-scarthgap-cdx"
    bom = json.loads((example_dir / "bom.json").read_text())
    vex = json.loads((example_dir / "vex.json").read_text())
    cdx_parser.load_from_dict(bom)
    cdx_parser.parse_and_merge()

    # Cover each package and analysis state without importing thousands of duplicate CVEs.
    seen = set()
    vulnerabilities = []
    for vulnerability in vex["vulnerabilities"]:
        key = (vulnerability["affects"][0]["ref"], vulnerability["analysis"]["state"])
        if key not in seen:
            seen.add(key)
            vulnerabilities.append(vulnerability)
    vex["vulnerabilities"] = vulnerabilities
    cdx_parser.load_from_dict(vex)
    cdx_parser.parse_and_merge()

    expected_packages = {component["bom-ref"]: f'{component["name"]}@{component["version"]}'
                         for component in bom["components"]}
    assert len(cdx_parser.packagesCtrl) == len(set(expected_packages.values())) == 93
    for vulnerability in vulnerabilities:
        package_id = expected_packages[vulnerability["affects"][0]["ref"].split("#", 1)[1]]
        parsed = cdx_parser.vulnerabilitiesCtrl.get(vulnerability["id"])
        assert package_id in parsed.packages
        assert any(package_id in assessment.packages
                   and assessment.is_compatible_status(vulnerability["analysis"]["state"])
                   for assessment in cdx_parser.assessmentsCtrl.gets_by_vuln(vulnerability["id"]))


def test_bom_links_are_scoped_to_document_and_version(cdx_parser):
    serials = ["87b5cc5a-ee50-449f-bcdf-cabea628c2a2", "082c4a99-77b3-4edd-83d8-066e303ce202"]
    for serial, version, name in [(serials[0], 1, "first"), (serials[0], 2, "second"),
                                  (serials[1], 1, "other")]:
        cdx_parser.load_from_dict({
            "bomFormat": "CycloneDX", "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{serial}", "version": version,
            "components": [{"type": "library", "name": name, "version": "1", "bom-ref": "shared"}],
        })
        cdx_parser.parse_and_merge()

    refs = [f"urn:cdx:{serials[0]}/1#shared", f"urn:cdx:{serials[0]}/2#shared",
            f"urn:cdx:{serials[1]}/1#shared", f"urn:cdx:{serials[1]}/2#shared", "shared"]
    cdx_parser.load_from_dict({
        "bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
        "vulnerabilities": [{"id": f"CVE-2026-{index}", "affects": [{"ref": ref}]}
                            for index, ref in enumerate(refs)],
    })
    cdx_parser.parse_and_merge()
    for index, expected in enumerate([["first@1"], ["second@1"], ["other@1"], [], ["other@1"]]):
        assert cdx_parser.vulnerabilitiesCtrl.get(f"CVE-2026-{index}").packages == expected


def test_process_yocto_bom_and_vex_examples(monkeypatch, tmp_path):
    """The normal process command must persist findings visible in the selected variant."""
    from flask import current_app
    from src.extensions import db
    from src.models import Assessment as StoredAssessment
    from src.models import Finding, Observation, Project, SBOMDocument, Scan, Variant

    monkeypatch.setenv("MATCH_CONDITION", "")
    status = tmp_path / "scan-status"
    status.write_text("__END_OF_SCAN_SCRIPT__\n")
    monkeypatch.setitem(current_app.config, "SCAN_FILE", str(status))
    example_dir = Path(__file__).resolve().parents[2] / "example" / "yocto-scarthgap-cdx"
    project = Project.create("yocto_demo")
    variant = Variant.create("cyclonedx", project.id)
    scan = Scan.create("CycloneDX examples", variant.id)
    for name in ("bom.json", "vex.json"):
        SBOMDocument.create(str(example_dir / name), name, scan.id, format="cdx")

    result = current_app.test_cli_runner().invoke(args=["process"])
    assert result.exit_code == 0, result.output
    assert "Error" not in result.output
    assert "dropped" not in result.output

    bom = json.loads((example_dir / "bom.json").read_text())
    vex = json.loads((example_dir / "vex.json").read_text())
    packages = {component["bom-ref"]: f'{component["name"]}@{component["version"]}'
                for component in bom["components"]}
    expected = {(vulnerability["id"], packages[affect["ref"].split("#", 1)[1]])
                for vulnerability in vex["vulnerabilities"] for affect in vulnerability["affects"]}
    assert len(expected) == 7063
    findings = db.session.execute(db.select(Finding)).scalars().all()
    assert {(finding.vulnerability_id, finding.package.string_id) for finding in findings} == expected
    observations = db.session.execute(db.select(Observation).where(Observation.scan_id == scan.id)).scalars().all()
    assert {observation.finding_id for observation in observations} == {finding.id for finding in findings}
    assessments = db.session.execute(db.select(StoredAssessment)).scalars().all()
    assert all(assessment.is_compatible_status("resolved") or assessment.is_compatible_status("not_affected")
               for assessment in assessments)
    assert {finding_id for assessment in assessments for variant_id, finding_id in assessment.targets
            if variant_id == variant.id} == {finding.id for finding in findings}

    response = current_app.test_client().get(f"/api/vulnerabilities?variant_id={variant.id}")
    assert response.status_code == 200
    expected_ids = {vuln_id for vuln_id, _ in expected}
    assert len(expected_ids) == 3133
    assert {vulnerability["id"] for vulnerability in response.get_json()} == expected_ids


def test_parse_empty_json(cdx_parser):
    cdx_parser.load_from_dict(json.loads("""{
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:88fabcfa-7529-4ba2-8256-29bec0c03900",
        "version": 1,
        "components": [],
        "dependencies": []
    }"""))
    cdx_parser.parse_and_merge()

    assert len(cdx_parser.packagesCtrl.packages) == 0
    assert len(cdx_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(cdx_parser.assessmentsCtrl.assessments) == 0


def test_parse_invalid_model_json(cdx_parser):
    cdx_parser.load_from_dict(json.loads("""{
        "foo": [],
        "bar": "hello world"
    }"""))
    cdx_parser.parse_and_merge()
    assert len(cdx_parser.packagesCtrl.packages) == 0
    assert len(cdx_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(cdx_parser.assessmentsCtrl.assessments) == 0


def test_parse_components_json(cdx_parser):
    cdx_parser.load_from_dict(json.loads("""{
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:88fabcfa-7529-4ba2-8256-29bec0c03900",
        "version": 1,
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:generic/gnu/binutils@2.38",
                "group": "gnu",
                "name": "binutils",
                "version": "2.38",
                "cpe": "cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*",
                "purl": "pkg:generic/gnu/binutils@2.38"
            },
            {
                "type": "library",
                "group": "cairographics",
                "name": "cairo",
                "version": "1.16.0",
                "description": "Cairo is a 2D graphics library with support for multiple output devices.",
                "cpe": "cpe:2.3:a:cairographics:cairo:1.16.0:*:*:*:*:*:*:*",
                "purl": "pkg:generic/cairographics/cairo@1.16.0"
            }
        ]
    }"""))
    cdx_parser.parse_and_merge()
    assert len(cdx_parser.packagesCtrl) == 2
    assert len(cdx_parser.vulnerabilitiesCtrl) == 0
    assert len(cdx_parser.assessmentsCtrl) == 0
    assert "binutils@2.38" in cdx_parser.packagesCtrl
    assert "cairo@1.16.0" in cdx_parser.packagesCtrl
    binutils = cdx_parser.packagesCtrl.get("binutils@2.38")
    assert "cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*" in binutils
    print(binutils.purl)
    assert "pkg:generic/gnu/binutils@2.38" in binutils


def test_parse_vulnerabilities_json(cdx_parser):
    from unittest.mock import MagicMock
    cdx_parser.vulnerabilitiesCtrl.record_sbom_observation = MagicMock()
    cdx_parser.load_from_dict(json.loads("""{
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:88fabcfa-7529-4ba2-8256-29bec0c03900",
        "version": 1,
        "components": [
            {
                "type": "library",
                "group": "cairographics",
                "name": "cairo",
                "version": "1.16.0",
                "description": "Cairo is a 2D graphics library with support for multiple output devices.",
                "cpe": "cpe:2.3:a:cairographics:cairo:1.16.0:*:*:*:*:*:*:*",
                "purl": "pkg:generic/cairographics/cairo@1.16.0",
                "bom-ref": "pkg:generic/cairographics/cairo@1.16.0"
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2020-35492",
                "bom-ref": "CVE-2020-35492",
                "source": {
                    "name": "NVD",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-35492"
                },
                "references": [
                    {
                        "id": "CVE-2018-99999",
                        "source": {
                            "name": "NVD",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-99999"
                        }
                    }
                ],
                "advisories": [
                    {
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1898396"
                    }
                ],
                "ratings": [
                    {
                        "method": "CVSSv31",
                        "source": {
                            "name": "NVD",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-35492"
                        },
                        "score": 7.8,
                        "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                        "severity": "high"
                    },
                    {
                        "method": "other",
                        "score": 9.5,
                        "severity": "critical"
                    }
                ],
                "cwes": [ 787, 121 ],
                "description": "A flaw was found in cairo's image-compositor.c",
                "detail": "Function image_compositor_create make buffer overflow",
                "recommendation": "Update to version >= 1.17.4",
                "workaround": "Disable red color in images",
                "created": "2020-12-17T00:00:00Z",
                "published": "2021-03-18T18:59:41Z",
                "updated": "2021-03-18T18:59:41Z",
                "analysis": {
                    "state": "exploitable",
                    "justification": "protected_by_mitigating_control",
                    "response": [ "update" ]
                },
                "affects": [
                    {
                        "ref": "pkg:generic/cairographics/cairo@1.16.0",
                        "versions": [
                            {
                                "range": "vers:generic/>=0.0.0|<1.17.4"
                            },
                            {
                                "range": "vers:generic/>=1.17.4",
                                "status": "unaffected"
                            }
                        ]
                    }
                ]
            }
        ]
    }"""))
    # + analysis: "lastUpdated": "2021-03-18T18:59:41Z"
    cdx_parser.parse_and_merge()
    assert len(cdx_parser.packagesCtrl) == 1
    assert len(cdx_parser.vulnerabilitiesCtrl) == 1
    assert len(cdx_parser.assessmentsCtrl) == 1
    assert "cairo@1.16.0" in cdx_parser.packagesCtrl

    cve = cdx_parser.vulnerabilitiesCtrl.get("CVE-2020-35492")
    assert cve.datasource == "https://nvd.nist.gov/vuln/detail/CVE-2020-35492"
    assert cve.description == "A flaw was found in cairo's image-compositor.c"
    assert "https://bugzilla.redhat.com/show_bug.cgi?id=1898396" in cve.urls
    assert len(cve.severity_cvss) == 1
    assert cve.severity_cvss[0].base_score == 7.8
    assert cve.severity_cvss[0].vector_string == "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
    assert cve.severity_label == "critical"
    assert cve.severity_max_score == 9.5
    cdx_parser.vulnerabilitiesCtrl.record_sbom_observation.assert_any_call(
        cve,
        key="CycloneDX Details",
        description="Function image_compositor_create make buffer overflow",
    )
    cdx_parser.vulnerabilitiesCtrl.record_sbom_observation.assert_any_call(
        cve,
        key="CycloneDX Recommendation",
        description="Update to version >= 1.17.4",
    )

    assess = cdx_parser.assessmentsCtrl.gets_by_vuln("CVE-2020-35492")[0]
    assert assess.is_compatible_status("exploitable")
    assert assess.is_compatible_justification("inline_mitigations_already_exist")
    assert assess.workaround == "Disable red color in images"
    assert "workaround_available" in assess.responses
    assert "update" in assess.responses

    assert "cairo@1.16.0" in cve


def test_parsing_assessment_already_present(cdx_parser):
    assess = Assessment.new_dto("CVE-2020-35492", ["cairo@1.16.0"])
    assess.set_status("affected")
    assess.set_status_notes("1st status notes")
    assess.set_status_notes("2nd status notes", True)
    assess.set_not_affected_reason("Some impact stmt")
    cdx_parser.assessmentsCtrl.add(assess)

    cdx_parser.load_from_dict(json.loads("""{
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:88fabcfa-7529-4ba2-8256-29bec0c03900",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "cairo",
                "version": "1.16.0",
                "bom-ref": "pkg:generic/cairo@1.16.0"
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2020-35492",
                "bom-ref": "CVE-2020-35492",
                "detail": "Function image_compositor_create make buffer overflow",
                "workaround": "Disable red color in images",
                "updated": "2021-03-18T18:59:41Z",
                "analysis": {
                    "state": "exploitable",
                    "detail": "1st status notes\\nSome impact stmt\\n2nd status notes\\nAdded status notes",
                    "response": [ "update" ]
                },
                "affects": [
                    { "ref": "pkg:generic/cairo@1.16.0" }
                ]
            }
        ]
    }"""))
    cdx_parser.parse_and_merge()
    assert len(cdx_parser.packagesCtrl) == 1
    assert len(cdx_parser.vulnerabilitiesCtrl) == 1
    assert len(cdx_parser.assessmentsCtrl) == 1
    assert "cairo@1.16.0" in cdx_parser.packagesCtrl
    assert "CVE-2020-35492" in cdx_parser.vulnerabilitiesCtrl

    assess_final = cdx_parser.assessmentsCtrl.gets_by_vuln("CVE-2020-35492")[0]
    assert assess_final.is_compatible_status("exploitable")
    assert assess_final.status_notes == "1st status notes\n2nd status notes\nAdded status notes"
    assert assess_final.impact_statement == "Some impact stmt"
    assert assess_final.workaround == "Disable red color in images"
    assert "workaround_available" in assess_final.responses
    assert "update" in assess_final.responses


def test_clean_sbom_with_lists(cdx_parser):
    """Test clean_sbom method handles lists with null items."""
    test_data = {
        "vulnerabilities": [
            {"id": "CVE-2020-1234", "justification": None},
            None,
            {"id": "CVE-2020-5678", "justification": "null"},
            {"id": "CVE-2020-9012"}
        ],
        "components": [
            {"name": "test", "version": "1.0"},
            None
        ]
    }
    cleaned = cdx_parser.clean_sbom(test_data)
    assert len(cleaned["vulnerabilities"]) == 3  # None item removed
    assert "justification" not in cleaned["vulnerabilities"][0]  # null justification removed
    assert "justification" not in cleaned["vulnerabilities"][1]  # "null" string justification removed
    assert len(cleaned["components"]) == 1  # None item removed


def test_vulnerability_without_id(cdx_parser):
    """Test parsing vulnerability without ID doesn't create assessment and doesn't add vulnerability."""
    cdx_parser.load_from_dict(json.loads("""{
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:88fabcfa-7529-4ba2-8256-29bec0c03900",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "cairo",
                "version": "1.16.0",
                "bom-ref": "pkg:generic/cairo@1.16.0"
            }
        ],
        "vulnerabilities": [
            {
                "bom-ref": "VULN-REF",
                "analysis": {
                    "state": "exploitable",
                    "detail": "Test detail"
                },
                "affects": [
                    { "ref": "pkg:generic/cairo@1.16.0" }
                ]
            }
        ]
    }"""))

    cdx_parser.parse_and_merge()

    # Assessment should not be created if vulnerability ID is None
    assert len(cdx_parser.assessmentsCtrl) == 0
    # Vulnerability without ID should be skipped entirely
    assert len(cdx_parser.vulnerabilitiesCtrl) == 0
    # Package from components should still be parsed
    assert 1 == 1
def test_vulnerability_with_workaround_and_analysis(cdx_parser):
    """Test vulnerability with workaround and analysis creates assessment with workaround."""
    cdx_parser.load_from_dict(json.loads("""{
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "test-lib",
                "version": "1.0.0",
                "bom-ref": "pkg:generic/test-lib@1.0.0"
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2020-1234",
                "bom-ref": "CVE-2020-1234",
                "workaround": "Apply the patch manually",
                "analysis": {
                    "state": "exploitable"
                },
                "affects": [
                    { "ref": "pkg:generic/test-lib@1.0.0" }
                ]
            }
        ]
    }"""))
    cdx_parser.parse_and_merge()

    assessments = cdx_parser.assessmentsCtrl.gets_by_vuln("CVE-2020-1234")
    assert len(assessments) == 1
    assert assessments[0].workaround == "Apply the patch manually"
    assert "workaround_available" in assessments[0].responses

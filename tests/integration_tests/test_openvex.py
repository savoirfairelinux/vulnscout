# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.views.openvex import OpenVex
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from src.models.assessment import Assessment
from src.controllers import ControllersCache
import json


@pytest.fixture
def openvex_parser():
    return OpenVex(ControllersCache())


@pytest.fixture
def pkg_ABC():
    return Package("abc", "1.2.3", ["cpe:2.3:a:abc:abc:1.2.3:*:*:*:*:*:*:*"], ["pkg:generic/abc@1.2.3"])


@pytest.fixture
def vuln_123():
    vuln = Vulnerability("CVE-1234-000", ["scanner"], "https://nvd.nist.gov/vuln/detail/CVE-1234-000", "unknown")
    vuln.add_package("abc@1.2.3")
    vuln.description = "A flaw was found in abc's image-compositor.c (...)"
    vuln.add_alias("CVE-1234-999")
    return vuln


@pytest.fixture
def assesment_123(pkg_ABC, vuln_123):
    assess = Assessment.new_dto(vuln_123.id, [pkg_ABC])
    assess.set_status("in_triage")
    return assess


def test_parse_empty_json(openvex_parser):
    openvex_parser.load_from_dict(json.loads("""{
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
        "author": "Savoir-faire Linux",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": 1,
        "statements": []
    }"""))
    assert len(openvex_parser.packagesCtrl.packages) == 0
    assert len(openvex_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(openvex_parser.assessmentsCtrl.assessments) == 0


def test_parse_invalid_model_json(openvex_parser):
    openvex_parser.load_from_dict(json.loads("""{
        "foo": [],
        "bar": { },
        "statements": [{}]
    }"""))
    assert len(openvex_parser.packagesCtrl.packages) == 0
    assert len(openvex_parser.vulnerabilitiesCtrl.vulnerabilities) == 0
    assert len(openvex_parser.assessmentsCtrl.assessments) == 0


def test_parse_statements(openvex_parser):
    openvex_parser.load_from_dict(json.loads("""{
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
        "author": "Savoir-faire Linux",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": 1,
        "statements": [
            {
                "vulnerability": {
                    "name": "CVE-2020-35492"
                },
                "products": [
                    {
                        "@id": "pkg:generic/cairo@1.16.0",
                        "identifiers": {
                            "cpe23": "cpe:2.3:a:cairographics:cairo:1.16.0:*:*:*:*:*:*:*",
                            "purl": "pkg:generic/cairo@1.16.0"
                        }
                    }
                ],
                "status": "affected"
            },
            {
                "vulnerability": {
                    "@id": "https://nvd.nist.gov/vuln/detail/CVE-2020-35492",
                    "name": "CVE-2020-35492",
                    "description": "A flaw was found in cairo's image-compositor.c (...)",
                    "aliases": ["CVE-1234-00000"]
                },
                "products": [
                    {
                        "@id": "pkg:generic/binutils@2.38",
                        "identifiers": {
                            "purl": "pkg:generic/binutils@2.38"
                        }
                    }
                ],
                "status": "affected"
            },
            {
                "vulnerability": {
                    "name": "CVE-2020-35492"
                },
                "products": [
                    {
                        "@id": "abc@1.2.3"
                    }
                ],
                "status": "affected"
            }
        ]
    }"""))
    assert len(openvex_parser.packagesCtrl.packages) == 3
    assert "cairo@1.16.0" in openvex_parser.packagesCtrl
    assert "binutils@2.38" in openvex_parser.packagesCtrl
    assert "abc@1.2.3" in openvex_parser.packagesCtrl

    assert len(openvex_parser.vulnerabilitiesCtrl.vulnerabilities) == 1
    vuln = openvex_parser.vulnerabilitiesCtrl.get("CVE-2020-35492")
    assert vuln is not None
    assert vuln.description == "A flaw was found in cairo's image-compositor.c (...)"
    assert len(vuln.aliases) == 1

    assert len(openvex_parser.assessmentsCtrl.assessments) == 3


def test_parse_statement_details(openvex_parser):
    openvex_parser.load_from_dict(json.loads("""{
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
        "author": "Savoir-faire Linux",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": 1,
        "statements": [
            {
                "vulnerability": {
                    "@id": "https://nvd.nist.gov/vuln/detail/CVE-2020-35492",
                    "name": "CVE-2020-35492",
                    "description": "A flaw was found in cairo's image-compositor.c (...)",
                    "aliases": ["CVE-1234-00000"]
                },
                "products": [
                    { "@id": "binutils@2.38" }
                ],
                "status": "not_affected",
                "justification": "inline_mitigations_already_exist",
                "impact_statement": "Color red was removed from image before being sent to cairo",
                "action_statement": "Use product version 7.10+",
                "action_statement_timestamp": "2023-01-08T18:02:03.647787998-06:00",
                "status_notes": "This vulnerability was mitigated by the use of a color filter in image-pipeline.c",
                "timestamp": "2023-01-06T15:05:42.647787998Z",
                "last_updated": "2023-01-08T18:02:03.647787998Z",

                "scanners": ["some_scanner"]
            }
        ]
    }"""))
    assert len(openvex_parser.packagesCtrl.packages) == 1
    assert len(openvex_parser.vulnerabilitiesCtrl.vulnerabilities) == 1
    vuln = openvex_parser.vulnerabilitiesCtrl.get("CVE-2020-35492")
    assert vuln.found_by == ["openvex"]
    assert len(openvex_parser.assessmentsCtrl.assessments) == 1
    assess = openvex_parser.assessmentsCtrl.gets_by_vuln("CVE-2020-35492")[0]
    assert assess.status == "not_affected"
    assert assess.justification == "inline_mitigations_already_exist"
    assert assess.impact_statement == "Color red was removed from image before being sent to cairo"
    assert assess.workaround == "Use product version 7.10+"
    assert assess.status_notes == "This vulnerability was mitigated by the use of a color filter in image-pipeline.c"
    assert assess.timestamp == "2023-01-06T15:05:42.647787998Z"

def test_parse_statement_details_not_openvex_source(openvex_parser):
    openvex_parser.load_from_dict(json.loads("""{
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
        "author": "Savoir-faire Linux",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": 1,
        "statements": [
            {
                "vulnerability": {
                    "@id": "https://nvd.nist.gov/vuln/detail/CVE-2020-35492",
                    "name": "CVE-2020-35492",
                    "description": "A flaw was found in cairo's image-compositor.c (...)",
                    "aliases": ["CVE-1234-00000"]
                },
                "products": [
                    { "@id": "binutils@2.38" }
                ],
                "status": "not_affected",
                "justification": "inline_mitigations_already_exist",
                "impact_statement": "Color red was removed from image before being sent to cairo",
                "action_statement": "Use product version 7.10+",
                "action_statement_timestamp": "2023-01-08T18:02:03.647787998-06:00",
                "status_notes": "This vulnerability was mitigated by the use of a color filter in image-pipeline.c",
                "timestamp": "2023-01-06T15:05:42.647787998Z",
                "last_updated": "2023-01-08T18:02:03.647787998Z",

                "scanners": ["some_scanner"]
            }
        ]
    }"""), found_by=["test"])
    assert len(openvex_parser.packagesCtrl.packages) == 1
    assert len(openvex_parser.vulnerabilitiesCtrl.vulnerabilities) == 1
    vuln = openvex_parser.vulnerabilitiesCtrl.get("CVE-2020-35492")
    assert vuln.found_by == ["test", "some_scanner"]
    assert len(openvex_parser.assessmentsCtrl.assessments) == 1
    assess = openvex_parser.assessmentsCtrl.gets_by_vuln("CVE-2020-35492")[0]
    assert assess.status == "not_affected"
    assert assess.justification == "inline_mitigations_already_exist"
    assert assess.impact_statement == "Color red was removed from image before being sent to cairo"
    assert assess.workaround == "Use product version 7.10+"
    assert assess.status_notes == "This vulnerability was mitigated by the use of a color filter in image-pipeline.c"
    assert assess.timestamp == "2023-01-06T15:05:42.647787998Z"

def test_encode_empty(openvex_parser):
    output = openvex_parser.to_dict(False, "MY_AUTHOR_NAME")
    assert {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "author": "MY_AUTHOR_NAME",
        "version": 1,
        "statements": []
    }.items() <= output.items()
    assert len(output["@id"]) >= 5
    assert len(output["timestamp"]) >= 5
    assert len(output["statements"]) == 0


def test_encode_with_data(openvex_parser, pkg_ABC, vuln_123, assesment_123):
    openvex_parser.packagesCtrl.add(pkg_ABC)
    openvex_parser.vulnerabilitiesCtrl.add(vuln_123)
    openvex_parser.assessmentsCtrl.add(assesment_123)
    output = openvex_parser.to_dict()
    assert len(output["statements"]) == 1
    statement = output["statements"][0]
    assert {
        "name": "CVE-1234-000",
        "description": "A flaw was found in abc's image-compositor.c (...)",
        "aliases": ["CVE-1234-999"],
        "@id": "https://nvd.nist.gov/vuln/detail/CVE-1234-000"
    }.items() <= statement["vulnerability"].items()
    assert len(statement["products"]) == 1
    assert {
        "@id": "pkg:generic/abc@1.2.3",
        "identifiers": {
            "cpe23": "cpe:2.3:a:abc:abc:1.2.3:*:*:*:*:*:*:*",
            "purl": "pkg:generic/abc@1.2.3"
        }
    }.items() <= statement["products"][0].items()
    assert statement["status"] == "under_investigation"


def test_encode_detailled_assessment(openvex_parser, assesment_123):
    assesment_123.set_status("not_affected")
    assesment_123.set_status_notes("This vulnerability is mitigated by the use of a color filter in image-pipeline.c")
    assesment_123.set_justification("protected_at_runtime")
    assesment_123.set_not_affected_reason("Color red was removed from image before being sent to cairo")
    assesment_123.set_workaround("Use product version 7.10+", "2023-01-08T18:02:03.647787998-06:00")
    openvex_parser.assessmentsCtrl.add(assesment_123)
    output = openvex_parser.to_dict()
    assert len(output["statements"]) == 1
    statement = output["statements"][0]
    assert {
        "status": "not_affected",
        "status_notes": "This vulnerability is mitigated by the use of a color filter in image-pipeline.c",
        "justification": "inline_mitigations_already_exist",
        "impact_statement": "Color red was removed from image before being sent to cairo",
    }.items() <= statement.items()
    assert "action_statement" not in statement


def test_load_from_dict_pkg_none_is_skipped(openvex_parser):
    """parse_package_section returns None for unrecognised products → continue (line 75)."""
    openvex_parser.load_from_dict({
        "statements": [
            {
                "vulnerability": {"name": "CVE-9999-PKGSKIP"},
                "products": [
                    # No identifiers, no '@id' with name@version pattern
                    {"@id": "http://example.com/some-product-without-version"}
                ],
                "status": "affected"
            }
        ]
    })
    # Vuln is added but assessment has no packages because pkg was None
    vuln = openvex_parser.vulnerabilitiesCtrl.get("CVE-9999-PKGSKIP")
    assert vuln is not None
    # No packages linked to the assessment
    assessments = list(openvex_parser.assessmentsCtrl.assessments.values())
    pkgs_across = [p for a in assessments if a.vuln_id == "CVE-9999-PKGSKIP" for p in a.packages]
    assert pkgs_across == []


def test_load_from_dict_no_status_skips_assessment(openvex_parser):
    """Statement without 'status' adds vuln but not assessment (line 83 continue)."""
    openvex_parser.load_from_dict({
        "statements": [
            {
                "vulnerability": {"name": "CVE-9999-NOSTATUS"},
                "products": [],
            }
        ]
    })
    vuln = openvex_parser.vulnerabilitiesCtrl.get("CVE-9999-NOSTATUS")
    assert vuln is not None
    assessments = [a for a in openvex_parser.assessmentsCtrl.assessments.values()
                   if a.vuln_id == "CVE-9999-NOSTATUS"]
    assert assessments == []


def test_all_assessments_db_exception(openvex_parser, assesment_123, vuln_123):
    """_all_assessments() silently catches DB exception (lines 107-108)."""
    from unittest.mock import patch as mock_patch
    openvex_parser.assessmentsCtrl.add(assesment_123)
    with mock_patch("src.views.openvex.Assessment.get_all", side_effect=RuntimeError("db fail")):
        result = openvex_parser._all_assessments()
    # In-memory assessment still returned
    assert any(str(a.id) == str(assesment_123.id) for a in result)


def test_to_dict_stmt_none_is_skipped(openvex_parser, pkg_ABC, vuln_123):
    """to_dict() skips assessment when to_openvex_dict() returns None (line 124)."""
    # A not_affected status without justification or impact_statement causes to_openvex_dict → None
    assess = Assessment.new_dto(vuln_123.id, [pkg_ABC.string_id])
    assess.set_status("not_affected")
    # No justification and no impact_statement → to_openvex_dict returns None
    openvex_parser.assessmentsCtrl.add(assess)
    output = openvex_parser.to_dict()
    assert len(output["statements"]) == 0


def test_to_dict_vuln_non_http_datasource_no_id(openvex_parser, pkg_ABC):
    """to_dict() skips '@id' on vuln when datasource does not start with http (line 129 skipped)."""
    vuln = Vulnerability("CVE-9999-NODS", ["scanner"], "NVD", "unknown")
    vuln.add_package(pkg_ABC)
    assess = Assessment.new_dto(vuln.id, [pkg_ABC.string_id])
    assess.set_status("affected")
    openvex_parser.vulnerabilitiesCtrl.add(vuln)
    openvex_parser.assessmentsCtrl.add(assess)
    output = openvex_parser.to_dict()
    for stmt in output["statements"]:
        v = stmt.get("vulnerability", {})
        if v.get("name") == "CVE-9999-NODS":
            assert "@id" not in v
            break


# ---------------------------------------------------------------------------
# to_dict() with a genuine multi-target assessment (DB-backed)
# ---------------------------------------------------------------------------

def _make_variant(project_id, name):
    from src.models.variant import Variant
    return Variant.create(f"openvex-multitarget-var-{name}", project_id)


def _make_finding(vuln_id, pkg_name):
    from src.models.package import Package as DBPackage
    from src.models.vulnerability import Vulnerability as DBVulnerability
    from src.models.finding import Finding
    pkg = DBPackage.find_or_create(pkg_name, "1.0")
    DBVulnerability.get_or_create(vuln_id)
    return Finding.get_or_create(pkg.id, vuln_id)


def test_to_dict_multi_target_assessment_emits_non_empty_products():
    """A genuine multi-target assessment (NULL scalar variant_id/finding_id)
    must not export a statement with empty ``products`` — its packages come
    from ``target_rows`` via ``Assessment.packages``'s fallback."""
    from src.models.project import Project
    from src.models.assessment import Assessment as DBAssessment

    project = Project.create("openvex-multitarget-proj")
    variant = _make_variant(project.id, "a")
    openssl = _make_finding("CVE-2026-7000", "openssl")
    zlib = _make_finding("CVE-2026-7000", "zlib")
    DBAssessment.create(
        status="not_affected", origin="custom",
        justification="vulnerable_code_not_present",
        targets=[(variant.id, openssl.id), (variant.id, zlib.id)],
        commit=True,
    )

    opvx = OpenVex(ControllersCache())
    doc = opvx.to_dict()

    stmts = [s for s in doc["statements"] if s["vulnerability"]["name"] == "CVE-2026-7000"]
    assert len(stmts) == 1
    product_ids = {p["@id"] for p in stmts[0]["products"]}
    assert product_ids == {"pkg:generic/openssl@1.0", "pkg:generic/zlib@1.0"}


def test_to_dict_scoped_export_does_not_leak_out_of_scope_package():
    """Scoping the export to one variant must not disclose a sibling
    variant's package from the same multi-target assessment."""
    from src.models.project import Project
    from src.models.assessment import Assessment as DBAssessment
    from src.helpers.export_scope import compute_export_scope

    project = Project.create("openvex-multitarget-scope-proj")
    variant_a = _make_variant(project.id, "scope-a")
    variant_b = _make_variant(project.id, "scope-b")
    openssl = _make_finding("CVE-2026-7001", "openssl")
    zlib = _make_finding("CVE-2026-7001", "zlib")
    DBAssessment.create(
        status="not_affected", origin="custom",
        justification="vulnerable_code_not_present",
        targets=[(variant_a.id, openssl.id), (variant_b.id, zlib.id)],
        commit=True,
    )

    scope = compute_export_scope(variant_id=variant_a.id)
    opvx = OpenVex(ControllersCache(scope=scope))
    doc = opvx.to_dict()

    stmts = [s for s in doc["statements"] if s["vulnerability"]["name"] == "CVE-2026-7001"]
    assert len(stmts) == 1
    product_ids = {p["@id"] for p in stmts[0]["products"]}
    assert product_ids == {"openssl@1.0"}
    assert "zlib@1.0" not in product_ids

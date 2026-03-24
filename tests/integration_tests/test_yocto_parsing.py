# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.views.yocto_vulns import YoctoVulns
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController
import json


@pytest.fixture
def yocto_parser():
    controllers = {}
    controllers["packages"] = PackagesController()
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    controllers["assessments"] = AssessmentsController(controllers["packages"], controllers["vulnerabilities"])
    return YoctoVulns(controllers)


def test_parse_empty_json(yocto_parser):
    yocto_parser.load_from_dict(json.loads("""{
        "version": "1",
        "package": []
    }"""))
    assert len(yocto_parser.packagesCtrl) == 0
    assert len(yocto_parser.vulnerabilitiesCtrl) == 0
    assert len(yocto_parser.assessmentsCtrl) == 0


def test_parse_invalid_model_json(yocto_parser):
    yocto_parser.load_from_dict(json.loads("""{
        "foo": [],
        "bar": { }
    }"""))
    assert len(yocto_parser.packagesCtrl) == 0
    assert len(yocto_parser.vulnerabilitiesCtrl) == 0
    assert len(yocto_parser.assessmentsCtrl) == 0


def test_parse_package_empty_json(yocto_parser):
    yocto_parser.load_from_dict(json.loads("""{
        "version": "1",
        "package": [
            {
                "name": "c-ares",
                "layer": "meta-oe",
                "version": "1.18.1",
                "products": [
                    {
                        "product": "c-ares",
                        "cvesInRecord": "No"
                    }
                ],
                "issue": []
            },
            {
                "foo": "bar"
            }
        ]
    }"""))
    assert len(yocto_parser.packagesCtrl) == 1
    assert len(yocto_parser.vulnerabilitiesCtrl) == 0
    assert len(yocto_parser.assessmentsCtrl) == 0
    assert "c-ares@1.18.1" in yocto_parser.packagesCtrl


def test_parse_package_vulnerabilities_json(yocto_parser):
    # Include two times the same package and include 3 vulnerabilities with one repeated two times
    # This is for testing deduplication work well
    yocto_parser.load_from_dict(json.loads("""{
        "version": "1",
        "package": [
            {
                "name": "c-ares",
                "layer": "meta-oe",
                "version": "1.18.1",
                "products": [
                    {
                        "product": "c-ares",
                        "cvesInRecord": "Yes"
                    }
                ],
                "issue": [
                    {
                        "id": "CVE-2007-3152",
                        "summary": "c-ares before 1.4.0 uses a predictable seed for the \
random number generator for the DNS Transaction ID field, which might allow remote attackers \
to spoof DNS responses by guessing the field value.",
                        "scorev2": "7.5",
                        "scorev3": "0.0",
                        "vector": "NETWORK",
                        "status": "Patched",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2007-3152"
                    },
                    {
                        "id": "CVE-2016-5180",
                        "summary": "Heap-based buffer overflow in the ares_create_query function \
in c-ares 1.x before 1.12.0 allows remote attackers to cause a denial of service \
(out-of-bounds write) or possibly execute arbitrary code via a hostname with an escaped trailing dot.",
                        "scorev2": "7.5",
                        "scorev3": "9.8",
                        "vector": "NETWORK",
                        "status": "Unpatched",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2016-5180"
                    }
                ]
            },
            {
                "name": "c-ares",
                "layer": "meta-oe",
                "version": "1.18.1",
                "products": [
                    {
                        "product": "c-ares",
                        "cvesInRecord": "Yes"
                    }
                ],
                "issue": [
                    {
                        "id": "CVE-2023-31124",
                        "summary": "c-ares is an asynchronous resolver library. When cross-compiling c-ares \
and using the autotools build system, CARES_RANDOM_FILE will not be set, as seen when cross compiling \
aarch64 android. This will downgrade to using rand() as a fallback which could allow an attacker to take \
advantage of the lack of entropy by not using a CSPRNG. This issue was patched in version 1.19.1.",
                        "scorev2": "0.0",
                        "scorev3": "3.7",
                        "vector": "LOCAL",
                        "status": "Ignored",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-31124"
                    },
                    {
                        "id": "CVE-2016-5180",
                        "summary": "Heap-based buffer overflow in the ares_create_query function \
in c-ares 1.x before 1.12.0 allows remote attackers to cause a denial of service \
(out-of-bounds write) or possibly execute arbitrary code via a hostname with an escaped trailing dot.",
                        "scorev2": "7.5",
                        "scorev3": "9.8",
                        "vector": "NETWORK",
                        "status": "Unpatched",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2016-5180"
                    }
                ]
            }
        ]
    }"""))
    assert len(yocto_parser.packagesCtrl) == 1
    assert len(yocto_parser.vulnerabilitiesCtrl) == 3
    assert len(yocto_parser.assessmentsCtrl) == 3
    assert "CVE-2007-3152" in yocto_parser.vulnerabilitiesCtrl
    assert "CVE-2016-5180" in yocto_parser.vulnerabilitiesCtrl
    assert "CVE-2023-31124" in yocto_parser.vulnerabilitiesCtrl

    cve_2007 = yocto_parser.vulnerabilitiesCtrl.get("CVE-2007-3152")
    cve_2016 = yocto_parser.vulnerabilitiesCtrl.get("CVE-2016-5180")
    cve_2023 = yocto_parser.vulnerabilitiesCtrl.get("CVE-2023-31124")
    assert len(cve_2007.severity_cvss) == 1
    assert cve_2007.severity_label == "high"
    assert len(cve_2016.severity_cvss) == 2
    assert cve_2016.severity_label == "critical"
    assert len(cve_2023.severity_cvss) == 1
    assert cve_2023.severity_label == "low"

    assessment_1 = yocto_parser.assessmentsCtrl.gets_by_vuln("CVE-2007-3152")[0]
    assessment_2 = yocto_parser.assessmentsCtrl.gets_by_vuln("CVE-2016-5180")[0]
    assessment_3 = yocto_parser.assessmentsCtrl.gets_by_vuln("CVE-2023-31124")[0]
    assert assessment_1.is_compatible_status("fixed")
    assert assessment_2.is_compatible_status("under_investigation")
    assert assessment_3.is_compatible_status("not_affected")


# ---------------------------------------------------------------------------
# Deduplication tests (found_corresponding_assessment logic)
# ---------------------------------------------------------------------------

SINGLE_PKG_PATCHED = json.loads("""{
    "version": "1",
    "package": [{
        "name": "c-ares", "version": "1.18.1",
        "issue": [{
            "id": "CVE-2007-3152",
            "status": "Patched",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2007-3152"
        }]
    }]
}""")

SINGLE_PKG_IGNORED = json.loads("""{
    "version": "1",
    "package": [{
        "name": "c-ares", "version": "1.18.1",
        "issue": [{
            "id": "CVE-2023-31124",
            "status": "Ignored",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-31124"
        }]
    }]
}""")

SINGLE_PKG_UNPATCHED = json.loads("""{
    "version": "1",
    "package": [{
        "name": "c-ares", "version": "1.18.1",
        "issue": [{
            "id": "CVE-2016-5180",
            "status": "Unpatched",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2016-5180"
        }]
    }]
}""")


def test_duplicate_patched_assessment_not_duplicated(yocto_parser):
    """Loading the same Patched issue twice must not create duplicate assessments."""
    yocto_parser.load_from_dict(SINGLE_PKG_PATCHED)
    yocto_parser.load_from_dict(SINGLE_PKG_PATCHED)

    assert len(yocto_parser.assessmentsCtrl) == 1
    assessment = yocto_parser.assessmentsCtrl.gets_by_vuln("CVE-2007-3152")[0]
    assert assessment.is_compatible_status("fixed")
    assert "Yocto reported vulnerability as Patched" in assessment.impact_statement


def test_duplicate_ignored_assessment_not_duplicated(yocto_parser):
    """Loading the same Ignored issue twice must not create duplicate assessments."""
    yocto_parser.load_from_dict(SINGLE_PKG_IGNORED)
    yocto_parser.load_from_dict(SINGLE_PKG_IGNORED)

    assert len(yocto_parser.assessmentsCtrl) == 1
    assessment = yocto_parser.assessmentsCtrl.gets_by_vuln("CVE-2023-31124")[0]
    assert assessment.is_compatible_status("not_affected")
    assert assessment.justification == "vulnerable_code_not_present"
    assert "Yocto reported vulnerability as Ignored" in assessment.impact_statement


def test_duplicate_unpatched_assessment_not_duplicated(yocto_parser):
    """Loading the same Unpatched issue twice must not create duplicate assessments."""
    yocto_parser.load_from_dict(SINGLE_PKG_UNPATCHED)
    yocto_parser.load_from_dict(SINGLE_PKG_UNPATCHED)

    assert len(yocto_parser.assessmentsCtrl) == 1
    assessment = yocto_parser.assessmentsCtrl.gets_by_vuln("CVE-2016-5180")[0]
    assert assessment.is_compatible_status("under_investigation")


# ---------------------------------------------------------------------------
# skip_patched (CVE_CHECK_EXCLUDE_PATCHED=true) branch tests
# ---------------------------------------------------------------------------

def test_skip_patched_no_prior_assessment_removes_vuln(yocto_parser, monkeypatch):
    """
    When CVE_CHECK_EXCLUDE_PATCHED=true and there is no prior assessment for a Patched
    vulnerability, the vulnerability must be removed entirely (no other scanner set it).
    """
    monkeypatch.setenv("CVE_CHECK_EXCLUDE_PATCHED", "true")
    yocto_parser.load_from_dict(SINGLE_PKG_PATCHED)

    assert len(yocto_parser.vulnerabilitiesCtrl) == 0
    assert len(yocto_parser.assessmentsCtrl) == 0


def test_skip_patched_prior_non_fixed_assessment_adds_fixed(yocto_parser, monkeypatch):
    """
    When CVE_CHECK_EXCLUDE_PATCHED=true and a prior non-fixed assessment exists, a new
    'fixed' assessment must be added to record the Yocto Patched status.
    """
    # First load: same vuln as Unpatched → creates an under_investigation assessment
    yocto_parser.load_from_dict(SINGLE_PKG_UNPATCHED)
    assert len(yocto_parser.assessmentsCtrl) == 1

    monkeypatch.setenv("CVE_CHECK_EXCLUDE_PATCHED", "true")
    # Second load: same vuln, now Patched + skip_patched active.
    # The prior assessment is under_investigation (not fixed), so a fixed one should be added.
    data_patched_same_vuln = json.loads("""{
        "version": "1",
        "package": [{
            "name": "c-ares", "version": "1.18.1",
            "issue": [{
                "id": "CVE-2016-5180",
                "status": "Patched",
                "link": "https://nvd.nist.gov/vuln/detail/CVE-2016-5180"
            }]
        }]
    }""")
    yocto_parser.load_from_dict(data_patched_same_vuln)

    # Vuln must still exist (was not removed because there was a prior assessment)
    assert "CVE-2016-5180" in yocto_parser.vulnerabilitiesCtrl
    assessments = yocto_parser.assessmentsCtrl.gets_by_vuln("CVE-2016-5180")
    assert len(assessments) == 2
    statuses = [a.get_status_openvex() for a in assessments]
    assert "fixed" in statuses
    assert "under_investigation" in statuses


def test_skip_patched_prior_fixed_assessment_skips(yocto_parser, monkeypatch):
    """
    When CVE_CHECK_EXCLUDE_PATCHED=true and the latest assessment is already 'fixed'
    (but not stamped by Yocto, so deduplication doesn't catch it), no new assessment
    must be created.
    """
    from src.models.assessment import Assessment
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability

    # Manually seed package, vulnerability and a 'fixed' assessment from another source
    pkg = Package("c-ares", "1.18.1", [], [])
    pkg.generate_generic_purl()
    yocto_parser.packagesCtrl.add(pkg)

    vuln = Vulnerability("CVE-2007-3152", ["other-scanner"], "", "unknown")
    vuln.add_package(pkg.string_id)
    vuln = yocto_parser.vulnerabilitiesCtrl.add(vuln)

    prior_assessment = Assessment.new_dto(vuln.id, [pkg.string_id])
    prior_assessment.set_status("fixed")
    prior_assessment.set_not_affected_reason("Fixed by upstream patch")
    yocto_parser.assessmentsCtrl.add(prior_assessment)

    assert len(yocto_parser.assessmentsCtrl) == 1

    monkeypatch.setenv("CVE_CHECK_EXCLUDE_PATCHED", "true")
    yocto_parser.load_from_dict(SINGLE_PKG_PATCHED)

    # Still only one assessment — the skip branch was taken
    assert len(yocto_parser.assessmentsCtrl) == 1
    assert yocto_parser.assessmentsCtrl.gets_by_vuln("CVE-2007-3152")[0].impact_statement == "Fixed by upstream patch"


# ---------------------------------------------------------------------------
# get_last_assessment branch coverage
# ---------------------------------------------------------------------------

def test_get_last_assessment_none_timestamp(yocto_parser):
    """_ts_key returns datetime.min when assessment timestamp is None (line 29)."""
    from src.models.assessment import Assessment
    a1 = Assessment.new_dto("CVE-MOCK-1", ["pkg@1.0"])
    a1.timestamp = None
    a2 = Assessment.new_dto("CVE-MOCK-1", ["pkg@1.0"])
    a2.timestamp = "2025-01-01T00:00:00"

    result = yocto_parser.get_last_assessment([a1, a2])
    assert result is a2  # a2 has a real timestamp, wins


def test_get_last_assessment_str_timestamp(yocto_parser):
    """_ts_key handles ISO string timestamps (lines 31-32)."""
    from src.models.assessment import Assessment
    a1 = Assessment.new_dto("CVE-MOCK-2", ["pkg@1.0"])
    a1.timestamp = "2023-06-01T00:00:00"
    a2 = Assessment.new_dto("CVE-MOCK-2", ["pkg@1.0"])
    a2.timestamp = "2024-06-01T00:00:00"

    result = yocto_parser.get_last_assessment([a1, a2])
    assert result is a2


def test_get_last_assessment_invalid_str_timestamp(yocto_parser):
    """_ts_key returns datetime.min for unparseable string timestamps (lines 33-34)."""
    from src.models.assessment import Assessment
    a1 = Assessment.new_dto("CVE-MOCK-3", ["pkg@1.0"])
    a1.timestamp = "INVALID_DATE"
    a2 = Assessment.new_dto("CVE-MOCK-3", ["pkg@1.0"])
    a2.timestamp = "2022-01-01T00:00:00"

    result = yocto_parser.get_last_assessment([a1, a2])
    assert result is a2  # a1 gets datetime.min, a2 wins


def test_get_last_assessment_naive_datetime(yocto_parser):
    """_ts_key adds UTC tzinfo to naive datetime (line 36)."""
    from src.models.assessment import Assessment
    from datetime import datetime
    a1 = Assessment.new_dto("CVE-MOCK-4", ["pkg@1.0"])
    a1.timestamp = datetime(2021, 1, 1, 0, 0, 0)  # naive datetime
    a2 = Assessment.new_dto("CVE-MOCK-4", ["pkg@1.0"])
    a2.timestamp = datetime(2022, 1, 1, 0, 0, 0)  # naive datetime

    result = yocto_parser.get_last_assessment([a1, a2])
    assert result is a2


def test_load_from_dict_issue_with_description(yocto_parser):
    """load_from_dict adds 'description' text when present in issue (line 75)."""
    data = {
        "version": "1",
        "package": [{
            "name": "desc-pkg",
            "version": "1.0",
            "issue": [{
                "id": "CVE-DESC-1",
                "status": "Unpatched",
                "description": "This is a detailed description.",
                "summary": "A short summary."
            }]
        }]
    }
    yocto_parser.load_from_dict(data)
    vuln = yocto_parser.vulnerabilitiesCtrl.get("CVE-DESC-1")
    assert vuln is not None
    # description text should have been added
    assert any("detailed description" in (t or "") for t in vuln.texts.values())


def test_load_from_dict_issue_without_status(yocto_parser):
    """load_from_dict skips assessment creation when 'status' is absent (line 102)."""
    data = {
        "version": "1",
        "package": [{
            "name": "nostatus-pkg",
            "version": "1.0",
            "issue": [{
                "id": "CVE-NOSTATUS-1",
                # no "status" key
                "summary": "Some vulnerability without a status."
            }]
        }]
    }
    yocto_parser.load_from_dict(data)
    # Vulnerability is created
    assert "CVE-NOSTATUS-1" in yocto_parser.vulnerabilitiesCtrl
    # But no assessment since status was absent
    assert len(yocto_parser.assessmentsCtrl) == 0


def test_yocto_summary_stored_as_description(yocto_parser):
    """
    GIVEN a Yocto issue that has a 'summary' field
    WHEN the JSON is parsed
    THEN the summary text should be stored under the 'description' key,
         not under 'summary'
    """
    data = {
        "version": "1",
        "package": [{
            "name": "libfoo",
            "version": "1.0",
            "issue": [{
                "id": "CVE-2024-SUMMARY",
                "status": "Unpatched",
                "summary": "This is the vulnerability summary text.",
                "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-SUMMARY"
            }]
        }]
    }
    yocto_parser.load_from_dict(data)
    vuln = yocto_parser.vulnerabilitiesCtrl.get("CVE-2024-SUMMARY")
    assert vuln is not None
    assert "description" in vuln.texts
    assert vuln.texts["description"] == "This is the vulnerability summary text."
    assert "summary" not in vuln.texts

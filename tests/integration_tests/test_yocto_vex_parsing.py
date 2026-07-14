# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import pytest

from src.views.yocto_vex import YoctoVex
from src.controllers import ControllersCache


@pytest.fixture
def yocto_vex_parser():
    controllers = ControllersCache()
    return YoctoVex(controllers)


@pytest.fixture
def yocto_vex_parser_with_scan():
    """Like yocto_vex_parser but with an active SBOMDocument so observations can be stored."""
    from src.models import Project, Variant, Scan, SBOMDocument
    project = Project.create("TestProject")
    variant = Variant.create("TestVariant", project.id)
    scan = Scan.create("test-scan", variant.id, scan_type="sbom")
    doc = SBOMDocument.create("/vex.json", "vex.json", scan.id, format="yocto_vex")

    controllers = ControllersCache()
    controllers.packages.current_sbom_document = doc
    return YoctoVex(controllers)


_BASE_PKG = {
    "name": "openssl",
    "version": "3.0.2",
    "layer": "meta",
    "cpes": ["cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"],
    "products": [{"product": "openssl", "cvesInRecord": "Yes"}],
}


def test_empty_input(yocto_vex_parser):
    yocto_vex_parser.load_from_dict({"version": "1", "package": []})
    assert len(yocto_vex_parser.packagesCtrl) == 0
    assert len(yocto_vex_parser.vulnerabilitiesCtrl) == 0


def test_missing_name_or_version_skipped(yocto_vex_parser):
    yocto_vex_parser.load_from_dict({"package": [{"name": "x"}, {"version": "1.0"}]})
    assert len(yocto_vex_parser.packagesCtrl) == 0


def test_package_cpes_stored(yocto_vex_parser):
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": []}]})
    pkgs = yocto_vex_parser.packagesCtrl.to_dict()
    assert "openssl@3.0.2::meta" in pkgs
    pkg = pkgs["openssl@3.0.2::meta"]
    assert any("openssl:openssl:3.0.2" in c for c in pkg.get("cpe", []))


def test_package_derived_cpe_from_products(yocto_vex_parser):
    """Products list generates extra derived CPEs."""
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": []}]})
    pkgs = yocto_vex_parser.packagesCtrl.to_dict()
    pkg = pkgs["openssl@3.0.2::meta"]
    # Derived CPE from products[0].product / version
    assert any("cpe:2.3:a:*:openssl:3.0.2" in c for c in pkg.get("cpe", []))


def test_layer_stored_as_supplier(yocto_vex_parser):
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": []}]})
    pkgs = yocto_vex_parser.packagesCtrl.to_dict()
    pkg = pkgs["openssl@3.0.2::meta"]
    assert pkg.get("supplier") == "meta"


def test_patch_file_stored_as_advisory(yocto_vex_parser):
    issue = {
        "id": "CVE-2022-0778",
        "status": "Patched",
        "patch-file": "/patches/CVE-2022-0778.patch",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    vulns = yocto_vex_parser.vulnerabilitiesCtrl.to_dict()
    assert "CVE-2022-0778" in vulns
    advisories = vulns["CVE-2022-0778"].get("advisories", [])
    assert any("/patches/CVE-2022-0778.patch" in (u or "") for u in advisories)


def test_detail_stored_in_status_notes(yocto_vex_parser):
    issue = {
        "id": "CVE-2022-0778",
        "status": "Patched",
        "detail": "fixed-version: Fixed in 3.0.3",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    assessments = yocto_vex_parser.assessmentsCtrl.to_dict()
    found = [a for a in assessments.values() if "CVE-2022-0778" in a.get("vuln_id", "")]
    assert found, "Expected an assessment for CVE-2022-0778"
    assert found[0].get("status_notes") == "fixed-version: Fixed in 3.0.3"


def test_cvss_v3_registered(yocto_vex_parser):
    issue = {
        "id": "CVE-2022-0778",
        "status": "Unpatched",
        "scorev3": "7.5",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    vulns = yocto_vex_parser.vulnerabilitiesCtrl.to_dict()
    vuln = vulns["CVE-2022-0778"]
    severity = vuln.get("severity", {})
    assert severity.get("max_score") == 7.5 or severity.get("min_score") == 7.5


def test_patched_status_creates_fixed_assessment(yocto_vex_parser):
    issue = {
        "id": "CVE-2022-0778",
        "status": "Patched",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    assessments = yocto_vex_parser.assessmentsCtrl.to_dict()
    found = [
        a for a in assessments.values()
        if "CVE-2022-0778" in a.get("vuln_id", "")
    ]
    assert found
    assert found[0]["status"] in ("fixed", "resolved")


def test_ignored_status_creates_not_affected_assessment(yocto_vex_parser):
    issue = {
        "id": "CVE-2021-0001",
        "status": "Ignored",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-0001",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    assessments = yocto_vex_parser.assessmentsCtrl.to_dict()
    found = [a for a in assessments.values() if "CVE-2021-0001" in a.get("vuln_id", "")]
    assert found
    assert found[0]["status"] == "not_affected"


def test_unpatched_status_creates_under_investigation_assessment(yocto_vex_parser):
    issue = {
        "id": "CVE-2021-0002",
        "status": "Unpatched",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-0002",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    assessments = yocto_vex_parser.assessmentsCtrl.to_dict()
    found = [a for a in assessments.values() if "CVE-2021-0002" in a.get("vuln_id", "")]
    assert found
    assert found[0]["status"] == "under_investigation"


def test_vex_description_recorded_as_sbom_observation(yocto_vex_parser_with_scan):
    issue = {
        "id": "CVE-2022-0778",
        "status": "Patched",
        "description": "Yocto VEX justification text",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    }
    yocto_vex_parser_with_scan.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    from src.models import SBOMObservation
    observations = SBOMObservation.get_by_vuln("CVE-2022-0778")
    assert any(
        o.key == "Yocto VEX Description" and o.description == "Yocto VEX justification text"
        for o in observations
    )


def test_no_duplicate_assessment_on_reparse(yocto_vex_parser):
    """Parsing the same Patched issue twice must not create duplicate assessments."""
    issue = {
        "id": "CVE-2022-0778",
        "status": "Patched",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    }
    data = {"package": [{**_BASE_PKG, "issue": [issue]}]}
    yocto_vex_parser.load_from_dict(data)
    yocto_vex_parser.load_from_dict(data)
    assessments = [
        a for a in yocto_vex_parser.assessmentsCtrl.to_dict().values()
        if "CVE-2022-0778" in a.get("vuln_id", "")
    ]
    assert len(assessments) == 1


def test_invalid_cvss_score_ignored(yocto_vex_parser):
    """A non-numeric score string must be parsed to None and skipped."""
    issue = {
        "id": "CVE-2022-0778",
        "status": "Unpatched",
        "scorev3": "not-a-number",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    vulns = yocto_vex_parser.vulnerabilitiesCtrl.to_dict()
    assert "CVE-2022-0778" in vulns
    severity = vulns["CVE-2022-0778"].get("severity", {})
    # No valid score was registered.
    assert severity.get("max_score") in (None, 0, 0.0)


def test_cvss_v4_registered(yocto_vex_parser):
    issue = {
        "id": "CVE-2024-9999",
        "status": "Unpatched",
        "scorev4": "9.8",
        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    vuln = yocto_vex_parser.vulnerabilitiesCtrl.to_dict()["CVE-2024-9999"]
    severity = vuln.get("severity", {})
    assert severity.get("max_score") == 9.8 or severity.get("min_score") == 9.8


def test_cvss_v2_registered(yocto_vex_parser):
    """A v2 score with a non-CVSS vector string keeps the vector."""
    issue = {
        "id": "CVE-2010-1234",
        "status": "Unpatched",
        "scorev2": "5.0",
        "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2010-1234",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    vuln = yocto_vex_parser.vulnerabilitiesCtrl.to_dict()["CVE-2010-1234"]
    severity = vuln.get("severity", {})
    assert severity.get("max_score") == 5.0 or severity.get("min_score") == 5.0


def test_vector_token_stored(yocto_vex_parser):
    """The short attack-vector token is read without error."""
    issue = {
        "id": "CVE-2022-0778",
        "status": "Unpatched",
        "vector": "AV:N",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    assert "CVE-2022-0778" in yocto_vex_parser.vulnerabilitiesCtrl.to_dict()


def test_issue_without_status_creates_no_assessment(yocto_vex_parser):
    issue = {
        "id": "CVE-2022-0778",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    assert "CVE-2022-0778" in yocto_vex_parser.vulnerabilitiesCtrl.to_dict()
    assessments = [
        a for a in yocto_vex_parser.assessmentsCtrl.to_dict().values()
        if "CVE-2022-0778" in a.get("vuln_id", "")
    ]
    assert assessments == []


def test_no_duplicate_assessment_on_reparse_ignored(yocto_vex_parser):
    issue = {
        "id": "CVE-2021-0001",
        "status": "Ignored",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-0001",
    }
    data = {"package": [{**_BASE_PKG, "issue": [issue]}]}
    yocto_vex_parser.load_from_dict(data)
    yocto_vex_parser.load_from_dict(data)
    assessments = [
        a for a in yocto_vex_parser.assessmentsCtrl.to_dict().values()
        if "CVE-2021-0001" in a.get("vuln_id", "")
    ]
    assert len(assessments) == 1


def test_no_duplicate_assessment_on_reparse_unpatched(yocto_vex_parser):
    issue = {
        "id": "CVE-2021-0002",
        "status": "Unpatched",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-0002",
    }
    data = {"package": [{**_BASE_PKG, "issue": [issue]}]}
    yocto_vex_parser.load_from_dict(data)
    yocto_vex_parser.load_from_dict(data)
    assessments = [
        a for a in yocto_vex_parser.assessmentsCtrl.to_dict().values()
        if "CVE-2021-0002" in a.get("vuln_id", "")
    ]
    assert len(assessments) == 1


def test_ignored_status_with_detail_reason(yocto_vex_parser):
    issue = {
        "id": "CVE-2021-0001",
        "status": "Ignored",
        "detail": "ignored: not applicable to this configuration",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-0001",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    found = [
        a for a in yocto_vex_parser.assessmentsCtrl.to_dict().values()
        if "CVE-2021-0001" in a.get("vuln_id", "")
    ]
    assert found
    assert found[0]["status"] == "not_affected"
    assert "ignored: not applicable to this configuration" in (found[0].get("impact_statement") or "")


def test_unpatched_status_with_detail_reason(yocto_vex_parser):
    issue = {
        "id": "CVE-2021-0002",
        "status": "Unpatched",
        "detail": "investigation pending upstream",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-0002",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    found = [
        a for a in yocto_vex_parser.assessmentsCtrl.to_dict().values()
        if "CVE-2021-0002" in a.get("vuln_id", "")
    ]
    assert found
    assert found[0]["status"] == "under_investigation"
    assert "investigation pending upstream" in (found[0].get("impact_statement") or "")


def test_skip_patched_no_prior_assessment_removes_vuln(yocto_vex_parser, monkeypatch):
    """With CVE_CHECK_EXCLUDE_PATCHED set, a Patched CVE with no prior
    assessment is dropped entirely."""
    monkeypatch.setenv("CVE_CHECK_EXCLUDE_PATCHED", "1")
    issue = {
        "id": "CVE-2022-0778",
        "status": "Patched",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    }
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [issue]}]})
    # The vulnerability is dropped from the in-memory store.
    assert "CVE-2022-0778" not in yocto_vex_parser.vulnerabilitiesCtrl.vulnerabilities
    assessments = [
        a for a in yocto_vex_parser.assessmentsCtrl.to_dict().values()
        if "CVE-2022-0778" in a.get("vuln_id", "")
    ]
    assert assessments == []


def test_skip_patched_prior_non_fixed_sets_fixed(yocto_vex_parser, monkeypatch):
    """With CVE_CHECK_EXCLUDE_PATCHED set and a prior non-fixed assessment,
    a Patched CVE is marked fixed."""
    monkeypatch.setenv("CVE_CHECK_EXCLUDE_PATCHED", "1")
    # First create an under_investigation assessment via an Unpatched issue.
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [{
        "id": "CVE-2022-0778",
        "status": "Unpatched",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    }]}]})
    # Now re-parse the same CVE as Patched with a detail reason.
    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [{
        "id": "CVE-2022-0778",
        "status": "Patched",
        "detail": "fixed-version: patched in 3.0.3",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    }]}]})
    statuses = {
        a["status"]
        for a in yocto_vex_parser.assessmentsCtrl.to_dict().values()
        if "CVE-2022-0778" in a.get("vuln_id", "")
    }
    assert "fixed" in statuses


def test_skip_patched_prior_fixed_creates_no_new_assessment(yocto_vex_parser, monkeypatch):
    """With CVE_CHECK_EXCLUDE_PATCHED set and an existing fixed assessment that
    does not originate from Yocto VEX, no additional assessment is created."""
    from src.models import Package, Assessment

    monkeypatch.setenv("CVE_CHECK_EXCLUDE_PATCHED", "1")

    # Pre-create the package and a fixed assessment carrying an unrelated reason.
    pkg = Package(
        _BASE_PKG["name"],
        _BASE_PKG["version"],
        list(_BASE_PKG["cpes"]),
        [],
        supplier=_BASE_PKG["layer"],
    )
    pkg.generate_generic_purl()
    pkg = yocto_vex_parser.packagesCtrl.add(pkg)

    pre = Assessment.new_dto("CVE-2022-0778", [pkg.string_id])
    pre.set_status("fixed")
    pre.set_not_affected_reason("Pre-existing fix from another source")
    yocto_vex_parser.assessmentsCtrl.add(pre)

    yocto_vex_parser.load_from_dict({"package": [{**_BASE_PKG, "issue": [{
        "id": "CVE-2022-0778",
        "status": "Patched",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    }]}]})

    assessments = [
        a for a in yocto_vex_parser.assessmentsCtrl.to_dict().values()
        if "CVE-2022-0778" in a.get("vuln_id", "")
    ]
    # Only the pre-existing fixed assessment remains.
    assert len(assessments) == 1
    assert assessments[0]["status"] == "fixed"

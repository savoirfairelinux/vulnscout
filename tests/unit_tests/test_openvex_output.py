# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for supplier-qualified OpenVEX product @id generation."""

from unittest.mock import MagicMock, patch
from src.views.openvex import OpenVex
from src.models.package import Package
from src.models.assessment import Assessment


def _make_pkg(name, version, supplier=""):
    pkg = Package(name, version, supplier=supplier)
    pkg.generate_generic_cpe()
    pkg.generate_generic_purl()
    return pkg


def _make_assessment(vuln_id, pkg):
    assess = Assessment.new_dto(vuln_id, [pkg.string_id])
    assess.set_status("affected")
    return assess


def _run_to_dict(pkgs, assessments):
    pkg_ctrl = MagicMock()
    pkg_ctrl.get = MagicMock(side_effect=lambda pid: next(
        (p for p in pkgs if p.string_id == pid), None
    ))
    vuln_ctrl = MagicMock()
    vuln_ctrl.get = MagicMock(return_value=None)
    assess_ctrl = MagicMock()
    assess_ctrl.assessments = {a.vuln_id: a for a in assessments}
    ctrl = {
        "packages": pkg_ctrl,
        "vulnerabilities": vuln_ctrl,
        "assessments": assess_ctrl,
    }
    with patch('src.views.openvex.Assessment.get_all', return_value=[]):
        view = OpenVex(ctrl)
        return view.to_dict()


def test_openvex_no_supplier_uses_generic_purl():
    pkg = _make_pkg("foo", "1.0")
    assess = _make_assessment("CVE-2024-1", pkg)
    result = _run_to_dict([pkg], [assess])
    product = result["statements"][0]["products"][0]
    assert product["@id"] == "pkg:generic/foo@1.0"


def test_openvex_supplier_uses_qualified_id():
    pkg = _make_pkg("foo", "1.0", supplier="Organization: Acme Corp (x@a.com)")
    assess = _make_assessment("CVE-2024-1", pkg)
    result = _run_to_dict([pkg], [assess])
    product = result["statements"][0]["products"][0]
    assert product["@id"] == "pkg:generic/acme-corp/foo@1.0"
    # identifiers.purl must remain generic
    assert product["identifiers"]["purl"] == "pkg:generic/foo@1.0"


def test_openvex_two_suppliers_produce_different_ids():
    pkg_a = _make_pkg("foo", "1.0", supplier="Organization: Acme Corp")
    pkg_b = _make_pkg("foo", "1.0", supplier="Organization: Bar Inc")
    assess_a = _make_assessment("CVE-2024-1", pkg_a)
    assess_b = _make_assessment("CVE-2024-2", pkg_b)
    result = _run_to_dict([pkg_a, pkg_b], [assess_a, assess_b])
    at_ids = [
        product["@id"]
        for stmt in result["statements"]
        for product in stmt["products"]
    ]
    assert len(set(at_ids)) == 2, f"Expected 2 distinct @ids, got: {at_ids}"


def test_openvex_empty_slug_uses_hash_fallback():
    """Supplier with no extractable name gets hash-based @id, not generic purl."""
    pkg = _make_pkg("foo", "1.0", supplier="Organization: ")
    assess = _make_assessment("CVE-2024-1", pkg)
    result = _run_to_dict([pkg], [assess])
    at_id = result["statements"][0]["products"][0]["@id"]
    assert at_id != "pkg:generic/foo@1.0"   # must NOT collide with no-supplier case
    assert "supplier-" in at_id             # hash-based fallback

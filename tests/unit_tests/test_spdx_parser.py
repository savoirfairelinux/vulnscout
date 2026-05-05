# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for SPDX v2.3 supplier field parsing."""

from unittest.mock import MagicMock
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from src.views.spdx import SPDX
from src.controllers.packages import PackagesController


def _make_controllers():
    pkg_ctrl = PackagesController()
    vuln_ctrl = MagicMock()
    assess_ctrl = MagicMock()
    return {
        "packages": pkg_ctrl,
        "vulnerabilities": vuln_ctrl,
        "assessments": assess_ctrl,
    }


def _make_spdx_pkg(name, version, supplier=None):
    """Build a minimal spdx_tools Package object."""
    from spdx_tools.spdx.model.package import Package as SpdxPkg
    from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion as NoAssert
    return SpdxPkg(
        spdx_id=f"SPDXRef-{name}",
        name=name,
        download_location=NoAssert(),
        version=version,
        supplier=supplier,
    )


def _make_sbom(packages):
    """Wrap a list of spdx_tools Packages in a minimal Document mock."""
    doc = MagicMock()
    doc.packages = packages
    return doc


def _make_view():
    ctrl = _make_controllers()
    view = SPDX(ctrl)
    return view, ctrl


def test_parse_supplier_organization():
    view, ctrl = _make_view()
    supplier_actor = Actor(ActorType.ORGANIZATION, "Acme Corp", "contact@acme.com")
    view.sbom = _make_sbom([_make_spdx_pkg("foo", "1.0", supplier=supplier_actor)])
    view.merge_components_into_controller()
    pkg = ctrl["packages"].get("foo@1.0::Organization: Acme Corp (contact@acme.com)")
    assert pkg is not None
    assert pkg.supplier == "Organization: Acme Corp (contact@acme.com)"


def test_parse_supplier_person_no_email():
    view, ctrl = _make_view()
    supplier_actor = Actor(ActorType.PERSON, "Jane Doe")
    view.sbom = _make_sbom([_make_spdx_pkg("foo", "1.0", supplier=supplier_actor)])
    view.merge_components_into_controller()
    pkg = ctrl["packages"].get("foo@1.0::Person: Jane Doe")
    assert pkg is not None
    assert pkg.supplier == "Person: Jane Doe"


def test_parse_supplier_noassertion():
    view, ctrl = _make_view()
    view.sbom = _make_sbom([_make_spdx_pkg("foo", "1.0", supplier=SpdxNoAssertion())])
    view.merge_components_into_controller()
    pkg = ctrl["packages"].get("foo@1.0")
    assert pkg is not None
    assert pkg.supplier == ""


def test_parse_supplier_absent():
    view, ctrl = _make_view()
    view.sbom = _make_sbom([_make_spdx_pkg("foo", "1.0", supplier=None)])
    view.merge_components_into_controller()
    pkg = ctrl["packages"].get("foo@1.0")
    assert pkg is not None
    assert pkg.supplier == ""


def test_two_packages_distinct_suppliers_both_stored():
    """Two same-name+version packages with different suppliers become separate entries."""
    view, ctrl = _make_view()
    acme = Actor(ActorType.ORGANIZATION, "Acme Corp")
    bar = Actor(ActorType.ORGANIZATION, "Bar Inc")
    pkg1 = _make_spdx_pkg("foo", "1.0", supplier=acme)
    pkg2 = _make_spdx_pkg("foo", "1.0", supplier=bar)
    pkg2.spdx_id = "SPDXRef-foo-bar"  # must differ
    view.sbom = _make_sbom([pkg1, pkg2])
    view.merge_components_into_controller()
    key_acme = "foo@1.0::Organization: Acme Corp"
    key_bar = "foo@1.0::Organization: Bar Inc"
    assert ctrl["packages"].get(key_acme) is not None
    assert ctrl["packages"].get(key_bar) is not None
    assert ctrl["packages"].get(key_acme) is not ctrl["packages"].get(key_bar)

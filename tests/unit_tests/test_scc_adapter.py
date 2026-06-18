# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Unit tests for src/controllers/scc_adapter.py.

All tests are pure in-process: they exercise the adapter helpers with real
sbom_cve_check types but no database connection.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from sbom_cve_check.vuln.comp_id import CompId

from src.controllers.scc_adapter import (
    _comp_ids_for_package,
    VsComponent,
    VsCompBuild,
    build_comp_build,
)


# ---------------------------------------------------------------------------
# _comp_ids_for_package
# ---------------------------------------------------------------------------

class TestCompIdsForPackage:

    def test_empty_inputs_returns_name_only(self):
        ids = _comp_ids_for_package("curl", "8.0", [], [])
        assert CompId(name="curl") in ids

    def test_valid_cpe_adds_comp_id(self):
        ids = _comp_ids_for_package(
            "openssl", "1.1.1",
            ["cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"],
            [],
        )
        # The CPE-derived CompId and the bare-name CompId must both be present.
        assert CompId(name="openssl") in ids
        # At least two identifiers: vendor-qualified + bare name.
        assert len(ids) >= 2

    def test_empty_cpe_string_skipped(self):
        ids = _comp_ids_for_package("bash", "5.0", ["", "  "], [])
        # Only the bare-name CompId from the empty/blank CPE strings.
        assert CompId(name="bash") in ids
        assert all(c.name == "bash" for c in ids)

    def test_invalid_cpe_skipped_gracefully(self):
        # build_from_cpe returns None for a bad CPE string; we verify no crash
        # and only the bare-name identifier is present.
        ids = _comp_ids_for_package("tool", "1.0", ["not-a-valid-cpe"], [])
        assert CompId(name="tool") in ids

    def test_build_from_cpe_exception_caught(self, monkeypatch):
        """If CompId.build_from_cpe raises (e.g. internal error), the exception
        is silently caught and the CPE is skipped."""
        from sbom_cve_check.vuln.comp_id import CompId as RealCompId
        monkeypatch.setattr(
            RealCompId, "build_from_cpe",
            staticmethod(lambda _cpe: (_ for _ in ()).throw(RuntimeError("forced error"))),
        )
        # Should not raise; the bare-name id is still added.
        ids = _comp_ids_for_package("pkg", "1.0", ["cpe:2.3:a:a:b:1:*:*:*:*:*:*:*"], [])
        assert CompId(name="pkg") in ids

    def test_valid_purl_adds_name(self):
        ids = _comp_ids_for_package(
            "requests", "2.28.0",
            [],
            ["pkg:pypi/requests@2.28.0"],
        )
        assert CompId(name="requests") in ids

    def test_empty_purl_skipped(self):
        ids = _comp_ids_for_package("lib", "1.0", [], ["", "  "])
        # Only the bare name.
        assert all(c.name == "lib" for c in ids)

    def test_invalid_purl_skipped_gracefully(self):
        ids = _comp_ids_for_package("lib", "1.0", [], ["not-a-purl"])
        assert CompId(name="lib") in ids

    def test_purl_with_no_name_skipped(self):
        # Craft a PURL whose parsed name is empty-string / None.
        # We patch PackageURL.from_string to return an object with name="".
        from unittest.mock import patch, MagicMock
        fake_purl = MagicMock()
        fake_purl.name = ""
        with patch("src.controllers.scc_adapter.PackageURL.from_string", return_value=fake_purl):
            ids = _comp_ids_for_package("mylib", "2.0", [], ["pkg:pypi/mylib@2.0"])
        assert CompId(name="mylib") in ids
        # No empty-name CompId was added.
        assert not any(c.name == "" for c in ids)

    def test_multiple_cpes_and_purls(self):
        ids = _comp_ids_for_package(
            "curl", "8.0",
            [
                "cpe:2.3:a:haxx:curl:8.0:*:*:*:*:*:*:*",
                "cpe:2.3:a:curl:curl:8.0:*:*:*:*:*:*:*",
            ],
            ["pkg:pypi/curl@8.0", "pkg:npm/curl@8.0"],
        )
        assert CompId(name="curl") in ids
        assert len(ids) >= 2

    def test_empty_name_does_not_add_blank_id(self):
        ids = _comp_ids_for_package("", "1.0", [], [])
        # Empty string name: the `if name:` guard prevents adding a blank id.
        assert len(ids) == 0


# ---------------------------------------------------------------------------
# VsComponent
# ---------------------------------------------------------------------------

class TestVsComponent:

    def _make(self, name="curl", version="8.0", cpes=(), purls=()):
        ids = {CompId(name=name)}
        return VsComponent(name, version, ids, tuple(cpes), tuple(purls))

    def test_name_property(self):
        comp = self._make("openssl", "1.1.1")
        assert comp.name == "openssl"

    def test_version_property(self):
        comp = self._make("curl", "8.0")
        assert comp.version == "8.0"

    def test_version_property_empty_returns_none(self):
        comp = self._make("curl", "")
        assert comp.version is None

    def test_pkg_version_property(self):
        comp = self._make("curl", "8.0")
        assert comp.pkg_version == "8.0"

    def test_pkg_version_empty_returns_none(self):
        comp = self._make("curl", "")
        assert comp.pkg_version is None

    def test_supplier_is_none(self):
        comp = self._make()
        assert comp.supplier is None

    def test_comp_type_is_none(self):
        comp = self._make()
        assert comp.comp_type is None

    def test_identifiers_property(self):
        ids = {CompId(name="openssl")}
        comp = VsComponent("openssl", "1.0", ids, (), ())
        assert comp.identifiers is ids

    def test_purls_property(self):
        comp = VsComponent(
            "curl", "8.0",
            {CompId(name="curl")},
            (),
            ("pkg:pypi/curl@8.0",),
        )
        assert comp.purls == {"pkg:pypi/curl@8.0"}

    def test_purls_empty(self):
        comp = self._make()
        assert comp.purls == set()


# ---------------------------------------------------------------------------
# VsCompBuild
# ---------------------------------------------------------------------------

class TestVsCompBuild:

    def _make(self, name="openssl", version="1.1.1", cpes=(), purls=()):
        ids = {CompId(name=name)}
        return VsCompBuild(name, version, ids, tuple(cpes), tuple(purls))

    def test_version_property(self):
        cb = self._make("curl", "8.0")
        assert cb.version == "8.0"

    def test_identifiers_property_is_tuple(self):
        cb = self._make()
        assert isinstance(cb.identifiers, tuple)
        assert len(cb.identifiers) >= 1

    def test_components_contains_vs_component(self):
        cb = self._make("bash", "5.2")
        comps = list(cb.components)
        assert len(comps) == 1
        assert isinstance(comps[0], VsComponent)
        assert comps[0].name == "bash"

    def test_build_name_property(self):
        cb = self._make("glibc", "2.38")
        assert cb.build_name == "glibc"

    def test_get_compiled_sources_empty(self):
        cb = self._make()
        # VulnScout SBOMs don't carry source-file lists; must return empty set
        # so the engine falls back to pure version-range evaluation.
        assert cb._get_compiled_sources() == set()

    def test_identifiers_are_sorted(self):
        ids = {CompId(name="z"), CompId(name="a"), CompId(name="m")}
        cb = VsCompBuild("pkg", "1.0", ids, (), ())
        names = [c.name for c in cb.identifiers]
        assert names == sorted(names)


# ---------------------------------------------------------------------------
# build_comp_build
# ---------------------------------------------------------------------------

class TestBuildCompBuild:

    def _pkg(self, name="openssl", version="1.1.1", cpe=None, purl=None):
        pkg = MagicMock()
        pkg.name = name
        pkg.version = version
        pkg.cpe = cpe or []
        pkg.purl = purl or []
        return pkg

    def test_valid_package_returns_vscompbuild(self):
        pkg = self._pkg(
            "openssl", "1.1.1",
            cpe=["cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"],
        )
        result = build_comp_build(pkg)
        assert isinstance(result, VsCompBuild)
        assert result.version == "1.1.1"

    def test_empty_version_returns_none(self):
        pkg = self._pkg("curl", "")
        assert build_comp_build(pkg) is None

    def test_none_version_returns_none(self):
        pkg = self._pkg("curl", None)
        assert build_comp_build(pkg) is None

    def test_whitespace_version_returns_none(self):
        pkg = self._pkg("curl", "   ")
        assert build_comp_build(pkg) is None

    def test_no_identifiers_returns_none(self):
        # A package with empty name and no CPE/PURL has no identifiers.
        pkg = self._pkg(name="", version="1.0", cpe=[], purl=[])
        assert build_comp_build(pkg) is None

    def test_purl_only_package(self):
        pkg = self._pkg(
            "requests", "2.28.0",
            cpe=[],
            purl=["pkg:pypi/requests@2.28.0"],
        )
        result = build_comp_build(pkg)
        assert isinstance(result, VsCompBuild)

    def test_name_and_version_only(self):
        # A bare name + version should yield a CompBuild with a name CompId.
        pkg = self._pkg("curl", "8.0", cpe=[], purl=[])
        result = build_comp_build(pkg)
        assert isinstance(result, VsCompBuild)
        assert CompId(name="curl") in set(result.identifiers)

    def test_strips_whitespace_from_name_and_version(self):
        pkg = self._pkg("  openssl  ", "  1.1.1  ")
        result = build_comp_build(pkg)
        assert result is not None
        assert result.version == "1.1.1"

    def test_invalid_cpe_skipped_gracefully(self):
        # Even with a bad CPE the bare-name identifier keeps the result valid.
        pkg = self._pkg("lib", "2.0", cpe=["garbage-cpe"])
        result = build_comp_build(pkg)
        assert isinstance(result, VsCompBuild)

    def test_ids_for_matching_works(self):
        pkg = self._pkg(
            "openssl", "1.1.1",
            cpe=["cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"],
        )
        cb = build_comp_build(pkg)
        ids = list(cb.ids_for_matching())
        names = [c.name for c in ids]
        assert "openssl" in names

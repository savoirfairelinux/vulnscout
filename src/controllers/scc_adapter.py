# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Adapters exposing VulnScout :class:`Package` objects to the sbom-cve-check engine.

The sbom-cve-check matching engine consumes :class:`~sbom_cve_check.sbom.component.Component`
and :class:`~sbom_cve_check.sbom.component.CompBuild` objects.  Rather than reproduce the
yocto/SPDX scaffolding the engine normally builds from an SBOM, we wrap VulnScout's own
``Package`` model directly.  Each ``Package`` becomes a single-component ``CompBuild`` whose
identifiers are derived from the package CPEs, PURLs and bare name — maximising matches across
ecosystems (OS packages via canonical CPE, pypi/npm via PURL/generic-CPE name).
"""

from __future__ import annotations

from collections.abc import Iterable

from packageurl import PackageURL

from sbom_cve_check.sbom.component import CompBuild, Component, CompType
from sbom_cve_check.vuln.comp_id import CompId


def _comp_ids_for_package(name: str, version: str, cpes: Iterable[str],
                          purls: Iterable[str]) -> set[CompId]:
    """Build the set of component identifiers used to match a package.

    Identifiers are collected from three sources so that a single package can be
    matched whichever way an advisory references it:

    * every CPE → :meth:`CompId.build_from_cpe` (carries vendor + canonical product)
    * every PURL package name → ``CompId(name=...)``
    * the bare package name → ``CompId(name=...)``
    """
    ids: set[CompId] = set()

    for cpe in cpes:
        if not cpe:
            continue
        try:
            cid = CompId.build_from_cpe(cpe)
        except Exception:
            cid = None
        if cid is not None:
            ids.add(cid)

    for purl in purls:
        if not purl:
            continue
        try:
            pname = PackageURL.from_string(purl).name
        except Exception:
            pname = None
        if pname:
            ids.add(CompId(name=pname.lower()))

    if name:
        ids.add(CompId(name=name.lower()))

    return ids


class VsComponent(Component):
    """Wrap a single VulnScout :class:`Package` as an engine ``Component``."""

    def __init__(self, name: str, version: str, identifiers: set[CompId],
                 cpes: tuple[str, ...], purls: tuple[str, ...]) -> None:
        self._name = name
        self._version = version
        self._identifiers = identifiers
        self._cpes = cpes
        self._purls = purls

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str | None:
        return self._version or None

    @property
    def pkg_version(self) -> str | None:
        return self._version or None

    @property
    def supplier(self) -> str | None:
        return None

    @property
    def comp_type(self) -> CompType | None:
        return None

    @property
    def identifiers(self) -> set[CompId]:
        return self._identifiers

    @property
    def purls(self) -> set[str]:
        return set(self._purls)


class VsCompBuild(CompBuild):
    """Wrap a single VulnScout :class:`Package` as an engine ``CompBuild``.

    A package maps to exactly one build holding one component, sharing the same
    version and identifiers (the invariant the engine expects).  Compiled-source
    refinement (kernel per-file trimming) is intentionally disabled: VulnScout's
    portable SBOM does not carry recipe source-file lists, so an empty set is
    returned, which makes the engine fall back to pure version-range evaluation.
    """

    def __init__(self, name: str, version: str, identifiers: set[CompId],
                 cpes: tuple[str, ...], purls: tuple[str, ...]) -> None:
        super().__init__()
        self._build_name = name
        self._version = version
        self._identifiers = tuple(sorted(identifiers))
        self._component = VsComponent(name, version, identifiers, cpes, purls)

    @property
    def version(self) -> str:
        return self._version

    @property
    def identifiers(self) -> tuple[CompId, ...]:
        return self._identifiers

    @property
    def components(self) -> Iterable[Component]:
        return [self._component]

    @property
    def build_name(self) -> str | None:
        return self._build_name

    def _get_compiled_sources(self) -> set[str]:
        return set()


def build_comp_build(pkg) -> VsCompBuild | None:
    """Create a :class:`VsCompBuild` from a VulnScout ``Package``.

    Returns ``None`` when the package carries neither a usable version nor any
    identifier the engine could match against.
    """
    name = (pkg.name or "").strip()
    version = (pkg.version or "").strip()
    cpes = tuple(pkg.cpe or [])
    purls = tuple(pkg.purl or [])

    identifiers = _comp_ids_for_package(name, version, cpes, purls)
    if not identifiers or not version:
        return None

    return VsCompBuild(name, version, identifiers, cpes, purls)

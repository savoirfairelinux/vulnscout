# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Thin wrapper around the sbom-cve-check matching engine.

Builds and caches an indexed :class:`~sbom_cve_check.database.manager.VulnDbManager`
backed by local NVD-FKIE + CVEList V5 git databases, with the products-alias and
CNA-role tables initialised.  The indexed manager is expensive to build (it reads
hundreds of thousands of advisory JSON files), so a single instance is cached for
the lifetime of the process.

Configuration (environment variables):

* ``SCC_DATABASES_DIR`` — directory holding the ``nvd-fkie`` and ``cvelist`` git
  clones.  Defaults to ``$XDG_CACHE_HOME/sbom_cve_check/databases`` (i.e.
  ``~/.cache/sbom_cve_check/databases``).
* ``SCC_GIT_FETCH_DEPTH`` — git fetch/clone depth (default ``1``: shallow clone).
* ``SCC_AUTO_UPDATE`` — ``"1"``/``"true"`` to allow the engine to fetch fresh
  advisories on startup, anything else disables network updates (default
  disabled, so scans run fully offline against the existing clones).
"""

from __future__ import annotations

import functools
import os
import pathlib
import threading
from collections.abc import Generator

from sbom_cve_check.analysis.computed_vuln import ComputedVulnInfo
from sbom_cve_check.database.db_git import GitDatabase
from sbom_cve_check.database.locking import init_global_databases_lock
from sbom_cve_check.database.manager import DatabasesConfigData, VulnDbManager
from sbom_cve_check.products.products import init_products_database
from sbom_cve_check.vuln.cna import init_cna_database

from .scc_adapter import build_comp_build

_ENGINE_LOCK = threading.Lock()
_ENGINE: "SccEngine | None" = None
_PURE_CACHES_INSTALLED = False


def _install_cpe_parse_caches() -> None:
    """Memoize the pure CPE-parsing helpers the engine calls repeatedly.

    ``VulnDbManager.get_applicable_vulns`` re-parses every CPE string of every
    candidate CVE, for every package it evaluates.  The same CPE strings recur
    across the thousands of packages in a Yocto image (most visibly the many
    sub-packages a single recipe expands into, e.g. ``busybox`` ->
    ``busybox-syslog`` / ``busybox-udhcpc`` ...), so the same strings are parsed
    tens of thousands of times per scan.  ``Cpe23.parse`` and
    ``CompId.build_from_cpe`` are pure functions of a string argument and return
    immutable objects, so memoizing them collapses that quadratic re-parsing
    into a one-off cost (profiling attributes the majority of per-package time
    to these two calls).  Only string/``None`` inputs are cached; ``Cpe23``
    instances pass straight through, so behaviour is unchanged.
    """
    global _PURE_CACHES_INSTALLED
    if _PURE_CACHES_INSTALLED:
        return
    from sbom_cve_check.vuln.cpe import Cpe23
    from sbom_cve_check.vuln.comp_id import CompId

    def _string_keyed(func, maxsize):
        cached = functools.lru_cache(maxsize=maxsize)(func)

        @functools.wraps(func)
        def wrapper(arg=None):
            if arg is None or isinstance(arg, str):
                return cached(arg)
            return func(arg)

        wrapper.cache_clear = cached.cache_clear
        return wrapper

    Cpe23.parse = staticmethod(_string_keyed(Cpe23.parse, 200_000))  # type: ignore[method-assign]
    CompId.build_from_cpe = staticmethod(_string_keyed(CompId.build_from_cpe, 200_000))  # type: ignore[method-assign]
    _PURE_CACHES_INSTALLED = True


def _databases_dir() -> pathlib.Path:
    """Resolve the directory holding the local advisory git clones."""
    env = os.getenv("SCC_DATABASES_DIR")
    if env and env.strip():
        return pathlib.Path(env).expanduser().resolve()
    cache = os.getenv("XDG_CACHE_HOME") or "~/.cache"
    return pathlib.Path(cache).expanduser().joinpath("sbom_cve_check", "databases").resolve()


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def _trust_git_directories(paths: list[pathlib.Path]) -> None:
    """Mark the local advisory git clones as safe for git to read.

    The clones are frequently owned by a different uid than the running process
    (e.g. a container running as root over volume-mounted, builder-owned
    databases).  Git's "dubious ownership" protection then makes ``git rev-parse``
    fail, which silently defeats sbom-cve-check's commit-keyed index cache: with
    no resolvable HEAD it rebuilds the whole index from hundreds of thousands of
    advisory files on every scan (minutes) instead of loading the cached index
    (about a second).

    Adding the directories to git's ``safe.directory`` list via the
    ``GIT_CONFIG_*`` environment variables (process-scoped, no files written)
    restores the cache fast-path.  Existing ``GIT_CONFIG_*`` entries are
    preserved.
    """
    try:
        count = int(os.environ.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        count = 0
    for path in paths:
        os.environ[f"GIT_CONFIG_KEY_{count}"] = "safe.directory"
        os.environ[f"GIT_CONFIG_VALUE_{count}"] = str(path)
        count += 1
    os.environ["GIT_CONFIG_COUNT"] = str(count)


class SccEngine:
    """Indexed sbom-cve-check engine ready to match VulnScout packages."""

    def __init__(self, databases_dir: pathlib.Path, fetch_depth: int,
                 auto_update: bool) -> None:
        self._databases_dir = databases_dir
        self._manager = VulnDbManager()

        nvd_dir = databases_dir.joinpath("nvd-fkie")
        cvelist_dir = databases_dir.joinpath("cvelist")
        for label, path in (("nvd-fkie", nvd_dir), ("cvelist", cvelist_dir)):
            if not path.is_dir() and not auto_update:
                raise RuntimeError(
                    f"Vulnerability database '{label}' not found at {path}. "
                    "Clone it (or set SCC_AUTO_UPDATE=1 to let the engine clone it) "
                    "before running scc-scan."
                )

        # Let git read the clones even when the process uid differs from the
        # clone owner, otherwise the engine bypasses its on-disk index cache and
        # rebuilds the whole index from every advisory file on each scan.
        _trust_git_directories([databases_dir, nvd_dir, cvelist_dir])

        # The git databases grab the global lock at construction time, so it must
        # be initialised first.  An empty config list makes it fall back to
        # SBOM_CVE_CHECK_DATABASES_DIR, which we point at our databases dir.
        os.environ.setdefault("SBOM_CVE_CHECK_DATABASES_DIR", str(databases_dir))
        init_global_databases_lock([])

        # Disable network fetches unless the operator explicitly opts in, so a
        # scan against an already-cloned DB never reaches out to the network.
        GitDatabase.DISABLE_AUTO_UPDATES_GLOBALLY = not auto_update

        db_sections = {
            "nvd-fkie": {
                "type": "cve-db-nvd-fkie",
                "path": str(nvd_dir),
                "git_fetch_depth": fetch_depth,
            },
            "cvelist": {
                "type": "cve-db-cvelist",
                "path": str(cvelist_dir),
                "git_fetch_depth": fetch_depth,
            },
        }
        self._manager.add_databases_from_configs(
            [DatabasesConfigData(databases_dir, db_sections)]
        )

        # Products alias table (vendor/product canonicalisation, e.g.
        # linux-yocto -> linux_kernel) and CNA-role table (needed for accurate
        # version-range scoping, including the Linux-kernel CNA special-case).
        init_products_database([], load_defaults=True)
        init_cna_database([])

        # Memoize the pure CPE-parsing helpers before any matching runs.
        _install_cpe_parse_caches()

        # Build the in-memory index (parallel across databases).  Expensive.
        self._manager.create_index()

        # Memoize per-CVE record reads so each advisory JSON file is opened and
        # parsed at most once per engine lifetime instead of once per
        # (package x candidate-CVE).  The same popular CVEs (curl, glibc,
        # openssl, the kernel ...) are candidates for nearly every package, so
        # without this the scan re-reads the same files thousands of times.
        self._install_get_vuln_caches()

        # Cache the applicable-vulnerability computation keyed on the matching
        # signature of a package (see :meth:`applicable_vulns`).
        self._applicable_cache: dict[
            tuple[frozenset, str | None],
            list[tuple[tuple, ...]],
        ] = {}
        # Cache the per-CVE version verdict (affected / not_affected / fixed /
        # under_investigation) under the same signature, so the costly
        # version-range evaluation runs once per signature instead of once per
        # sibling package.
        self._verdict_cache: dict[
            tuple[frozenset, str | None], dict[str, str]
        ] = {}

    def _install_get_vuln_caches(self) -> None:
        """Wrap every database's ``get_vuln`` with a bounded per-record cache."""
        databases = getattr(self._manager, "_databases", None)
        if not databases:
            return
        for dbs in databases.values():
            for db in dbs:
                if getattr(db.get_vuln, "__wrapped__", None) is not None:
                    continue
                db.get_vuln = functools.lru_cache(maxsize=65_536)(db.get_vuln)

    @staticmethod
    def _vex_status_str(computed: ComputedVulnInfo) -> str:
        """Map an engine VEX assessment to a VulnScout OpenVEX status string.

        Triggers the engine's (expensive) version-range evaluation via
        ``computed.vex_assessment``.
        """
        from sbom_cve_check.vuln.vex import VexStatus

        status = computed.vex_assessment.status
        if status == VexStatus.AFFECTED:
            return "affected"
        if status == VexStatus.NOT_AFFECTED:
            return "not_affected"
        if status == VexStatus.FIXED:
            return "fixed"
        return "under_investigation"

    def applicable_vulns(
        self, pkg
    ) -> Generator[tuple[ComputedVulnInfo, str], None, None]:
        """Yield ``(ComputedVulnInfo, status)`` for every applicable vuln of a package.

        ``status`` is the OpenVEX verdict string (``affected`` /
        ``not_affected`` / ``fixed`` / ``under_investigation``).

        Many packages in a Yocto image share an identical *matching* signature
        even though they are distinct packages.  The clearest case is the kernel:
        a single recipe expands into the ``linux-*`` package plus hundreds of
        ``kernel-module-*`` sub-packages, and every one of them carries the same
        ``linux_kernel`` / ``linux`` CPE at the same version.  The kernel's
        product name resolves to tens of thousands of candidate CVEs, so without
        caching each of those hundreds of sub-packages re-evaluates the very same
        ~16k advisories and re-runs the very same version-range verdicts — the
        dominant cost of a full scan.

        Both the applicable-vulnerability set and the per-CVE version verdict are
        pure functions of the package's *index-relevant* identifiers and version:
        an identifier whose product name is absent from the index can neither
        pull a candidate CVE nor loosely match one (the index and the loose-match
        check are both derived from each advisory's applicable component names),
        so it is dropped from the signature.  Packages sharing a signature
        therefore share both heavy computations; only the cheap per-package
        :class:`ComputedVulnInfo` wrappers (which carry the correct component for
        reporting) are rebuilt, so results are unchanged.
        """
        comp_build = build_comp_build(pkg)
        if comp_build is None:
            return

        index = self._manager._index_comp_vuln
        relevant_ids = frozenset(
            cid for cid in comp_build.ids_for_matching() if cid.name in index
        )
        key = (relevant_ids, comp_build.version)

        entry_groups = self._applicable_cache.get(key)
        if entry_groups is None:
            entry_groups = [
                computed._vuln_db_entries
                for computed in self._manager.get_applicable_vulns(comp_build)
            ]
            # Bound memory across long-lived engines handling many scans.
            if len(self._applicable_cache) >= 50_000:
                self._applicable_cache.clear()
                self._verdict_cache.clear()
            self._applicable_cache[key] = entry_groups

        verdicts = self._verdict_cache.setdefault(key, {})
        for entries in entry_groups:
            computed = ComputedVulnInfo(comp_build, entries)
            cve_id = str(computed.identifier)
            status = verdicts.get(cve_id)
            if status is None:
                status = self._vex_status_str(computed)
                verdicts[cve_id] = status
            yield computed, status


def get_engine() -> SccEngine:
    """Return the process-wide indexed engine, building it on first use."""
    global _ENGINE
    if _ENGINE is not None:
        return _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is None:
            depth_env = os.getenv("SCC_GIT_FETCH_DEPTH")
            try:
                fetch_depth = int(depth_env) if depth_env else 1
            except ValueError:
                fetch_depth = 1
            _ENGINE = SccEngine(
                databases_dir=_databases_dir(),
                fetch_depth=fetch_depth,
                auto_update=_truthy(os.getenv("SCC_AUTO_UPDATE")),
            )
    return _ENGINE


def reset_engine() -> None:
    """Drop the cached engine (used by tests to force a rebuild)."""
    global _ENGINE
    with _ENGINE_LOCK:
        _ENGINE = None

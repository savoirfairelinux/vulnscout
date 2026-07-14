# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Thin wrapper around the sbom-cve-check matching engine.

Builds and caches an indexed :class:`~sbom_cve_check.database.manager.VulnDbManager`
backed by local NVD-FKIE + CVEList V5 git databases, with the products-alias and
CNA-role tables initialised.  The indexed manager is expensive to build (it reads
hundreds of thousands of advisory JSON files), so a single instance is cached for
the lifetime of the process.

Configuration (environment variables):

* ``SBOM_CVE_CHECK_DATABASES_DIR`` — directory holding the ``nvd-fkie`` and ``cvelist`` git
  clones.  Defaults to a ``local_databases`` sub-directory of the VulnScout
  cache directory (``$VULNSCOUT_CACHE_DIR/local_databases``, i.e.
  ``/cache/vulnscout/local_databases`` inside the container), so the advisory
  clones live next to ``vulnscout.db`` instead of in a separate XDG cache tree.
* ``SBOM_CVE_CHECK_GIT_FETCH_DEPTH`` — git fetch/clone depth (default ``1``: shallow clone).
* ``SBOM_CVE_CHECK_AUTO_UPDATE`` — ``"1"``/``"true"`` to let the engine clone/fetch fresh
  advisories (default ``"1"``).  The databases are refreshed before *every* scan so each
  run uses up-to-date advisories.  Set to ``"0"`` to run in offline mode against
  already-cloned databases.
"""

from __future__ import annotations

import functools
import logging
import os
import pathlib
import threading
from collections.abc import Generator
from typing import cast

from sbom_cve_check.database.db_git import GitDatabase
from sbom_cve_check.database.locking import init_global_databases_lock
from sbom_cve_check.database.manager import DatabasesConfigData, VulnDbManager
from sbom_cve_check.products.products import init_products_database
from sbom_cve_check.vuln.cna import init_cna_database
from sbom_cve_check.analysis.computed_vuln import ComputedVulnInfo
from sbom_cve_check.database.db_nvd import NvdFkieVulnDatabase
from sbom_cve_check.vuln.vuln import CveId
from sbom_cve_check.vuln.vex import VexStatus as _VexStatus
from .scc_adapter import build_comp_build

_logger = logging.getLogger(__name__)

_ENGINE_LOCK = threading.Lock()
_ENGINE: "SccEngine | None" = None
_PURE_CACHES_INSTALLED = False

# Sentinel distinguishing "attribute genuinely absent" (upstream rename) from a
# legitimate ``None`` value when reaching into sbom-cve-check internals.
_MISSING = object()


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

        wrapper.cache_clear = cached.cache_clear  # type: ignore[attr-defined]
        return wrapper

    Cpe23.parse = staticmethod(_string_keyed(Cpe23.parse, 200_000))  # type: ignore[method-assign]
    CompId.build_from_cpe = staticmethod(_string_keyed(CompId.build_from_cpe, 200_000))  # type: ignore[method-assign]
    _PURE_CACHES_INSTALLED = True


def _databases_dir() -> pathlib.Path:
    """Resolve the directory holding the local advisory git clones.

    Defaults to a ``local_databases`` sub-directory of the VulnScout cache
    directory so the NVD-FKIE and CVEList clones sit next to ``vulnscout.db`` instead
    of in a separate ``~/.cache/sbom_cve_check`` tree.
    """
    env = os.getenv("SBOM_CVE_CHECK_DATABASES_DIR")
    if env and env.strip():
        return pathlib.Path(env).expanduser().resolve()
    cache = os.getenv("VULNSCOUT_CACHE_DIR") or "/cache/vulnscout"
    return pathlib.Path(cache).expanduser().joinpath("local_databases").resolve()


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
        self._fetch_depth = fetch_depth
        self._auto_update = auto_update
        # Serialises per-scan database refreshes so two concurrent scans never
        # fetch / rebuild the index at the same time.
        self._refresh_lock = threading.Lock()
        # Tracks which "upstream internal changed" warnings have already been
        # emitted so a rename in sbom-cve-check is logged once, not per lookup.
        self._degraded_warnings: set = set()
        self._manager = VulnDbManager()

        nvd_dir = databases_dir.joinpath("nvd-fkie")
        cvelist_dir = databases_dir.joinpath("cvelist")
        for label, path in (("nvd-fkie", nvd_dir), ("cvelist", cvelist_dir)):
            if not path.is_dir() and not auto_update:
                raise RuntimeError(
                    f"Vulnerability database '{label}' not found at {path}. "
                    "Clone it before running sbom-cve-check-scan, or set "
                    "SBOM_CVE_CHECK_AUTO_UPDATE=1 to let the engine clone it automatically."
                )

        # When network updates are allowed the clones may not exist yet; make sure
        # the parent directory is present so git can create them on first fetch.
        if auto_update:
            databases_dir.mkdir(parents=True, exist_ok=True)

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

    def _warn_degraded(self, key: str, message: str) -> None:
        """Log ``message`` once per ``key`` when an upstream internal looks renamed.

        The engine reaches into a handful of private sbom-cve-check attributes
        (``VulnDbManager._databases``, ``NvdFkieVulnDatabase``, the advisory
        record's ``_json``).  If any of those is renamed by an upstream version
        bump the old ``getattr(..., None)`` fall-back silently returned no data
        for every lookup — indistinguishable from "not in DB".  Failing loudly
        (once) makes such a break diagnosable instead of globally invisible.
        """
        if key not in self._degraded_warnings:
            self._degraded_warnings.add(key)
            _logger.error(message)

    def _managed_databases(self) -> dict:
        """Return the manager's ``_databases`` mapping, warning once if it is gone.

        ``_databases`` is a private attribute of the upstream manager.  A
        missing attribute (rename / API change) is distinguished from a legit
        empty mapping via a sentinel so the former is logged as an error and the
        latter is not.
        """
        databases = getattr(self._manager, "_databases", _MISSING)
        if databases is _MISSING:
            self._warn_degraded(
                "manager_databases",
                "sbom-cve-check VulnDbManager has no '_databases' attribute — "
                "the upstream library layout may have changed; every advisory "
                "lookup will return no data. Check sbom-cve-check compatibility.",
            )
            return {}
        return cast("dict", databases) or {}

    def _install_get_vuln_caches(self) -> None:
        """Wrap every database's ``get_vuln`` with a bounded per-record cache."""
        databases = self._managed_databases()
        if not databases:
            return
        for dbs in databases.values():
            for db in dbs:
                if getattr(db.get_vuln, "__wrapped__", None) is not None:
                    continue
                db.get_vuln = functools.lru_cache(maxsize=65_536)(db.get_vuln)

    def _git_databases(self) -> list:
        """Return the underlying ``GitDatabase`` objects of every managed DB."""
        result: list = []
        databases = self._managed_databases()
        if not databases:
            return result
        for dbs in databases.values():
            for db in dbs:
                git_db = getattr(db, "git_database", None)
                if git_db is not None:
                    result.append(git_db)
        return result

    def _clear_caches(self) -> None:
        """Drop every per-scan cache so a refreshed index is never served stale data."""
        self._applicable_cache.clear()
        self._verdict_cache.clear()
        databases = self._managed_databases()
        if databases:
            for dbs in databases.values():
                for db in dbs:
                    clear = getattr(getattr(db, "get_vuln", None), "cache_clear", None)
                    if callable(clear):
                        clear()

    def refresh_databases(self) -> bool:
        """Fetch fresh advisories for each git database before a scan.

        Called once per scan (see :func:`get_engine`).  The process-wide engine is
        built once and reused, so without this the NVD-FKIE / CVEList clones would
        only ever be fetched at construction (the first scan of the process).  When
        ``SBOM_CVE_CHECK_AUTO_UPDATE`` is enabled this force-fetches every clone so
        each scan runs against up-to-date databases; when it is disabled it is a
        no-op (offline mode, scans run against the existing clones).

        The expensive in-memory index is only rebuilt when a clone actually advanced
        to a new commit, in which case the per-scan caches are dropped as well so no
        stale verdict survives.  Network / git failures are logged and swallowed so a
        transient fetch error never aborts an otherwise-runnable scan.

        :return: ``True`` if any clone advanced and the index was rebuilt.
        """
        if not self._auto_update:
            return False
        with self._refresh_lock:
            changed = False
            for git_db in self._git_databases():
                before = git_db.get_date_last_commit()
                try:
                    git_db.update(force_update=True)
                except Exception as exc:  # noqa: BLE001 - never abort a scan on fetch error
                    _logger.warning(
                        "sbom-cve-check database refresh failed (using existing clone): %s",
                        exc,
                    )
                    continue
                after = git_db.get_date_last_commit()
                if before != after:
                    changed = True
            if changed:
                self._manager.create_index()
                self._clear_caches()
            return changed

    @staticmethod
    def _vex_status_str(computed: "ComputedVulnInfo") -> str:
        """Map an engine VEX assessment to a VulnScout OpenVEX status string.

        Triggers the engine's (expensive) version-range evaluation via
        ``computed.vex_assessment``.
        """
        status = computed.vex_assessment.status
        if status == _VexStatus.AFFECTED:
            return "affected"
        if status == _VexStatus.NOT_AFFECTED:
            return "not_affected"
        if status == _VexStatus.FIXED:
            return "fixed"
        return "under_investigation"

    def applicable_vulns(
        self, pkg
    ) -> Generator[tuple["ComputedVulnInfo", str], None, None]:
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

    def get_nvd_cve_json(self, cve_id: str) -> "dict | None":
        """Return the raw NVD JSON for a CVE from the local NVD-FKIE database.

        The NVD-FKIE git feed stores the same JSON schema as the NVD API v2
        response, so the result can be passed directly to
        :func:`~src.controllers.nvd_extract.extract_cve_details`.
        Returns ``None`` if the CVE is not present in the local database.
        """
        databases = self._managed_databases()
        if not databases:
            return None
        try:
            cve_id_obj = CveId(cve_id.upper().strip())
        except Exception:
            return None
        nvd_db_seen = False
        for dbs in databases.values():
            for db in dbs:
                if not isinstance(db, NvdFkieVulnDatabase):
                    continue
                nvd_db_seen = True
                # get_vuln may be lru_cache-wrapped by _install_get_vuln_caches;
                # calling it directly is fine — the cache avoids repeated disk reads.
                entry = db.get_vuln(cve_id_obj)
                if entry is not None:
                    raw = getattr(entry, "_json", _MISSING)
                    if raw is _MISSING:
                        self._warn_degraded(
                            "entry_json",
                            "sbom-cve-check advisory record has no '_json' "
                            "attribute — the upstream library layout may have "
                            "changed; NVD CVE JSON lookups will return no data. "
                            "Check sbom-cve-check compatibility.",
                        )
                        return None
                    return cast("dict | None", raw)
        if not nvd_db_seen:
            self._warn_degraded(
                "no_nvd_fkie_db",
                "sbom-cve-check databases are present but none is an "
                "NvdFkieVulnDatabase — the upstream database class may have "
                "changed; NVD CVE JSON lookups will return no data. "
                "Check sbom-cve-check compatibility.",
            )
        return None


def get_engine() -> SccEngine:
    """Return the process-wide indexed engine, building it on first use.

    The engine is expensive to build and is cached for the lifetime of the
    process.  Every call refreshes the advisory git clones before returning so
    scans always run against up-to-date data.  Call this from full-scan paths.
    For single-CVE look-ups that do not need an immediate git fetch, use
    :func:`get_cve_json` instead (it reuses the cached engine without
    triggering a refresh).
    """
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is None:
            depth_env = os.getenv("SBOM_CVE_CHECK_GIT_FETCH_DEPTH")
            try:
                fetch_depth = int(depth_env) if depth_env else 1
            except ValueError:
                fetch_depth = 1
            _ENGINE = SccEngine(
                databases_dir=_databases_dir(),
                fetch_depth=fetch_depth,
                auto_update=_truthy(os.getenv("SBOM_CVE_CHECK_AUTO_UPDATE")),
            )
    _ENGINE.refresh_databases()
    return _ENGINE


def reset_engine() -> None:
    """Drop the cached engine (used by tests to force a rebuild)."""
    global _ENGINE
    with _ENGINE_LOCK:
        _ENGINE = None


def get_cve_json(cve_id: str) -> "dict | None":
    """Look up a CVE by ID in the local NVD-FKIE database.

    Reuses the already-built engine without triggering a git fetch so
    single-CVE look-ups (e.g. from the UI refresh button) are fast.  If no
    engine has been built yet it falls back to :func:`get_engine` which
    performs the initial build (including a first fetch).

    Returns the raw NVD CVE JSON dict (same schema as NVD API v2) or ``None``
    if the CVE is not found or the database is not yet initialised.
    """
    with _ENGINE_LOCK:
        engine = _ENGINE
    if engine is None:
        # Engine not yet built — the first build includes a fetch.
        engine = get_engine()
    try:
        return engine.get_nvd_cve_json(cve_id)
    except Exception as exc:
        _logger.warning("Failed to look up %s in local NVD database: %s", cve_id, exc)
        return None

# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import datetime
import time
import os
import json
import urllib.request
import urllib.error
from typing import Optional

from ..models.vulnerability import Vulnerability
from ..controllers.packages import PackagesController
from ..controllers.epss_db import EPSS_DB
from ..controllers.nvd_db import NVD_DB
from ..helpers.verbose import verbose
from ..models.cvss import CVSS
from ..models.metrics import Metrics as MetricsModel
from ..extensions import db


# ---------------------------------------------------------------------------
# Remote-refresh delay helpers
# ---------------------------------------------------------------------------

_NEVER = datetime.timedelta.max
_ALWAYS = None  # sentinel: always re-fetch


def parse_refresh_delay(value: Optional[str]) -> Optional[datetime.timedelta]:
    """Parse a REFRESH_REMOTE_DELAY string into a timedelta.

    Accepted formats:
      * ``\"never\"``  – only fetch data that was never fetched before
      * ``\"always\"`` – always re-fetch regardless of age
      * ``\"<N>h\"``   – re-fetch when data is older than N hours  (e.g. ``48h``, default)
      * ``"<N>d"``   – re-fetch when data is older than N days   (e.g. ``7d``)
      * ``"<N>w"``   – re-fetch when data is older than N weeks  (e.g. ``2w``)
      * ``"<N>m"``   – re-fetch when data is older than N minutes (e.g. ``30m``)

    Returns ``datetime.timedelta.max`` for ``"never"``, ``None`` for
    ``"always"``, or a :class:`datetime.timedelta` for duration values.
    """
    if value is None:
        return _NEVER
    v = value.strip().lower()
    if v == "never":
        return _NEVER
    if v == "always":
        return _ALWAYS
    units = {"h": "hours", "d": "days", "w": "weeks", "m": "minutes"}
    if v and v[-1] in units:
        try:
            return datetime.timedelta(**{units[v[-1]]: float(v[:-1])})
        except ValueError:
            pass
    raise ValueError(
        f"Invalid REFRESH_REMOTE_DELAY value {value!r}. "
        "Use 'never', 'always', or a duration like '48h', '7d', '2w', '30m'."
    )


def _should_refetch(fetched_at: Optional[datetime.datetime], delay: Optional[datetime.timedelta]) -> bool:
    """Return True if the entry should be (re-)fetched.

    * delay is ``None`` (always)         → always True
    * ``fetched_at`` is ``None``         → True  (never fetched)
    * delay is ``timedelta.max`` (never) → False (already fetched, skip)
    * otherwise                          → True if the data is older than *delay*
    """
    if delay is _ALWAYS:
        return True
    if fetched_at is None:
        return True
    if delay is _NEVER:
        return False
    assert delay
    return (datetime.datetime.utcnow() - fetched_at) >= delay


def _persist_vuln_to_db(
        vuln: Vulnerability, pkg_id_cache=None, finding_cache=None,
        db_record_cache=None, use_savepoint: bool = True) -> None:
    """Silently persist a Vulnerability to the DB.

    Uses a SAVEPOINT so that a failure (e.g. IntegrityError) only rolls
    back this single entity instead of the whole ``batch_session()``
    transaction. Set use_savepoint=False when already inside batch_session()
    for better performance during bulk operations.

    *pkg_id_cache* and *finding_cache* are optional dicts from
    ``PackagesController`` that avoid redundant SELECT queries.

    *db_record_cache* (``{vuln_id: record}``) avoids the ``get_by_id``
    SELECT for vulnerabilities already fetched in this session.

    Args:
        vuln: The vulnerability to persist
        pkg_id_cache: Optional cache of package IDs to avoid SELECT queries
        finding_cache: Optional cache of findings
        db_record_cache: Optional cache of DB Vulnerability records
        use_savepoint: If True (default), use SAVEPOINT. Set False in batch context.
    """
    try:
        from ..extensions import db
        if use_savepoint:
            with db.session.begin_nested():
                Vulnerability.persist_from_transient(
                    vuln,
                    pkg_id_cache=pkg_id_cache,
                    finding_cache=finding_cache,
                    db_record_cache=db_record_cache,
                )
        else:
            # Skip SAVEPOINT for better perf in bulk operations
            Vulnerability.persist_from_transient(
                vuln,
                pkg_id_cache=pkg_id_cache,
                finding_cache=finding_cache,
                db_record_cache=db_record_cache,
            )
    except Exception as e:
        verbose(f"[_persist_vuln_to_db {vuln.id!r}] {e}")


class VulnerabilitiesController:
    """
    A class to handle a list of vulnerabilities, de-duplicating them and handling low-level stuff.
    Vulnerabilities can be added, removed, retrieved and exported or imported as dictionaries.

    Also provides DB-level CRUD helpers (``serialize``, ``create_db``, etc.)
    previously found in ``VulnerabilityDBController``.
    """

    safe_url_regex = r"[^a-zA-Z0-9_\-\.]"
    """Regex to remove unsafe characters from URLs."""

    def __init__(self, pkgCtrl: PackagesController):
        """Take an instance of PackagesController to resolve package dependencies as parameter."""
        self.packagesCtrl = pkgCtrl
        self.vulnerabilities: dict[str, Vulnerability] = {}
        """A dictionary of vulnerabilities, indexed by their id."""
        self.alias_registered: dict[str, str] = {}
        self.use_savepoints: bool = True
        """Set to False during batch operations inside batch_session() for better performance."""
        self._persisted_ids: set[str] = set()
        """IDs of vulnerabilities already persisted to DB — skip re-persist when unchanged."""
        self._encountered_this_run: set[str] = set()
        """Canonical IDs of vulnerabilities encountered (added/merged) during the current
        processing run.  Used by merger_ci to scope observation creation so that only
        findings for vulns actually present in this run's input files receive an
        observation for the new scan — preventing cross-variant observation leakage."""
        self._db_record_cache: dict = {}
        """Cache of {vuln_id: DB record} — avoids get_by_id SELECT in persist_from_transient."""
        self.epss_api = EPSS_DB()
        self.nvd_api = NVD_DB(nvd_api_key=os.getenv("NVD_API_KEY"))
        self._preload_cache()

    def _preload_cache(self) -> None:
        """Bulk-load all vulnerabilities from the DB into the in-memory caches.

        Called once at construction time so that subsequent :meth:`get` calls
        are pure dict lookups — zero extra SELECTs per vulnerability.

        Populates transient DTO attributes directly from the already
        eager-loaded ``findings`` and ``metrics`` relationships to avoid the
        expensive ``to_dict()`` → ``from_dict()`` serialisation round-trip.
        """
        try:
            for rec in Vulnerability.get_all():
                # Populate transient package list from eager-loaded findings
                for f in (rec.findings or []):
                    if f.package:
                        rec.add_package(f.package.string_id)
                # Populate transient CVSS list from eager-loaded metrics
                for m in (rec.metrics or []):
                    try:
                        rec.register_cvss(CVSS(
                            m.version,
                            m.vector or "",
                            m.author or "unknown",
                            float(m.score) if m.score is not None else 0.0,
                            0.0,
                            0.0,
                        ))
                    except Exception as e:
                        verbose(f"[VulnerabilitiesController._preload_cache register_cvss {rec.id!r}] {e}")
                self.vulnerabilities[rec.id] = rec
                self._persisted_ids.add(rec.id)
                rec._persisted_packages = set(rec.packages)  # track persisted packages to skip redundant DB work
                # Cache the DB record so persist_from_transient skips get_by_id.
                self._db_record_cache[rec.id] = rec
                # Pre-populate Metrics._seen so from_cvss skips the SELECT
                # for every metric that already exists in the DB.
                for m in (rec.metrics or []):
                    MetricsModel._seen.add((
                        rec.id,
                        m.version,
                        float(m.score) if m.score is not None else None,
                    ))
                # aliases are transient-only and not persisted to the DB;
                # nothing to register here on a fresh load.
        except Exception as e:
            verbose(f"[VulnerabilitiesController._preload_cache] {e}")
    # ------------------------------------------------------------------

    def get(self, vuln_id: str):
        """Return a vulnerability by id (str) or None if not found. Also look for aliases."""
        if vuln_id in self.vulnerabilities:
            return self.vulnerabilities[vuln_id]
        if vuln_id in self.alias_registered:
            return self.vulnerabilities[self.alias_registered[vuln_id]]
        # Fall back to DB
        try:
            rec = Vulnerability.get_by_id(vuln_id)
            if rec:
                vuln = Vulnerability.from_dict(rec.to_dict())
                self.vulnerabilities[vuln.id] = vuln
                return vuln
        except Exception as e:
            verbose(f"[VulnerabilitiesController.get {vuln_id!r}] {e}")
        return None

    def add(self, vulnerability: Vulnerability) -> Vulnerability:
        """
        Add a vulnerability to the list, merging it with an existing one if present.
        Return the vulnerability as is if added, or the merged vulnerability if already existing.

        Persistence is skipped for vulnerabilities that are already persisted
        and have not gained new packages in this call — avoiding redundant
        get_by_id SELECTs and update_record commits on every re-encounter.
        """
        assert vulnerability is not None
        _caches = dict(
            pkg_id_cache=self.packagesCtrl._db_id_cache,
            finding_cache=self.packagesCtrl._finding_cache,
            db_record_cache=self._db_record_cache,
        )

        def _persist_if_needed(stored: Vulnerability, new_packages: set[str],
                               merged: bool = False) -> None:
            """Persist if this vuln has new packages, hasn't been persisted yet,
            or was just merged with new metadata (texts/CVSS/links).

            The ``persist_from_transient`` method already performs its own
            change detection (comparing in-memory values against the cached DB
            record), so calling it when there are no actual changes is cheap —
            just a dict lookup + a few comparisons — and avoids silently
            dropping metadata updates when only texts/CVSS/links changed
            without new packages.
            """
            canonical_id = stored.id
            known_pkgs = stored._persisted_packages
            if known_pkgs is None:
                # First persist for this vuln
                _persist_vuln_to_db(stored, use_savepoint=self.use_savepoints, **_caches)
                stored._persisted_packages = set(stored.packages)
                self._persisted_ids.add(canonical_id)
            elif (new_packages - known_pkgs) or merged:
                # New packages or metadata may have changed — re-persist.
                _persist_vuln_to_db(stored, use_savepoint=self.use_savepoints, **_caches)
                stored._persisted_packages = set(stored.packages)
            # else: already persisted, nothing new — skip DB entirely

        if vulnerability.id in self.vulnerabilities:
            stored = self.vulnerabilities[vulnerability.id]
            old_pkgs = set(stored.packages)
            stored.merge(vulnerability)
            new_pkgs = set(vulnerability.packages)
            _persist_if_needed(stored, new_pkgs - old_pkgs, merged=True)
            self._encountered_this_run.add(stored.id)
            return stored

        if vulnerability.id in self.alias_registered:
            canonical = self.alias_registered[vulnerability.id]
            stored = self.vulnerabilities[canonical]
            old_pkgs = set(stored.packages)
            stored.merge(vulnerability)
            new_pkgs = set(vulnerability.packages)
            _persist_if_needed(stored, new_pkgs - old_pkgs, merged=True)
            self._encountered_this_run.add(stored.id)
            return stored

        for alias in vulnerability.aliases:
            if alias in self.vulnerabilities:
                self.register_alias(vulnerability.aliases, alias)
                self.register_alias([vulnerability.id], alias)
                stored = self.vulnerabilities[alias]
                old_pkgs = set(stored.packages)
                stored.merge(vulnerability)
                new_pkgs = set(vulnerability.packages)
                _persist_if_needed(stored, new_pkgs - old_pkgs, merged=True)
                self._encountered_this_run.add(stored.id)
                return stored
            if alias in self.alias_registered:
                canonical = self.alias_registered[alias]
                self.register_alias(vulnerability.aliases, canonical)
                self.register_alias([vulnerability.id], canonical)
                stored = self.vulnerabilities[canonical]
                old_pkgs = set(stored.packages)
                stored.merge(vulnerability)
                new_pkgs = set(vulnerability.packages)
                _persist_if_needed(stored, new_pkgs - old_pkgs, merged=True)
                self._encountered_this_run.add(stored.id)
                return stored

        # Genuinely new vulnerability
        self.register_alias(vulnerability.aliases, vulnerability.id)
        self.vulnerabilities[vulnerability.id] = vulnerability
        _persist_if_needed(vulnerability, set(vulnerability.packages))
        self._encountered_this_run.add(vulnerability.id)
        return self.vulnerabilities[vulnerability.id]

    def register_alias(self, alias: list, vuln_id: str):
        """Allow to register an list of alias pointing to a vulnerability id."""
        for a in alias:
            if a not in self.alias_registered and a != vuln_id:
                self.alias_registered[a] = vuln_id

    def remove(self, vuln_id: str) -> bool:
        """Remove a vulnerability by id (str) and return True if removed, False if not found."""
        if vuln_id in self.vulnerabilities:
            del self.vulnerabilities[vuln_id]
            self._persisted_ids.discard(vuln_id)
            aliases_to_remove = []
            for alias, id in self.alias_registered.items():
                if id == vuln_id:
                    aliases_to_remove.append(alias)

            for alias in aliases_to_remove:
                del self.alias_registered[alias]
            return True
        return False

    def fetch_epss_scores(self):
        from ..controllers.epss_progress import EPSSProgressTracker
        start_time = time.time()
        nb_vuln = 0

        refresh_delay = parse_refresh_delay(os.environ.get("REFRESH_REMOTE_DELAY"))

        # Only CVE-prefixed IDs exist in the EPSS database.
        # Bulk-fetch epss_fetched_at timestamps to avoid N+1 queries.
        all_cve_ids = [vid for vid in self.vulnerabilities if vid.startswith("CVE-")]
        fetched_at_map = Vulnerability.get_fetched_at_bulk(all_cve_ids)  # {id: (epss_fa, nvd_fa)}

        cve_vulns = {}
        skipped_non_cve = len(self.vulnerabilities) - len(all_cve_ids)
        skipped_fresh = 0
        for vid in all_cve_ids:
            epss_fa = fetched_at_map.get(vid, (None, None))[0]
            if _should_refetch(epss_fa, refresh_delay):
                cve_vulns[vid] = self.vulnerabilities[vid]
            else:
                skipped_fresh += 1

        total = len(cve_vulns)
        msg = f"=== EPSS: starting enrichment for {total} CVEs"
        if skipped_non_cve:
            msg += f" ({skipped_non_cve} non-CVE IDs skipped)"
        if skipped_fresh:
            msg += f" ({skipped_fresh} already up-to-date, skipped)"
        print(msg, flush=True)

        tracker = EPSSProgressTracker()
        tracker.start("epss_enrichment")
        tracker.update("epss_enrichment", 0, total, f"EPSS enrichment: 0/{total}")

        # Batch in chunks of 100 (FIRST.org API limit).
        # DB commits happen every 500 CVEs to minimise write-transaction overhead.
        BATCH_SIZE = 100
        DB_COMMIT_EVERY = 500
        cve_ids = list(cve_vulns.keys())
        chunks = [cve_ids[i:i + BATCH_SIZE] for i in range(0, len(cve_ids), BATCH_SIZE)]

        processed = 0
        for chunk_idx, chunk in enumerate(chunks, 1):
            try:
                batch_results = self.epss_api.api_get_epss_batch(chunk)
            except Exception as e:
                verbose(f"[fetch_epss_scores batch {chunk_idx}] {e}")
                processed += len(chunk)
                tracker.update("epss_enrichment", processed, total, f"EPSS enrichment: {processed}/{total}")
                continue

            for cve_id in chunk:
                result = batch_results.get(cve_id)
                if result is None:
                    continue
                vuln = cve_vulns[cve_id]
                try:
                    vuln.set_epss(result['score'], result['percentile'])
                    rec = self._db_record_cache.get(cve_id) or Vulnerability.get_by_id(cve_id)
                    if rec is not None:
                        rec.update_record(
                            epss_score=result['score'],
                            epss_fetched_at=datetime.datetime.utcnow(),
                            commit=False,
                        )
                    nb_vuln += 1
                except Exception as e:
                    verbose(f"[fetch_epss_scores {cve_id!r}] {e}")
            processed += len(chunk)
            tracker.update("epss_enrichment", processed, total, f"EPSS enrichment: {processed}/{total}")
            # Commit once every 500 CVEs processed.
            if processed % DB_COMMIT_EVERY < BATCH_SIZE:
                try:
                    db.session.commit()
                    print(f"=== EPSS: committed {processed}/{total}", flush=True)
                except Exception as e:
                    verbose(f"[fetch_epss_scores commit at {processed}] {e}")
                    db.session.rollback()

        # Final commit for any remaining deferred EPSS updates.
        try:
            db.session.commit()
        except Exception as e:
            verbose(f"[fetch_epss_scores final commit] {e}")
            db.session.rollback()

        tracker.complete()
        print(f"=== EPSS: done — enriched {nb_vuln}/{total} CVEs in {time.time() - start_time:.1f}s.", flush=True)

    @staticmethod
    def _fetch_ghsa_published(vuln_id: str) -> Optional[str]:
        """Fetch the published date for a single GHSA advisory (thread-safe)."""
        url = f"https://api.github.com/advisories/{vuln_id}"
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/vnd.github+json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))
                return data.get("published_at")
        except urllib.error.HTTPError as e:
            print(f"Error for {vuln_id}: {e.code}")
        except urllib.error.URLError as e:
            print(f"Error for {vuln_id}: {e.reason}")
        except Exception as e:
            print(f"Error for {vuln_id}: {e}")
        return None

    def fetch_published_dates(self):
        """Fetch published dates for all vulnerabilities from local cache / GHSA API.

        CVE-prefixed IDs are looked up from the local NVD SQLite cache (if
        available).  GHSA-prefixed IDs are fetched from the GitHub Advisories
        API via a thread pool.  All errors are silently caught so that a
        single failure never aborts the whole run.
        """
        import sqlite3
        from concurrent.futures import ThreadPoolExecutor, as_completed

        nvd_db_path = os.path.join(
            os.getenv("VULNSCOUT_CACHE_DIR", "/cache/vulnscout"), "nvd.db"
        )

        # CVE vulns: try local NVD SQLite cache
        for vuln in self.vulnerabilities.values():
            if vuln.id.startswith("CVE-"):
                try:
                    conn = sqlite3.connect(nvd_db_path)
                    cursor = conn.execute(
                        "SELECT published FROM cves WHERE id = ?", (vuln.id,)
                    )
                    row = cursor.fetchone()
                    if row and row[0]:
                        vuln.published = row[0]
                    conn.close()
                except Exception:
                    pass

        # GHSA vulns: fetch via GitHub Advisories API
        ghsa_vulns = {vid: v for vid, v in self.vulnerabilities.items() if "GHSA" in vid}
        if ghsa_vulns:
            max_workers = min(10, len(ghsa_vulns))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_id = {
                    executor.submit(self._fetch_ghsa_published, vid): vid
                    for vid in ghsa_vulns
                }
                for future in as_completed(future_to_id, timeout=60):
                    vid = future_to_id[future]
                    try:
                        published = future.result(timeout=15)
                        if published:
                            ghsa_vulns[vid].published = published
                    except Exception:
                        pass

    def fetch_nvd_data(self):
        """Fetch NVD data (published date, weaknesses, versions_data, patch_url) for all vulnerabilities.

        CVE-prefixed IDs are looked up via the NVD API. GHSA-prefixed IDs use
        the GitHub Advisories API (published date only). Results are written to
        the in-memory vulnerability objects and persisted to the main DB.
        All per-CVE failures are logged and silently skipped so that a single
        unreachable CVE never aborts the whole enrichment run.
        Progress is reported via the NVDProgressTracker singleton so that
        /api/nvd/progress reflects the live enrichment state.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from ..controllers.nvd_progress import NVDProgressTracker

        start_time = time.time()
        nb_vuln = 0

        refresh_delay = parse_refresh_delay(os.environ.get("REFRESH_REMOTE_DELAY"))

        # Bulk-fetch nvd_fetched_at timestamps to avoid N+1 queries.
        all_ids = list(self.vulnerabilities.keys())
        fetched_at_map = Vulnerability.get_fetched_at_bulk(all_ids)  # {id: (epss_fa, nvd_fa)}

        ghsa_vulns = {}
        nvd_vulns = []
        skipped_fresh = 0
        for vuln in self.vulnerabilities.values():
            nvd_fa = fetched_at_map.get(vuln.id, (None, None))[1]
            if not _should_refetch(nvd_fa, refresh_delay):
                skipped_fresh += 1
                continue
            if "GHSA" in vuln.id:
                ghsa_vulns[vuln.id] = vuln
            else:
                nvd_vulns.append(vuln)

        total = len(nvd_vulns) + len(ghsa_vulns)
        msg = f"=== NVD: starting enrichment — {len(nvd_vulns)} CVEs + {len(ghsa_vulns)} GHSAs"
        if skipped_fresh:
            msg += f" ({skipped_fresh} already up-to-date, skipped)"
        print(msg, flush=True)
        tracker = NVDProgressTracker()
        tracker.start("nvd_enrichment")

        # NVD lookups via API
        DB_COMMIT_EVERY = 100
        done = 0
        for vuln in nvd_vulns:
            try:
                result = self.nvd_api.fetch_cve_data(vuln.id)
                if result and result.get("not_found"):
                    # NVD has no record for this CVE (404 or empty result set).
                    # Persist nvd_fetched_at as a sentinel so it is not re-queried
                    # on every restart; _should_refetch will retry after REFRESH_REMOTE_DELAY.
                    print(f"=== NVD: {vuln.id} not found in NVD database.", flush=True)
                    try:
                        rec = self._db_record_cache.get(vuln.id) or Vulnerability.get_by_id(vuln.id)
                        if rec is not None:
                            rec.update_record(nvd_fetched_at=datetime.datetime.utcnow(), commit=False)
                    except Exception as e:
                        verbose(f"[fetch_nvd_data not_found sentinel {vuln.id!r}] {e}")
                elif result:
                    if result.get("published"):
                        vuln.published = result["published"]
                    vuln.weaknesses = result.get("weaknesses")
                    vuln.versions_data = result.get("versions_data")
                    vuln.patch_url = result.get("patch_url")
                    vuln.nvd_last_modified = result.get("lastModified")
                    # Persist the enriched fields
                    try:
                        rec = self._db_record_cache.get(vuln.id) or Vulnerability.get_by_id(vuln.id)
                        if rec is not None:
                            publish_date = None
                            if vuln.published:
                                try:
                                    publish_date = datetime.date.fromisoformat(str(vuln.published)[:10])
                                except ValueError:
                                    pass
                            rec.update_record(
                                publish_date=publish_date or rec.publish_date,
                                weaknesses=vuln.weaknesses,
                                versions_data=vuln.versions_data,
                                patch_url=vuln.patch_url,
                                nvd_last_modified=vuln.nvd_last_modified,
                                nvd_fetched_at=datetime.datetime.utcnow(),
                                commit=False,
                            )
                    except Exception as e:
                        verbose(f"[fetch_nvd_data persist {vuln.id!r}] {e}")
                    nb_vuln += 1
            except Exception as e:
                verbose(f"[fetch_nvd_data {vuln.id!r}] {e}")
            done += 1
            tracker.update("nvd_enrichment", done, total, f"NVD enrichment: {done}/{total} ({vuln.id})")
            if done % DB_COMMIT_EVERY == 0:
                try:
                    db.session.commit()
                    print(f"=== NVD: committed {done}/{total}", flush=True)
                except Exception as e:
                    verbose(f"[fetch_nvd_data commit at {done}] {e}")
                    db.session.rollback()

        # Fetch GHSA dates concurrently with a thread pool and a timeout
        if ghsa_vulns:
            max_workers = min(10, len(ghsa_vulns))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_id = {
                    executor.submit(self._fetch_ghsa_published, vid): vid
                    for vid in ghsa_vulns
                }
                for future in as_completed(future_to_id, timeout=60):
                    vid = future_to_id[future]
                    try:
                        published = future.result(timeout=15)
                        if published:
                            ghsa_vulns[vid].published = published
                            try:
                                publish_date = datetime.date.fromisoformat(str(published)[:10])
                                rec = self._db_record_cache.get(vid) or Vulnerability.get_by_id(vid)
                                if rec is not None:
                                    rec.update_record(
                                        publish_date=publish_date,
                                        nvd_fetched_at=datetime.datetime.utcnow(),
                                        commit=False,
                                    )
                            except Exception as e:
                                verbose(f"[fetch_nvd_data persist GHSA {vid!r}] {e}")
                            nb_vuln += 1
                    except Exception as e:
                        print(f"Error for {vid}: {e}")
                    done += 1
                    tracker.update("nvd_enrichment", done, total, f"NVD enrichment: {done}/{total} ({vid})")

        # Final commit for any remaining deferred NVD/GHSA updates.
        try:
            db.session.commit()
        except Exception as e:
            verbose(f"[fetch_nvd_data final commit] {e}")
            db.session.rollback()
        tracker.complete()
        print(
            f"=== NVD: done — enriched {nb_vuln}/{total} vulnerabilities in {time.time() - start_time:.1f}s.",
            flush=True,
        )

    def to_dict(self) -> dict:
        """Export the list of vulnerabilities preferring in-memory data when available."""
        if self.vulnerabilities:
            return {k: v.to_dict() for k, v in self.vulnerabilities.items()}
        try:
            return {r.id: r.to_dict() for r in Vulnerability.get_all()}
        except Exception as e:
            verbose(f"[VulnerabilitiesController.to_dict] {e}")
            return {}

    @staticmethod
    def from_dict(pkgCtrl, data: dict):
        """
        Import a list of vulnerabilities from a dictionary of dictionaries.
        Require a PackagesController instance.
        Return a new instance of VulnerabilitiesController.
        """
        item = VulnerabilitiesController(pkgCtrl)
        for k, v in data.items():
            item.add(Vulnerability.from_dict(v))
        return item

    def resolve_id(self, vuln_id: str) -> dict:
        """Return a dictionary with the id of the vulnerability and a boolean to indicate if it is an alias."""
        if vuln_id in self.vulnerabilities:
            return {"is_alias": False, "id": vuln_id}
        if vuln_id in self.alias_registered:
            return {"is_alias": True, "id": self.alias_registered[vuln_id]}
        return {"is_alias": False, "id": None}

    def __contains__(self, item):
        """
        Check if the item is in the vulnerabilities list.
        The item can be a Vulnerability class or a string representation of Vulnerability.id.
        """
        if isinstance(item, str):
            if item in self.vulnerabilities:
                return True
            if item in self.alias_registered:
                return True
        elif isinstance(item, Vulnerability):
            if item.id in self.vulnerabilities:
                return True
            if item.id in self.alias_registered:
                return True
        return False

    def __len__(self):
        """Return the number of vulnerabilities in the list."""
        return len(self.vulnerabilities)

    def __iter__(self):
        """Allow iteration over the list of vulnerabilities.

        When the in-memory dict is populated (during scan processing) it is
        used directly — this avoids the expensive DB round-trip + N+1 lazy
        loading that killed performance in the output phase.
        When the in-memory dict is empty (web routes) the DB is queried
        with eager loading instead.
        """
        if self.vulnerabilities:
            yield from self.vulnerabilities.values()
            return
        try:
            for record in Vulnerability.get_all():
                yield Vulnerability.from_dict(record.to_dict())
            return
        except Exception as e:
            verbose(f"[VulnerabilitiesController.__iter__] {e}")

    # ------------------------------------------------------------------
    # DB-level helpers  (merged from VulnerabilityDBController)
    # ------------------------------------------------------------------

    @staticmethod
    def serialize(record: Vulnerability) -> dict:
        """Return a JSON-serialisable dict representation of *record*."""
        return {
            "id": record.id,
            "description": record.description,
            "status": record.status,
            "publish_date": record.publish_date.isoformat() if record.publish_date else None,
            "attack_vector": record.attack_vector,
            "epss_score": float(record.epss_score) if record.epss_score is not None else None,
            "links": record.links or [],
        }

    @staticmethod
    def serialize_list(records: list[Vulnerability]) -> list[dict]:
        """Return a list of serialised vulnerability dicts."""
        return [VulnerabilitiesController.serialize(r) for r in records]

    @staticmethod
    def get_db(vuln_id: str) -> Optional[Vulnerability]:
        """Return the DB record matching *vuln_id*, or ``None``."""
        return Vulnerability.get_by_id(vuln_id)

    @staticmethod
    def get_all_db() -> list[Vulnerability]:
        """Return all vulnerability records from the DB ordered by id."""
        return Vulnerability.get_all()

    @staticmethod
    def create_db(
        vuln_id: str,
        description: Optional[str] = None,
        status: Optional[str] = None,
        publish_date: Optional[datetime.date | str] = None,
        attack_vector: Optional[str] = None,
        epss_score: Optional[float] = None,
        links: Optional[list] = None,
    ) -> Vulnerability:
        """Validate inputs and create a new :class:`Vulnerability` DB record.

        :raises ValueError: if *vuln_id* is empty or blank.
        """
        vuln_id = vuln_id.strip()
        if not vuln_id:
            raise ValueError("Vulnerability id must not be empty.")
        if isinstance(publish_date, str) and publish_date:
            publish_date = datetime.date.fromisoformat(publish_date)
        safe_date: Optional[datetime.date] = publish_date if isinstance(publish_date, datetime.date) else None
        return Vulnerability.create_record(
            id=vuln_id,
            description=description,
            status=status,
            publish_date=safe_date,
            attack_vector=attack_vector,
            epss_score=epss_score,
            links=links,
        )

    @staticmethod
    def get_or_create_db(vuln_id: str, **kwargs) -> Vulnerability:
        """Return an existing record by id, or create and persist a new one.

        :raises ValueError: if *vuln_id* is empty or blank.
        """
        vuln_id = vuln_id.strip()
        if not vuln_id:
            raise ValueError("Vulnerability id must not be empty.")
        return Vulnerability.get_or_create(vuln_id, **kwargs)

    @staticmethod
    def update_db(
        record: Vulnerability | str,
        **kwargs,
    ) -> Vulnerability:
        """Update *record* fields.  *record* may be a model instance or an id string.

        :raises ValueError: if the record is not found.
        """
        if isinstance(record, Vulnerability):
            resolved = record
        else:
            found = Vulnerability.get_by_id(record)
            if found is None:
                raise ValueError("Vulnerability record not found.")
            resolved = found
        return resolved.update_record(**kwargs)

    @staticmethod
    def delete_db(record: Vulnerability | str) -> None:
        """Delete *record*.  *record* may be a model instance or an id string.

        :raises ValueError: if the record is not found.
        """
        if isinstance(record, Vulnerability):
            resolved = record
        else:
            found = Vulnerability.get_by_id(record)
            if found is None:
                raise ValueError("Vulnerability record not found.")
            resolved = found
        resolved.delete_record()

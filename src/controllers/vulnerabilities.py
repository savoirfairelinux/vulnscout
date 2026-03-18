# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import datetime
import time
import sqlite3
import os
import json
import urllib.request
from typing import Optional

from ..models.vulnerability import Vulnerability
from ..controllers.packages import PackagesController
from ..controllers.epss_db import EPSS_DB


def _persist_vuln_to_db(vuln: Vulnerability, pkg_id_cache=None, finding_cache=None, is_new: bool = False) -> None:
    """Silently persist a Vulnerability to the DB.

    Uses a SAVEPOINT so that a failure (e.g. IntegrityError) only rolls
    back this single entity instead of the whole ``batch_session()``
    transaction.

    *pkg_id_cache* and *finding_cache* are optional dicts from
    ``PackagesController`` that avoid redundant SELECT queries.
    *is_new* when ``True`` tells ``persist_from_transient`` to skip
    the ``get_by_id`` SELECT and go straight to INSERT.
    """
    try:
        from ..extensions import db
        with db.session.begin_nested():
            Vulnerability.persist_from_transient(
                vuln,
                pkg_id_cache=pkg_id_cache,
                finding_cache=finding_cache,
                is_new=is_new,
            )
    except Exception:
        pass


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
        self.epss_db = EPSS_DB("/cache/vulnscout/epss.db")
        self.nvd_db_path = os.getenv("NVD_DB_PATH", "/cache/vulnscout/nvd.db")
        self._preload_cache()

    def _preload_cache(self) -> None:
        """Bulk-load all vulnerabilities from the DB into the in-memory caches.

        Called once at construction time so that subsequent :meth:`get` calls
        are pure dict lookups — zero extra SELECTs per vulnerability.

        Populates transient DTO attributes directly from the already
        eager-loaded ``findings`` and ``metrics`` relationships to avoid the
        expensive ``to_dict()`` → ``from_dict()`` serialisation round-trip.
        """
        from ..models.cvss import CVSS
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
                    except Exception:
                        pass
                self.vulnerabilities[rec.id] = rec
                # aliases are transient-only and not persisted to the DB;
                # nothing to register here on a fresh load.
        except Exception:
            pass

    # ------------------------------------------------------------------
    # In-memory management  (used by parsers during scan ingestion)
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
        except Exception:
            pass
        return None

    def add(self, vulnerability: Vulnerability) -> Optional[Vulnerability]:
        """
        Add a vulnerability to the list, merging it with an existing one if present.
        Return the vulnerability as is if added, or the merged vulnerability if already existing.
        """
        if vulnerability is None:
            return
        _caches = dict(
            pkg_id_cache=self.packagesCtrl._db_id_cache,
            finding_cache=self.packagesCtrl._finding_cache,
        )
        if vulnerability.id in self.vulnerabilities:
            self.vulnerabilities[vulnerability.id].merge(vulnerability)
            _persist_vuln_to_db(self.vulnerabilities[vulnerability.id], **_caches)
            return self.vulnerabilities[vulnerability.id]
        if vulnerability.id in self.alias_registered:
            self.vulnerabilities[self.alias_registered[vulnerability.id]].merge(vulnerability)
            _persist_vuln_to_db(self.vulnerabilities[self.alias_registered[vulnerability.id]], **_caches)
            return self.vulnerabilities[self.alias_registered[vulnerability.id]]

        for alias in vulnerability.aliases:
            if alias in self.vulnerabilities:
                self.register_alias(vulnerability.aliases, alias)
                self.register_alias([vulnerability.id], alias)
                self.vulnerabilities[alias].merge(vulnerability)
                _persist_vuln_to_db(self.vulnerabilities[alias], **_caches)
                return self.vulnerabilities[alias]
            if alias in self.alias_registered:
                self.register_alias(vulnerability.aliases, self.alias_registered[alias])
                self.register_alias([vulnerability.id], self.alias_registered[alias])
                self.vulnerabilities[self.alias_registered[alias]].merge(vulnerability)
                _persist_vuln_to_db(self.vulnerabilities[self.alias_registered[alias]], **_caches)
                return self.vulnerabilities[self.alias_registered[alias]]

        self.register_alias(vulnerability.aliases, vulnerability.id)
        self.vulnerabilities[vulnerability.id] = vulnerability
        _persist_vuln_to_db(vulnerability, is_new=True, **_caches)
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
            aliases_to_remove = []
            for alias, id in self.alias_registered.items():
                if id == vuln_id:
                    aliases_to_remove.append(alias)

            for alias in aliases_to_remove:
                del self.alias_registered[alias]
            return True
        return False

    def fetch_epss_scores(self):
        start_time = time.time()
        nb_vuln = 0

        for vuln in self.vulnerabilities.values():
            result = self.epss_db.get_score(vuln.id)
            if result:
                vuln.set_epss(result['score'], result['percentile']),
                nb_vuln += 1

        print(f"Fetched EPSS data for {nb_vuln} vulnerabilities from local DB in {time.time() - start_time} seconds.")

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
        """Fetch published dates from NVD database for all vulnerabilities."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        start_time = time.time()
        nb_vuln = 0

        # Separate GHSA vulns (need HTTP) from NVD vulns (local DB lookup)
        ghsa_vulns = {}
        nvd_vulns = []
        for vuln in self.vulnerabilities.values():
            if "GHSA" in vuln.id:
                ghsa_vulns[vuln.id] = vuln
            else:
                nvd_vulns.append(vuln)

        # Batch NVD lookups from local SQLite DB
        try:
            conn = sqlite3.connect(self.nvd_db_path)
            cursor = conn.cursor()
            for vuln in nvd_vulns:
                result = cursor.execute(
                    "SELECT published FROM nvd_vulns WHERE id = ?;",
                    (vuln.id,)
                ).fetchone()
                if result and result[0]:
                    vuln.published = result[0]
                    nb_vuln += 1
            conn.close()
        except Exception as e:
            print(f"Error fetching published dates from NVD DB: {e}")

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
                            nb_vuln += 1
                    except Exception as e:
                        print(f"Error for {vid}: {e}")

        print(f"Fetched published dates for {nb_vuln} vulnerabilities in {time.time() - start_time:.1f}s.")

    def to_dict(self) -> dict:
        """Export the list of vulnerabilities preferring in-memory data when available."""
        if self.vulnerabilities:
            return {k: v.to_dict() for k, v in self.vulnerabilities.items()}
        try:
            return {r.id: r.to_dict() for r in Vulnerability.get_all()}
        except Exception:
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
        except Exception:
            pass

    # ------------------------------------------------------------------
    # DB-level helpers  (merged from VulnerabilityDBController)
    # ------------------------------------------------------------------

    @staticmethod
    def serialize(record: Vulnerability) -> dict:
        """Return a JSON-serialisable dict representation of *record*."""
        return {
            "id": record.id,
            "description": record.description,
            "yocto_description": record.yocto_description,
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
        yocto_description: Optional[str] = None,
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
            yocto_description=yocto_description,
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

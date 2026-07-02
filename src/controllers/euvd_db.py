# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""ENISA EUVD (European Vulnerability Database) enrichment client.

Two ENISA data dumps are downloaded and cached on disk (both refreshed daily
by ENISA at 07:00 UTC), mirroring the way the ``sbom-cve-check`` engine keeps a
whole advisory database locally instead of querying per-CVE:

1. **Full CVE -> EUVD id mapping** (``/api/dump/cve-euvd-mapping``, ~10 MB CSV
   with ~340k rows of ``euvd_id,cve_id``).  This is the *alias* source: every
   published CVE that ENISA tracks gets its EUVD identifier, independent of any
   exploitation status.

2. **EU KEV dump** (``/api/kev/dump``, small JSON array).  This is the
   *known-exploited* source: the consolidated CISA KEV + ENISA EU KEV list.  It
   feeds the ``euvd_known_exploited`` ("Known exploitable") flag.

Data sources (per https://euvd.enisa.europa.eu/apidoc):
    https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping
    https://euvdservices.enisa.europa.eu/api/kev/dump

The mapping CSV is shaped like::

    euvd_id,cve_id
    EUVD-2021-9696,CVE-2021-22555

The KEV dump is a JSON array of objects shaped like::

    {"cveId": "CVE-2021-22555", "euvdId": "EUVD-2021-9696",
     "dateAdded": "2025-10-06", "sources": ["cisa_kev"]}

Some KEV entries additionally carry ``vendorProject`` / ``product`` fields.
All network/parse failures degrade gracefully (stale cache, then empty) so
enrichment never blocks an existing workflow.
"""

import csv
import io
import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from ..helpers.base_api_client import BaseAPIClient

EUVD_KEV_DUMP_URL = "https://euvdservices.enisa.europa.eu/api/kev/dump"
EUVD_CVE_MAPPING_URL = "https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping"
EUVD_VULNERABILITY_URL = "https://euvd.enisa.europa.eu/vulnerability"

# Cache freshness window: refresh the dumps at most once per day.
CACHE_MAX_AGE_SECONDS = 24 * 60 * 60

# ENISA EUVD identifiers look like ``EUVD-2021-9696``. Validate ids coming from
# the (semi-trusted) ENISA dumps before storing them or building public URLs.
_EUVD_ID_RE = re.compile(r'^EUVD-\d{4}-\d+$')


class EUVD_DB(BaseAPIClient):
    """Client for the ENISA EUVD dumps with on-disk caching.

    Exposes two enrichment sources:

    * :meth:`get_full_mapping` — the complete ``CVE -> EUVD id`` alias map,
      built from the daily CVE-to-EUVD mapping CSV (~340k rows).
    * :meth:`get_mapping` — the EU KEV (known-exploited) map, built from the
      EU KEV JSON dump.

    Both dumps are cached as files under ``$VULNSCOUT_CACHE_DIR/euvd``
    (``/cache/vulnscout/euvd`` by default) and refreshed once a day. All
    network/parse failures degrade gracefully to a stale cache, then to an
    empty result, so enrichment never blocks an existing workflow.
    """

    def __init__(self, cache_dir: Optional[str] = None) -> None:
        super().__init__()
        base = cache_dir or os.getenv("VULNSCOUT_CACHE_DIR") or "/cache/vulnscout"
        euvd_dir = os.path.join(base, "euvd")
        self.cache_path = os.path.join(euvd_dir, "euvd_kev.json")
        self.mapping_cache_path = os.path.join(euvd_dir, "euvd_cve_mapping.csv")

    # ------------------------------------------------------------------
    # Download / cache
    # ------------------------------------------------------------------

    @staticmethod
    def _path_is_fresh(path: str) -> bool:
        try:
            age = time.time() - os.path.getmtime(path)
            return age < CACHE_MAX_AGE_SECONDS
        except OSError:
            return False

    def _cache_is_fresh(self) -> bool:
        return self._path_is_fresh(self.cache_path)

    def _read_cache(self) -> Optional[list]:
        try:
            with open(self.cache_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else None
        except (OSError, json.JSONDecodeError):
            return None

    def _write_cache(self, data: list) -> None:
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            tmp_path = f"{self.cache_path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp_path, self.cache_path)
        except OSError as e:
            print(f"[EUVD] Failed to write cache: {e}", flush=True)

    def download_dump(self, force: bool = False) -> list:
        """Return the EU KEV dump as a list of entries.

        Uses the on-disk cache when it is younger than
        :data:`CACHE_MAX_AGE_SECONDS` unless *force* is ``True``. On network
        failure falls back to any existing (possibly stale) cache, then to an
        empty list.
        """
        if not force and self._cache_is_fresh():
            cached = self._read_cache()
            if cached is not None:
                return cached

        try:
            req = urllib.request.Request(
                EUVD_KEV_DUMP_URL, headers={"Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status != 200:
                    raise urllib.error.HTTPError(
                        EUVD_KEV_DUMP_URL, response.status, "unexpected status", {}, None  # type: ignore[arg-type]
                    )
                # The KEV endpoint returns a top-level JSON array, so decode
                # to ``Any`` rather than the dict-typed base-client helper.
                data: Any = json.loads(response.read().decode())
        except Exception as e:
            print(f"[EUVD] Failed to download dump: {e}", flush=True)
            stale = self._read_cache()
            return stale if stale is not None else []

        # The endpoint returns a top-level array; tolerate a wrapping object.
        if isinstance(data, dict):
            entries = data.get("data") or data.get("items") or []
        else:
            entries = data

        if not isinstance(entries, list):
            return []

        self._write_cache(entries)
        return entries

    def download_mapping(self, force: bool = False) -> str:
        """Return the full CVE -> EUVD id mapping as raw CSV text.

        Downloads the daily ``/api/dump/cve-euvd-mapping`` CSV (~10 MB, ~340k
        rows) and caches it on disk. Uses the on-disk cache when it is younger
        than :data:`CACHE_MAX_AGE_SECONDS` unless *force* is ``True``. On
        network failure falls back to any existing (possibly stale) cache, then
        to an empty string.
        """
        if not force and self._path_is_fresh(self.mapping_cache_path):
            cached = self._read_mapping_cache()
            if cached:
                return cached

        try:
            req = urllib.request.Request(
                EUVD_CVE_MAPPING_URL, headers={"Accept": "text/csv"}
            )
            with urllib.request.urlopen(req, timeout=60) as response:
                if response.status != 200:
                    raise urllib.error.HTTPError(
                        EUVD_CVE_MAPPING_URL, response.status, "unexpected status", {}, None  # type: ignore[arg-type]
                    )
                text = response.read().decode("utf-8")
        except Exception as e:
            print(f"[EUVD] Failed to download CVE mapping: {e}", flush=True)
            stale = self._read_mapping_cache()
            return stale if stale else ""

        # Guard against truncated / unexpected payloads: a valid dump starts
        # with the ``euvd_id,cve_id`` header. Fall back to the cache otherwise.
        first_line = text.splitlines()[0] if text else ""
        if "cve_id" not in first_line:
            stale = self._read_mapping_cache()
            return stale if stale else ""

        self._write_mapping_cache(text)
        return text

    def _read_mapping_cache(self) -> Optional[str]:
        try:
            with open(self.mapping_cache_path, "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return None

    def _write_mapping_cache(self, text: str) -> None:
        try:
            os.makedirs(os.path.dirname(self.mapping_cache_path), exist_ok=True)
            tmp_path = f"{self.mapping_cache_path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.replace(tmp_path, self.mapping_cache_path)
        except OSError as e:
            print(f"[EUVD] Failed to write CVE mapping cache: {e}", flush=True)

    # ------------------------------------------------------------------
    # Mapping
    # ------------------------------------------------------------------

    @staticmethod
    def is_valid_euvd_id(euvd_id: Optional[str]) -> bool:
        """Return ``True`` when *euvd_id* matches the ``EUVD-YYYY-N`` shape."""
        return bool(euvd_id and _EUVD_ID_RE.match(euvd_id))

    @staticmethod
    def parse_cve_mapping(csv_text: str) -> dict[str, str]:
        """Parse the CVE-to-EUVD mapping CSV into an upper-cased ``CVE -> EUVD``.

        The CSV has a ``euvd_id,cve_id`` header. Rows missing either value, or
        carrying a malformed EUVD id, are skipped; the first EUVD id seen for a
        CVE wins. CVE keys are upper-cased so lookups are case-insensitive.
        """
        mapping: dict[str, str] = {}
        if not csv_text:
            return mapping
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            cve = (row.get("cve_id") or "").strip()
            euvd = (row.get("euvd_id") or "").strip()
            if not cve or not EUVD_DB.is_valid_euvd_id(euvd):
                continue
            key = cve.upper()
            if key not in mapping:
                mapping[key] = euvd
        return mapping

    def get_full_mapping(self, force: bool = False) -> dict[str, str]:
        """Download (cached) the full CVE mapping CSV and parse it.

        Returns the complete ``CVE -> EUVD id`` alias map for every published
        CVE that ENISA tracks (independent of exploitation status).
        """
        return self.parse_cve_mapping(self.download_mapping(force=force))

    @staticmethod
    def build_mapping(entries: list) -> dict[str, dict]:
        """Build an upper-cased ``CVE -> {euvd_id, sources, date_added}`` map.

        Entries missing a CVE id, or carrying a missing/malformed EUVD id, are
        skipped. When a CVE appears more than once the first entry wins.
        """
        mapping: dict[str, dict] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            cve_id = entry.get("cveId") or entry.get("cveID")
            euvd_id = entry.get("euvdId") or entry.get("euvdID")
            if not cve_id or not EUVD_DB.is_valid_euvd_id(str(euvd_id) if euvd_id else None):
                continue
            key = str(cve_id).upper()
            if key in mapping:
                continue
            sources = entry.get("sources")
            mapping[key] = {
                "euvd_id": str(euvd_id),
                "sources": sources if isinstance(sources, list) else [],
                "date_added": entry.get("dateAdded"),
            }
        return mapping

    def get_mapping(self, force: bool = False) -> dict[str, dict]:
        """Convenience: download (cached) the dump and build the CVE map."""
        return self.build_mapping(self.download_dump(force=force))

    @staticmethod
    def euvd_url(euvd_id: str) -> str:
        """Return the public ENISA EUVD page URL for *euvd_id*."""
        return f"{EUVD_VULNERABILITY_URL}/{euvd_id}"

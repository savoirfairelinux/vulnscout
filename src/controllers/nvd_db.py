# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import urllib.request
import urllib.parse
import urllib.error
from ..helpers.fixs_scrapper import FixsScrapper
from ..helpers.base_api_client import BaseAPIClient
from typing import Optional, Tuple
import time


class NVD_DB(BaseAPIClient):
    """
    API client for NVD (National Vulnerability Database).
    Fetches CVE data directly from the NVD API without local caching.
    """

    # HTTP status codes that should not be retried (permanent client errors)
    _NON_RETRYABLE_STATUSES = {400, 403, 404}

    def __init__(self, nvd_api_key: Optional[str] = None):
        super().__init__()
        self.nvd_api_key = nvd_api_key or None

    def _call_nvd_api(self, params: dict | None = None) -> Tuple[int, dict]:
        """
        Call the NVD API and return the status code as int and response as a dictionary.
        """
        if params is None:
            params = {}
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)

        headers = {
            'User-Agent': 'vulnscout/1.0 (https://github.com/savoirfairelinux/vulnscout)',
            'Accept': 'application/json',
        }
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key

        from ..helpers.verbose import verbose
        verbose(f"[NVD API] GET {url}")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                resp_status = response.status
                raw = response.read()

            verbose(f"[NVD API] status={resp_status} body_len={len(raw)}")
            try:
                resp_json = json.loads(raw.decode())
            except json.JSONDecodeError:
                print(
                    f"NVD API responded with invalid JSON (status {resp_status}). "
                    f"Body preview: {raw[:200]!r}. "
                    "Adding a free NVD API key can help avoid this error.",
                    flush=True,
                )
                resp_json = {}

            return resp_status, resp_json

        except urllib.error.HTTPError as e:
            body_preview = b""
            try:
                body_preview = e.read(200)
            except Exception:
                pass
            if e.code not in {429}:  # 429 = rate-limited, expected under load
                print(
                    f"NVD API HTTP {e.code} for URL: {url} — {e.reason}. "
                    f"Body preview: {body_preview!r}",
                    flush=True,
                )
            return e.code, {}
        except Exception as e:
            print(f"Error calling NVD API: {e}", flush=True)
            raise e

    def api_get_cve(self, cve_id: str) -> Tuple[int, dict]:
        """
        Call the NVD API to get a specific CVE.
        """
        retry = 0
        status = 0
        while retry <= 3:
            time.sleep(10 * retry)
            status, data = self._call_nvd_api({"cveId": cve_id.strip()})
            if status == 200:
                return status, data
            elif status in self._NON_RETRYABLE_STATUSES:
                return status, data
            else:
                retry += 1
        raise ConnectionError(
            f"Failed to call NVD API after 3 retries (status: {status}, cveId: {cve_id}).\n"
            "Providing an NVD API key may help prevent this error.\n"
            "If the issue persists after adding the API key, it may have been invalidated."
        )

    def api_weaknesses_to_list_str(self, weaknesses: list) -> list[str]:
        """
        Convert a list of weaknesses obtained from API to a list of strings.
        """
        weaks = set([x["value"] for publisher in weaknesses for x in publisher["description"]])
        return list(weaks)

    def api_references_filter_patches(self, references: list) -> list[str]:
        """
        Filter a list of references to get only the ones related to git patches.
        """
        return [x["url"] for x in references if "tags" in x and "Patch" in x["tags"]]

    def fetch_cve_data(self, cve_id: str) -> Optional[dict]:
        """
        Fetch and parse NVD data for a single CVE directly from the API.

        Returns a dict with keys:
            published, lastModified, weaknesses, versions_data, patch_url

        Returns None on transient/connection failures (caller should retry later).
        Returns {"not_found": True} when NVD definitively has no record for this
        CVE (200 with empty result set) — caller should persist a sentinel so
        the CVE is not re-queried on every restart.

        Note: NVD API v2 always returns HTTP 200 for CVE queries — a 404 is
        never a "CVE not found" signal but always a network/proxy problem.
        """
        try:
            status, data = self.api_get_cve(cve_id)
            if status == 404:
                print(
                    f"NVD API returned unexpected HTTP 404 for {cve_id}. "
                    "NVD API v2 always returns HTTP 200 for CVE queries; "
                    "a 404 indicates a network or proxy issue. "
                    "This CVE will be retried on the next sync.",
                    flush=True,
                )
                return None
            if status == 200 and not data.get("vulnerabilities"):
                total = data.get("totalResults", "?")
                print(
                    f"NVD API returned 200 for {cve_id} but 0 results "
                    f"(totalResults={total}). Keys in response: {list(data.keys())}",
                    flush=True,
                )
                return {"not_found": True}
            if status != 200:
                return None
            vuln = data["vulnerabilities"][0]
            cve = vuln["cve"]
            fix_scrapper = FixsScrapper()
            fix_scrapper.search_in_nvd(vuln)
            return {
                "published": cve.get("published"),
                "lastModified": cve.get("lastModified"),
                "weaknesses": (
                    self.api_weaknesses_to_list_str(cve["weaknesses"])
                    if "weaknesses" in cve else []
                ),
                "versions_data": fix_scrapper.list_per_packages(),
                "patch_url": (
                    self.api_references_filter_patches(cve["references"])
                    if "references" in cve else []
                ),
            }
        except ConnectionError:
            print(f"NVD API unavailable for {cve_id}, skipping enrichment.", flush=True)
            return None
        except Exception as e:
            print(f"Error fetching NVD data for {cve_id}: {e}", flush=True)
            return None

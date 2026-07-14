# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""NVD CVE data client — supports both local (NVD-FKIE) and REST API modes.

The preferred mode is **local**: CVE data is sourced from the local NVD-FKIE
git feed managed by sbom-cve-check (see
:func:`~src.controllers.scc_engine.get_cve_json`).  No network calls, no rate
limits, no API key needed.

The **api** mode queries the NVD REST API v2 directly.  An optional API key
(``NVD_API_KEY`` env var or constructor param) increases the rate limit from
5 to 50 requests per 30 seconds.
"""

import json
import os
import urllib.request
import urllib.parse
import urllib.error
import time
from typing import Optional, Tuple

from ..helpers.fixs_scrapper import FixsScrapper
from ..helpers.base_api_client import BaseAPIClient
from .nvd_extract import extract_cve_details, api_weaknesses_to_list_str, api_references_filter_patches


class NVD_DB(BaseAPIClient):
    """NVD CVE data client.

    Re-exports the pure extraction helpers as static methods so existing call
    sites that use ``NVD_DB.extract_cve_details(cve)`` continue to work.
    Also provides the full NVD REST API v2 client for *api* mode.
    """

    # HTTP status codes that should not be retried (permanent client errors)
    _NON_RETRYABLE_STATUSES = {400, 403, 404}

    # Pure extraction helpers — available as both static class methods and
    # module-level functions (imported from nvd_extract).
    extract_cve_details = staticmethod(extract_cve_details)

    def __init__(self, nvd_api_key: Optional[str] = None):
        super().__init__()
        api_key = nvd_api_key if nvd_api_key is not None else os.getenv("NVD_API_KEY")
        self.nvd_api_key = api_key or None

    def _call_nvd_api(self, params: dict | None = None) -> Tuple[int, dict, dict[str, str]]:
        """Call the NVD REST API and return (status, body, headers).

        Header names are normalised to lower-case for case-insensitive lookup.
        """
        if params is None:
            params = {}
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)

        headers: dict[str, str] = {
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
                resp_headers = {k.lower(): v for k, v in response.headers.items()}
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
            return resp_status, resp_json, resp_headers

        except urllib.error.HTTPError as e:
            body_preview = b""
            resp_headers_err: dict[str, str] = {}
            try:
                body_preview = e.read(200)
            except Exception:
                pass
            try:
                if e.headers:
                    resp_headers_err = {k.lower(): v for k, v in e.headers.items()}
            except Exception:
                pass
            if e.code not in {429}:
                print(
                    f"NVD API HTTP {e.code} for URL: {url} — {e.reason}. "
                    f"Body preview: {body_preview!r}",
                    flush=True,
                )
            return e.code, {}, resp_headers_err
        except Exception as exc:
            print(f"Error calling NVD API: {exc}", flush=True)
            raise exc

    def api_get_cve(self, cve_id: str, max_retries: int = 3) -> Tuple[int, dict]:
        """Call the NVD API to get a specific CVE.

        *max_retries* caps retry attempts (default 3).  Pass ``max_retries=0``
        for a single non-blocking attempt suitable for synchronous contexts.
        """
        retry = 0
        status = 0
        data: dict = {}
        while retry <= max_retries:
            time.sleep(10 * retry)
            status, data, _ = self._call_nvd_api({"cveId": cve_id.strip()})
            if status == 200:
                return status, data
            elif status in self._NON_RETRYABLE_STATUSES:
                return status, data
            else:
                retry += 1
        return status, data

    def api_get_cves_by_cpe(
        self,
        cpe_name: str,
        results_per_page: int = 100,
        use_virtual_match: bool = False,
    ) -> list[dict]:
        """Query the NVD API for CVEs matching a CPE name.

        When *use_virtual_match* is ``True`` the ``virtualMatchString`` param is
        sent instead of ``cpeName``.  Handles pagination transparently.
        """
        all_vulns: list[dict] = []
        start_index = 0
        first_request = True
        while True:
            retry = 0
            status = 0
            data: dict = {}
            while retry <= 3:
                if not first_request or retry > 0:
                    time.sleep(max(6, 10 * retry))
                first_request = False
                param_key = "virtualMatchString" if use_virtual_match else "cpeName"
                status, data, _ = self._call_nvd_api({
                    param_key: cpe_name,
                    "startIndex": start_index,
                    "resultsPerPage": results_per_page,
                })
                if status == 200:
                    break
                elif status in self._NON_RETRYABLE_STATUSES:
                    return all_vulns
                else:
                    retry += 1
            if status != 200:
                break
            vulns = data.get("vulnerabilities", [])
            all_vulns.extend(vulns)
            total = data.get("totalResults", 0)
            start_index += results_per_page
            if start_index >= total:
                break
        return all_vulns

    def api_probe_cve(self, cve_id: str) -> Tuple[int, dict, dict[str, str]]:
        """Single direct probe call used by settings key validation."""
        return self._call_nvd_api({"cveId": cve_id.strip()})

    def api_weaknesses_to_list_str(self, weaknesses: list) -> list[str]:
        """Convert a list of weakness objects to a list of CWE strings."""
        return api_weaknesses_to_list_str(weaknesses)

    def api_references_filter_patches(self, references: list) -> list[str]:
        """Filter a list of references to only those tagged as patches."""
        return api_references_filter_patches(references)

    def fetch_cve_data(self, cve_id: str) -> Optional[dict]:
        """Fetch and parse NVD REST API data for a single CVE.

        Returns ``None`` on transient failures; ``{"not_found": True}`` when the
        CVE is definitively absent from NVD.
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
                    api_weaknesses_to_list_str(cve["weaknesses"])
                    if "weaknesses" in cve else []
                ),
                "versions_data": fix_scrapper.list_per_packages(),
                "patch_url": (
                    api_references_filter_patches(cve["references"])
                    if "references" in cve else []
                ),
            }
        except Exception as exc:
            print(f"Error fetching NVD data for {cve_id}: {exc}", flush=True)
            return None

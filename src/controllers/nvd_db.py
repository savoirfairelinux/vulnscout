# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import urllib.request
import urllib.parse
from ..helpers.fixs_scrapper import FixsScrapper
from typing import Optional, Tuple
import time
import sys
import os

sys.tracebacklimit = 0  # disable traceback


class NVD_DB:
    """
    API client for NVD (National Vulnerability Database).
    Fetches CVE data directly from the NVD API without local caching.
    """

    def __init__(self, nvd_api_key: Optional[str] = None):
        self.nvd_api_key = nvd_api_key
        self._setup_proxy()

    def _setup_proxy(self):
        """
        Set up proxy handler if proxy environment variables are set.
        """
        proxies = {}
        if os.getenv('HTTP_PROXY') or os.getenv('http_proxy'):
            proxies['http'] = os.getenv('HTTP_PROXY') or os.getenv('http_proxy')
        if os.getenv('HTTPS_PROXY') or os.getenv('https_proxy'):
            proxies['https'] = os.getenv('HTTPS_PROXY') or os.getenv('https_proxy')

        if proxies:
            proxy_handler = urllib.request.ProxyHandler(proxies)
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)

    def _call_nvd_api(self, params: dict = {}) -> Tuple[int, dict]:
        """
        Call the NVD API and return the status code as int and response as a dictionary.
        """
        txt_params = "&".join(
            [
                f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
                for k, v in params.items()
            ]
        )
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{txt_params}"

        headers = {
            'Content-Type': 'application/json'
        }
        if self.nvd_api_key is not None:
            headers['apiKey'] = self.nvd_api_key

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req) as response:
                resp_status = response.status
                try:
                    resp_json = json.loads(response.read().decode())
                except json.decoder.JSONDecodeError:
                    print("NVD API responded with invalid JSON. Adding an free NVD API key "
                          + f"can help to avoid this error. (status: {resp_status})", flush=True)
                    resp_json = {}

            return resp_status, resp_json

        except urllib.error.HTTPError as e:
            print(f"HTTP Error calling NVD API: {e.code} - {e.reason}", flush=True)
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
            status, data = self._call_nvd_api({"cveId": cve_id})
            if status == 200:
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

    def api_references_filter_patchs(self, references: list) -> list[str]:
        """
        Filter a list of references to get only the ones related to git patches.
        """
        return [x["url"] for x in references if "tags" in x and "Patch" in x["tags"]]

    def fetch_cve_data(self, cve_id: str) -> Optional[dict]:
        """
        Fetch and parse NVD data for a single CVE directly from the API.

        Returns a dict with keys:
            published, lastModified, weaknesses, versions_data, patch_url

        Returns None if the CVE is not found or on any API/parse failure.
        """
        try:
            status, data = self.api_get_cve(cve_id)
            if status != 200 or not data.get("vulnerabilities"):
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
                    self.api_references_filter_patchs(cve["references"])
                    if "references" in cve else []
                ),
            }
        except ConnectionError:
            print(f"NVD API unavailable for {cve_id}, skipping enrichment.", flush=True)
            return None
        except Exception as e:
            print(f"Error fetching NVD data for {cve_id}: {e}", flush=True)
            return None

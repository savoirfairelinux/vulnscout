# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import urllib.request
import urllib.parse
import json
from typing import Optional
import os

EPSS_API_URL = "https://api.first.org/data/1.0/epss"


class EPSS_DB:
    """
    API client for EPSS (Exploit Prediction Scoring System).
    Fetches scores directly from the FIRST.org API without local caching.
    """

    def __init__(self):
        self._setup_proxy()

    def _setup_proxy(self):
        """Set up proxy handler if proxy environment variables are set."""
        proxies = {}
        if os.getenv('HTTP_PROXY') or os.getenv('http_proxy'):
            proxies['http'] = os.getenv('HTTP_PROXY') or os.getenv('http_proxy')
        if os.getenv('HTTPS_PROXY') or os.getenv('https_proxy'):
            proxies['https'] = os.getenv('HTTPS_PROXY') or os.getenv('https_proxy')

        if proxies:
            proxy_handler = urllib.request.ProxyHandler(proxies)
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)

    def api_get_epss(self, cve_id: str) -> Optional[dict]:
        """
        Fetch the EPSS score for a single CVE directly from the FIRST.org API.

        Returns a dict with keys ``score`` (float) and ``percentile`` (float),
        or ``None`` if the CVE has no EPSS entry or on any failure.
        """
        try:
            url = f"{EPSS_API_URL}?cve={urllib.parse.quote(cve_id, safe='')}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status != 200:
                    return None
                data = json.loads(response.read().decode())
                entries = data.get("data", [])
                if entries:
                    entry = entries[0]
                    return {
                        "score": float(entry["epss"]),
                        "percentile": float(entry["percentile"]),
                    }
                return None
        except Exception as e:
            print(f"Error fetching EPSS for {cve_id}: {e}", flush=True)
            return None

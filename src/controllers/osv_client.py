# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""
Lightweight client for the OSV.dev API (https://api.osv.dev).

No API key is required.  The main endpoint used is:
  POST https://api.osv.dev/v1/query   — query by PURL
"""

import json
import urllib.request
import urllib.error
import time


OSV_API_BASE = "https://api.osv.dev/v1"


class OSVClient:
    """Query the OSV.dev API for vulnerabilities by PURL."""

    def __init__(self, timeout: int = 30):
        self._timeout = timeout

    def query_by_purl(self, purl: str, retries: int = 3) -> list[dict]:
        """Query OSV for vulnerabilities affecting *purl*.

        Returns a (possibly empty) list of vulnerability objects.
        Each object follows the OSV schema:
          https://ossf.github.io/osv-schema/
        """
        body = json.dumps({"package": {"purl": purl}}).encode("utf-8")
        url = f"{OSV_API_BASE}/query"

        for attempt in range(retries):
            if attempt > 0:
                time.sleep(min(2 ** attempt, 10))
            try:
                req = urllib.request.Request(
                    url,
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data.get("vulns", [])
            except urllib.error.HTTPError as e:
                if e.code in (400, 404):
                    # Bad PURL or not found — don't retry
                    return []
                if attempt == retries - 1:
                    raise
            except (urllib.error.URLError, TimeoutError, OSError):
                if attempt == retries - 1:
                    raise
        return []

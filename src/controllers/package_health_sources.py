# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Read-only JSON clients for OpenSSF Scorecard, deps.dev and OSV (no API key required)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

SCORECARD_API = "https://api.scorecard.dev"
DEPSDEV_API = "https://api.deps.dev/v3"
OSV_API = "https://api.osv.dev/v1"
GITHUB_API = "https://api.github.com"
USER_AGENT = "VulnScout (+https://github.com/savoirfairelinux/vulnscout)"


class JsonApi:
    """GET JSON documents below a fixed base URL; every path segment is percent-encoded."""

    def __init__(self, base_url: str, timeout: float = 15.0, retries: int = 3, backoff: float = 1.0,
                 headers: dict[str, str] | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = max(1, retries)
        self.backoff = backoff
        self.headers = {"Accept": "application/json", "User-Agent": USER_AGENT, **(headers or {})}

    def get(self, *segments: str) -> dict | None:
        """Return the decoded document, ``None`` on 400/404, or raise once retries are exhausted."""
        url = "/".join([self.base_url, *(urllib.parse.quote(segment, safe="") for segment in segments)])
        request = urllib.request.Request(url, headers=self.headers)
        attempt = 0
        while True:
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                return payload if isinstance(payload, dict) else None
            except urllib.error.HTTPError as error:
                if error.code in (400, 404):
                    return None
                failure: Exception = error
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
                failure = error
            attempt += 1
            if attempt >= self.retries:
                raise failure
            time.sleep(self.backoff * 2 ** (attempt - 1))

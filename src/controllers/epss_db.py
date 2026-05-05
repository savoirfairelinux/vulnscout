# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import urllib.request
import urllib.parse
import urllib.error
from typing import Optional
from ..helpers.base_api_client import BaseAPIClient

EPSS_API_URL = "https://api.first.org/data/v1/epss"


class EPSS_DB(BaseAPIClient):
    """
    API client for EPSS (Exploit Prediction Scoring System).
    Fetches scores directly from the FIRST.org API without local caching.
    """

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
                data = self._decode_response_json(response)
                entries = data.get("data", [])
                if entries:
                    entry = entries[0]
                    return {
                        "score": float(entry["epss"]),
                        "percentile": float(entry["percentile"]),
                    }
                return None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None  # CVE has no EPSS score — not an error
            print(f"Error fetching EPSS for {cve_id}: {e}", flush=True)
            return None
        except Exception as e:
            print(f"Error fetching EPSS for {cve_id}: {e}", flush=True)
            return None

    def api_get_epss_batch(self, cve_ids: list[str]) -> dict[str, dict]:
        """
        Fetch EPSS scores for a batch of CVE IDs in a single API call.

        The FIRST.org API accepts up to 100 comma-separated CVE IDs per request.
        Returns a dict mapping each CVE ID that has a score to
        ``{"score": float, "percentile": float}``.
        CVE IDs with no score are absent from the returned dict.
        """
        if not cve_ids:
            return {}
        try:
            encoded = ",".join(urllib.parse.quote(c, safe='') for c in cve_ids)
            url = f"{EPSS_API_URL}?cve={encoded}&limit={len(cve_ids)}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status != 200:
                    return {}
                data = self._decode_response_json(response)
                results = {}
                for entry in data.get("data", []):
                    cve = entry.get("cve")
                    if cve:
                        results[cve] = {
                            "score": float(entry["epss"]),
                            "percentile": float(entry["percentile"]),
                        }
                return results
        except urllib.error.HTTPError as e:
            print(f"Error fetching EPSS batch: {e}", flush=True)
            return {}
        except Exception as e:
            print(f"Error fetching EPSS batch: {e}", flush=True)
            return {}

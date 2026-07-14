# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Pure extraction helpers for NVD CVE JSON.

These functions operate on the raw NVD CVE dict as returned by the
NVD API v2 *and* as stored in the local NVD-FKIE git feed — both use
the same JSON schema.
"""

from __future__ import annotations

import datetime


def extract_cve_details(cve: dict) -> dict:
    """Extract description, severity, links, weaknesses from an NVD CVE dict.

    *cve* is the ``cve`` object from a single entry — either from
    ``vulnerabilities[n]["cve"]`` (NVD API) or directly from a FKIE
    advisory JSON file. Returns a dict with keys matching the
    ``Vulnerability.update_record`` / ``create_record`` signature.
    """
    # Description — prefer English
    description = None
    for desc in cve.get("descriptions", []):
        if desc.get("lang", "").startswith("en"):
            description = desc.get("value")
            break
    if description is None:
        descs = cve.get("descriptions", [])
        if descs:
            description = descs[0].get("value")

    # Severity label + base score — try CVSS v3.1, v3.0, v4.0, v2.0
    severity = None
    base_score = None
    attack_vector = None
    cvss_version = None
    cvss_vector = None
    cvss_exploitability = None
    cvss_impact = None
    metrics = cve.get("metrics", {})
    _metric_version_map = {
        "cvssMetricV31": "3.1",
        "cvssMetricV30": "3.0",
        "cvssMetricV40": "4.0",
        "cvssMetricV2": "2.0",
    }
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, [])
        if metric_list:
            primary = next(
                (m for m in metric_list if m.get("type") == "Primary"),
                metric_list[0],
            )
            cvss_data = primary.get("cvssData", {})
            severity = (
                primary.get("baseSeverity")
                or cvss_data.get("baseSeverity")
                or ""
            ).lower() or None
            base_score = cvss_data.get("baseScore")
            attack_vector = cvss_data.get("attackVector")
            cvss_version = _metric_version_map.get(metric_key)
            cvss_vector = cvss_data.get("vectorString")
            cvss_exploitability = primary.get("exploitabilityScore")
            cvss_impact = primary.get("impactScore")
            break

    # References / links
    links = [
        ref.get("url")
        for ref in cve.get("references", [])
        if ref.get("url")
    ]
    # Always include the NVD detail page
    cve_id = cve.get("id", "")
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    if nvd_url not in links:
        links.insert(0, nvd_url)

    # Published date
    published = cve.get("published")
    publish_date = None
    if published:
        try:
            publish_date = datetime.date.fromisoformat(str(published)[:10])
        except ValueError:
            pass

    # Weaknesses
    weaknesses = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val and val not in weaknesses:
                weaknesses.append(val)

    return {
        "description": description,
        "status": severity,
        "base_score": base_score,
        "attack_vector": attack_vector,
        "cvss_version": cvss_version,
        "cvss_vector": cvss_vector,
        "cvss_exploitability": cvss_exploitability,
        "cvss_impact": cvss_impact,
        "links": links,
        "publish_date": publish_date,
        "weaknesses": weaknesses or None,
        "nvd_last_modified": cve.get("lastModified"),
    }


def api_weaknesses_to_list_str(weaknesses: list) -> list[str]:
    """Flatten a NVD ``weaknesses`` list to a deduplicated list of strings."""
    return list({x["value"] for publisher in weaknesses for x in publisher["description"]})


def api_references_filter_patches(references: list) -> list[str]:
    """Filter a NVD ``references`` list to URLs tagged as patches."""
    return [x["url"] for x in references if "tags" in x and "Patch" in x["tags"]]

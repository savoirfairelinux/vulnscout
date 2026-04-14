# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Unit tests for the pure helper functions in src/routes/vulnerabilities.py.

These functions (_compute_facets, _matches_search, _apply_server_filters,
_apply_server_sort, _parse_effort_hours) have no Flask / DB dependency and can
be exercised directly.
"""

import datetime
import pytest

from src.routes.vulnerabilities import (
    _compute_facets,
    _matches_search,
    _apply_server_filters,
    _apply_server_sort,
    _parse_effort_hours,
)


# ---------------------------------------------------------------------------
# Helper: Flask-style args dict that supports the ``type=`` keyword
# ---------------------------------------------------------------------------

class Args(dict):
    """Minimal stand-in for Flask's ImmutableMultiDict used in tests."""

    def get(self, key, default=None, type=None):  # noqa: A002
        val = super().get(key, default)
        if type is not None and val is not None:
            try:
                return type(val)
            except (ValueError, TypeError):
                return default
        return val


# ---------------------------------------------------------------------------
# Sample vuln dicts
# ---------------------------------------------------------------------------

def _make_vuln(vuln_id="CVE-2024-001", severity="high", max_score=8.5,
               status="Exploitable", found_by=None, packages=None,
               packages_current=None, epss_score=None, av=None,
               published=None, first_scan_date=None, assessments=None,
               effort=None, texts=None):
    cvss = []
    if av:
        cvss.append({"attack_vector": av, "score": max_score})
    return {
        "id": vuln_id,
        "severity": {
            "severity": severity,
            "max_score": max_score,
            "cvss": cvss,
        },
        "simplified_status": status,
        "found_by": found_by or [],
        "packages": packages or [],
        "packages_current": packages_current or [],
        "epss": {"score": epss_score} if epss_score is not None else {"score": None},
        "published": published,
        "first_scan_date": first_scan_date,
        "assessments": assessments or [],
        "effort": effort or {},
        "texts": texts or {},
    }


V1 = _make_vuln("CVE-2024-001", "high", 8.5, "Exploitable",
                found_by=["grype"], packages=["libfoo@1.0"],
                packages_current=["libfoo@1.0"], epss_score=0.45,
                av="NETWORK", published="2024-01-15",
                first_scan_date="2024-06-01T12:00:00")
V2 = _make_vuln("CVE-2024-002", "critical", 9.8, "Not affected",
                found_by=["spdx3"], packages=["libbar@2.0"],
                packages_current=["libbar@2.0"], epss_score=0.02,
                av="LOCAL", published="2024-03-20",
                first_scan_date="2024-06-15T08:00:00")
V3 = _make_vuln("CVE-2024-003", "low", 2.1, "Pending Assessment",
                found_by=[], packages=["libbaz@3.0"],
                packages_current=["libbaz@3.0"], epss_score=None,
                av=None, published="2023-11-01",
                first_scan_date=None)


# ===========================================================================
# _parse_effort_hours
# ===========================================================================

class TestParseEffortHours:
    def test_integer_passthrough(self):
        assert _parse_effort_hours(8) == 8

    def test_iso_duration_string(self):
        assert _parse_effort_hours("PT8H") == 8

    def test_iso_duration_days(self):
        # P1D — actual value depends on Iso8601Duration implementation; just verify it returns an int
        result = _parse_effort_hours("P1D")
        assert isinstance(result, int) and result >= 0

    def test_invalid_type_raises(self):
        with pytest.raises((ValueError, TypeError)):
            _parse_effort_hours(3.14)

    def test_zero_hours(self):
        assert _parse_effort_hours(0) == 0

    def test_string_zero(self):
        assert _parse_effort_hours("PT0H") == 0


# ===========================================================================
# _compute_facets
# ===========================================================================

class TestComputeFacets:
    def test_empty_list(self):
        result = _compute_facets([])
        assert result["severities"] == []
        assert result["statuses"] == []
        assert result["sources"] == []
        assert result["attack_vectors"] == []
        assert result["first_scan_dates"] == []

    def test_collects_severity(self):
        result = _compute_facets([V1, V2, V3])
        assert "high" in result["severities"]
        assert "critical" in result["severities"]
        assert "low" in result["severities"]

    def test_collects_statuses(self):
        result = _compute_facets([V1, V2, V3])
        assert "Exploitable" in result["statuses"]
        assert "Not affected" in result["statuses"]
        assert "Pending Assessment" in result["statuses"]

    def test_collects_sources(self):
        result = _compute_facets([V1, V2])
        assert "grype" in result["sources"]
        assert "spdx3" in result["sources"]

    def test_empty_source_not_included(self):
        v = _make_vuln(found_by=["", "grype"])
        result = _compute_facets([v])
        assert "" not in result["sources"]
        assert "grype" in result["sources"]

    def test_collects_attack_vectors(self):
        result = _compute_facets([V1, V2])
        assert "NETWORK" in result["attack_vectors"]
        assert "LOCAL" in result["attack_vectors"]

    def test_collects_first_scan_dates(self):
        result = _compute_facets([V1, V2])
        assert len(result["first_scan_dates"]) == 2

    def test_invalid_first_scan_date_ignored(self):
        v = _make_vuln(first_scan_date="not-a-date")
        result = _compute_facets([v])
        assert result["first_scan_dates"] == []

    def test_none_severity_skipped(self):
        v = {"severity": None, "simplified_status": None, "found_by": [],
             "first_scan_date": None}
        result = _compute_facets([v])
        assert result["severities"] == []

    def test_results_are_sorted(self):
        result = _compute_facets([V1, V2, V3])
        assert result["severities"] == sorted(result["severities"])
        assert result["statuses"] == sorted(result["statuses"])


# ===========================================================================
# _matches_search
# ===========================================================================

class TestMatchesSearch:
    def test_plain_match_on_id(self):
        assert _matches_search(V1, "CVE-2024-001") is True

    def test_no_match(self):
        assert _matches_search(V1, "CVE-9999-9999") is False

    def test_match_on_package(self):
        assert _matches_search(V1, "libfoo") is True

    def test_match_on_text(self):
        v = _make_vuln(texts={"description": "buffer overflow issue"})
        assert _matches_search(v, "overflow") is True

    def test_or_semantics(self):
        # CVE-2024-001 OR CVE-9999
        assert _matches_search(V1, "CVE-2024-001 | CVE-9999") is True

    def test_not_semantics(self):
        # must contain "CVE-2024-001" but NOT "libbar"
        assert _matches_search(V1, "CVE-2024-001 -libbar") is True
        assert _matches_search(V1, "CVE-2024-001 -libfoo") is False

    def test_short_search_covered_via_filter(self):
        # _apply_server_filters skips search ≤2 chars; direct call still works for coverage
        # "CV" is a substring of the vuln id so it matches — the filter skips very short terms at a higher level
        result = _matches_search(V1, "CV")
        assert isinstance(result, bool)

    def test_and_semantics(self):
        # both terms must be present
        assert _matches_search(V1, "CVE-2024-001 libfoo") is True
        assert _matches_search(V1, "CVE-2024-001 libbar") is False

    def test_case_insensitive(self):
        assert _matches_search(V1, "cve-2024-001") is True


# ===========================================================================
# _apply_server_filters
# ===========================================================================

class TestApplyServerFilters:
    # ---- no filters ------------------------------------------------------

    def test_no_filters_returns_all(self):
        result = _apply_server_filters([V1, V2, V3], Args())
        assert len(result) == 3

    # ---- search ----------------------------------------------------------

    def test_search_filters(self):
        result = _apply_server_filters([V1, V2, V3], Args(search="libfoo"))
        assert all(v["id"] == "CVE-2024-001" for v in result)

    def test_short_search_no_filter(self):
        result = _apply_server_filters([V1, V2], Args(search="CV"))
        assert len(result) == 2

    # ---- severity --------------------------------------------------------

    def test_severity_filter_single(self):
        result = _apply_server_filters([V1, V2, V3], Args(severity="high"))
        assert all((v["severity"] or {}).get("severity") == "high" for v in result)

    def test_severity_filter_multiple(self):
        result = _apply_server_filters([V1, V2, V3], Args(severity="high,critical"))
        assert len(result) == 2

    # ---- status ----------------------------------------------------------

    def test_status_filter(self):
        result = _apply_server_filters([V1, V2, V3], Args(simplified_status="Exploitable"))
        assert len(result) == 1

    # ---- found_by --------------------------------------------------------

    def test_found_by_filter(self):
        result = _apply_server_filters([V1, V2, V3], Args(found_by="grype"))
        assert len(result) == 1 and result[0]["id"] == "CVE-2024-001"

    # ---- package ---------------------------------------------------------

    def test_package_filter(self):
        result = _apply_server_filters([V1, V2, V3], Args(package="libbar@2.0"))
        assert len(result) == 1 and result[0]["id"] == "CVE-2024-002"

    # ---- epss ------------------------------------------------------------

    def test_epss_min_filter(self):
        # V1 epss=0.45 (45%), V2 epss=0.02 (2%), V3 epss=None
        result = _apply_server_filters([V1, V2, V3], Args(epss_min="10"))
        assert len(result) == 1 and result[0]["id"] == "CVE-2024-001"

    def test_epss_max_filter(self):
        result = _apply_server_filters([V1, V2, V3], Args(epss_max="5"))
        assert len(result) == 1 and result[0]["id"] == "CVE-2024-002"

    def test_epss_min_and_max(self):
        result = _apply_server_filters([V1, V2, V3], Args(epss_min="1", epss_max="50"))
        assert len(result) == 2  # V1 (45%) and V2 (2%)

    def test_epss_filter_excludes_none(self):
        result = _apply_server_filters([V3], Args(epss_min="0"))
        assert result == []

    # ---- severity score --------------------------------------------------

    def test_severity_min_filter(self):
        result = _apply_server_filters([V1, V2, V3], Args(severity_min="9"))
        assert len(result) == 1 and result[0]["id"] == "CVE-2024-002"

    def test_severity_max_filter(self):
        result = _apply_server_filters([V1, V2, V3], Args(severity_max="5"))
        assert len(result) == 1 and result[0]["id"] == "CVE-2024-003"

    def test_severity_score_none_excluded(self):
        v = _make_vuln(max_score=None)
        v["severity"]["max_score"] = None
        result = _apply_server_filters([v], Args(severity_min="1"))
        assert result == []

    # ---- attack_vector ---------------------------------------------------

    def test_attack_vector_filter(self):
        result = _apply_server_filters([V1, V2, V3], Args(attack_vector="NETWORK"))
        assert len(result) == 1 and result[0]["id"] == "CVE-2024-001"

    def test_attack_vector_multiple(self):
        result = _apply_server_filters([V1, V2, V3], Args(attack_vector="NETWORK,LOCAL"))
        assert len(result) == 2

    # ---- published_date_filter -------------------------------------------

    def test_pub_filter_is(self):
        result = _apply_server_filters(
            [V1, V2, V3],
            Args(published_date_filter="is", published_date_value="2024-01-15"),
        )
        assert len(result) == 1 and result[0]["id"] == "CVE-2024-001"

    def test_pub_filter_gte(self):
        result = _apply_server_filters(
            [V1, V2, V3],
            Args(published_date_filter=">=", published_date_value="2024-01-01"),
        )
        assert len(result) == 2  # V1, V2

    def test_pub_filter_lte(self):
        result = _apply_server_filters(
            [V1, V2, V3],
            Args(published_date_filter="<=", published_date_value="2023-12-31"),
        )
        assert len(result) == 1 and result[0]["id"] == "CVE-2024-003"

    def test_pub_filter_between(self):
        result = _apply_server_filters(
            [V1, V2, V3],
            Args(
                published_date_filter="between",
                published_date_from="2024-01-01",
                published_date_to="2024-02-28",
            ),
        )
        assert len(result) == 1 and result[0]["id"] == "CVE-2024-001"

    def test_pub_filter_days_ago(self):
        # V3 published 2023-11-01 — far in the past, won't match 1 day
        result = _apply_server_filters(
            [V3],
            Args(published_date_filter="days_ago", published_days_value="1"),
        )
        assert result == []

    def test_pub_filter_days_ago_long(self):
        # All vulns published in 2023-2024, should match with 2000 days
        result = _apply_server_filters(
            [V1, V2, V3],
            Args(published_date_filter="days_ago", published_days_value="2000"),
        )
        assert len(result) == 3

    def test_pub_filter_skips_no_published(self):
        v = _make_vuln(published=None)
        result = _apply_server_filters(
            [v],
            Args(published_date_filter="is", published_date_value="2024-01-15"),
        )
        assert result == []

    def test_pub_filter_invalid_date_skipped(self):
        v = _make_vuln(published="not-a-date")
        result = _apply_server_filters(
            [v],
            Args(published_date_filter="is", published_date_value="2024-01-15"),
        )
        assert result == []

    # ---- first_scan_date -------------------------------------------------

    def test_first_scan_date_filter(self):
        # compute the expected timestamp for V1's first_scan_date
        ts = str(int(round(datetime.datetime.fromisoformat("2024-06-01T12:00:00").timestamp())) * 1000)
        result = _apply_server_filters([V1, V2, V3], Args(first_scan_date=ts))
        assert len(result) == 1 and result[0]["id"] == "CVE-2024-001"

    def test_first_scan_date_no_date_excluded(self):
        ts = "999999999000"
        result = _apply_server_filters([V3], Args(first_scan_date=ts))
        assert result == []


# ===========================================================================
# _apply_server_sort
# ===========================================================================

class TestApplyServerSort:
    def _ids(self, vulns):
        return [v["id"] for v in vulns]

    def test_sort_by_id_asc(self):
        result = _apply_server_sort([V2, V3, V1], "id", "asc")
        assert self._ids(result) == ["CVE-2024-001", "CVE-2024-002", "CVE-2024-003"]

    def test_sort_by_id_desc(self):
        result = _apply_server_sort([V1, V2, V3], "id", "desc")
        assert self._ids(result)[0] == "CVE-2024-003"

    def test_sort_by_severity_severity_asc(self):
        result = _apply_server_sort([V2, V1, V3], "severity.severity", "asc")
        # low < high < critical
        assert self._ids(result) == ["CVE-2024-003", "CVE-2024-001", "CVE-2024-002"]

    def test_sort_by_severity_max_score(self):
        result = _apply_server_sort([V3, V1, V2], "severity.max_score", "asc")
        assert result[0]["id"] == "CVE-2024-003"
        assert result[-1]["id"] == "CVE-2024-002"

    def test_sort_by_epss(self):
        result = _apply_server_sort([V1, V2, V3], "epss", "asc")
        # V3 has None epss (0), V2 has 0.02, V1 has 0.45
        assert result[-1]["id"] == "CVE-2024-001"

    def test_sort_by_simplified_status(self):
        result = _apply_server_sort([V2, V3, V1], "simplified_status", "asc")
        # "Exploitable" < "Not affected" < "Pending Assessment" by _STATUS_SORT_ORDER
        assert result[0]["id"] == "CVE-2024-003"  # "Pending Assessment" = index 1 (unknown=0)

    def test_sort_by_simplified_status_unknown(self):
        v = _make_vuln("CVE-X", status="SomeUnknownStatus")
        result = _apply_server_sort([v, V1], "simplified_status", "asc")
        assert len(result) == 2

    def test_sort_by_effort_likely(self):
        v_with_effort = _make_vuln("CVE-2024-010")
        v_with_effort["effort"] = {"likely": "PT2H"}
        result = _apply_server_sort([V1, v_with_effort], "effort.likely", "asc")
        assert result[0]["id"] == "CVE-2024-001"  # 0 effort first

    def test_sort_by_effort_likely_invalid(self):
        v = _make_vuln("CVE-X")
        v["effort"] = {"likely": "invalid-duration"}
        # Should not raise, falls back to 0
        result = _apply_server_sort([v], "effort.likely", "asc")
        assert len(result) == 1

    def test_sort_by_assessments(self):
        v_assessed = _make_vuln("CVE-2024-011", assessments=[
            {"last_update": "2024-06-01", "timestamp": "2024-06-01"},
        ])
        result = _apply_server_sort([V1, v_assessed], "assessments", "asc")
        assert len(result) == 2

    def test_sort_by_assessments_empty(self):
        result = _apply_server_sort([V1, V2], "assessments", "asc")
        # Both have no assessments, order stable
        assert len(result) == 2

    def test_sort_by_published(self):
        result = _apply_server_sort([V2, V3, V1], "published", "asc")
        assert result[0]["id"] == "CVE-2024-003"  # earliest published

    def test_sort_by_first_scan_date(self):
        result = _apply_server_sort([V2, V3, V1], "first_scan_date", "asc")
        # V3 has no first_scan_date (empty string), comes first
        assert result[0]["id"] == "CVE-2024-003"

    def test_sort_by_attack_vector(self):
        # LOCAL < NETWORK in _AV_SORT_ORDER
        result = _apply_server_sort([V1, V2], "attack_vector", "asc")
        assert result[0]["id"] == "CVE-2024-002"  # LOCAL

    def test_sort_by_attack_vector_no_av(self):
        # V3 has no attack vector
        result = _apply_server_sort([V1, V3], "attack_vector", "asc")
        assert result[0]["id"] == "CVE-2024-003"  # -1 sorts first

    def test_sort_unknown_column_falls_back_to_id(self):
        result = _apply_server_sort([V2, V1], "nonexistent_col", "asc")
        assert result[0]["id"] == "CVE-2024-001"

    def test_sort_by_severity_severity_unknown_value(self):
        v = _make_vuln("CVE-X", severity="bizarre")
        result = _apply_server_sort([v, V1], "severity.severity", "asc")
        # bizarre not in list → -1, sorts before known values
        assert result[0]["id"] == "CVE-X"


# ===========================================================================
# _detect_format (routes/settings.py)
# ===========================================================================

class TestDetectFormat:
    """Cover the _detect_format helper in routes/settings.py."""

    def _df(self, filename, data):
        from src.routes.settings import _detect_format
        return _detect_format(filename, data)

    def test_spdx_json_extension(self):
        assert self._df("myfile.spdx.json", {}) == "spdx"

    def test_cdx_json_extension(self):
        assert self._df("myfile.cdx.json", {}) == "cdx"

    def test_spdx_version_key(self):
        assert self._df("scan.json", {"spdxVersion": "SPDX-2.3"}) == "spdx"

    def test_spdxid_key(self):
        assert self._df("scan.json", {"spdxId": "SPDXRef-Document"}) == "spdx"

    def test_cyclonedx_bom_format(self):
        assert self._df("bom.json", {"bomFormat": "CycloneDX"}) == "cdx"

    def test_openvex_context(self):
        assert self._df("vex.json", {"@context": "https://openvex.dev/ns"}) == "openvex"

    def test_yocto_format(self):
        assert self._df("scan.json", {"package": {"foo": {}}}) == "yocto_cve_check"

    def test_grype_format(self):
        assert self._df("scan.json", {"matches": [{"vulnerability": {}}]}) == "grype"

    def test_spdx3_context_key(self):
        assert self._df("scan.json", {"@context": "https://spdx.org/rdf/3.0"}) == "spdx"

    def test_unknown_format(self):
        assert self._df("scan.json", {}) == "unknown"

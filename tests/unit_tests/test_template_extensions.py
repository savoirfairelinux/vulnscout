# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.views.templates import TemplatesExtensions


class MockEnv:
    def __init__(self):
        self.filters = {}
        self.globals = {}


@pytest.fixture
def extensions():
    main = MockEnv()
    TemplatesExtensions(main)
    return main


def test_status(extensions):
    vulns = [{"status": "in_triage"}, {"status": "affected"}, {"status": "resolved"}]
    assert extensions.filters["status"](vulns, "in_triage") == [{"status": "in_triage"}]
    assert extensions.filters["status"](vulns, "none") == []
    assert extensions.filters["status"](vulns, None) == []
    allow = ["affected", "resolved"]
    assert extensions.filters["status"](vulns, allow) == [{"status": "affected"}, {"status": "resolved"}]

    assert extensions.filters["status_active"](vulns) == [{"status": "in_triage"}, {"status": "affected"}]


def test_severity(extensions):
    a = {"severity": {"severity": "low"}}
    b = {"severity": {"severity": "medium"}}
    c = {"severity": {"severity": "high"}}
    vulns = [a, b, c]
    assert extensions.filters["severity"](vulns, "medium") == [b]
    assert extensions.filters["severity"](vulns, "none") == []
    assert extensions.filters["severity"](vulns, None) == []
    assert extensions.filters["severity"](vulns, ["low", "high"]) == [a, c]


def test_limit_results(extensions):
    vulns = [{"id": "1"}, {"id": "2"}, {"id": "3"}]
    assert extensions.filters["limit"](vulns, 2) == [{"id": "1"}, {"id": "2"}]
    assert extensions.filters["limit"](vulns, 0) == []
    assert extensions.filters["limit"](vulns, 4) == [{"id": "1"}, {"id": "2"}, {"id": "3"}]


def test_filter_epss(extensions):
    a = {"epss": {"score": 0.5}}
    b = {"epss": {"score": 0.3}}
    c = {"epss": {"score": 0.7}}
    vulns = [a, b, c]
    vulns_dict = {"a": a, "b": b, "c": c}
    assert extensions.filters["epss_score"](vulns, 50) == [a, c]
    assert extensions.filters["epss_score"](vulns_dict, 50) == [a, c]

    assert extensions.filters["sort_by_epss"](vulns) == [c, a, b]
    assert extensions.filters["sort_by_epss"](vulns_dict) == [c, a, b]


def test_sort_by_effort(extensions):
    a = {"effort": {"likely": "PT5H"}}
    b = {"effort": {"likely": "PT20M"}}
    c = {"effort": {"likely": "P1W"}}
    vulns = [a, b, c]
    vulns_dict = {"a": a, "b": b, "c": c}
    assert extensions.filters["sort_by_effort"](vulns) == [c, a, b]
    assert extensions.filters["sort_by_effort"](vulns_dict) == [c, a, b]


def test_pretty_iso8601(extensions):
    assert extensions.filters["print_iso8601"](None) == "N/A"
    assert extensions.filters["print_iso8601"]("2020-05-01T00:00:00") == "2020 May 01 - 00:00"
    assert extensions.filters["print_iso8601"]("2020-12-01T00:00:00+01:00") == "2020 Dec 01 - 00:00"
    assert extensions.filters["print_iso8601"]("P0D") == "N/A"
    assert extensions.filters["print_iso8601"]("P4D") == "4d"
    assert extensions.filters["print_iso8601"]("P10D") == "2w"
    assert extensions.filters["print_iso8601"]("P3Y2M1W4DT6H5M") == "3y 2mo 1w 4d 6h 5m"


def test_sort_by_last_modified(extensions):
    a = {"last_assessment": {"timestamp": "2020-08-01T03:00:00"}}
    b = {"last_assessment": {"timestamp": "2020-05-01T04:00:00"}}
    c = {"last_assessment": {"timestamp": "2024-01-01T00:00:00"}}
    vulns = [a, b, c]
    vulns_dict = {"a": a, "b": b, "c": c}
    assert extensions.filters["sort_by_last_modified"](vulns) == [c, a, b]
    assert extensions.filters["sort_by_last_modified"](vulns_dict) == [c, a, b]


def test_filter_last_assessment_date_greater_than(extensions):
    """Test filtering with > operator"""
    a = {"last_assessment": {"timestamp": "2026-01-01T10:00:00"}}
    b = {"last_assessment": {"timestamp": "2026-01-02T15:00:00"}}
    c = {"last_assessment": {"timestamp": "2025-12-31T23:59:59"}}
    vulns = [a, b, c]
    
    # After 2026-01-01 (exclusive - should not include anything on that day)
    result = extensions.filters["last_assessment_date"](vulns, ">2026-01-01")
    assert result == [b]
    
    # Test with dict input
    vulns_dict = {"a": a, "b": b, "c": c}
    result = extensions.filters["last_assessment_date"](vulns_dict, ">2026-01-01")
    assert result == [b]


def test_filter_last_assessment_date_greater_than_or_equal(extensions):
    """Test filtering with >= operator"""
    a = {"last_assessment": {"timestamp": "2026-01-01T10:00:00"}}
    b = {"last_assessment": {"timestamp": "2026-01-02T15:00:00"}}
    c = {"last_assessment": {"timestamp": "2025-12-31T23:59:59"}}
    vulns = [a, b, c]
    
    # After or on 2026-01-01 (inclusive)
    result = extensions.filters["last_assessment_date"](vulns, ">=2026-01-01")
    assert result == [a, b]


def test_filter_last_assessment_date_less_than(extensions):
    """Test filtering with < operator"""
    a = {"last_assessment": {"timestamp": "2026-01-01T10:00:00"}}
    b = {"last_assessment": {"timestamp": "2026-01-02T15:00:00"}}
    c = {"last_assessment": {"timestamp": "2025-12-31T23:59:59"}}
    vulns = [a, b, c]
    
    # Before 2026-01-02 (exclusive - should not include anything on that day)
    result = extensions.filters["last_assessment_date"](vulns, "<2026-01-02")
    assert result == [a, c]


def test_filter_last_assessment_date_less_than_or_equal(extensions):
    """Test filtering with <= operator"""
    a = {"last_assessment": {"timestamp": "2026-01-01T10:00:00"}}
    b = {"last_assessment": {"timestamp": "2026-01-02T15:00:00"}}
    c = {"last_assessment": {"timestamp": "2025-12-31T23:59:59"}}
    vulns = [a, b, c]
    
    # Before or on 2026-01-01 (inclusive)
    result = extensions.filters["last_assessment_date"](vulns, "<=2026-01-01")
    assert result == [a, c]


def test_filter_last_assessment_date_range(extensions):
    """Test filtering with date range"""
    a = {"last_assessment": {"timestamp": "2026-01-01T10:00:00"}}
    b = {"last_assessment": {"timestamp": "2026-01-15T15:00:00"}}
    c = {"last_assessment": {"timestamp": "2026-01-31T23:59:59"}}
    d = {"last_assessment": {"timestamp": "2026-02-01T00:00:00"}}
    vulns = [a, b, c, d]
    
    # Between 2026-01-01 and 2026-01-31 (inclusive)
    result = extensions.filters["last_assessment_date"](vulns, "2026-01-01..2026-01-31")
    assert result == [a, b, c]


def test_filter_last_assessment_date_exact(extensions):
    """Test filtering with exact date"""
    a = {"last_assessment": {"timestamp": "2026-01-01T10:00:00"}}
    b = {"last_assessment": {"timestamp": "2026-01-01T23:59:59"}}
    c = {"last_assessment": {"timestamp": "2026-01-02T00:00:00"}}
    d = {"last_assessment": {"timestamp": "2025-12-31T23:59:59"}}
    vulns = [a, b, c, d]
    
    # Exact date 2026-01-01 (includes all times on that day)
    result = extensions.filters["last_assessment_date"](vulns, "2026-01-01")
    assert result == [a, b]


def test_filter_last_assessment_date_no_assessment(extensions):
    """Test filtering when vulnerabilities have no last_assessment"""
    a = {"last_assessment": {"timestamp": "2026-01-01T10:00:00"}}
    b = {}  # No last_assessment
    c = {"last_assessment": None}  # None last_assessment
    d = {"last_assessment": {}}  # No timestamp
    vulns = [a, b, c, d]
    
    result = extensions.filters["last_assessment_date"](vulns, ">2025-12-31")
    assert result == [a]


def test_filter_last_assessment_date_invalid_format(extensions):
    """Test that invalid date formats return all vulnerabilities"""
    a = {"last_assessment": {"timestamp": "2026-01-01T10:00:00"}}
    b = {"last_assessment": {"timestamp": "2026-01-02T15:00:00"}}
    vulns = [a, b]
    
    # Invalid date format should return all
    result = extensions.filters["last_assessment_date"](vulns, "invalid-date")
    assert result == vulns
    
    # Invalid range format should return all
    result = extensions.filters["last_assessment_date"](vulns, "2026-01-01..2026-01-02..2026-01-03")
    assert result == vulns


def test_filter_last_assessment_date_invalid_timestamp(extensions):
    """Test that invalid timestamps in vulnerabilities are handled gracefully"""
    a = {"last_assessment": {"timestamp": "2026-01-01T10:00:00"}}
    b = {"last_assessment": {"timestamp": "invalid-timestamp"}}
    c = {"last_assessment": {"timestamp": "2026-01-02T15:00:00"}}
    vulns = [a, b, c]
    
    # Should only include valid dates that match the filter
    result = extensions.filters["last_assessment_date"](vulns, ">=2026-01-01")
    assert result == [a, c]


def test_filter_publish_date_greater_than(extensions):
    """Test filtering with > operator"""
    a = {"published": "2026-01-01T10:00:00"}
    b = {"published": "2026-01-02T15:00:00"}
    c = {"published": "2025-12-31T23:59:59"}
    vulns = [a, b, c]
    
    # After 2026-01-01 (exclusive - should not include anything on that day)
    result = extensions.filters["filter_by_publish_date"](vulns, ">2026-01-01")
    assert result == [b]
    
    # Test with dict input
    vulns_dict = {"a": a, "b": b, "c": c}
    result = extensions.filters["filter_by_publish_date"](vulns_dict, ">2026-01-01")
    assert result == [b]


def test_filter_publish_date_greater_than_or_equal(extensions):
    """Test filtering with >= operator"""
    a = {"published": "2026-01-01T10:00:00"}
    b = {"published": "2026-01-02T15:00:00"}
    c = {"published": "2025-12-31T23:59:59"}
    vulns = [a, b, c]
    
    # After or on 2026-01-01 (inclusive)
    result = extensions.filters["filter_by_publish_date"](vulns, ">=2026-01-01")
    assert result == [a, b]


def test_filter_publish_date_less_than(extensions):
    """Test filtering with < operator"""
    a = {"published": "2026-01-01T10:00:00"}
    b = {"published": "2026-01-02T15:00:00"}
    c = {"published": "2025-12-31T23:59:59"}
    vulns = [a, b, c]
    
    # Before 2026-01-02 (exclusive - should not include anything on that day)
    result = extensions.filters["filter_by_publish_date"](vulns, "<2026-01-02")
    assert result == [a, c]


def test_filter_publish_date_less_than_or_equal(extensions):
    """Test filtering with <= operator"""
    a = {"published": "2026-01-01T10:00:00"}
    b = {"published": "2026-01-02T15:00:00"}
    c = {"published": "2025-12-31T23:59:59"}
    vulns = [a, b, c]
    
    # Before or on 2026-01-01 (inclusive)
    result = extensions.filters["filter_by_publish_date"](vulns, "<=2026-01-01")
    assert result == [a, c]


def test_filter_publish_date_range(extensions):
    """Test filtering with date range"""
    a = {"published": "2026-01-01T10:00:00"}
    b = {"published": "2026-01-15T15:00:00"}
    c = {"published": "2026-01-31T23:59:59"}
    d = {"published": "2026-02-01T00:00:00"}
    vulns = [a, b, c, d]
    
    # Between 2026-01-01 and 2026-01-31 (inclusive)
    result = extensions.filters["filter_by_publish_date"](vulns, "2026-01-01..2026-01-31")
    assert result == [a, b, c]


def test_filter_publish_date_exact(extensions):
    """Test filtering with exact date"""
    a = {"published": "2026-01-01T10:00:00"}
    b = {"published": "2026-01-01T23:59:59"}
    c = {"published": "2026-01-02T00:00:00"}
    d = {"published": "2025-12-31T23:59:59"}
    vulns = [a, b, c, d]
    
    # Exact date 2026-01-01 (includes all times on that day)
    result = extensions.filters["filter_by_publish_date"](vulns, "2026-01-01")
    assert result == [a, b]


def test_filter_publish_date_no_publish_data(extensions):
    """Test filtering when vulnerabilities have no published field"""
    a = {"published": "2026-01-01T10:00:00"}
    b = {}  # No published field
    c = {"published": None}  # None published
    vulns = [a, b, c]
    
    result = extensions.filters["filter_by_publish_date"](vulns, ">2025-12-31")
    assert result == [a]


def test_filter_publish_date_invalid_format(extensions):
    """Test that invalid date formats return all vulnerabilities"""
    a = {"published": "2026-01-01T10:00:00"}
    b = {"published": "2026-01-02T15:00:00"}
    vulns = [a, b]
    
    # Invalid date format should return all
    result = extensions.filters["filter_by_publish_date"](vulns, "invalid-date")
    assert result == vulns
    
    # Invalid range format should return all
    result = extensions.filters["filter_by_publish_date"](vulns, "2026-01-01..2026-01-02..2026-01-03")
    assert result == vulns


def test_filter_publish_date_invalid_timestamp(extensions):
    """Test that invalid timestamps in vulnerabilities are handled gracefully"""
    a = {"published": "2026-01-01T10:00:00"}
    b = {"published": "invalid-timestamp"}
    c = {"published": "2026-01-02T15:00:00"}
    vulns = [a, b, c]
    
    # Should only include valid dates that match the filter
    result = extensions.filters["filter_by_publish_date"](vulns, ">=2026-01-01")
    assert result == [a, c]


def test_filter_publish_date_include_unknown(extensions):
    """Test filtering with include_unknown parameter"""
    a = {"published": "2026-01-01T10:00:00"}
    b = {"published": "2026-01-02T15:00:00"}
    c = {}  # No published field
    d = {"published": None}  # None published
    e = {"published": "2025-12-31T23:59:59"}
    vulns = [a, b, c, d, e]
    
    # Test without include_unknown (default) - should only include items matching date filter
    result = extensions.filters["filter_by_publish_date"](vulns, ">2026-01-01")
    assert result == [b]
    
    # Test with include_unknown=True - should include matching dates + unknown items
    result = extensions.filters["filter_by_publish_date"](vulns, ">2026-01-01", True)
    assert result == [b, c, d]


def test_filter_publish_date_include_unknown_gte(extensions):
    """Test include_unknown=True with >= operator"""
    a = {"published": "2026-01-02T10:00:00"}
    b = {}  # No published field
    c = {"published": None}
    d = {"published": "2025-12-31T23:59:59"}
    vulns = [a, b, c, d]

    result = extensions.filters["filter_by_publish_date"](vulns, ">=2026-01-01", True)
    assert result == [a, b, c]


def test_filter_publish_date_include_unknown_lte(extensions):
    """Test include_unknown=True with <= operator"""
    a = {"published": "2026-01-01T10:00:00"}
    b = {}  # No published field
    c = {"published": None}
    d = {"published": "2026-01-02T00:00:00"}
    vulns = [a, b, c, d]

    result = extensions.filters["filter_by_publish_date"](vulns, "<=2026-01-01", True)
    assert result == [a, b, c]


def test_filter_publish_date_include_unknown_lt(extensions):
    """Test include_unknown=True with < operator"""
    a = {"published": "2025-12-31T10:00:00"}
    b = {}  # No published field
    c = {"published": None}
    d = {"published": "2026-01-02T00:00:00"}
    vulns = [a, b, c, d]

    result = extensions.filters["filter_by_publish_date"](vulns, "<2026-01-01", True)
    assert result == [a, b, c]


def test_filter_publish_date_include_unknown_range(extensions):
    """Test include_unknown=True with range operator"""
    a = {"published": "2026-01-15T10:00:00"}
    b = {}  # No published field
    c = {"published": None}
    d = {"published": "2026-02-01T00:00:00"}
    vulns = [a, b, c, d]

    result = extensions.filters["filter_by_publish_date"](vulns, "2026-01-01..2026-01-31", True)
    assert result == [a, b, c]


def test_filter_publish_date_include_unknown_exact(extensions):
    """Test include_unknown=True with exact date"""
    a = {"published": "2026-01-01T10:00:00"}
    b = {}  # No published field
    c = {"published": None}
    d = {"published": "2026-01-02T10:00:00"}
    vulns = [a, b, c, d]

    result = extensions.filters["filter_by_publish_date"](vulns, "2026-01-01", True)
    assert result == [a, b, c]


def test_filter_last_assessment_date_timezone_aware(extensions):
    """Test filter_last_assessment_date with timezone-aware timestamps (astimezone branch)"""
    # timezone-aware timestamps (with +HH:MM) hit the else:.astimezone() branch
    a = {"last_assessment": {"timestamp": "2026-01-01T12:00:00+02:00"}}  # = 2026-01-01T10:00Z
    b = {"last_assessment": {"timestamp": "2026-01-02T00:00:00+00:00"}}  # = 2026-01-02T00:00Z
    c = {"last_assessment": {"timestamp": "2025-12-31T23:00:00-01:00"}}  # = 2026-01-01T00:00Z
    vulns = [a, b, c]

    # range filter
    result = extensions.filters["last_assessment_date"](vulns, "2026-01-01..2026-01-01")
    assert a in result
    assert c in result
    assert b not in result

    # >= filter
    result = extensions.filters["last_assessment_date"](vulns, ">=2026-01-02")
    assert result == [b]

    # > filter
    result = extensions.filters["last_assessment_date"](vulns, ">2026-01-01")
    assert result == [b]

    # <= filter
    result = extensions.filters["last_assessment_date"](vulns, "<=2026-01-01")
    assert a in result
    assert c in result
    assert b not in result

    # < filter
    result = extensions.filters["last_assessment_date"](vulns, "<2026-01-01")
    assert result == []

    # exact filter
    result = extensions.filters["last_assessment_date"](vulns, "2026-01-01")
    assert a in result
    assert c in result
    assert b not in result


def test_filter_publish_date_timezone_aware(extensions):
    """Test filter_publish_date with timezone-aware published timestamps (astimezone branch)"""
    a = {"published": "2026-01-01T12:00:00+02:00"}  # = 2026-01-01T10:00Z
    b = {"published": "2026-01-02T00:00:00+00:00"}  # = 2026-01-02T00:00Z
    c = {"published": "2025-12-31T23:00:00-01:00"}  # = 2026-01-01T00:00Z
    vulns = [a, b, c]

    # range filter
    result = extensions.filters["filter_by_publish_date"](vulns, "2026-01-01..2026-01-01")
    assert a in result
    assert c in result
    assert b not in result

    # >= filter
    result = extensions.filters["filter_by_publish_date"](vulns, ">=2026-01-02")
    assert result == [b]

    # > filter
    result = extensions.filters["filter_by_publish_date"](vulns, ">2026-01-01")
    assert result == [b]

    # <= filter
    result = extensions.filters["filter_by_publish_date"](vulns, "<=2026-01-01")
    assert a in result
    assert c in result
    assert b not in result

    # < filter
    result = extensions.filters["filter_by_publish_date"](vulns, "<2026-01-01")
    assert result == []

    # exact filter
    result = extensions.filters["filter_by_publish_date"](vulns, "2026-01-01")
    assert a in result
    assert c in result
    assert b not in result


# ---------------------------------------------------------------------------
# Exception handler coverage for filter_last_assessment_date
# These tests trigger the defensive except-branches in each filter operator.
# ---------------------------------------------------------------------------

class TestFilterLastAssessmentDateExceptions:
    """Cover the inner (invalid timestamp) and outer (invalid filter date) exception handlers."""

    VALID_VULN = {"last_assessment": {"timestamp": "2026-06-15T12:00:00"}}
    INVALID_TS_VULN = {"last_assessment": {"timestamp": "not-a-date"}}
    NO_ASSESS_VULN = {"other": "data"}

    def test_range_filter_inner_exception(self, extensions):
        """Inner exception: invalid timestamp inside range filter (lines 335-336)."""
        vulns = [self.VALID_VULN, self.INVALID_TS_VULN]
        result = extensions.filters["last_assessment_date"](vulns, "2026-01-01..2026-12-31")
        assert self.VALID_VULN in result
        assert self.INVALID_TS_VULN not in result

    def test_range_filter_outer_exception(self, extensions):
        """Outer exception: unparseable date range returns all (lines 337-338)."""
        vulns = [self.VALID_VULN]
        result = extensions.filters["last_assessment_date"](vulns, "INVALID-DATE..ALSO-INVALID")
        assert result == vulns

    def test_gte_filter_outer_exception(self, extensions):
        """Outer exception: unparseable >=filter date returns all (lines 357-358)."""
        vulns = [self.VALID_VULN]
        result = extensions.filters["last_assessment_date"](vulns, ">=NOT-A-DATE")
        assert result == vulns

    def test_gt_filter_inner_exception(self, extensions):
        """Inner exception: invalid timestamp inside > filter (lines 375-376)."""
        vulns = [self.VALID_VULN, self.INVALID_TS_VULN]
        result = extensions.filters["last_assessment_date"](vulns, ">2026-01-01")
        assert self.VALID_VULN in result
        assert self.INVALID_TS_VULN not in result

    def test_gt_filter_outer_exception(self, extensions):
        """Outer exception: unparseable >filter date returns all (lines 377-378)."""
        vulns = [self.VALID_VULN]
        result = extensions.filters["last_assessment_date"](vulns, ">NOT-A-DATE")
        assert result == vulns

    def test_lte_filter_inner_exception(self, extensions):
        """Inner exception: invalid timestamp inside <= filter (lines 395-396)."""
        vulns = [self.VALID_VULN, self.INVALID_TS_VULN]
        result = extensions.filters["last_assessment_date"](vulns, "<=2026-12-31")
        assert self.VALID_VULN in result
        assert self.INVALID_TS_VULN not in result

    def test_lte_filter_outer_exception(self, extensions):
        """Outer exception: unparseable <=filter date returns all (lines 397-398)."""
        vulns = [self.VALID_VULN]
        result = extensions.filters["last_assessment_date"](vulns, "<=NOT-A-DATE")
        assert result == vulns

    def test_lt_filter_inner_exception(self, extensions):
        """Inner exception: invalid timestamp inside < filter (lines 415-416)."""
        vulns = [self.INVALID_TS_VULN]
        result = extensions.filters["last_assessment_date"](vulns, "<2027-01-01")
        assert result == []

    def test_lt_filter_outer_exception(self, extensions):
        """Outer exception: unparseable <filter date returns all (lines 417-418)."""
        vulns = [self.VALID_VULN]
        result = extensions.filters["last_assessment_date"](vulns, "<NOT-A-DATE")
        assert result == vulns

    def test_exact_filter_inner_exception(self, extensions):
        """Inner exception: invalid timestamp inside exact date filter (covers inner except)."""
        vulns = [self.VALID_VULN, self.INVALID_TS_VULN]
        result = extensions.filters["last_assessment_date"](vulns, "2026-06-15")
        assert self.VALID_VULN in result
        assert self.INVALID_TS_VULN not in result

    def test_exact_filter_outer_exception(self, extensions):
        """Outer exception: unparseable exact date returns all (lines 437-438)."""
        vulns = [self.VALID_VULN]
        result = extensions.filters["last_assessment_date"](vulns, "NOT-A-DATE")
        assert result == vulns


# ---------------------------------------------------------------------------
# Exception handler coverage for filter_publish_date
# ---------------------------------------------------------------------------

class TestFilterPublishDateExceptions:
    """Cover the inner (invalid published date) and outer (invalid filter) exception handlers."""

    VALID_VULN = {"published": "2026-06-15T12:00:00"}
    INVALID_PUB_VULN = {"published": "not-a-date"}
    NO_PUB_VULN = {"other": "data"}

    def test_range_filter_inner_exception(self, extensions):
        """Inner exception: invalid published date inside range filter (lines 499-500)."""
        vulns = [self.VALID_VULN, self.INVALID_PUB_VULN]
        result = extensions.filters["filter_by_publish_date"](vulns, "2026-01-01..2026-12-31")
        assert self.VALID_VULN in result
        assert self.INVALID_PUB_VULN not in result

    def test_range_filter_outer_exception(self, extensions):
        """Outer exception: unparseable date range returns all (lines 505-506)."""
        vulns = [self.VALID_VULN]
        result = extensions.filters["filter_by_publish_date"](vulns, "INVALID..INVALID")
        assert result == vulns

    def test_gte_filter_inner_exception(self, extensions):
        """Inner exception: invalid published date inside >= filter (lines ~520)."""
        vulns = [self.VALID_VULN, self.INVALID_PUB_VULN]
        result = extensions.filters["filter_by_publish_date"](vulns, ">=2026-01-01")
        assert self.VALID_VULN in result
        assert self.INVALID_PUB_VULN not in result

    def test_gte_filter_outer_exception(self, extensions):
        """Outer exception: unparseable >=filter date returns all (lines 529-530)."""
        vulns = [self.VALID_VULN]
        result = extensions.filters["filter_by_publish_date"](vulns, ">=NOT-A-DATE")
        assert result == vulns

    def test_gt_filter_inner_exception(self, extensions):
        """Inner exception: invalid published date inside > filter (lines ~540)."""
        vulns = [self.VALID_VULN, self.INVALID_PUB_VULN]
        result = extensions.filters["filter_by_publish_date"](vulns, ">2026-01-01")
        assert self.VALID_VULN in result
        assert self.INVALID_PUB_VULN not in result

    def test_gt_filter_outer_exception(self, extensions):
        """Outer exception: unparseable >filter date returns all (lines 547-548)."""
        vulns = [self.VALID_VULN]
        result = extensions.filters["filter_by_publish_date"](vulns, ">NOT-A-DATE")
        assert result == vulns

    def test_lte_filter_inner_exception(self, extensions):
        """Inner exception: invalid published date inside <= filter (lines ~560)."""
        vulns = [self.VALID_VULN, self.INVALID_PUB_VULN]
        result = extensions.filters["filter_by_publish_date"](vulns, "<=2026-12-31")
        assert self.VALID_VULN in result
        assert self.INVALID_PUB_VULN not in result

    def test_lte_filter_outer_exception(self, extensions):
        """Outer exception: unparseable <=filter date returns all (lines 553-554)."""
        vulns = [self.VALID_VULN]
        result = extensions.filters["filter_by_publish_date"](vulns, "<=NOT-A-DATE")
        assert result == vulns

    def test_lt_filter_inner_exception(self, extensions):
        """Inner exception: invalid published date inside < filter (lines ~575)."""
        vulns = [self.INVALID_PUB_VULN]
        result = extensions.filters["filter_by_publish_date"](vulns, "<2027-01-01")
        assert result == []

    def test_lt_filter_outer_exception(self, extensions):
        """Outer exception: unparseable <filter date returns all (lines 571-572)."""
        vulns = [self.VALID_VULN]
        result = extensions.filters["filter_by_publish_date"](vulns, "<NOT-A-DATE")
        assert result == vulns

    def test_exact_filter_inner_exception(self, extensions):
        """Inner exception: invalid published date inside exact date filter (lines ~590)."""
        vulns = [self.VALID_VULN, self.INVALID_PUB_VULN]
        result = extensions.filters["filter_by_publish_date"](vulns, "2026-06-15")
        assert self.VALID_VULN in result
        assert self.INVALID_PUB_VULN not in result

    def test_exact_filter_outer_exception(self, extensions):
        """Outer exception: unparseable exact date returns all (lines 621-622)."""
        vulns = [self.VALID_VULN]
        result = extensions.filters["filter_by_publish_date"](vulns, "NOT-A-DATE")
        assert result == vulns


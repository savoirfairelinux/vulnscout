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

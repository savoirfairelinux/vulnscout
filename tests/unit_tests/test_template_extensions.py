# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.views.templates import TemplatesExtensions


class MockEnv:
    def __init__(self):
        self.filters = {}


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

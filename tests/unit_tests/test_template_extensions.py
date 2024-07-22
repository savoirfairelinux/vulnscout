# -*- coding: utf-8 -*-
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
    assert extensions.filters["epss_score"](vulns, 50) == [a, c]
    assert extensions.filters["sort_by_epss"](vulns) == [c, a, b]

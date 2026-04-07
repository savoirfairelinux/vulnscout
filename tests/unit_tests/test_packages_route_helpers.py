# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Unit tests for helper functions in src/routes/packages.py."""

import pytest
from src.routes.packages import _score_to_severity, _SEVERITY_INDEX


class TestScoreToSeverity:
    """Tests for _score_to_severity()."""

    def test_none_returns_none(self):
        assert _score_to_severity(None) == "NONE"

    def test_zero_returns_none(self):
        assert _score_to_severity(0) == "NONE"

    def test_below_4_returns_low(self):
        assert _score_to_severity(0.1) == "LOW"
        assert _score_to_severity(1.0) == "LOW"
        assert _score_to_severity(3.9) == "LOW"

    def test_4_returns_medium(self):
        assert _score_to_severity(4.0) == "MEDIUM"

    def test_between_4_and_7_returns_medium(self):
        assert _score_to_severity(5.5) == "MEDIUM"
        assert _score_to_severity(6.9) == "MEDIUM"

    def test_7_returns_high(self):
        assert _score_to_severity(7.0) == "HIGH"

    def test_between_7_and_9_returns_high(self):
        assert _score_to_severity(8.0) == "HIGH"
        assert _score_to_severity(8.9) == "HIGH"

    def test_9_returns_critical(self):
        assert _score_to_severity(9.0) == "CRITICAL"

    def test_above_9_returns_critical(self):
        assert _score_to_severity(9.5) == "CRITICAL"
        assert _score_to_severity(10.0) == "CRITICAL"


class TestSeverityIndex:
    """Tests for _SEVERITY_INDEX ordering consistency."""

    def test_none_lowest(self):
        assert _SEVERITY_INDEX["NONE"] < _SEVERITY_INDEX["LOW"]

    def test_low_less_than_medium(self):
        assert _SEVERITY_INDEX["LOW"] < _SEVERITY_INDEX["MEDIUM"]

    def test_medium_less_than_high(self):
        assert _SEVERITY_INDEX["MEDIUM"] < _SEVERITY_INDEX["HIGH"]

    def test_high_less_than_critical(self):
        assert _SEVERITY_INDEX["HIGH"] < _SEVERITY_INDEX["CRITICAL"]

    def test_unknown_between_none_and_low(self):
        assert _SEVERITY_INDEX["NONE"] < _SEVERITY_INDEX["UNKNOWN"]
        assert _SEVERITY_INDEX["UNKNOWN"] < _SEVERITY_INDEX["LOW"]

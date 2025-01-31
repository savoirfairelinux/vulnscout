# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.models.iso8601_duration import Iso8601Duration


@pytest.fixture
def full_duration():
    return Iso8601Duration("P1.25Y2M3W4DT5.5H6M7.20S")


@pytest.fixture
def overloaded_duration():
    return Iso8601Duration("P1Y11M3W4DT10H59M70S")


def test_parse_complete_string(full_duration):
    """
    GIVEN an ISO 8601 with all field filled
    WHEN the string is parsed
    THEN the duration is correctly set
    """
    assert full_duration.years == 1
    assert full_duration.months == 5    # 0.25Y = 3M
    assert full_duration.weeks == 3
    assert full_duration.days == 4
    assert full_duration.hours == 5
    assert full_duration.minutes == 36  # 0.5H = 30M
    assert full_duration.seconds == 7   # truncated from 7.20S
    assert str(full_duration) == "P1Y5M3W4DT5H36M7S"
    assert full_duration.__repr__() == "Iso8601Duration(P1Y5M3W4DT5H36M7S)"


def test_overloaded_values(overloaded_duration):
    """
    GIVEN an ISO 8601 with values that exceed the maximum (eg. 70 seconds)
    WHEN the string is parsed
    THEN the duration is correctly set
    """
    assert overloaded_duration.years == 2     # 1+1 = 2Y
    assert overloaded_duration.months == 0    # 11+1 % 12 = 0M
    assert overloaded_duration.weeks == 0     # 3+1 % 4 = 0w
    assert overloaded_duration.days == 0      # 4+1 % 5 = 0d
    assert overloaded_duration.hours == 3     # 10+1 % 8 = 3h
    assert overloaded_duration.minutes == 0   # 59+1%60 = 0m
    assert overloaded_duration.seconds == 10  # 70-60 = 10s
    assert str(overloaded_duration) == "P2YT3H10S"


def test_parse_zero_duration():
    """
    GIVEN an ISO 8601 with all or somes fields set to 0
    WHEN the string is parsed
    THEN the duration is correctly set
    """
    full_0 = Iso8601Duration("P0Y0M0W0DT0H0M0S")
    days_0 = Iso8601Duration("P0D")
    seconds_0 = Iso8601Duration("PT0S")
    assert full_0 == days_0 == seconds_0 == 0
    assert str(full_0) == str(days_0) == str(seconds_0) == "P0D"


def test_fail_negative_values():
    """
    GIVEN an ISO 8601 with negative values
    WHEN the string is parsed
    THEN raise a ValueError
    """
    with pytest.raises(ValueError):
        Iso8601Duration("P-1Y")
    with pytest.raises(ValueError):
        Iso8601Duration("P1Y-1M")
    with pytest.raises(ValueError):
        Iso8601Duration("P1Y1M-1W")
    with pytest.raises(ValueError):
        Iso8601Duration("P1Y1M1W-1D")
    with pytest.raises(ValueError):
        Iso8601Duration("P1Y1M1W1D-1H")
    with pytest.raises(ValueError):
        Iso8601Duration("P1Y1M1W1DT-1M")
    with pytest.raises(ValueError):
        Iso8601Duration("P1Y1M1W1DT1H-1S")


def test_empty_strings():
    """
    GIVEN valus that are not valid ISO 8601 durations
    WHEN the string is parsed
    THEN raise a ValueError
    """
    with pytest.raises(ValueError):
        Iso8601Duration(None)
    with pytest.raises(ValueError):
        Iso8601Duration("")
    with pytest.raises(ValueError):
        Iso8601Duration("abc")
    with pytest.raises(ValueError):
        Iso8601Duration("P")
    with pytest.raises(ValueError):
        Iso8601Duration("PT")
    with pytest.raises(ValueError):
        Iso8601Duration("P0S")
    with pytest.raises(ValueError):
        Iso8601Duration("PT0Y")
    with pytest.raises(ValueError):
        Iso8601Duration("PaY")
    with pytest.raises(ValueError):
        Iso8601Duration("P.Y")


def test_compare_duration(overloaded_duration):
    """
    GIVEN two ISO 8601 durations
    WHEN comparing them
    THEN the comparison is correctly done
    """
    assert Iso8601Duration("P2YT3H10S") == overloaded_duration
    assert Iso8601Duration("P0D") == 0
    assert not Iso8601Duration("P0D") > 0
    assert not Iso8601Duration("P0D") < 0
    assert Iso8601Duration("P0D") == "PT0S"
    assert Iso8601Duration("P1Y") <= overloaded_duration
    assert Iso8601Duration("P1Y") >= "PT5M"
    assert Iso8601Duration("P1Y") != "PT5M"
    assert Iso8601Duration("P1Y")
    assert not Iso8601Duration("P0D")


def test_math_operation_duration():
    """
    GIVEN two ISO 8601 durations
    WHEN performing math operations +, -, *, /
    THEN the operations are correctly done
    """
    assert Iso8601Duration("PT5M") + 0 == "PT5M"
    with pytest.raises(ValueError):
        Iso8601Duration("PT5M") + 5
    assert Iso8601Duration("PT5M") + "PT5M" == "PT10M"

    assert Iso8601Duration("PT5M") - 0 == "PT5M"
    with pytest.raises(ValueError):
        Iso8601Duration("PT5M") - 3
    assert Iso8601Duration("PT5M") - "PT3M" == "PT120S"

    with pytest.raises(ValueError):
        Iso8601Duration("PT5M") - "P1Y"
    with pytest.raises(ValueError):
        Iso8601Duration("PT5M") + "P-1Y"

    assert Iso8601Duration("PT5M") * 10 == "PT50M"
    assert Iso8601Duration("PT5M") * 0 == "PT0S"
    assert Iso8601Duration("PT5M") * 0.5 == "PT2M30S"
    assert Iso8601Duration("PT1H") * 40 == "P1W"
    with pytest.raises(ValueError):
        Iso8601Duration("PT5M") * "PT5M"
    with pytest.raises(ValueError):
        Iso8601Duration("PT5M") * -1

    assert Iso8601Duration("PT5M") / 10 == "PT30S"
    assert Iso8601Duration("PT5M") // 10 == "PT30S"
    with pytest.raises(ValueError):
        Iso8601Duration("PT5M") / "PT5M"

# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.controllers.conditions_parser import ConditionParser


@pytest.fixture
def parser():
    return ConditionParser()


def test_true_and_false(parser):
    """
    GIVEN a condition parser
    WHEN parsing a string with True and False
    THEN check the result is correct
    """
    assert parser.evaluate("true == true", None) is True
    assert parser.evaluate("true == false", None) is False
    assert parser.evaluate("true != false", None) is True


def test_using_data(parser):
    """
    GIVEN a condition parser
    WHEN parsing a string with data
    THEN check the result is correct
    """
    assert parser.evaluate("true == false", {"true": False}) is True
    assert parser.evaluate("a == 2", {"a": 2}) is True
    assert parser.evaluate("a == 2", {"a": 3}) is False
    assert parser.evaluate("str1 == str2", {"str1": "test", "str2": "test"}) is True
    assert parser.evaluate("str1 == str2", {"str1": "foo", "str2": "bar"}) is False


def test_not_operation(parser):
    """
    GIVEN a condition parser
    WHEN parsing a string with not operation
    THEN check the result is correct
    """
    assert parser.evaluate("not true == true", None) is False
    assert parser.evaluate("not false == true", None) is True
    assert parser.evaluate("not a == 42", {"a": 42}) is False
    assert parser.evaluate("not a == true", {"a": None}) is True


def test_comparators(parser):
    """
    GIVEN a condition parser
    WHEN parsing a string with comparators
    THEN check the result is correct
    """
    assert parser.evaluate("2 < 3", None) is True
    assert parser.evaluate("2 > 3", None) is False
    assert parser.evaluate("2 <= 3", None) is True
    assert parser.evaluate("2 >= 3", None) is False
    assert parser.evaluate("2 == 3", None) is False
    assert parser.evaluate("2 != 3", None) is True


def test_and_or_operations(parser):
    """
    GIVEN a condition parser
    WHEN parsing a string with and and or operations
    THEN check the result is correct
    """
    assert parser.evaluate("true == a and true == a", {"a": True}) is True
    assert parser.evaluate("true == a and true == a", {"a": False}) is False
    assert parser.evaluate("true == a or a == false", {"a": True}) is True
    assert parser.evaluate("true == a or a == false", {"a": False}) is True


def test_percentage(parser):
    """
    GIVEN a condition parser
    WHEN parsing a string with percentage
    THEN check the result is correct
    """
    assert parser.evaluate("50% == 0.5", None) is True
    assert parser.evaluate("50% == 0.51", None) is False


def test_parenthesis(parser):
    """
    GIVEN a condition parser
    WHEN parsing a string with parenthesis
    THEN check the result is correct
    """
    assert parser.evaluate("false == false or (not true == false)", None) is True
    assert parser.evaluate("a > 5% and (a < 150% or a == 2)", {"a": 2}) is True
    assert parser.evaluate("a > 5% and (a < 150% or a == 2)", {"a": 3}) is False


def test_invalid(parser):
    """
    GIVEN a condition parser
    WHEN parsing a string with invalid data
    THEN check the result is correct
    """
    with pytest.raises(Exception):
        parser.evaluate("unknown == 2", None)
    with pytest.raises(Exception):
        parser.evaluate("true", None)
    with pytest.raises(Exception):
        parser.evaluate("true == true == true", None)
    with pytest.raises(Exception):
        parser.evaluate("true == true and", None)
    with pytest.raises(Exception):
        parser.evaluate("true == true", "invalid")


def test_complex_scenario(parser):
    """
    GIVEN a condition parser
    WHEN parsing a string with complex scenario
    THEN check the result is correct
    """
    conditions = "(epss > 5% or (cvss >= 4 and fix_exist == true) or cvss >= 9)" \
        + " and not (fixed == true or ignored == true)"

    assert parser.evaluate(conditions, {
        "epss": 0.06,
        "cvss": 3,
        "fix_exist": True,
        "fixed": False,
        "ignored": False
    }) is True
    assert parser.evaluate(conditions, {
        "epss": 0.002,
        "cvss": 3,
        "fix_exist": True,
        "fixed": False,
        "ignored": False
    }) is False
    assert parser.evaluate(conditions, {
        "epss": 0.06,
        "cvss": 3,
        "fix_exist": True,
        "fixed": True,
        "ignored": False
    }) is False


def test_invalid_identifier(parser):
    """Unknown identifier in a non-None data dict raises Exception (line 84)."""
    with pytest.raises(Exception, match="Invalid identifier"):
        parser.evaluate("nope == true", {})


def test_invalid_percentage_non_numeric(parser):
    """Percentage: LHS resolves to a non-numeric string → raises ValueError (lines 93-95)."""
    with pytest.raises(ValueError, match="Invalid percentage value"):
        # Bypass the string parser; the grammar only accepts numeric LHS for %.
        # Directly call _eval_internal with an identifier that resolves to a
        # non-numeric string so the float() call on line 92 raises ValueError.
        parser.data = {"str_val": "notanumber"}
        parser._eval_internal([["str_val", "%"]])


def test_invalid_3element_unknown_operator(parser):
    """3-element condition with an unknown operator raises Exception (line 115)."""
    with pytest.raises(Exception, match="Invalid condition"):
        # Build a raw condition list directly to bypass the string parser
        cp = ConditionParser()
        cp._eval_internal([1, "**", 2])


def test_invalid_4element_condition(parser):
    """Condition with more than 3 elements raises Exception (line 116)."""
    with pytest.raises(Exception, match="Invalid condition size"):
        cp = ConditionParser()
        cp._eval_internal([1, "==", 2, "=="])


def test_invalid_element_non_string_leaf(parser):
    """Single-element list whose element is not str/int/float/bool raises Exception (line 85)."""
    with pytest.raises(Exception, match="Invalid element"):
        cp = ConditionParser()
        cp._eval_internal([None])


def test_invalid_2element_unknown_pair():
    """2-element list that is neither [not, x] nor [y, %] raises Exception (line 95)."""
    with pytest.raises(Exception, match="Invalid condition"):
        cp = ConditionParser()
        cp.data = {}
        cp._eval_internal(["a", "b"])

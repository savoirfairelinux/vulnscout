# -*- coding: utf-8 -*-
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
    assert parser.evaluate(conditions, {
        "epss": 0.002,
        "cvss": 7.4,
        "fix_exist": True,
        "fixed": False,
        "ignored": False
    }) is True
    assert parser.evaluate(conditions, {
        "epss": 0.002,
        "cvss": 9,
        "fix_exist": False,
        "fixed": False,
        "ignored": False
    }) is True

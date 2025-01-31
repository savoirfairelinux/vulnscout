# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pyparsing as pp


class ConditionParser:
    """
    Parser class to evaluate conditions safely
    Langage supported: identifier, int, float, true, false, percentage, ==, !=, <, >, <=, >=, not, and, or, ()
    More examples and information in unit tests and in documentation
    """

    def __init__(self, debug=False):
        """
        Initialize a parser using pyparsing and custom expression language
        :param debug: Enable debug mode in pyparsing
        """
        self.debug = debug
        self.data = {}
        self.cache_parsed = ("", None)

        pp.ParserElement.enable_left_recursion()

        LPAR, RPAR = map(pp.Suppress, "()")
        comparator = pp.oneOf("== != < > <= >=").set_name("comparator")
        NOT, AND, OR = map(pp.CaselessKeyword, "not and or".split())

        ident = pp.Word(pp.alphas + "_", pp.alphanums + "_-:").set_name("identifier")
        number = (pp.pyparsing_common.real() | pp.pyparsing_common.signed_integer()).set_name("number")
        percentage = pp.Group(number + pp.Char("%")).set_name("percentage")

        element = (ident | percentage | number).set_name("element")
        condition_base = pp.Group(element + comparator + element).set_name("condition_base")
        condition = (
            pp.Group(LPAR + condition_base + RPAR)
            | condition_base
        ).set_name("condition").set_debug(flag=debug)

        self.conditions = pp.Forward()
        self.conditions <<= (
            pp.Group(self.conditions + AND + self.conditions).set_name("and").set_debug(flag=debug)
            | pp.Group(self.conditions + OR + self.conditions).set_name("or").set_debug(flag=debug)
            | pp.Group(NOT + self.conditions).set_name("not").set_debug(flag=debug)
            | pp.Group(LPAR + self.conditions + RPAR).set_name("conditions_group").set_debug(flag=debug)
            | condition
        ).set_name("conditions")

    def parse_string(self, conditions: str, parse_all=True):
        """
        Parse a conditions (string) and return the parsed object
        Not intended for public use, use evaluate() instead
        :param conditions: Conditions to parse
        :param parse_all: Parse all conditions or just the first one
        :return: Parsed object
        """
        return self.conditions.parse_string(conditions, parse_all=parse_all)

    def _eval_internal(self, condition: list):
        """
        Evaluate a part of a condition
        Not intended for public use, use evaluate() instead
        :param condition: Parsed condition
        :return: Result of the evaluation
        """
        if type(condition) is not list:
            condition = [condition]

        if len(condition) == 1:
            if type(condition[0]) is list:
                return self._eval_internal(condition[0])
            if type(condition[0]) is int or type(condition[0]) is float or type(condition[0]) is bool:
                return condition[0]
            if type(condition[0]) is str:
                if condition[0] in self.data:
                    return self.data[condition[0]]
                elif condition[0] == "true":
                    return True
                elif condition[0] == "false":
                    return False
                else:
                    raise Exception(f"Invalid identifier: {condition[0]}")
            raise Exception(f"Invalid element: {condition}")

        if len(condition) == 2:
            if condition[0] == "not":
                return not self._eval_internal(condition[1])
            if condition[1] == "%":
                try:
                    return float(self._eval_internal(condition[0])) / 100
                except ValueError:
                    raise ValueError(f"Invalid percentage value: {condition[0]} cannot be converted to float.")
            raise Exception(f"Invalid condition: {condition}")

        if len(condition) == 3:
            if condition[1] == "==":
                return self._eval_internal(condition[0]) == self._eval_internal(condition[2])
            if condition[1] == "!=":
                return self._eval_internal(condition[0]) != self._eval_internal(condition[2])
            if condition[1] == "<":
                return self._eval_internal(condition[0]) < self._eval_internal(condition[2])
            if condition[1] == ">":
                return self._eval_internal(condition[0]) > self._eval_internal(condition[2])
            if condition[1] == "<=":
                return self._eval_internal(condition[0]) <= self._eval_internal(condition[2])
            if condition[1] == ">=":
                return self._eval_internal(condition[0]) >= self._eval_internal(condition[2])

            if condition[1] == "and":
                return self._eval_internal(condition[0]) and self._eval_internal(condition[2])
            if condition[1] == "or":
                return self._eval_internal(condition[0]) or self._eval_internal(condition[2])
            raise Exception(f"Invalid condition: {condition}")
        raise Exception(f"Invalid condition size ({len(condition)}): {condition}")

    def evaluate(self, conditions: str, data: dict) -> bool:
        """
        Evaluate a condition string with a dictionary of data
        :param conditions: Conditions to evaluate
        :param data: Dictionary of data to use in the conditions
        :return: Result of the evaluation
        """
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary or None")
        self.data = data

        if self.cache_parsed[0] != conditions or self.cache_parsed[1] is None:
            conds = self.parse_string(conditions).asList()
            self.cache_parsed = (conditions, conds)

        res = self._eval_internal(self.cache_parsed[1])
        self.data = {}
        return res

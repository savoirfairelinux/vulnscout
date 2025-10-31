# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import pytest
from unittest.mock import patch, mock_open
from io import StringIO
import sys

from src.helpers.verbose import verbose


class TestVerbose:
    """Test cases for the verbose helper function."""

    @patch.dict(os.environ, {}, clear=True)
    def test_verbose_disabled_by_default(self, capsys):
        """Test that verbose does not print when VERBOSE_MODE is not set."""
        verbose("test message")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    @patch.dict(os.environ, {"VERBOSE_MODE": "false"})
    def test_verbose_disabled_when_false(self, capsys):
        """Test that verbose does not print when VERBOSE_MODE is 'false'."""
        verbose("test message")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    @patch.dict(os.environ, {"VERBOSE_MODE": "true"})
    def test_verbose_enabled_when_true(self, capsys):
        """Test that verbose prints when VERBOSE_MODE is 'true'."""
        verbose("test message")
        captured = capsys.readouterr()
        assert captured.out == "test message\n"
        assert captured.err == ""

    @patch.dict(os.environ, {"VERBOSE_MODE": "True"})
    def test_verbose_disabled_case_sensitive(self, capsys):
        """Test that verbose is case-sensitive and only 'true' enables it."""
        verbose("test message")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    @patch.dict(os.environ, {"VERBOSE_MODE": "TRUE"})
    def test_verbose_disabled_uppercase(self, capsys):
        """Test that verbose does not work with uppercase 'TRUE'."""
        verbose("test message")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    @patch.dict(os.environ, {"VERBOSE_MODE": "true"})
    def test_verbose_multiple_objects(self, capsys):
        """Test that verbose handles multiple objects correctly."""
        verbose("first", "second", "third")
        captured = capsys.readouterr()
        assert captured.out == "first second third\n"

    @patch.dict(os.environ, {"VERBOSE_MODE": "true"})
    def test_verbose_custom_separator(self, capsys):
        """Test that verbose respects custom separator."""
        verbose("first", "second", "third", sep=", ")
        captured = capsys.readouterr()
        assert captured.out == "first, second, third\n"

    @patch.dict(os.environ, {"VERBOSE_MODE": "true"})
    def test_verbose_custom_end(self, capsys):
        """Test that verbose respects custom end parameter."""
        verbose("test message", end="")
        captured = capsys.readouterr()
        assert captured.out == "test message"

    @patch.dict(os.environ, {"VERBOSE_MODE": "true"})
    def test_verbose_custom_end_and_separator(self, capsys):
        """Test that verbose respects both custom separator and end."""
        verbose("first", "second", sep=" | ", end=" END\n")
        captured = capsys.readouterr()
        assert captured.out == "first | second END\n"

    @patch.dict(os.environ, {"VERBOSE_MODE": "true"})
    def test_verbose_to_file(self):
        """Test that verbose can write to a file."""
        test_file = StringIO()
        verbose("test message", file=test_file)
        test_file.seek(0)
        content = test_file.read()
        assert content == "test message\n"

    @patch.dict(os.environ, {"VERBOSE_MODE": "true"})
    def test_verbose_to_stderr(self, capsys):
        """Test that verbose can write to stderr."""
        verbose("error message", file=sys.stderr)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "error message\n"

    @patch.dict(os.environ, {"VERBOSE_MODE": "true"})
    def test_verbose_flush_parameter(self, capsys):
        """Test that verbose respects flush parameter."""
        # Since we can't easily test the flush behavior with capsys,
        # we just ensure the function call doesn't fail
        verbose("test message", flush=False)
        captured = capsys.readouterr()
        assert captured.out == "test message\n"

    @patch.dict(os.environ, {"VERBOSE_MODE": "true"})
    def test_verbose_empty_message(self, capsys):
        """Test that verbose handles empty messages."""
        verbose()
        captured = capsys.readouterr()
        assert captured.out == "\n"

    @patch.dict(os.environ, {"VERBOSE_MODE": "true"})
    def test_verbose_none_objects(self, capsys):
        """Test that verbose handles None objects."""
        verbose(None, None)
        captured = capsys.readouterr()
        assert captured.out == "None None\n"

    @patch.dict(os.environ, {"VERBOSE_MODE": "true"})
    def test_verbose_mixed_types(self, capsys):
        """Test that verbose handles mixed object types."""
        verbose("string", 42, True, None, [1, 2, 3])
        captured = capsys.readouterr()
        assert captured.out == "string 42 True None [1, 2, 3]\n"

    @patch.dict(os.environ, {"VERBOSE_MODE": "random_value"})
    def test_verbose_disabled_with_random_value(self, capsys):
        """Test that verbose is disabled for any value other than 'true'."""
        verbose("test message")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    @patch.dict(os.environ, {"VERBOSE_MODE": ""})
    def test_verbose_disabled_with_empty_string(self, capsys):
        """Test that verbose is disabled when VERBOSE_MODE is empty string."""
        verbose("test message")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    @patch.dict(os.environ, {"VERBOSE_MODE": "true"})
    def test_verbose_complex_objects(self, capsys):
        """Test that verbose handles complex objects like dicts."""
        test_dict = {"key": "value", "number": 123}
        verbose("Dict:", test_dict)
        captured = capsys.readouterr()
        expected = "Dict: {'key': 'value', 'number': 123}\n"
        assert captured.out == expected
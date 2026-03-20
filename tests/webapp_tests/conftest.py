# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared fixtures for webapp tests.

Patches EPSS_DB so Flask route handlers that instantiate
VulnerabilitiesController don't need /cache/vulnscout/epss.db on disk.
"""

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture(autouse=True)
def mock_epss_db():
    """Replace EPSS_DB with a harmless mock for every webapp test."""
    mock = MagicMock()
    # Return None from get_score so fetch_epss_scores() skips set_epss()
    mock.get_score.return_value = None
    with patch("src.controllers.vulnerabilities.EPSS_DB", return_value=mock):
        yield mock

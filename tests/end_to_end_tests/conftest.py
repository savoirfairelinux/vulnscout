# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared fixtures for end-to-end tests.

Patches EPSS_DB so tests don't need /cache/vulnscout/epss.db on disk.
merger_ci._run_main() wraps all DB operations with batch_session() which
degrades gracefully when there is no Flask app context, and every
individual persist helper is guarded with try/except — so the in-memory
controller state (which the tests assert on) is always correct.
"""

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture(autouse=True)
def mock_epss_db():
    """Replace EPSS_DB with a harmless mock for every end-to-end test."""
    mock = MagicMock()
    # Return None from api_get_epss so fetch_epss_scores() skips set_epss()
    mock.api_get_epss.return_value = None
    with patch("src.controllers.vulnerabilities.EPSS_DB", return_value=mock):
        yield mock

# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared fixtures for integration tests.

Provides a Flask application context with an in-memory SQLite database
and patches EPSS_DB so tests don't need /cache/vulnscout/epss.db on disk.
"""

import os
import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture(autouse=True)
def flask_app_ctx():
    """Push a Flask app context with in-memory SQLite for every integration test."""
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        from src.bin.webapp import create_app
        from src.extensions import db
        app = create_app()
        app.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        with app.app_context():
            db.create_all()
            yield
            db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture(autouse=True)
def mock_epss_db(flask_app_ctx):
    """Replace EPSS_DB with a harmless mock for every integration test."""
    mock = MagicMock()
    # Return None from api_get_epss so fetch_epss_scores() skips set_epss()
    mock.api_get_epss.return_value = None
    with patch("src.controllers.vulnerabilities.EPSS_DB", return_value=mock):
        yield mock

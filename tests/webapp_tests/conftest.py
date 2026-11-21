# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared fixtures for webapp tests.

Patches EPSS_DB so Flask route handlers that instantiate
VulnerabilitiesController don't need /cache/vulnscout/epss.db on disk.
"""

import uuid
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from sqlalchemy import create_engine, text

from src.extensions import db


@pytest.fixture()
def postgres_app(postgres_uri):
    engine = create_engine(postgres_uri)
    schema = f"vulnscout_test_{uuid.uuid4().hex}"
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    application = Flask(__name__)
    application.config.update(
        SQLALCHEMY_DATABASE_URI=postgres_uri,
        SQLALCHEMY_ENGINE_OPTIONS={
            "connect_args": {"options": f"-csearch_path={schema} -cstatement_timeout=10000"},
        },
    )
    db.init_app(application)
    try:
        with application.app_context():
            db.create_all()
        yield application
    finally:
        with application.app_context():
            db.session.remove()
            db.engine.dispose()
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()


@pytest.fixture(autouse=True)
def mock_epss_db():
    """Replace EPSS_DB with a harmless mock for every webapp test."""
    mock = MagicMock()
    # Return None from api_get_epss so fetch_epss_scores() skips set_epss()
    mock.api_get_epss.return_value = None
    with patch("src.controllers.vulnerabilities.EPSS_DB", return_value=mock):
        yield mock

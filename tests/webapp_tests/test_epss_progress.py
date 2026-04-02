# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for src/routes/epss_progress.py — covering the GET endpoint."""

import pytest
import os
from src.bin.webapp import create_app


@pytest.fixture()
def app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        with application.app_context():
            from src.extensions import db as _db
            _db.create_all()
            yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


def test_get_epss_progress(client):
    """GET /api/epss/progress returns progress dict with expected keys."""
    resp = client.get("/api/epss/progress")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "in_progress" in data
    assert "phase" in data
    assert "current" in data
    assert "total" in data
    assert "message" in data

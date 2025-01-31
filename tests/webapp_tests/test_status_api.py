# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import json
from src.bin.webapp import create_app


@pytest.fixture()
def init_status_file(tmp_path):
    status_path = tmp_path / "status.txt"
    status_path.write_text("4 merging something")
    return status_path


@pytest.fixture()
def app(init_status_file):
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SCAN_FILE": init_status_file,
    })
    print(app.config)

    yield app

    # clean up / reset resources here
    # tmp_file are automatically deleted by pytest


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()


def test_get_status(client):
    response = client.get("/api/scan/status")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "running"
    assert isinstance(data["maxsteps"], int)
    assert data["step"] == 4
    assert data["step"] <= data["maxsteps"]
    assert "merging something" in data["message"]


def test_get_api_packages(client):
    response = client.get("/api/packages?format=list")
    assert response.status_code == 503
    data = json.loads(response.data)
    assert data["error"] == "Scan not finished"

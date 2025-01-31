# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.bin.webapp import create_app


@pytest.fixture()
def init_static_files(tmp_path):
    (tmp_path / "index.html").write_text("<html>This is homepage</html>")
    (tmp_path / "hello.js").write_text("Hello World")
    (tmp_path / "status.txt").write_text("__END_OF_SCAN_SCRIPT__")
    return tmp_path


@pytest.fixture()
def app(init_static_files):
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SCAN_FILE": init_static_files / "status.txt",
    })
    app.static_folder = init_static_files

    yield app

    # clean up / reset resources here
    # tmp_file are automatically deleted by pytest


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()


def test_get_homepage(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.data == b"<html>This is homepage</html>"


def test_get_static_file(client):
    response = client.get("/hello.js")
    assert response.status_code == 200
    assert "application/javascript" in response.content_type or "text/javascript" in response.content_type
    assert response.data == b"Hello World"


def test_CORS_options(client):
    response = client.options("/anything")
    assert response.status_code == 200
    assert response.data == b"OK"

# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.helpers.add_middleware import FlaskWithMiddleware


@pytest.fixture()
def app():
    app = FlaskWithMiddleware(__name__)
    app.config.update({
        "TESTING": True,
    })

    @app.route("/demo1/abc")
    def demo1_abc():
        return "demo1_abc"

    @app.middleware("/demo1")
    def demo1_middleware():
        return "demo1_middleware"

    @app.route("/demo1/def")
    def demo1_def():
        return "demo1_def"

    @app.route("/demo2/xyz")
    def demo2_xyz():
        return "demo2_xyz"

    # other setup can go here

    yield app

    # clean up / reset resources here


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()


def test_route_before_middleware(client):
    response = client.get("/demo1/abc")
    assert b"demo1_abc" in response.data


def test_route_after_middleware(client):
    response = client.get("/demo1/def")
    assert b"demo1_middleware" in response.data


def test_route_outside_middleware(client):
    response = client.get("/demo2/xyz")
    assert b"demo2_xyz" in response.data

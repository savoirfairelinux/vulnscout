# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import re

import pytest
from flask import Flask, url_for

from src.bin.webapp import create_app
from src.routes.openapi import init_app


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    application = create_app()
    application.config.update(TESTING=True, SCAN_FILE="nonexistent-swagger-ui-scan-status")
    return application


def test_swagger_ui_uses_local_assets_before_scan(app):
    client = app.test_client()
    response = client.get("/api/openapi/ui")
    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert not app._INT_SCAN_FINISHED

    html = response.get_data(as_text=True)
    assert "http://" not in html
    assert "https://" not in html
    assert "cdn" not in html.lower()
    assert 'url: "/api/openapi"' in html
    assert "validatorUrl: null" in html
    assert "persistAuthorization: false" in html
    assert "queryConfigEnabled: false" in html
    assert "StandaloneLayout" not in html
    assets = re.findall(r'(?:href|src)="([^"]+)"', html)
    assert len(assets) == 3
    for asset in assets:
        assert asset.startswith("/swagger-ui-assets/")
        assert client.get(asset).status_code == 200
    assert not app._INT_SCAN_FINISHED


@pytest.mark.parametrize(("filename", "mimetypes", "marker"), [
    ("swagger-ui.css", {"text/css"}, b".swagger-ui"),
    ("swagger-ui-bundle.js", {"text/javascript", "application/javascript"}, b"SwaggerUIBundle"),
    ("favicon-32x32.png", {"image/png"}, b"\x89PNG\r\n\x1a\n"),
    ("swagger-ui.css.map", {"application/json"}, b'"sources"'),
    ("swagger-ui-bundle.js.map", {"application/json"}, b'"sources"'),
])
def test_swagger_assets_have_local_content_before_scan(app, filename, mimetypes, marker):
    response = app.test_client().get(f"/swagger-ui-assets/{filename}")
    assert response.status_code == 200
    assert response.mimetype in mimetypes
    assert marker in response.data
    assert not app._INT_SCAN_FINISHED


@pytest.mark.parametrize("filename", [
    "missing.js",
    "index.html",
    "index.j2",
    "swagger-initializer.js",
    "../__init__.py",
    "%2e%2e/%2e%2e/requirements/base.txt",
    "C:/Windows/win.ini",
])
def test_swagger_assets_reject_missing_demo_and_invalid_paths(app, filename):
    response = app.test_client().get(f"/swagger-ui-assets/{filename}")
    assert response.status_code == 404


def test_swagger_urls_respect_script_name(app):
    client = app.test_client()
    prefix = "/tools/vulnscout"
    response = client.get("/api/openapi/ui", environ_overrides={"SCRIPT_NAME": prefix})
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert f'url: "{prefix}/api/openapi"' in html
    assets = re.findall(r'(?:href|src)="([^"]+)"', html)
    assert len(assets) == 3
    for asset in assets:
        assert asset.startswith(f"{prefix}/swagger-ui-assets/")
        assert client.get(
            asset.removeprefix(prefix), environ_overrides={"SCRIPT_NAME": prefix},
        ).status_code == 200
    assert client.get(
        "/api/openapi", environ_overrides={"SCRIPT_NAME": prefix},
    ).status_code == 200


def test_swagger_assets_are_not_api_operations_and_aliases_remain_available(app):
    client = app.test_client()
    canonical = client.get("/api/openapi")
    assert canonical.status_code == 200
    assert client.get("/api").json == canonical.json
    assert client.get("/api/openapi.json").json == canonical.json
    assert not any("swagger-ui-assets" in path for path in canonical.json["paths"])
    with app.test_request_context():
        assert url_for("openapi_spec") == "/api/openapi"


def test_swagger_ui_works_with_standalone_flask():
    application = Flask(__name__)
    init_app(application)
    client = application.test_client()
    assert client.get("/api/openapi/ui").status_code == 200
    assert client.get("/swagger-ui-assets/swagger-ui-bundle.js").status_code == 200

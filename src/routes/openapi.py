# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import Flask, Response

from ..helpers.openapi import build_openapi_spec


_SWAGGER_UI_HTML = """<!doctype html>
<html lang=\"en\">
    <head>
        <meta charset=\"utf-8\" />
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
        <title>VulnScout OpenAPI UI</title>
        <link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css\" />
        <style>
            html, body { margin: 0; padding: 0; }
            #swagger-ui { min-height: 100vh; }
        </style>
    </head>
    <body>
        <div id=\"swagger-ui\"></div>
        <script src=\"https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js\"></script>
        <script src=\"https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-standalone-preset.js\"></script>
        <script>
            window.ui = SwaggerUIBundle({
                url: '/api/openapi',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
                layout: 'StandaloneLayout',
            });
        </script>
    </body>
</html>
"""


def init_app(app: Flask) -> None:
    def openapi_spec() -> dict:
        """Return the OpenAPI document for the Flask REST API.

        OpenAPI:
        response 200 JsonObject Generated OpenAPI specification document.
        """
        return build_openapi_spec(app)

    def openapi_ui() -> Response:
        """Return Swagger UI bound to the canonical OpenAPI endpoint.

        OpenAPI:
        response 200 html Interactive Swagger UI page.
        """
        return Response(_SWAGGER_UI_HTML, mimetype="text/html")

    app.add_url_rule("/api", endpoint="openapi_spec", view_func=openapi_spec, methods=["GET"])
    app.add_url_rule("/api/openapi", endpoint="openapi_spec", view_func=openapi_spec, methods=["GET"])
    app.add_url_rule("/api/openapi.json", endpoint="openapi_spec", view_func=openapi_spec, methods=["GET"])
    app.add_url_rule("/api/openapi/ui", endpoint="openapi_ui", view_func=openapi_ui, methods=["GET"])

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import Flask, Response, abort, render_template_string, send_from_directory, url_for
from swagger_ui_bundle import swagger_ui_path

from ..helpers.openapi import build_openapi_spec


_SWAGGER_UI_HTML = """<!doctype html>
<html lang=\"en\">
    <head>
        <meta charset=\"utf-8\" />
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
        <title>VulnScout OpenAPI UI</title>
        <link rel=\"icon\" href=\"{{ url_for('swagger_ui_asset', filename='favicon-32x32.png') }}\" />
        <link rel=\"stylesheet\" href=\"{{ url_for('swagger_ui_asset', filename='swagger-ui.css') }}\" />
        <style>
            html, body { margin: 0; padding: 0; }
            #swagger-ui { min-height: 100vh; }
        </style>
    </head>
    <body>
        <div id=\"swagger-ui\"></div>
        <script src=\"{{ url_for('swagger_ui_asset', filename='swagger-ui-bundle.js') }}\"></script>
        <script>
            window.ui = SwaggerUIBundle({
                url: {{ spec_url | tojson }},
                dom_id: '#swagger-ui',
                deepLinking: true,
                validatorUrl: null,
                persistAuthorization: false,
                queryConfigEnabled: false,
                presets: [SwaggerUIBundle.presets.apis],
                layout: 'BaseLayout',
            });
        </script>
    </body>
</html>
"""

_SWAGGER_UI_ASSETS = frozenset({
    "swagger-ui.css",
    "swagger-ui.css.map",
    "swagger-ui-bundle.js",
    "swagger-ui-bundle.js.map",
    "favicon-32x32.png",
})


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
        return Response(
            render_template_string(_SWAGGER_UI_HTML, spec_url=url_for("openapi_spec")),
            mimetype="text/html",
        )

    def swagger_ui_asset(filename: str) -> Response:
        """Serve only UI resources, not the bundled demo or its initializer."""
        if filename not in _SWAGGER_UI_ASSETS:
            abort(404)
        return send_from_directory(
            swagger_ui_path, filename,
            mimetype="application/json" if filename.endswith(".map") else None,
        )

    # url_for chooses the first registered rule for this shared endpoint.
    app.add_url_rule("/api/openapi", endpoint="openapi_spec", view_func=openapi_spec, methods=["GET"])
    app.add_url_rule("/api", endpoint="openapi_spec", view_func=openapi_spec, methods=["GET"])
    app.add_url_rule("/api/openapi.json", endpoint="openapi_spec", view_func=openapi_spec, methods=["GET"])
    app.add_url_rule("/api/openapi/ui", endpoint="openapi_ui", view_func=openapi_ui, methods=["GET"])
    app.add_url_rule(
        "/swagger-ui-assets/<path:filename>", endpoint="swagger_ui_asset",
        view_func=swagger_ui_asset, methods=["GET"],
    )

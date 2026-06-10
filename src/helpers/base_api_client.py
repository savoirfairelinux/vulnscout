# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import http.client
import json
from typing import Any

from .proxy import install_proxy_opener


class BaseAPIClient:
    """Shared base class for HTTP API clients.

    Installs proxy support on construction and exposes a helper to decode
    JSON from an urllib HTTP response object.
    """

    def __init__(self) -> None:
        install_proxy_opener()

    @staticmethod
    def _decode_response_json(response: http.client.HTTPResponse) -> dict[str, Any]:
        """Decode JSON from an urllib HTTP response object."""
        return json.loads(response.read().decode())

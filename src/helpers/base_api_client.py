# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
from .proxy import install_proxy_opener


class BaseAPIClient:
    """Shared base class for HTTP API clients.

    Installs proxy support on construction and exposes a helper to decode
    JSON from an urllib HTTP response object.
    """

    def __init__(self):
        install_proxy_opener()

    @staticmethod
    def _decode_response_json(response) -> dict:
        """Decode JSON from an urllib HTTP response object."""
        return json.loads(response.read().decode())

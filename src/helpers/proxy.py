# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import urllib.request


def install_proxy_opener() -> None:
    """Install a global urllib opener configured with HTTP/HTTPS proxy env vars.

    Reads the standard ``HTTP_PROXY``, ``http_proxy``, ``HTTPS_PROXY``, and
    ``https_proxy`` environment variables.  Does nothing when none are set.
    """
    proxies: dict[str, str] = {}
    if os.getenv('HTTP_PROXY') or os.getenv('http_proxy'):
        proxies['http'] = str(os.getenv('HTTP_PROXY') or os.getenv('http_proxy'))
    if os.getenv('HTTPS_PROXY') or os.getenv('https_proxy'):
        proxies['https'] = str(os.getenv('HTTPS_PROXY') or os.getenv('https_proxy'))

    if proxies:
        proxy_handler = urllib.request.ProxyHandler(proxies)
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)

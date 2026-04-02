# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for src/helpers/proxy.py — covering proxy env var branches."""

import urllib.request
from unittest.mock import patch, MagicMock
from src.helpers.proxy import install_proxy_opener


def test_no_proxy_env_vars(monkeypatch):
    """When no proxy env vars are set, install_opener is not called."""
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("http_proxy", raising=False)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    with patch.object(urllib.request, "install_opener") as mock_install:
        install_proxy_opener()
        mock_install.assert_not_called()


def test_http_proxy_set(monkeypatch):
    """When HTTP_PROXY is set, a proxy opener is installed."""
    monkeypatch.setenv("HTTP_PROXY", "http://proxy:8080")
    monkeypatch.delenv("http_proxy", raising=False)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    with patch.object(urllib.request, "install_opener") as mock_install:
        install_proxy_opener()
        mock_install.assert_called_once()


def test_https_proxy_set(monkeypatch):
    """When HTTPS_PROXY is set, a proxy opener is installed."""
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("http_proxy", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy:8443")
    monkeypatch.delenv("https_proxy", raising=False)
    with patch.object(urllib.request, "install_opener") as mock_install:
        install_proxy_opener()
        mock_install.assert_called_once()


def test_both_proxies_set(monkeypatch):
    """When both HTTP and HTTPS proxy env vars are set, opener is installed."""
    monkeypatch.setenv("HTTP_PROXY", "http://proxy:8080")
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy:8443")
    monkeypatch.delenv("http_proxy", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    with patch.object(urllib.request, "install_opener") as mock_install:
        install_proxy_opener()
        mock_install.assert_called_once()


def test_lowercase_proxy_vars(monkeypatch):
    """Lowercase http_proxy / https_proxy env vars are also honoured."""
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.setenv("http_proxy", "http://proxy:8080")
    monkeypatch.setenv("https_proxy", "https://proxy:8443")
    with patch.object(urllib.request, "install_opener") as mock_install:
        install_proxy_opener()
        mock_install.assert_called_once()

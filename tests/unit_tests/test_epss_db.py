# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import pytest
from unittest.mock import MagicMock

from src.controllers.epss_db import EPSS_DB


class FakeResp:
    def __init__(self, status=200, data=None):
        self.status = status
        self._data = data or {}

    def read(self):
        return json.dumps(self._data).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def test_api_get_epss_success(monkeypatch):
    payload = {
        "status": "OK",
        "data": [{"cve": "CVE-2021-44228", "epss": "0.97514", "percentile": "1.00000"}]
    }
    monkeypatch.setattr(
        "src.controllers.epss_db.urllib.request.urlopen",
        lambda req, timeout=10: FakeResp(200, payload)
    )
    db = EPSS_DB()
    result = db.api_get_epss("CVE-2021-44228")
    assert result is not None
    assert abs(result["score"] - 0.97514) < 1e-5
    assert abs(result["percentile"] - 1.0) < 1e-5


def test_api_get_epss_not_found(monkeypatch):
    payload = {"status": "OK", "data": []}
    monkeypatch.setattr(
        "src.controllers.epss_db.urllib.request.urlopen",
        lambda req, timeout=10: FakeResp(200, payload)
    )
    db = EPSS_DB()
    result = db.api_get_epss("CVE-9999-0000")
    assert result is None


def test_api_get_epss_non_200(monkeypatch):
    monkeypatch.setattr(
        "src.controllers.epss_db.urllib.request.urlopen",
        lambda req, timeout=10: FakeResp(404, {})
    )
    db = EPSS_DB()
    result = db.api_get_epss("CVE-2021-44228")
    assert result is None


def test_api_get_epss_network_error(monkeypatch):
    def boom(req, timeout=10):
        raise OSError("timeout")

    monkeypatch.setattr("src.controllers.epss_db.urllib.request.urlopen", boom)
    db = EPSS_DB()
    # Should return None on failure, not raise
    result = db.api_get_epss("CVE-2021-44228")
    assert result is None


def test_api_get_epss_malformed_response(monkeypatch):
    class BadResp:
        status = 200
        def read(self):
            return b"not json"
        def __enter__(self): return self
        def __exit__(self, *args): pass

    monkeypatch.setattr(
        "src.controllers.epss_db.urllib.request.urlopen",
        lambda req, timeout=10: BadResp()
    )
    db = EPSS_DB()
    result = db.api_get_epss("CVE-2021-44228")
    assert result is None


def test_epss_db_no_args():
    """EPSS_DB() should be constructable with no arguments."""
    db = EPSS_DB()
    assert hasattr(db, "api_get_epss")


# ---------------------------------------------------------------------------
# api_get_epss — HTTPError paths (lines 52-55)
# ---------------------------------------------------------------------------

def test_api_get_epss_http_error_404(monkeypatch):
    """HTTPError with code 404 should return None silently."""
    import urllib.error

    def raise_404(req, timeout=10):
        raise urllib.error.HTTPError(
            url="http://example.com", code=404, msg="Not Found",
            hdrs=None, fp=None
        )

    monkeypatch.setattr("src.controllers.epss_db.urllib.request.urlopen", raise_404)
    db = EPSS_DB()
    result = db.api_get_epss("CVE-9999-0000")
    assert result is None


def test_api_get_epss_http_error_500(monkeypatch):
    """HTTPError with non-404 code should return None and print."""
    import urllib.error

    def raise_500(req, timeout=10):
        raise urllib.error.HTTPError(
            url="http://example.com", code=500, msg="Server Error",
            hdrs=None, fp=None
        )

    monkeypatch.setattr("src.controllers.epss_db.urllib.request.urlopen", raise_500)
    db = EPSS_DB()
    result = db.api_get_epss("CVE-2021-44228")
    assert result is None


# ---------------------------------------------------------------------------
# api_get_epss_batch (lines 69-93)
# ---------------------------------------------------------------------------

def test_api_get_epss_batch_empty_list(monkeypatch):
    """Batch with empty list returns empty dict without calling API."""
    db = EPSS_DB()
    result = db.api_get_epss_batch([])
    assert result == {}


def test_api_get_epss_batch_success(monkeypatch):
    """Batch returns scores for all CVEs present in the API response."""
    payload = {
        "status": "OK",
        "data": [
            {"cve": "CVE-2021-44228", "epss": "0.97514", "percentile": "1.00000"},
            {"cve": "CVE-2023-0001", "epss": "0.12345", "percentile": "0.56789"},
        ]
    }
    monkeypatch.setattr(
        "src.controllers.epss_db.urllib.request.urlopen",
        lambda req, timeout=30: FakeResp(200, payload)
    )
    db = EPSS_DB()
    result = db.api_get_epss_batch(["CVE-2021-44228", "CVE-2023-0001"])
    assert len(result) == 2
    assert abs(result["CVE-2021-44228"]["score"] - 0.97514) < 1e-5
    assert abs(result["CVE-2023-0001"]["percentile"] - 0.56789) < 1e-5


def test_api_get_epss_batch_non_200(monkeypatch):
    """Batch with non-200 response returns empty dict."""
    monkeypatch.setattr(
        "src.controllers.epss_db.urllib.request.urlopen",
        lambda req, timeout=30: FakeResp(500, {})
    )
    db = EPSS_DB()
    result = db.api_get_epss_batch(["CVE-2021-44228"])
    assert result == {}


def test_api_get_epss_batch_http_error(monkeypatch):
    """Batch with HTTPError returns empty dict."""
    import urllib.error

    def raise_err(req, timeout=30):
        raise urllib.error.HTTPError(
            url="http://example.com", code=503, msg="Unavailable",
            hdrs=None, fp=None
        )

    monkeypatch.setattr("src.controllers.epss_db.urllib.request.urlopen", raise_err)
    db = EPSS_DB()
    result = db.api_get_epss_batch(["CVE-2021-44228"])
    assert result == {}


def test_api_get_epss_batch_network_error(monkeypatch):
    """Batch with generic exception returns empty dict."""
    def boom(req, timeout=30):
        raise OSError("connection refused")

    monkeypatch.setattr("src.controllers.epss_db.urllib.request.urlopen", boom)
    db = EPSS_DB()
    result = db.api_get_epss_batch(["CVE-2021-44228"])
    assert result == {}


def test_api_get_epss_batch_partial_data(monkeypatch):
    """Batch returns only CVEs present in the response; missing ones are absent."""
    payload = {
        "status": "OK",
        "data": [
            {"cve": "CVE-2021-44228", "epss": "0.97514", "percentile": "1.00000"},
        ]
    }
    monkeypatch.setattr(
        "src.controllers.epss_db.urllib.request.urlopen",
        lambda req, timeout=30: FakeResp(200, payload)
    )
    db = EPSS_DB()
    result = db.api_get_epss_batch(["CVE-2021-44228", "CVE-9999-0000"])
    assert "CVE-2021-44228" in result
    assert "CVE-9999-0000" not in result
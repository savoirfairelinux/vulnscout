# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import socket
import urllib.error
from email.message import Message
from unittest.mock import MagicMock

import pytest

from src.controllers import epss_db
from src.controllers.epss_db import EPSS_DB


class FakeResp:
    def __init__(self, status=200, data=None):
        self.status = status
        self.headers = Message()
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


@pytest.mark.parametrize("error", [
    urllib.error.URLError(socket.gaierror(socket.EAI_AGAIN, "temporary DNS failure")),
    urllib.error.URLError(TimeoutError("connect timed out")),
    TimeoutError("read timed out"),
])
def test_api_get_epss_batch_retries_transient_errors(monkeypatch, error):
    cve = "CVE-2024-0001"
    response = FakeResp(200, {
        "status": "OK", "data": [{"cve": cve, "epss": "0.5", "percentile": "0.7"}],
    })
    request = MagicMock(side_effect=[error, response])
    sleep = MagicMock()
    monkeypatch.setattr(epss_db.urllib.request, "urlopen", request)
    monkeypatch.setattr(epss_db.time, "sleep", sleep)

    assert EPSS_DB().api_get_epss_batch([cve]) == {cve: {"score": 0.5, "percentile": 0.7}}
    assert request.call_count == 2
    sleep.assert_called_once()
    assert 1 <= sleep.call_args.args[0] <= 1.25


@pytest.mark.parametrize("error", [
    urllib.error.URLError(socket.gaierror(socket.EAI_NONAME, "permanent DNS failure")),
    urllib.error.HTTPError("http://example.com", 503, "Unavailable", None, None),
])
def test_api_get_epss_batch_does_not_retry_other_errors(monkeypatch, error):
    request = MagicMock(side_effect=error)
    monkeypatch.setattr(epss_db.urllib.request, "urlopen", request)
    with pytest.raises(type(error)) as raised:
        EPSS_DB().api_get_epss_batch(["CVE-2024-0001"])
    assert raised.value is error
    request.assert_called_once()


def test_strict_single_request_does_not_retry_timeouts(monkeypatch):
    request = MagicMock(side_effect=TimeoutError("read timed out"))
    monkeypatch.setattr(epss_db.urllib.request, "urlopen", request)
    with pytest.raises(TimeoutError):
        EPSS_DB().api_get_epss("CVE-2024-0001", strict=True)
    request.assert_called_once()


def test_api_get_epss_batch_non_200(monkeypatch):
    """An unsuccessful response must not look like missing scores."""
    monkeypatch.setattr(
        "src.controllers.epss_db.urllib.request.urlopen",
        lambda req, timeout=30: FakeResp(500, {})
    )
    db = EPSS_DB()
    with pytest.raises(urllib.error.HTTPError, match="500"):
        db.api_get_epss_batch(["CVE-2021-44228"])


def test_api_get_epss_batch_http_error(monkeypatch):
    """HTTP failures propagate so callers can record failed targets."""
    import urllib.error

    def raise_err(req, timeout=30):
        raise urllib.error.HTTPError(
            url="http://example.com", code=503, msg="Unavailable",
            hdrs=None, fp=None
        )

    monkeypatch.setattr("src.controllers.epss_db.urllib.request.urlopen", raise_err)
    db = EPSS_DB()
    with pytest.raises(urllib.error.HTTPError, match="503"):
        db.api_get_epss_batch(["CVE-2021-44228"])


def test_api_get_epss_batch_network_error(monkeypatch):
    """Transport failures propagate instead of returning missing scores."""
    def boom(req, timeout=30):
        raise OSError("connection refused")

    monkeypatch.setattr("src.controllers.epss_db.urllib.request.urlopen", boom)
    db = EPSS_DB()
    with pytest.raises(OSError, match="connection refused"):
        db.api_get_epss_batch(["CVE-2021-44228"])


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


@pytest.mark.parametrize("payload", [
    {}, {"status": "OK"}, {"status": "ERROR", "data": []},
    {"status": "OK", "data": [], "total": 1}, {"status": "OK", "data": [{}]},
    {"status": "OK", "data": [], "error": "failed"},
])
def test_epss_malformed_success_response_is_not_absence(monkeypatch, payload):
    monkeypatch.setattr("src.controllers.epss_db.urllib.request.urlopen", lambda *_a, **_kw: FakeResp(200, payload))
    with pytest.raises(ValueError):
        EPSS_DB().api_get_epss("CVE-2024-0001", strict=True)


def test_epss_explicit_empty_is_distinct_from_invalid_json(monkeypatch):
    response = FakeResp(200, {"status": "OK", "data": [], "total": 0})
    request = MagicMock(return_value=response)
    monkeypatch.setattr(epss_db.urllib.request, "urlopen", request)
    assert EPSS_DB().api_get_epss_batch(["CVE-2024-0001"]) == {}
    request.assert_called_once()
    request.reset_mock()
    monkeypatch.setattr(response, "read", lambda: b"not-json")
    with pytest.raises(ValueError):
        EPSS_DB().api_get_epss_batch(["CVE-2024-0001"])
    request.assert_called_once()

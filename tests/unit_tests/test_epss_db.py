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


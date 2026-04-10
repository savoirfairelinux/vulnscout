# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import pytest

from src.controllers.nvd_db import NVD_DB


class FakeResp:
    def __init__(self, status=200, body=b'{"ok": true}'):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def test_call_nvd_api_json_decode(monkeypatch):
    monkeypatch.setattr("src.controllers.nvd_db.urllib.request.urlopen",
                        lambda req, timeout=None: FakeResp(200, b"not json"))
    db = NVD_DB()
    status, data = db._call_nvd_api({"foo": "bar"})
    assert status == 200
    assert data == {}


def test_call_nvd_api_exception(monkeypatch):
    def boom(req, timeout=None):
        raise RuntimeError("boom")
    monkeypatch.setattr("src.controllers.nvd_db.urllib.request.urlopen", boom)
    db = NVD_DB()
    with pytest.raises(RuntimeError):
        db._call_nvd_api({"x": "y"})


def test_api_get_cve_retry_success(monkeypatch):
    seq = [(500, {}), (429, {}), (200, {"ok": True})]

    def fake_call(self, params):
        return seq.pop(0)

    monkeypatch.setattr(NVD_DB, "_call_nvd_api", fake_call)
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB()
    status, data = db.api_get_cve("CVE-2020-0001")
    assert status == 200 and data == {"ok": True}


def test_api_get_cve_retry_fail(monkeypatch):
    monkeypatch.setattr(NVD_DB, "_call_nvd_api", lambda self, p: (500, {}))
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB()
    with pytest.raises(ConnectionError):
        db.api_get_cve("CVE-2020-0002")


def test_api_weaknesses_to_list_str():
    db = NVD_DB()
    weaks = [
        {"description": [{"value": "CWE-79"}]},
        {"description": [{"value": "CWE-79"}]},
        {"description": [{"value": "CWE-20"}]},
    ]
    result = db.api_weaknesses_to_list_str(weaks)
    assert sorted(result) == ["CWE-20", "CWE-79"]


def test_api_references_filter_patches():
    db = NVD_DB()
    refs = [
        {"url": "https://example.com/patch.diff", "tags": ["Patch"]},
        {"url": "https://example.com/info", "tags": ["Exploit"]},
        {"url": "https://example.com/other"},
    ]
    result = db.api_references_filter_patches(refs)
    assert result == ["https://example.com/patch.diff"]


def test_fetch_cve_data_success(monkeypatch):
    class FakeFixScrapper:
        def search_in_nvd(self, vuln):
            pass

        def list_per_packages(self):
            return {"pkg": {"fix": ["1.1"], "affected": ["1.0"]}}

    monkeypatch.setattr("src.controllers.nvd_db.FixsScrapper", FakeFixScrapper)

    api_resp = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "published": "2024-01-01T00:00:00Z",
                    "lastModified": "2024-01-02T00:00:00Z",
                    "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                    "references": [
                        {"url": "https://example.com/patch", "tags": ["Patch"]},
                    ],
                }
            }
        ]
    }

    monkeypatch.setattr(NVD_DB, "api_get_cve", lambda self, cve_id: (200, api_resp))

    db = NVD_DB()
    result = db.fetch_cve_data("CVE-2024-0001")

    assert result is not None
    assert result["published"] == "2024-01-01T00:00:00Z"
    assert result["lastModified"] == "2024-01-02T00:00:00Z"
    assert result["weaknesses"] == ["CWE-79"]
    assert result["patch_url"] == ["https://example.com/patch"]
    assert result["versions_data"] == {"pkg": {"fix": ["1.1"], "affected": ["1.0"]}}


def test_fetch_cve_data_not_found(monkeypatch):
    monkeypatch.setattr(NVD_DB, "api_get_cve", lambda self, cve_id: (200, {"vulnerabilities": []}))
    db = NVD_DB()
    # Empty result set means NVD definitively has no record — sentinel returned
    assert db.fetch_cve_data("CVE-9999-0000") == {"not_found": True}


def test_fetch_cve_data_connection_error(monkeypatch):
    def fail(self, cve_id):
        raise ConnectionError("API down")

    monkeypatch.setattr(NVD_DB, "api_get_cve", fail)
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB()
    # Should return None, not raise
    assert db.fetch_cve_data("CVE-2024-0001") is None


def test_fetch_cve_data_no_weaknesses_no_references(monkeypatch):
    class FakeFixScrapper:
        def search_in_nvd(self, vuln):
            pass

        def list_per_packages(self):
            return {}

    monkeypatch.setattr("src.controllers.nvd_db.FixsScrapper", FakeFixScrapper)

    api_resp = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0002",
                    "published": "2024-02-01T00:00:00Z",
                    "lastModified": "2024-02-02T00:00:00Z",
                }
            }
        ]
    }
    monkeypatch.setattr(NVD_DB, "api_get_cve", lambda self, cve_id: (200, api_resp))

    db = NVD_DB()
    result = db.fetch_cve_data("CVE-2024-0002")
    assert result["weaknesses"] == []
    assert result["patch_url"] == []


@pytest.mark.parametrize("status_code", [400, 403, 404])
def test_api_get_cve_non_retryable_returns_immediately(monkeypatch, status_code):
    """Non-retryable status codes (404, 403, 400) should return after the first attempt."""
    call_count = 0

    def fake_call(self, params):
        nonlocal call_count
        call_count += 1
        return status_code, {}

    monkeypatch.setattr(NVD_DB, "_call_nvd_api", fake_call)
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB()
    s, d = db.api_get_cve("CVE-2019-5747")
    assert s == status_code
    assert d == {}
    assert call_count == 1, "Should not retry on non-retryable status codes"


def test_fetch_cve_data_404_returns_none(monkeypatch):
    """A 404 from the NVD API should return None (retryable error), not the not_found sentinel.

    NVD API v2 never returns HTTP 404 for CVE queries — it always returns 200
    (with totalResults=0 when the CVE is absent).  A 404 therefore indicates a
    network or proxy issue and must not be cached as a permanent "not found".
    """
    monkeypatch.setattr(NVD_DB, "api_get_cve", lambda self, cve_id: (404, {}))
    db = NVD_DB()
    assert db.fetch_cve_data("CVE-2019-5747") is None


def test_call_nvd_api_404_no_print(monkeypatch, capsys):
    """A 404 HTTPError should not print an error message."""
    import urllib.error

    def boom(req, timeout=None):
        raise urllib.error.HTTPError(url="", code=404, msg="Not Found", hdrs=None, fp=None)

    monkeypatch.setattr("src.controllers.nvd_db.urllib.request.urlopen", boom)
    db = NVD_DB()
    status, data = db._call_nvd_api({"cveId": "CVE-2019-5747"})
    assert status == 404
    assert data == {}


def test_empty_api_key_not_sent_as_header(monkeypatch):
    """An empty-string NVD_API_KEY must NOT be sent as a header.

    The entrypoint exports NVD_API_KEY="" when no key is configured.
    Sending ``apiKey: ""`` causes the NVD API to return HTTP 404.
    """
    captured_headers = {}

    def fake_urlopen(req, timeout=None):
        captured_headers.update(dict(req.headers))
        return FakeResp(200, json.dumps({"vulnerabilities": [], "totalResults": 0}).encode())

    monkeypatch.setattr("src.controllers.nvd_db.urllib.request.urlopen", fake_urlopen)
    db = NVD_DB(nvd_api_key="")
    db._call_nvd_api({"cveId": "CVE-2020-1967"})
    assert "Apikey" not in captured_headers and "apiKey" not in captured_headers


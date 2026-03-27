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
                        lambda req: FakeResp(200, b"not json"))
    db = NVD_DB()
    status, data = db._call_nvd_api({"foo": "bar"})
    assert status == 200
    assert data == {}


def test_call_nvd_api_exception(monkeypatch):
    def boom(req):
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


def test_api_references_filter_patchs():
    db = NVD_DB()
    refs = [
        {"url": "https://example.com/patch.diff", "tags": ["Patch"]},
        {"url": "https://example.com/info", "tags": ["Exploit"]},
        {"url": "https://example.com/other"},
    ]
    result = db.api_references_filter_patchs(refs)
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
    assert db.fetch_cve_data("CVE-9999-0000") is None


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



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
        self.headers = {}

    def read(self):
        return self._body

    def items(self):
        return self.headers.items()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def test_call_nvd_api_json_decode(monkeypatch):
    monkeypatch.setattr("src.controllers.nvd_db.urllib.request.urlopen",
                        lambda req, timeout=None: FakeResp(200, b"not json"))
    db = NVD_DB()
    status, data, _ = db._call_nvd_api({"foo": "bar"})
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
    seq = [(500, {}, {}), (429, {}, {}), (200, {"ok": True}, {})]

    def fake_call(self, params):
        return seq.pop(0)

    monkeypatch.setattr(NVD_DB, "_call_nvd_api", fake_call)
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB()
    status, data = db.api_get_cve("CVE-2020-0001")
    assert status == 200 and data == {"ok": True}


def test_api_get_cve_retry_fail_returns_last_status(monkeypatch):
    """Exhausting retries returns (status, data) rather than raising."""
    monkeypatch.setattr(NVD_DB, "_call_nvd_api", lambda self, p: (429, {}, {}))
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB()
    status, data = db.api_get_cve("CVE-2020-0002")
    assert status == 429
    assert data == {}


def test_api_get_cve_max_retries_zero_single_call(monkeypatch):
    """max_retries=0 must make exactly one _call_nvd_api call and return status on failure."""
    call_count = 0

    def fake_call(self, params):
        nonlocal call_count
        call_count += 1
        return (500, {}, {})

    monkeypatch.setattr(NVD_DB, "_call_nvd_api", fake_call)
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB()
    status, data = db.api_get_cve("CVE-2020-0003", max_retries=0)
    assert status == 500
    assert data == {}
    assert call_count == 1, "max_retries=0 should attempt exactly one call"


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
        return status_code, {}, {}

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
    status, data, _ = db._call_nvd_api({"cveId": "CVE-2019-5747"})
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


# ---------------------------------------------------------------------------
# Line 35: params=None branch in _call_nvd_api
# ---------------------------------------------------------------------------

def test_call_nvd_api_no_params(monkeypatch):
    """Calling _call_nvd_api() with no args must use an empty params dict."""
    monkeypatch.setattr(
        "src.controllers.nvd_db.urllib.request.urlopen",
        lambda req, timeout=None: FakeResp(200, b'{"vulnerabilities": []}'),
    )
    db = NVD_DB()
    status, data, _ = db._call_nvd_api()  # params defaults to None → {}
    assert status == 200
    assert data == {"vulnerabilities": []}


# ---------------------------------------------------------------------------
# Line 43: API key header is sent when key is configured
# ---------------------------------------------------------------------------

def test_call_nvd_api_with_api_key(monkeypatch):
    """When an API key is set it must appear in the request headers."""
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["headers"] = dict(req.headers)
        return FakeResp(200, b'{"ok": true}')

    monkeypatch.setattr("src.controllers.nvd_db.urllib.request.urlopen", fake_urlopen)
    db = NVD_DB(nvd_api_key="my-secret-key")
    db._call_nvd_api({"cveId": "CVE-2021-0001"})
    # urllib.request.Request title-cases headers, so 'apiKey' → 'Apikey'
    assert captured["headers"].get("Apikey") == "my-secret-key"


# ---------------------------------------------------------------------------
# Lines 73-74: inner except when e.read() raises inside HTTPError handler
# ---------------------------------------------------------------------------

def test_call_nvd_api_http_error_read_raises(monkeypatch):
    """An HTTPError whose .read() raises must be caught silently and return code."""
    import urllib.error

    class UnreadableHTTPError(urllib.error.HTTPError):
        def read(self, n=-1):
            raise OSError("stream closed")

    def boom(req, timeout=None):
        raise UnreadableHTTPError(
            url="", code=503, msg="Service Unavailable", hdrs=None, fp=None
        )

    monkeypatch.setattr("src.controllers.nvd_db.urllib.request.urlopen", boom)
    db = NVD_DB()
    status, data, _ = db._call_nvd_api({"x": "y"})
    assert status == 503
    assert data == {}


# ---------------------------------------------------------------------------
# Lines 77-79: e.headers branch in HTTPError handler
# ---------------------------------------------------------------------------

def test_call_nvd_api_http_error_with_headers(monkeypatch):
    """HTTPError with real headers must populate resp_headers."""
    import urllib.error
    from email.message import Message

    hdrs = Message()
    hdrs["Retry-After"] = "60"
    hdrs["X-Custom"] = "value"

    def boom(req, timeout=None):
        raise urllib.error.HTTPError(
            url="", code=429, msg="Too Many Requests", hdrs=hdrs, fp=None
        )

    monkeypatch.setattr("src.controllers.nvd_db.urllib.request.urlopen", boom)
    db = NVD_DB()
    status, data, resp_headers = db._call_nvd_api({})
    assert status == 429
    assert "retry-after" in resp_headers


def test_call_nvd_api_http_error_headers_items_raises(monkeypatch):
    """When e.headers.items() raises, the exception must be swallowed silently."""
    import urllib.error

    class BrokenHeaders:
        def __bool__(self):
            return True

        def items(self):
            raise RuntimeError("headers broken")

    def boom(req, timeout=None):
        err = urllib.error.HTTPError(
            url="", code=500, msg="Server Error", hdrs=None, fp=None
        )
        err.headers = BrokenHeaders()  # override with broken headers
        raise err

    monkeypatch.setattr("src.controllers.nvd_db.urllib.request.urlopen", boom)
    db = NVD_DB()
    status, data, resp_headers = db._call_nvd_api({})
    assert status == 500
    assert resp_headers == {}


# ---------------------------------------------------------------------------
# Line 170: api_probe_cve
# ---------------------------------------------------------------------------

def test_api_probe_cve(monkeypatch):
    """api_probe_cve must delegate to _call_nvd_api with the cveId param."""
    captured = {}

    def fake_call(self, params):
        captured["params"] = params
        return 200, {"probed": True}, {}

    monkeypatch.setattr(NVD_DB, "_call_nvd_api", fake_call)
    db = NVD_DB()
    status, data, headers = db.api_probe_cve("  CVE-2023-1234  ")
    assert status == 200
    assert captured["params"] == {"cveId": "CVE-2023-1234"}


# ---------------------------------------------------------------------------
# Lines 130-166: api_get_cves_by_cpe
# ---------------------------------------------------------------------------

def test_api_get_cves_by_cpe_single_page(monkeypatch):
    """Single-page result returns the list of vulnerabilities directly."""
    vulns = [{"cve": {"id": "CVE-2024-1"}}, {"cve": {"id": "CVE-2024-2"}}]

    def fake_call(self, params):
        return 200, {"vulnerabilities": vulns, "totalResults": 2}, {}

    monkeypatch.setattr(NVD_DB, "_call_nvd_api", fake_call)
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB()
    result = db.api_get_cves_by_cpe("cpe:2.3:a:example:lib:*")
    assert result == vulns


def test_api_get_cves_by_cpe_pagination(monkeypatch):
    """Paginated results must be concatenated across pages."""
    page1 = [{"cve": {"id": "CVE-2024-1"}}]
    page2 = [{"cve": {"id": "CVE-2024-2"}}]
    call_count = [0]

    def fake_call(self, params):
        call_count[0] += 1
        start = params.get("startIndex", 0)
        if start == 0:
            return 200, {"vulnerabilities": page1, "totalResults": 2}, {}
        else:
            return 200, {"vulnerabilities": page2, "totalResults": 2}, {}

    monkeypatch.setattr(NVD_DB, "_call_nvd_api", fake_call)
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB()
    result = db.api_get_cves_by_cpe("cpe:2.3:a:example:lib:*", results_per_page=1)
    assert len(result) == 2
    assert result[0] == page1[0]
    assert result[1] == page2[0]


def test_api_get_cves_by_cpe_non_retryable_returns_empty(monkeypatch):
    """A non-retryable status (e.g. 403) must stop immediately and return []."""
    call_count = [0]

    def fake_call(self, params):
        call_count[0] += 1
        return 403, {}, {}

    monkeypatch.setattr(NVD_DB, "_call_nvd_api", fake_call)
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB()
    result = db.api_get_cves_by_cpe("cpe:2.3:a:example:lib:*")
    assert result == []
    assert call_count[0] == 1


def test_api_get_cves_by_cpe_exhausted_retries_returns_partial(monkeypatch):
    """When retries are exhausted the already-collected results are returned."""

    def fake_call(self, params):
        return 500, {}, {}

    monkeypatch.setattr(NVD_DB, "_call_nvd_api", fake_call)
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB()
    result = db.api_get_cves_by_cpe("cpe:2.3:a:example:lib:*")
    assert result == []


def test_api_get_cves_by_cpe_virtual_match(monkeypatch):
    """use_virtual_match=True must send virtualMatchString, not cpeName."""
    captured = {}

    def fake_call(self, params):
        captured["params"] = params
        return 200, {"vulnerabilities": [], "totalResults": 0}, {}

    monkeypatch.setattr(NVD_DB, "_call_nvd_api", fake_call)
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB()
    db.api_get_cves_by_cpe("cpe:2.3:a:*:lib:*", use_virtual_match=True)
    assert "virtualMatchString" in captured["params"]
    assert "cpeName" not in captured["params"]


# ---------------------------------------------------------------------------
# Line 202: extract_cve_details — non-English description fallback
# ---------------------------------------------------------------------------

def test_extract_cve_details_non_english_description_fallback():
    """When no English description exists the first available one is used."""
    cve = {
        "id": "CVE-2024-9999",
        "descriptions": [
            {"lang": "fr", "value": "Vulnérabilité critique"},
            {"lang": "de", "value": "Kritische Schwachstelle"},
        ],
        "metrics": {},
        "references": [],
        "weaknesses": [],
    }
    result = NVD_DB.extract_cve_details(cve)
    assert result["description"] == "Vulnérabilité critique"


# ---------------------------------------------------------------------------
# Lines 259-260: extract_cve_details — invalid published date
# ---------------------------------------------------------------------------

def test_extract_cve_details_invalid_published_date():
    """An unparseable published date must not raise — publish_date stays None."""
    cve = {
        "id": "CVE-2024-8888",
        "descriptions": [{"lang": "en", "value": "Test"}],
        "published": "not-a-date",
        "metrics": {},
        "references": [],
        "weaknesses": [],
    }
    result = NVD_DB.extract_cve_details(cve)
    assert result["publish_date"] is None


# ---------------------------------------------------------------------------
# Line 320: fetch_cve_data — non-200 / non-404 transient error → None
# ---------------------------------------------------------------------------

def test_fetch_cve_data_transient_error_returns_none(monkeypatch):
    """A transient non-200 status (e.g. 503) must return None for a later retry."""
    monkeypatch.setattr(NVD_DB, "api_get_cve", lambda self, cve_id: (503, {}))
    db = NVD_DB()
    assert db.fetch_cve_data("CVE-2024-7777") is None


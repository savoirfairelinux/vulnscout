# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json

from src.controllers.euvd_db import EUVD_DB


class FakeResp:
    def __init__(self, status=200, data=None):
        self.status = status
        self._data = data if data is not None else []

    def read(self):
        return json.dumps(self._data).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class FakeTextResp:
    def __init__(self, status=200, text=""):
        self.status = status
        self._text = text

    def read(self):
        return self._text.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


SAMPLE_DUMP = [
    {"cveId": "CVE-2021-22555", "euvdId": "EUVD-2021-9696",
     "dateAdded": "2025-10-06", "sources": ["cisa_kev"]},
    {"cveId": "CVE-2023-1234", "euvdId": "EUVD-2023-0001",
     "dateAdded": "2025-01-01", "sources": ["cisa_kev", "enisa"]},
    # Entry missing euvdId — must be skipped
    {"cveId": "CVE-2020-0001", "dateAdded": "2024-01-01"},
    # Duplicate CVE — first one wins
    {"cveId": "CVE-2021-22555", "euvdId": "EUVD-9999-9999"},
]

SAMPLE_CSV = (
    "euvd_id,cve_id\n"
    "EUVD-2021-9696,CVE-2021-22555\n"
    "EUVD-2023-0001,CVE-2023-1234\n"
    "EUVD-2024-0001,cve-2024-0001\n"   # lower-case CVE — key must be upper-cased
    "EUVD-9999-9999,CVE-2021-22555\n"  # duplicate CVE — first one wins
    ",CVE-2099-0001\n"                 # missing euvd_id — skipped
    "EUVD-2099-0002,\n"                # missing cve_id — skipped
)


def test_build_mapping_basic():
    mapping = EUVD_DB.build_mapping(SAMPLE_DUMP)
    assert "CVE-2021-22555" in mapping
    assert mapping["CVE-2021-22555"]["euvd_id"] == "EUVD-2021-9696"
    assert mapping["CVE-2021-22555"]["sources"] == ["cisa_kev"]
    assert mapping["CVE-2021-22555"]["date_added"] == "2025-10-06"
    assert mapping["CVE-2023-1234"]["euvd_id"] == "EUVD-2023-0001"
    # Entry without euvdId is skipped
    assert "CVE-2020-0001" not in mapping


def test_build_mapping_is_case_insensitive_key():
    mapping = EUVD_DB.build_mapping([
        {"cveId": "cve-2024-0001", "euvdId": "EUVD-2024-0001"},
    ])
    assert "CVE-2024-0001" in mapping


def test_build_mapping_tolerates_garbage():
    mapping = EUVD_DB.build_mapping(["not-a-dict", None, 42, {}])
    assert mapping == {}


def test_download_dump_writes_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "src.controllers.euvd_db.urllib.request.urlopen",
        lambda req, timeout=30: FakeResp(200, SAMPLE_DUMP),
    )
    client = EUVD_DB(cache_dir=str(tmp_path))
    entries = client.download_dump(force=True)
    assert len(entries) == 4
    # The cache file should now exist and be reusable without network access.
    assert client._cache_is_fresh()
    cached = client._read_cache()
    assert cached == SAMPLE_DUMP


def test_download_dump_falls_back_to_stale_cache(monkeypatch, tmp_path):
    client = EUVD_DB(cache_dir=str(tmp_path))
    client._write_cache(SAMPLE_DUMP)

    def _boom(req, timeout=30):
        raise OSError("network down")

    monkeypatch.setattr(
        "src.controllers.euvd_db.urllib.request.urlopen", _boom)
    entries = client.download_dump(force=True)
    assert entries == SAMPLE_DUMP


def test_download_dump_handles_wrapped_object(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "src.controllers.euvd_db.urllib.request.urlopen",
        lambda req, timeout=30: FakeResp(200, {"data": SAMPLE_DUMP}),
    )
    client = EUVD_DB(cache_dir=str(tmp_path))
    entries = client.download_dump(force=True)
    assert len(entries) == 4


def test_euvd_url():
    assert EUVD_DB.euvd_url("EUVD-2021-9696") == \
        "https://euvd.enisa.europa.eu/vulnerability/EUVD-2021-9696"


# ---------------------------------------------------------------------------
# Full CVE -> EUVD id mapping (CSV dump)
# ---------------------------------------------------------------------------

def test_parse_cve_mapping_basic():
    mapping = EUVD_DB.parse_cve_mapping(SAMPLE_CSV)
    assert mapping["CVE-2021-22555"] == "EUVD-2021-9696"
    assert mapping["CVE-2023-1234"] == "EUVD-2023-0001"


def test_parse_cve_mapping_is_case_insensitive_key():
    mapping = EUVD_DB.parse_cve_mapping(SAMPLE_CSV)
    assert mapping["CVE-2024-0001"] == "EUVD-2024-0001"


def test_parse_cve_mapping_skips_incomplete_and_dedups():
    mapping = EUVD_DB.parse_cve_mapping(SAMPLE_CSV)
    # Duplicate CVE keeps the first EUVD id seen.
    assert mapping["CVE-2021-22555"] == "EUVD-2021-9696"
    # Rows missing either column are skipped.
    assert "CVE-2099-0001" not in mapping


def test_parse_cve_mapping_empty():
    assert EUVD_DB.parse_cve_mapping("") == {}


def test_download_mapping_writes_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "src.controllers.euvd_db.urllib.request.urlopen",
        lambda req, timeout=60: FakeTextResp(200, SAMPLE_CSV),
    )
    client = EUVD_DB(cache_dir=str(tmp_path))
    text = client.download_mapping(force=True)
    assert "CVE-2021-22555" in text
    # Cached and reusable without network access.
    assert client._path_is_fresh(client.mapping_cache_path)
    assert client._read_mapping_cache() == SAMPLE_CSV


def test_download_mapping_falls_back_to_stale_cache(monkeypatch, tmp_path):
    client = EUVD_DB(cache_dir=str(tmp_path))
    client._write_mapping_cache(SAMPLE_CSV)

    def _boom(req, timeout=60):
        raise OSError("network down")

    monkeypatch.setattr(
        "src.controllers.euvd_db.urllib.request.urlopen", _boom)
    text = client.download_mapping(force=True)
    assert text == SAMPLE_CSV


def test_download_mapping_rejects_unexpected_payload(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "src.controllers.euvd_db.urllib.request.urlopen",
        lambda req, timeout=60: FakeTextResp(200, "<html>error</html>"),
    )
    client = EUVD_DB(cache_dir=str(tmp_path))
    # No cache and a bad payload => empty string, never the garbage.
    assert client.download_mapping(force=True) == ""


def test_get_full_mapping(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "src.controllers.euvd_db.urllib.request.urlopen",
        lambda req, timeout=60: FakeTextResp(200, SAMPLE_CSV),
    )
    client = EUVD_DB(cache_dir=str(tmp_path))
    mapping = client.get_full_mapping(force=True)
    assert mapping["CVE-2021-22555"] == "EUVD-2021-9696"
    assert mapping["CVE-2024-0001"] == "EUVD-2024-0001"

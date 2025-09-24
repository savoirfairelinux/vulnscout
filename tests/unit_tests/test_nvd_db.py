# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import sqlite3
import pytest

from src.controllers.nvd_db import NVD_DB


def test_init_version_mismatch(tmp_path):
    db_path = tmp_path / "nvd.db"
    # Pre-create DB with incompatible version
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS nvd_metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT);")
    cur.execute("INSERT OR REPLACE INTO nvd_metadata (key, value) VALUES ('version', ?);", ("old-version",))
    conn.commit()
    conn.close()

    with pytest.raises(Exception):
        NVD_DB(str(db_path))


def test_set_writing_flag(tmp_path):
    db = NVD_DB(str(tmp_path / "nvd2.db"))
    db.set_writing_flag(True)
    flag = db.cursor.execute(
        "SELECT value FROM nvd_metadata WHERE key = 'writing_flag';"
    ).fetchone()[0]
    assert flag == "true"

    db.set_writing_flag(False)
    flag = db.cursor.execute(
        "SELECT value FROM nvd_metadata WHERE key = 'writing_flag';"
    ).fetchone()[0]
    assert flag == "false"


def test_call_nvd_api_json_decode(monkeypatch, tmp_path):
    class FakeResp:
        def __init__(self, status=200, body=b"not json"):
            self.status = status
            self._body = body

        def read(self):
            return self._body

    class FakeConn:
        def __init__(self, host, port):
            self.host = host
            self.port = port
            self.closed = False

        def request(self, method, path, headers=None):
            # Accept all calls
            pass

        def getresponse(self):
            return FakeResp(200, b"not json")

        def close(self):
            self.closed = True

    monkeypatch.setattr("src.controllers.nvd_db.http.client.HTTPSConnection", FakeConn)

    db = NVD_DB(str(tmp_path / "nvd3.db"))
    status, data = db._call_nvd_api({"foo": "bar"})
    assert status == 200
    assert data == {}  # invalid JSON path returns empty dict


def test_call_nvd_api_exception(monkeypatch, tmp_path):
    class FakeConnErr:
        def __init__(self, host, port):
            pass

        def request(self, method, path, headers=None):
            raise RuntimeError("boom")

        def close(self):
            pass

    monkeypatch.setattr("src.controllers.nvd_db.http.client.HTTPSConnection", FakeConnErr)

    db = NVD_DB(str(tmp_path / "nvd4.db"))
    with pytest.raises(RuntimeError):
        db._call_nvd_api({"x": "y"})


def test_api_get_cve_retry_success(monkeypatch, tmp_path):
    seq = [(500, {}), (429, {}), (200, {"ok": True})]

    def fake_call(self, params):
        return seq.pop(0)

    monkeypatch.setattr("src.controllers.nvd_db.NVD_DB._call_nvd_api", fake_call)
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB(str(tmp_path / "nvd5.db"))
    status, data = db.api_get_cve("CVE-2020-0001")
    assert status == 200 and data == {"ok": True}


def test_api_get_cve_retry_fail(monkeypatch, tmp_path):
    def fake_call(self, params):
        return (500, {})

    monkeypatch.setattr("src.controllers.nvd_db.NVD_DB._call_nvd_api", fake_call)
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB(str(tmp_path / "nvd6.db"))
    with pytest.raises(Exception):
        db.api_get_cve("CVE-2020-0002")


def test_api_get_from_index_and_by_date(monkeypatch, tmp_path):
    calls = {"idx": 0}

    def fake_call(self, params):
        calls["idx"] += 1
        if calls["idx"] == 1:
            return (200, {"ok": "index"})
        return (200, {"ok": "date"})

    monkeypatch.setattr("src.controllers.nvd_db.NVD_DB._call_nvd_api", fake_call)
    monkeypatch.setattr("src.controllers.nvd_db.time.sleep", lambda *_: None)

    db = NVD_DB(str(tmp_path / "nvd7.db"))
    s1, d1 = db.api_get_from_index(0)
    assert s1 == 200 and d1["ok"] == "index"

    s2, d2 = db.api_get_by_date("2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z", 0)
    assert s2 == 200 and d2["ok"] == "date"


def test_helpers_and_write_result_to_db(monkeypatch, tmp_path):
    class FakeFixScrapper:
        def search_in_nvd(self, vuln):
            pass

        def list_per_packages(self):
            return {"pkg": ["1.0"]}

    monkeypatch.setattr("src.controllers.nvd_db.FixsScrapper", FakeFixScrapper)

    db = NVD_DB(str(tmp_path / "nvd8.db"))

    data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2000-0001",
                    "published": "2000-01-01T00:00:00Z",
                    "lastModified": "2000-01-02T00:00:00Z",
                    "weaknesses": [
                        {"description": [{"value": "CWE-79"}]},
                        {"description": [{"value": "CWE-79"}]},
                        {"description": [{"value": "CWE-20"}]},
                    ],
                    "references": [
                        {"url": "https://example.com/patch.diff", "tags": ["Patch"]},
                        {"url": "https://example.com/info", "tags": ["Exploit"]},
                    ],
                }
            }
        ]
    }

    ok = db.write_result_to_db(data)
    assert ok is True
    row = db.cursor.execute(
        "SELECT id, published, lastModified, weaknesses, versions_data, patch_url FROM nvd_vulns WHERE id = ?;",
        ("CVE-2000-0001",),
    ).fetchone()
    assert row is not None
    assert row[0] == "CVE-2000-0001"
    weaks = json.loads(row[3])
    assert sorted(weaks) == ["CWE-20", "CWE-79"]
    patches = json.loads(row[5])
    assert patches == ["https://example.com/patch.diff"]


def test_build_initial_db(monkeypatch, tmp_path):
    db = NVD_DB(str(tmp_path / "nvd9.db"))

    # Simulate two batches: first yields 2 of 3, then yields last one
    batches = [
        (200, {"vulnerabilities": [{}, {}], "totalResults": 3}),
        (200, {"vulnerabilities": [{}], "totalResults": 3}),
    ]

    def fake_get_from_index(self, start_index):
        return batches.pop(0)

    monkeypatch.setattr("src.controllers.nvd_db.NVD_DB.api_get_from_index", fake_get_from_index)
    monkeypatch.setattr("src.controllers.nvd_db.NVD_DB.write_result_to_db", lambda self, data: True)

    it = db.build_initial_db()
    steps = list(it)
    assert steps == [(2, 3), (3, 3)]
    assert db.last_index == 3
    meta = db.cursor.execute(
        "SELECT value FROM nvd_metadata WHERE key = 'last_index';"
    ).fetchone()
    assert meta and meta[0] == "3"


def test_find_120_days_interval():
    db = NVD_DB(":memory:")

    short_start = "2024-01-01T00:00:00+00:00"
    short_end = "2024-02-01T00:00:00+00:00"
    st, en, done = db._find_120_days_interval(short_start, short_end)
    # When less than 120 days, include +/- 1 day and done=True
    assert done is True
    # End is after start by at least 1 day
    assert en > st

    long_start = "2020-01-01T00:00:00+00:00"
    long_end = "2024-01-01T00:00:00+00:00"
    st2, en2, done2 = db._find_120_days_interval(long_start, long_end)
    # For long ranges, only a 119-day window (with +/- 1 day applied) and done=False
    assert done2 is False
    # en2 should be after st2
    assert en2 > st2


def test_update_db_flow(monkeypatch, tmp_path):
    db = NVD_DB(str(tmp_path / "nvd10.db"))
    db.last_modified = "2023-01-01T00:00:00+00:00"

    # Force a single small window and mark it as final (done=True)
    monkeypatch.setattr(
        "src.controllers.nvd_db.NVD_DB._find_120_days_interval",
        lambda self, start, end: ("2024-01-01T00:00:00", "2024-01-02T00:00:00", True),
    )
    monkeypatch.setattr(
        "src.controllers.nvd_db.NVD_DB.api_get_by_date",
        lambda self, s, e, i: (200, {"vulnerabilities": [{}], "totalResults": 1}),
    )
    monkeypatch.setattr("src.controllers.nvd_db.NVD_DB.write_result_to_db", lambda self, data: True)

    progress = list(db.update_db())
    assert len(progress) == 1
    assert "2024-01-01T00:00:00 - 2024-01-02T00:00:00 : 1 / 1" in progress[0]

    # Metadata last_modified updated
    meta = db.cursor.execute(
        "SELECT value FROM nvd_metadata WHERE key = 'last_modified';"
    ).fetchone()
    assert meta and isinstance(meta[0], str) and len(meta[0]) > 0


def test_update_db_no_metadata_raises(tmp_path):
    db = NVD_DB(str(tmp_path / "nvd11.db"))
    db.last_modified = ""
    with pytest.raises(Exception):
        list(db.update_db())
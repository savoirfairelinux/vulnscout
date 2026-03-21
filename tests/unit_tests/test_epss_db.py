# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import gzip
from datetime import datetime, timedelta

from src.controllers.epss_db import EPSS_DB


def _write_gz(path: str, text: str):
    with gzip.open(path, "wt") as f:
        f.write(text)


def test_update_epss_and_query(monkeypatch, tmp_path):
    def fake_urlretrieve(url, filename):
        _write_gz(
            filename,
            "\n".join(
                [
                    "# some banner line without headers",
                    "cve,epss,percentile",
                    "CVE-2020-1234,0.123,0.95",
                    "NOT-A-CVE,0.5,0.3",  # should be skipped
                    "CVE-2020-9999,foo,0.2",  # invalid epss -> skipped
                    "CVE-2020-8888,0.5,bar",  # invalid percentile -> skipped
                    "CVE-2020-0001,0.001,0.01",
                ]
            ),
        )
        return (filename, None)

    monkeypatch.setattr("src.controllers.epss_db.urllib.request.urlretrieve", fake_urlretrieve)

    db = EPSS_DB(str(tmp_path / "epss.db"))
    db.update_epss()

    s1 = db.get_score("CVE-2020-1234")
    assert s1 and abs(s1["score"] - 0.123) < 1e-9 and abs(s1["percentile"] - 0.95) < 1e-9

    s2 = db.get_score("CVE-2020-0001")
    assert s2 and abs(s2["score"] - 0.001) < 1e-9 and abs(s2["percentile"] - 0.01) < 1e-9

    assert db.get_score("CVE-DOES-NOT-EXIST") is None
    # last_updated just set -> should not need update for default 1 day
    assert db.needs_update() is False


def test_update_epss_no_valid_header_raises(monkeypatch, tmp_path):
    def fake_urlretrieve(url, filename):
        # No header line containing cve, epss, percentile -> should raise ValueError
        _write_gz(
            filename,
            "\n".join(
                [
                    "this,is,not,a,valid,header",
                    "1,2,3,4,5,6",
                    "foo,bar,baz",
                ]
            ),
        )
        return (filename, None)

    monkeypatch.setattr("src.controllers.epss_db.urllib.request.urlretrieve", fake_urlretrieve)

    db = EPSS_DB(str(tmp_path / "epss_no_header.db"))
    with pytest.raises(ValueError):
        db.update_epss()

    # No metadata written -> needs_update should be True
    assert db.needs_update() is True


def test_needs_update_paths(tmp_path):
    db = EPSS_DB(str(tmp_path / "epss_meta_only.db"))

    # No metadata present -> True
    assert db.needs_update() is True

    # Insert invalid timestamp -> True via exception path
    db.cursor.execute(
        "INSERT OR REPLACE INTO epss_metadata (key, value) VALUES ('last_updated', ?);",
        ("INVALID-TIMESTAMP",),
    )
    db.conn.commit()
    assert db.needs_update() is True

    # Insert an old timestamp -> True for small 'days', False for larger 'days'
    old_ts = (datetime.utcnow() - timedelta(days=3)).isoformat()
    db.cursor.execute(
        "INSERT OR REPLACE INTO epss_metadata (key, value) VALUES ('last_updated', ?);",
        (old_ts,),
    )
    db.conn.commit()
    assert db.needs_update(1) is True
    assert db.needs_update(5) is False


def test_update_epss_with_http_proxy(monkeypatch, tmp_path):
    """update_epss() sets up a proxy handler when HTTP_PROXY env var is set (lines 40, 45-47)."""
    import urllib.request as _urllib_request

    installed_opener = []

    def fake_install_opener(opener):
        installed_opener.append(opener)

    def fake_urlretrieve(url, filename):
        _write_gz(filename, "cve,epss,percentile\nCVE-2024-1111,0.1,0.5\n")
        return (filename, None)

    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example.com:3128")
    monkeypatch.setattr("src.controllers.epss_db.urllib.request.install_opener", fake_install_opener)
    monkeypatch.setattr("src.controllers.epss_db.urllib.request.urlretrieve", fake_urlretrieve)

    db = EPSS_DB(str(tmp_path / "epss_proxy.db"))
    db.update_epss()

    assert len(installed_opener) == 1
    monkeypatch.delenv("HTTP_PROXY")


def test_update_epss_with_https_proxy(monkeypatch, tmp_path):
    """update_epss() sets up a proxy handler when HTTPS_PROXY env var is set (lines 42, 45-47)."""
    installed_opener = []

    def fake_install_opener(opener):
        installed_opener.append(opener)

    def fake_urlretrieve(url, filename):
        _write_gz(filename, "cve,epss,percentile\nCVE-2024-2222,0.2,0.6\n")
        return (filename, None)

    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.example.com:3128")
    monkeypatch.setattr("src.controllers.epss_db.urllib.request.install_opener", fake_install_opener)
    monkeypatch.setattr("src.controllers.epss_db.urllib.request.urlretrieve", fake_urlretrieve)

    db = EPSS_DB(str(tmp_path / "epss_https_proxy.db"))
    db.update_epss()

    assert len(installed_opener) == 1
    monkeypatch.delenv("HTTPS_PROXY")
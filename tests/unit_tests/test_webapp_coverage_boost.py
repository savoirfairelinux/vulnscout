# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

from types import SimpleNamespace

import pytest
from flask import Flask

from src.bin import webapp as webapp_mod
import src.controllers.vulnerabilities as vulnerabilities_mod


class _InlineThread:
    """Replace threading.Thread so targets run immediately in tests."""

    def __init__(self, target, name=None, daemon=None):
        self._target = target
        self.name = name
        self.daemon = daemon

    def start(self):
        self._target()


def test_launch_enrichment_executes_epss_and_nvd(monkeypatch):
    calls: list[str] = []

    fake_session = SimpleNamespace(autoflush=True)
    fake_db = SimpleNamespace(session=fake_session)

    def _record_post_treatment(_controllers):
        calls.append("epss")

    def _record_fetch_nvd(self):
        calls.append("nvd")

    monkeypatch.setattr(webapp_mod, "db", fake_db)
    monkeypatch.setattr(webapp_mod.threading, "Thread", _InlineThread)
    monkeypatch.setattr(webapp_mod, "post_treatment", _record_post_treatment)
    monkeypatch.setattr(
        vulnerabilities_mod.VulnerabilitiesController,
        "fetch_nvd_data",
        _record_fetch_nvd,
    )

    app = Flask(__name__)
    webapp_mod._launch_enrichment(app)

    assert fake_session.autoflush is False
    assert "epss" in calls
    assert "nvd" in calls


def test_launch_enrichment_catches_and_logs_failures(monkeypatch, capsys):
    fake_session = SimpleNamespace(autoflush=True)
    fake_db = SimpleNamespace(session=fake_session)

    def _raise_in_fetch(self):
        raise RuntimeError("nvd failure")

    def _raise_in_post_treatment(_controllers):
        raise RuntimeError("epss failure")

    monkeypatch.setattr(webapp_mod, "db", fake_db)
    monkeypatch.setattr(webapp_mod.threading, "Thread", _InlineThread)
    monkeypatch.setattr(webapp_mod, "post_treatment", _raise_in_post_treatment)
    monkeypatch.setattr(
        vulnerabilities_mod.VulnerabilitiesController,
        "fetch_nvd_data",
        _raise_in_fetch,
    )

    app = Flask(__name__)
    webapp_mod._launch_enrichment(app)

    out = capsys.readouterr().out
    assert "[enrichment/epss]" in out
    assert "[enrichment/nvd]" in out


def test_create_app_triggers_enrichment_when_scan_finished(monkeypatch, tmp_path):
    status_file = tmp_path / "status.txt"
    status_file.write_text("__END_OF_SCAN_SCRIPT__")

    calls: list[str] = []

    def _record_launch(_app):
        calls.append("launched")

    def _register_api_ping(app):
        @app.route("/api/ping")
        def _ping():
            return {"ok": True}

    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setattr(webapp_mod, "_launch_enrichment", _record_launch)
    monkeypatch.setattr(webapp_mod, "init_app", _register_api_ping)
    monkeypatch.setattr(webapp_mod, "init_merger_cli", lambda _app: None)

    app = webapp_mod.create_app()
    app.config["SCAN_FILE"] = str(status_file)
    app.config["TESTING"] = False

    client = app.test_client()
    response = client.get("/api/ping")

    assert response.status_code == 200
    assert calls == ["launched"]


def test_create_app_swallows_pragma_setup_error(monkeypatch):
    def _broken_text(*_args, **_kwargs):
        raise RuntimeError("broken pragma")

    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setattr(webapp_mod.db, "text", _broken_text)

    app = webapp_mod.create_app()

    assert app is not None


def test_stop_handler_prints_and_exits(capsys):
    with pytest.raises(SystemExit) as err:
        webapp_mod.stop_handler(None, None)

    assert err.value.code == 0
    assert "Stopping Flask server" in capsys.readouterr().out

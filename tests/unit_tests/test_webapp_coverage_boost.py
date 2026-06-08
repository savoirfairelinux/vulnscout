# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

from types import SimpleNamespace

import pytest
from flask import Flask

from src.bin import webapp as webapp_mod


class _InlineThread:
    """Replace threading.Thread so targets run immediately in tests."""

    def __init__(self, target, name=None, daemon=None):
        self._target = target
        self.name = name
        self.daemon = daemon

    def start(self):
        self._target()


def _make_fake_db(cve_ids):
    """Build a minimal fake db object whose session.execute() chain returns cve_ids."""
    mock_scalars = SimpleNamespace(all=lambda: cve_ids)
    mock_result = SimpleNamespace(scalars=lambda: mock_scalars)
    fake_session = SimpleNamespace(autoflush=True, execute=lambda *a, **kw: mock_result)
    fake_db = SimpleNamespace(session=fake_session, select=lambda *a, **kw: SimpleNamespace(
        filter=lambda *a, **kw: None
    ))
    return fake_db, fake_session


def test_launch_enrichment_executes_epss(monkeypatch):
    calls: list[str] = []

    fake_db, fake_session = _make_fake_db(["CVE-2024-1234", "CVE-2024-5678"])

    def _record_run_epss_refresh(_app, _cve_ids):
        calls.append("epss")

    monkeypatch.setattr(webapp_mod, "db", fake_db)
    monkeypatch.setattr(webapp_mod.threading, "Thread", _InlineThread)
    monkeypatch.setattr(webapp_mod, "run_epss_refresh", _record_run_epss_refresh)
    monkeypatch.setattr(webapp_mod.EPSSProgressTracker, "start_if_idle", staticmethod(lambda *a: True))
    monkeypatch.setattr(webapp_mod.EPSSProgressTracker, "update", staticmethod(lambda *a, **kw: None))

    app = Flask(__name__)
    webapp_mod._launch_enrichment(app)

    assert fake_session.autoflush is False
    assert "epss" in calls


def test_launch_enrichment_catches_and_logs_failures(monkeypatch, capsys):
    fake_db, fake_session = _make_fake_db(["CVE-2024-1234"])

    def _raise_in_run_epss_refresh(_app, _cve_ids):
        raise RuntimeError("epss failure")

    monkeypatch.setattr(webapp_mod, "db", fake_db)
    monkeypatch.setattr(webapp_mod.threading, "Thread", _InlineThread)
    monkeypatch.setattr(webapp_mod, "run_epss_refresh", _raise_in_run_epss_refresh)
    monkeypatch.setattr(webapp_mod.EPSSProgressTracker, "start_if_idle", staticmethod(lambda *a: True))
    monkeypatch.setattr(webapp_mod.EPSSProgressTracker, "update", staticmethod(lambda *a, **kw: None))

    app = Flask(__name__)
    webapp_mod._launch_enrichment(app)

    out = capsys.readouterr().out
    assert "[enrichment/epss]" in out


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

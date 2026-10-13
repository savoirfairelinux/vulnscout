# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

from threading import Event
from types import SimpleNamespace

import pytest
from flask import Flask

from src.bin import webapp as webapp_mod
from src.controllers import operation_queue as operation_queue_mod
from src.controllers.operation_registry import registry


@pytest.fixture()
def captured_submissions(monkeypatch):
    """Record submissions without running jobs in the background."""
    registry.clear()
    submissions: list[dict] = []

    def _submit(self, op_id, lane, runner, ctx):
        submissions.append(
            {"op_id": op_id, "lane": lane, "runner": runner, "ctx": ctx}
        )

    monkeypatch.setattr(operation_queue_mod.OperationQueue, "submit", _submit)
    yield submissions
    registry.clear()


def test_scan_completion_warms_cache_without_queuing_epss(
    monkeypatch, tmp_path, captured_submissions,
):
    status_file = tmp_path / "status.txt"
    status_file.write_text("__END_OF_SCAN_SCRIPT__")

    cache_started = Event()

    def _register_api_ping(app):
        @app.route("/api/ping")
        def _ping():
            return {"ok": True}

    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setattr(webapp_mod, "_warm_scan_list_cache", lambda _app: cache_started.set())
    monkeypatch.setattr(webapp_mod, "init_app", _register_api_ping)
    monkeypatch.setattr(webapp_mod, "init_merger_cli", lambda _app: None)

    app = webapp_mod.create_app()
    app.config["SCAN_FILE"] = str(status_file)
    app.config["TESTING"] = False
    app.config["BACKGROUND_TASK_DELAY"] = 0

    client = app.test_client()
    response = client.get("/api/ping")

    assert response.status_code == 200
    assert cache_started.wait(timeout=5)
    assert captured_submissions == []
    assert registry.get("enrichment:boot") is None


def test_schedule_background_tasks_warms_cache_without_epss_enrichment(
    monkeypatch, captured_submissions,
):
    calls: list[str] = []

    class _InlineTimer:
        def __init__(self, delay, target):
            assert delay == 0
            self._target = target
            self.name = None
            self.daemon = False

        def start(self):
            self._target()

    monkeypatch.setattr(webapp_mod.threading, "Timer", _InlineTimer)
    monkeypatch.setattr(webapp_mod, "_warm_scan_list_cache", lambda _app: calls.append("cache"))

    app = Flask(__name__)
    app.config["BACKGROUND_TASK_DELAY"] = 0
    webapp_mod._schedule_background_tasks(app)

    assert calls == ["cache"]
    assert captured_submissions == []
    assert registry.get("enrichment:boot") is None


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


def test_refresh_sqlite_stats_skips_non_sqlite_backends(monkeypatch):
    statements: list[str] = []

    stub_db = SimpleNamespace(
        engine=SimpleNamespace(dialect=SimpleNamespace(name="postgresql")),
        session=SimpleNamespace(
            execute=lambda statement: statements.append(statement),
            commit=lambda: statements.append("commit"),
            rollback=lambda: statements.append("rollback"),
        ),
        text=str,
    )
    monkeypatch.setattr(webapp_mod, "db", stub_db)

    webapp_mod._refresh_sqlite_stats(Flask(__name__))

    assert statements == []


def test_refresh_sqlite_stats_rolls_back_and_reports_failures(monkeypatch, capsys):
    events: list[str] = []

    def _fail(_statement):
        raise RuntimeError("analyze failure")

    stub_db = SimpleNamespace(
        engine=SimpleNamespace(dialect=SimpleNamespace(name="sqlite")),
        session=SimpleNamespace(
            execute=_fail,
            commit=lambda: events.append("commit"),
            rollback=lambda: events.append("rollback"),
        ),
        text=str,
    )
    monkeypatch.setattr(webapp_mod, "db", stub_db)

    webapp_mod._refresh_sqlite_stats(Flask(__name__))

    assert events == ["rollback"]
    assert "[sqlite-stats] analyze failure" in capsys.readouterr().out

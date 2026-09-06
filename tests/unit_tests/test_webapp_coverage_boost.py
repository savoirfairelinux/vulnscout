# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

from types import SimpleNamespace

import pytest
from flask import Flask

from src.bin import webapp as webapp_mod
from src.controllers import operation_queue as operation_queue_mod
from src.controllers.operation_registry import (
    KIND_ENRICHMENT, LANE_PIPELINE, registry,
)


class _InlineThread:
    """Replace threading.Thread so targets run immediately in tests."""

    def __init__(self, target, name=None, daemon=None):
        self._target = target
        self.name = name
        self.daemon = daemon

    def start(self):
        self._target()


@pytest.fixture()
def captured_submissions(monkeypatch):
    """Record what ``_launch_enrichment`` hands to the operation queue."""
    registry.clear()
    submissions: list[dict] = []

    def _submit(op_id, lane, runner, ctx):
        submissions.append(
            {"op_id": op_id, "lane": lane, "runner": runner, "ctx": ctx}
        )

    monkeypatch.setattr(operation_queue_mod.queue, "submit", _submit)
    yield submissions
    registry.clear()


def test_boot_enrichment_is_registered_as_a_pipeline_operation(
    captured_submissions,
):
    webapp_mod._launch_enrichment(Flask(__name__))

    operation = registry.get("enrichment:boot")
    assert operation is not None
    assert operation["kind"] == KIND_ENRICHMENT
    assert operation["source"] == "epss"
    assert operation["lane"] == LANE_PIPELINE

    assert len(captured_submissions) == 1
    submission = captured_submissions[0]
    assert submission["op_id"] == "enrichment:boot"
    assert submission["lane"] == LANE_PIPELINE
    assert submission["ctx"].op_id == "enrichment:boot"


def test_boot_enrichment_is_not_queued_twice(captured_submissions):
    app = Flask(__name__)
    webapp_mod._launch_enrichment(app)
    webapp_mod._launch_enrichment(app)

    assert len(captured_submissions) == 1


def test_boot_enrichment_runs_post_treatment_with_a_reporter(
    captured_submissions, monkeypatch
):
    fake_session = SimpleNamespace(autoflush=True)
    monkeypatch.setattr(webapp_mod, "db", SimpleNamespace(session=fake_session))

    reporters: list[object] = []
    monkeypatch.setattr(
        webapp_mod, "post_treatment",
        lambda _controllers, reporter=None: reporters.append(reporter),
    )

    webapp_mod._launch_enrichment(Flask(__name__))
    submission = captured_submissions[0]
    submission["runner"](submission["ctx"])

    assert fake_session.autoflush is False
    assert reporters == [submission["ctx"]]


def test_boot_enrichment_failure_reaches_the_queue(
    captured_submissions, monkeypatch
):
    """The runner raises so the queue can mark the operation as failed."""
    monkeypatch.setattr(
        webapp_mod, "db", SimpleNamespace(session=SimpleNamespace(autoflush=True))
    )

    def _raise(_controllers, reporter=None):
        raise RuntimeError("epss failure")

    monkeypatch.setattr(webapp_mod, "post_treatment", _raise)

    webapp_mod._launch_enrichment(Flask(__name__))
    submission = captured_submissions[0]
    with pytest.raises(RuntimeError, match="epss failure"):
        submission["runner"](submission["ctx"])


def test_create_app_schedules_background_tasks_when_scan_finished(monkeypatch, tmp_path):
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
    monkeypatch.setattr(webapp_mod, "_schedule_background_tasks", _record_launch)
    monkeypatch.setattr(webapp_mod, "init_app", _register_api_ping)
    monkeypatch.setattr(webapp_mod, "init_merger_cli", lambda _app: None)

    app = webapp_mod.create_app()
    app.config["SCAN_FILE"] = str(status_file)
    app.config["TESTING"] = False

    client = app.test_client()
    response = client.get("/api/ping")

    assert response.status_code == 200
    assert calls == ["launched"]


def test_schedule_background_tasks_starts_both_jobs(monkeypatch):
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
    monkeypatch.setattr(webapp_mod, "_launch_enrichment", lambda _app: calls.append("epss"))
    monkeypatch.setattr(webapp_mod, "_warm_scan_list_cache", lambda _app: calls.append("cache"))

    app = Flask(__name__)
    app.config["BACKGROUND_TASK_DELAY"] = 0
    webapp_mod._schedule_background_tasks(app)

    assert calls == ["epss", "cache"]


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

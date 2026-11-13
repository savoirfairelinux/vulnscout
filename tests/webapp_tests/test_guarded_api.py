# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""The GuardedApi turn guard applies to its own loopback port only."""

import json
import socket
import urllib.error
import urllib.request

import pytest
from flask import make_response, request

from src.bin.webapp import create_app
from src.controllers.guarded_api import GuardedApi
from . import write_demo_files


@pytest.fixture()
def app(tmp_path, monkeypatch):
    files = {"status": tmp_path / "status.txt"}
    write_demo_files(files)
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    application = create_app()
    application.config.update({"TESTING": True, "SCAN_FILE": files["status"]})

    @application.route("/guarded-test/<name>", methods=["GET", "POST", "PUT"])
    def guarded_test(name):
        return {"name": name, "method": request.method}

    return application


@pytest.fixture()
def api(app):
    guarded = GuardedApi(app)
    guarded.start()
    yield guarded
    guarded.stop()


class RejectPosts:
    """Rejects POST /guarded-test/reject, accepts every other mutating request; records every response."""

    def __init__(self):
        self.allowed = []
        self.recorded = []

    def allow(self):
        self.allowed.append((request.method, request.path))
        if request.method == "POST" and request.path.endswith("/reject"):
            return make_response({"error": "Rejected by the turn."}, 403)
        return None

    def record(self, response):
        self.recorded.append((request.method, request.path, response.status_code, response.get_json(silent=True)))


def _call(url, method, path):
    data = json.dumps({}).encode() if method != "GET" else None
    req = urllib.request.Request(f"{url}{path}", data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_armed_guard_applies_to_its_port_only(app, api):
    guard = RejectPosts()
    api.arm(guard)

    assert _call(api.url, "POST", "/guarded-test/reject") == (403, {"error": "Rejected by the turn."})
    response = app.test_client().post("/guarded-test/reject", json={})
    assert response.status_code == 200
    assert response.get_json() == {"name": "reject", "method": "POST"}
    assert guard.allowed == [("POST", "/guarded-test/reject")]


def test_record_sees_accepted_and_rejected_responses(api):
    guard = RejectPosts()
    api.arm(guard)

    assert _call(api.url, "PUT", "/guarded-test/ok")[0] == 200
    assert _call(api.url, "POST", "/guarded-test/reject")[0] == 403
    assert _call(api.url, "GET", "/guarded-test/read")[0] == 200

    assert guard.allowed == [("PUT", "/guarded-test/ok"), ("POST", "/guarded-test/reject")]
    assert guard.recorded == [
        ("PUT", "/guarded-test/ok", 200, {"name": "ok", "method": "PUT"}),
        ("POST", "/guarded-test/reject", 403, {"error": "Rejected by the turn."}),
        ("GET", "/guarded-test/read", 200, {"name": "read", "method": "GET"}),
    ]


def test_disarmed_api_rejects_mutating_requests(api):
    api.arm(RejectPosts())
    api.arm(None)

    assert _call(api.url, "POST", "/guarded-test/ok") == (403, {"error": "No AI turn is running."})
    assert _call(api.url, "PUT", "/guarded-test/ok") == (403, {"error": "No AI turn is running."})
    assert _call(api.url, "GET", "/guarded-test/ok") == (200, {"name": "ok", "method": "GET"})


def test_start_leaves_the_scan_gate_alone(app):
    app._INT_SCAN_FINISHED = False
    guarded = GuardedApi(app)
    try:
        guarded.start()
        assert app._INT_SCAN_FINISHED is False
    finally:
        guarded.stop()


def test_stop_is_idempotent_and_frees_the_port(app):
    guarded = GuardedApi(app)
    url = guarded.start()
    assert guarded.start() == url
    port = int(url.rsplit(":", 1)[1])

    guarded.stop()
    guarded.stop()

    assert guarded.url is None
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))

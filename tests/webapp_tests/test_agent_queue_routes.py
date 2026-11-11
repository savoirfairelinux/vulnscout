# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""The AI queue over HTTP and SSE: access checks, validation, request and conversation routes, the stream."""

import asyncio
import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.controllers import agent_queue as aq
from src.controllers.event_bus import EventBus
from src.routes import events as events_module
from ..cli_tests.test_cmd_ai_assess import _seed, app  # noqa: F401

USAGE = {"cost": 1, "input_tokens": 2, "output_tokens": 3}
UNKNOWN = "00000000-0000-4000-8000-000000000000"
ROUTES = [
    ("get", "/api/agent/queue"), ("get", "/api/agent/queue/stream"), ("post", "/api/agent/queue"),
    ("delete", "/api/agent/queue"), ("get", f"/api/agent/queue/requests/{UNKNOWN}"),
    ("delete", f"/api/agent/queue/requests/{UNKNOWN}"), ("post", f"/api/agent/queue/requests/{UNKNOWN}/stop"),
    ("post", f"/api/agent/queue/requests/{UNKNOWN}/retry"), ("get", "/api/agent/conversations/main"),
    ("delete", f"/api/agent/conversations/{UNKNOWN}"), ("delete", "/api/agent/conversations"),
    ("post", "/api/agent/conversations/main/reset"),
]


async def _answer(call):
    call.on_session(f"s-{call.request.id}")
    call.session.session_id, call.session.session_scope = f"s-{call.request.id}", call.scope
    return "answer", dict(USAGE)


class Runner:
    """The injected runner: scripted behaviours first, then plain answers."""

    def __init__(self):
        self.script = []

    async def __call__(self, call):
        return await (self.script.pop(0) if self.script else _answer)(call)


@pytest.fixture()
def env(app, monkeypatch):  # noqa: F811
    from src.routes import agent

    with app.app_context():
        ids = _seed()

    async def delete(token, session_id):
        pass

    monkeypatch.setattr(agent, "_delete_session", delete)
    monkeypatch.setattr(agent, "_agent_connection", agent.Conversation())
    monkeypatch.setattr(events_module, "HEARTBEAT_SECONDS", 0.05)
    runner = Runner()
    queue = aq.AgentQueue(app, runner=runner, events=EventBus(replay_size=64), autostart=False)
    monkeypatch.setattr(aq, "agent_queue", queue)
    yield SimpleNamespace(app=app, client=app.test_client(), q=queue, runner=runner, ids=ids)
    queue.shutdown()


def _post(env, actions, conversation="per-action", **extra):
    return env.client.post("/api/agent/queue", json={"conversation": conversation, "source": "web",
                                                     "actions": actions, **extra})


def _message(text="Hello"):
    return {"kind": "message", "text": text}


def _blocked(env):
    """Make the next turn wait for the returned event; returns (started, release)."""
    started, release = threading.Event(), threading.Event()

    async def run(call):
        started.set()
        while not release.is_set():
            await asyncio.sleep(0.01)
        return await _answer(call)

    env.runner.script.append(run)
    return started, release


def _in_thread(env, lane):
    thread = threading.Thread(target=env.q.run_once, args=(lane,))
    thread.start()
    return thread


# ---------------------------------------------------------------- access


@pytest.mark.parametrize("method,path", ROUTES)
def test_every_route_rejects_remote_clients_and_foreign_origins(env, method, path):
    response = getattr(env.client, method)(path, environ_overrides={"REMOTE_ADDR": "192.0.2.1"})
    assert response.status_code == 403
    assert response.get_json()["error"] == "Agent chat is available only on localhost."
    assert response.headers["Cache-Control"] == "no-store"
    response = getattr(env.client, method)(path, headers={"Origin": "http://evil.example"})
    assert response.status_code == 403
    assert response.get_json()["error"] == "Invalid request origin."


# ---------------------------------------------------------------- submit


@pytest.mark.parametrize("body, error", [
    (None, "Send a JSON object."),
    (["Hello"], "Send a JSON object."),
    ({"conversation": "main", "source": "web", "actions": [_message()], "require_ready": "yes"},
     "require_ready must be a boolean."),
    ({"source": "web", "actions": [_message()]}, "Invalid conversation."),
    ({"conversation": "main", "actions": [_message()]}, "Invalid request source"),
    ({"conversation": "main", "source": "x" * 101, "actions": [_message()]}, "Invalid request source"),
    ({"conversation": "main", "source": "web", "model": "x" * 101, "actions": [_message()]},
     "Invalid model selection."),
    ({"conversation": "main", "source": "web", "model": "gpt\n4", "actions": [_message()]},
     "Invalid model selection."),
    ({"conversation": "main", "source": "web", "timeout": 0, "actions": [_message()]}, "Invalid timeout"),
    ({"conversation": "main", "source": "web", "timeout": 3601, "actions": [_message()]}, "Invalid timeout"),
    ({"conversation": "main", "source": "web", "timeout": True, "actions": [_message()]}, "Invalid timeout"),
    ({"conversation": "main", "source": "web", "context": {"page": "invalid"}, "actions": [_message()]}, ""),
    ({"conversation": "main", "source": "web", "actions": []}, "Send between 1 and 500 actions."),
    ({"conversation": "main", "source": "web", "actions": [_message()] * 501}, "Send between 1 and 500 actions."),
    ({"conversation": "main", "source": "web", "actions": "Hello"}, "Send between 1 and 500 actions."),
    ({"conversation": "main", "source": "web", "actions": ["Hello"]}, "Each action must be an object."),
    ({"conversation": "main", "source": "web", "actions": [{"kind": "chat"}]}, "Invalid action kind"),
    ({"conversation": "main", "source": "web", "actions": [{**_message(), "key": "k" * 501}]}, "Invalid action key"),
    ({"conversation": "main", "source": "web", "actions": [_message("")]}, "Enter a message of at most 8000"),
    ({"conversation": "main", "source": "web", "actions": [_message("  ")]}, "Enter a message of at most 8000"),
    ({"conversation": "main", "source": "web", "actions": [_message("x" * 8001)]}, "Enter a message of at most 8000"),
    ({"conversation": "per-action", "source": "web", "actions": [_message()]},
     "Messages go to the main conversation"),
    ({"conversation": "main", "source": "web", "actions": [{"kind": "assess", "vuln_id": "CVE-2024-0001"}]},
     "run in their own conversations"),
    ({"conversation": "per-action", "source": "web", "actions": [{"kind": "assess", "vuln_id": "bad id"}]},
     "Invalid vulnerability ID."),
    ({"conversation": "per-action", "source": "web", "actions": [{"kind": "assess", "vuln_id": 7}]},
     "Invalid vulnerability ID."),
    ({"conversation": "per-action", "source": "web",
      "actions": [{"kind": "assess", "vuln_id": "CVE-2024-0001", "targets": []}]}, "targets must list"),
    ({"conversation": "per-action", "source": "web", "actions": [{
        "kind": "assess", "vuln_id": "CVE-2024-0001",
        "targets": [{"variant_id": UNKNOWN, "package": "zlib@1.2"}] * 1001}]}, "targets must list"),
    ({"conversation": "per-action", "source": "web", "actions": [{
        "kind": "assess", "vuln_id": "CVE-2024-0001", "targets": [{"variant_id": "x86", "package": "zlib@1.2"}]}]},
     "Invalid target variant ID."),
    ({"conversation": "per-action", "source": "web", "actions": [{
        "kind": "assess", "vuln_id": "CVE-2024-0001", "targets": [{"variant_id": UNKNOWN, "package": "x" * 301}]}]},
     "at most 300 characters"),
    ({"conversation": "per-action", "source": "web", "actions": [{"kind": "review", "assessment_id": "a1"}]},
     "Invalid assessment ID."),
    ({"conversation": "per-action", "source": "web",
      "actions": [{"kind": "review", "assessment_id": UNKNOWN, "variant_id": "x86"}]}, "Invalid variant ID."),
    ({"conversation": "per-action", "source": "web",
      "actions": [{"kind": "review", "assessment_id": UNKNOWN, "finding_ids": ["f1"]}]}, "Invalid finding ID."),
    ({"conversation": "per-action", "source": "web",
      "actions": [{"kind": "review", "assessment_id": UNKNOWN}]}, f"Assessment {UNKNOWN} not found."),
])
def test_invalid_submissions_return_json_400_and_queue_nothing(env, body, error):
    response = env.client.post("/api/agent/queue", json=body)
    assert response.status_code == 400
    assert response.is_json and error in response.get_json()["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert env.q.snapshot()["requests"] == []


def test_submit_uppercases_vulnerabilities_and_reports_skipped_duplicates(env):
    response = _post(env, [{"kind": "assess", "vuln_id": "cve-2024-0001", "key": "k"}])
    assert response.status_code == 202 and response.headers["Cache-Control"] == "no-store"
    [created] = response.get_json()["requests"]
    assert set(created) == {"id", "key", "conversation_id"} and response.get_json()["skipped"] == []
    assert env.q.get_request(created["id"])["vuln_id"] == "CVE-2024-0001"
    again = _post(env, [{"kind": "assess", "vuln_id": "CVE-2024-0001", "key": "k"},
                        {"kind": "assess", "vuln_id": "CVE-2024-0004"}]).get_json()
    assert again["skipped"] == [{"key": "k", "request_id": created["id"], "request_ids": [created["id"]]}]
    assert len(again["requests"]) == 1


@pytest.mark.parametrize("config, code", [
    ("", "no_ai_config"),
    ("AI_PROVIDER=bogus\n", "invalid_config"),
    ("AI_PROVIDER=github\nAI_AUTH_CREDENTIALS=gho_test\n", "github_signed_out"),
])
def test_require_ready_reports_why_nothing_can_run(env, monkeypatch, config, code):
    from src.routes import agent

    async def signed_out(token):
        return {"authenticated": False}

    monkeypatch.setattr(agent, "_token_status", signed_out)
    Path(os.environ["VULNSCOUT_CONFIG"]).write_text(config)
    response = _post(env, [_message()], "main", require_ready=True)
    assert response.status_code == 409
    assert response.get_json()["code"] == code and response.get_json()["error"]
    assert env.q.snapshot()["requests"] == []


def test_messages_need_an_existing_live_conversation(env):
    response = _post(env, [_message()], UNKNOWN)
    assert response.status_code == 404 and response.get_json()["error"] == aq.NOT_AVAILABLE
    [action] = _post(env, [{"kind": "assess", "vuln_id": "CVE-2024-0001"}]).get_json()["requests"]
    env.q.run_once("action")
    env.q._conversations[action["conversation_id"]].archived = True
    response = _post(env, [_message()], action["conversation_id"])
    assert response.status_code == 409 and response.get_json() == {"error": aq.ARCHIVED}


# ---------------------------------------------------------------- turn errors (formerly the message endpoint's)


def test_a_missing_mcp_server_fails_the_request(env, monkeypatch, tmp_path):
    monkeypatch.setenv("VULNSCOUT_MCP_SERVER_PATH", str(tmp_path / "missing_server.py"))
    [request] = _post(env, [_message()], "main").get_json()["requests"]
    env.q.run_once("chat")
    record = env.client.get(f"/api/agent/queue/requests/{request['id']}").get_json()
    assert (record["status"], record["error_code"], record["error"]) == ("failed", "mcp", aq.MCP_MISSING)


def test_missing_skills_fail_an_action_follow_up(env, monkeypatch, tmp_path):
    from src.routes import agent_skills

    [action] = _post(env, [{"kind": "assess", "vuln_id": "CVE-2024-0001"}]).get_json()["requests"]
    env.q.run_once("action")
    monkeypatch.setenv("VULNSCOUT_SKILLS_PATH", str(tmp_path / "missing"))
    env.q._runner = aq.default_runner
    [follow] = _post(env, [_message("Why?")], action["conversation_id"]).get_json()["requests"]
    env.q.run_once("chat")
    record = env.client.get(f"/api/agent/queue/requests/{follow['id']}").get_json()
    assert (record["status"], record["error_code"]) == ("failed", "skills")
    assert record["error"] == agent_skills.SKILLS_MISSING_ERROR


def test_skill_errors_are_reported(env):
    from src.routes import agent_skills

    async def broken(call):
        raise agent_skills.AgentSkillError("Agent skill cve-assessment could not be loaded.")

    env.runner.script.append(broken)
    [action] = _post(env, [{"kind": "assess", "vuln_id": "CVE-2024-0001"}]).get_json()["requests"]
    env.q.run_once("action")
    record = env.client.get(f"/api/agent/queue/requests/{action['id']}").get_json()
    assert record["error_code"] == "skills"
    assert record["error"] == "Agent skill cve-assessment could not be loaded."
    assert record["result"]["outcome"] == "failed"


# ---------------------------------------------------------------- requests


def test_request_routes_remove_retry_stop_and_clear(env):
    client = env.client
    assert client.get(f"/api/agent/queue/requests/{UNKNOWN}").status_code == 404
    for path in (f"/api/agent/queue/requests/{UNKNOWN}/stop", f"/api/agent/queue/requests/{UNKNOWN}/retry"):
        assert client.post(path).status_code == 404
    assert client.delete(f"/api/agent/queue/requests/{UNKNOWN}").status_code == 404

    first, second, third = _post(env, [_message("a"), _message("b"), _message("c")], "main").get_json()["requests"]
    snapshot = client.get("/api/agent/queue")
    assert snapshot.headers["Cache-Control"] == "no-store"
    assert [r["position"] for r in snapshot.get_json()["requests"]] == [1, 2, 3]
    assert client.delete(f"/api/agent/queue/requests/{first['id']}").get_json() == {"status": "removed"}
    assert client.post(f"/api/agent/queue/requests/{second['id']}/stop").get_json() == {"status": "removed"}
    response = client.post(f"/api/agent/queue/requests/{third['id']}/retry")
    assert response.status_code == 409 and "failed" in response.get_json()["error"]

    async def boom(call):
        raise RuntimeError("boom")

    env.runner.script.append(boom)
    env.q.run_once("chat")
    assert client.get(f"/api/agent/queue/requests/{third['id']}").get_json()["status"] == "failed"
    assert client.post(f"/api/agent/queue/requests/{third['id']}/retry").get_json() == {"status": "queued"}
    _post(env, [_message("d")], "main")
    assert client.delete("/api/agent/queue").get_json() == {"removed": 2}
    assert client.get("/api/agent/queue").get_json()["requests"] == []


def test_a_running_request_is_stopped_not_removed(env):
    started, release = _blocked(env)
    [request] = _post(env, [_message()], "main").get_json()["requests"]
    thread = _in_thread(env, "chat")
    try:
        assert started.wait(10)
        response = env.client.delete(f"/api/agent/queue/requests/{request['id']}")
        assert response.status_code == 409
        response = env.client.post("/api/agent/conversations/main/reset")
        assert response.status_code == 409
        assert env.client.post(f"/api/agent/queue/requests/{request['id']}/stop").get_json() == {
            "status": "stopping"}
    finally:
        release.set()
        thread.join(10)
    assert env.client.get(f"/api/agent/queue/requests/{request['id']}").get_json()["status"] == "cancelled"


# ---------------------------------------------------------------- conversations


def test_conversation_routes(env):
    client = env.client
    [message] = _post(env, [_message()], "main").get_json()["requests"]
    [action] = _post(env, [{"kind": "assess", "vuln_id": "CVE-2024-0001"}]).get_json()["requests"]
    env.q.run_once("chat")
    main = client.get("/api/agent/conversations/main")
    assert main.headers["Cache-Control"] == "no-store"
    assert [m["role"] for m in main.get_json()["messages"]] == ["user", "assistant"]
    assert main.get_json()["usage"]["cost"] == 1
    assert client.get(f"/api/agent/conversations/{UNKNOWN}").status_code == 404
    assert client.delete(f"/api/agent/conversations/{UNKNOWN}").status_code == 404
    assert client.delete("/api/agent/conversations/main").status_code == 409
    response = client.delete(f"/api/agent/conversations/{action['conversation_id']}")
    assert response.status_code == 409  # still queued
    env.q.run_once("action")
    conversation = client.get(f"/api/agent/conversations/{action['conversation_id']}").get_json()
    assert conversation["title"].startswith("Assess CVE-2024-0001") and conversation["live"] is None
    assert client.delete(f"/api/agent/conversations/{action['conversation_id']}").get_json() == {"deleted": 1}
    _post(env, [{"kind": "assess", "vuln_id": "CVE-2024-0004"}])
    env.q.run_once("action")
    assert client.delete("/api/agent/conversations").get_json() == {"deleted": 1}
    reset = client.post("/api/agent/conversations/main/reset").get_json()
    assert reset["id"] == "main" and reset["messages"] == [] and reset["usage"]["cost"] is None
    assert env.q.get_request(message["id"])["status"] == "done"


# ---------------------------------------------------------------- stream


class _Reader:
    def __init__(self, response):
        self.response = response
        self._iterator = iter(response.response)

    def next_frame(self):
        chunk = next(self._iterator)
        frame = {"id": None, "event": None, "data": None}
        for line in (chunk.decode() if isinstance(chunk, bytes) else chunk).strip().splitlines():
            key, _, value = line.partition(": ")
            frame[key] = json.loads(value) if key == "data" else value
        return frame

    def next_frame_of(self, event_type):
        for _ in range(50):
            frame = self.next_frame()
            if frame["event"] == event_type:
                return frame
        raise AssertionError(f"no {event_type!r} frame arrived")


@pytest.fixture()
def open_stream(env):
    readers = []

    def _open(**kwargs):
        response = env.client.get("/api/agent/queue/stream", **kwargs)
        assert response.status_code == 200
        readers.append(_Reader(response))
        return readers[-1]

    yield _open
    for reader in reversed(readers):  # stream_with_context keeps request contexts pushed: close them LIFO
        reader.response.close()


def test_the_stream_starts_with_a_snapshot_then_sends_queue_events(env, open_stream):
    reader = open_stream()
    assert reader.response.mimetype == "text/event-stream"
    assert reader.response.headers["Cache-Control"] == "no-store, no-transform"
    snapshot = reader.next_frame()
    assert snapshot["event"] == "snapshot"
    assert set(snapshot["data"]) == {"epoch", "seq", "paused", "requests", "history", "conversations",
                                     "connection_revision"}
    assert snapshot["id"] == f"{env.q.events.epoch}:{snapshot['data']['seq']}"
    [request] = _post(env, [_message()], "main").get_json()["requests"]
    queued = reader.next_frame_of("queue")
    assert [r["id"] for r in queued["data"]["requests"]] == [request["id"]]

    replayed = open_stream(headers={"Last-Event-ID": snapshot["id"]}).next_frame()
    assert (replayed["event"], replayed["id"]) == ("queue", queued["id"])
    for cursor in (f"other-epoch:{snapshot['data']['seq']}", "garbage"):
        assert open_stream(headers={"Last-Event-ID": cursor}).next_frame()["event"] == "snapshot"


def test_streams_share_the_stream_cap(env, open_stream, monkeypatch):
    monkeypatch.setenv("VULNSCOUT_SSE_MAX_STREAMS", "1")
    open_stream().next_frame()
    refused = env.client.get("/api/agent/queue/stream")
    assert refused.status_code == 503 and "no-store" in refused.headers["Cache-Control"]
    assert refused.get_json() == {"error": "Too many concurrent event streams"}


def test_the_stream_is_reachable_before_the_scan_finishes(env, open_stream, tmp_path):
    unfinished = tmp_path / "unfinished.txt"
    unfinished.write_text("3 still importing")
    env.app.config["SCAN_FILE"] = str(unfinished)
    env.app._INT_SCAN_FINISHED = False
    assert open_stream().next_frame()["event"] == "snapshot"
    assert env.client.get("/api/agent/queue").status_code == 503
    response = _post(env, [_message()], "main")
    assert response.status_code == 503 and response.get_json() == {"error": "Scan not finished"}
    assert env.q.snapshot()["requests"] == []

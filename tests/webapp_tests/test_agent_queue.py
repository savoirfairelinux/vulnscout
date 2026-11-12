# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""The backend AI queue: scheduling, dedupe, stop, pause, connection changes, caps and progress."""

import asyncio
import json
import os
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.controllers import agent_queue as aq
from src.controllers.event_bus import EventBus
from src.extensions import db as _db
from ..cli_tests.test_cmd_ai_assess import _seed, app  # noqa: F401

USAGE = {"cost": 1, "input_tokens": 2, "output_tokens": 3}


class Recorder(EventBus):
    def __init__(self):
        super().__init__(replay_size=1000)
        self.log = []

    def publish(self, event_type, data):
        self.log.append((event_type, data))
        return super().publish(event_type, data)

    def of(self, event_type):
        return [data for kind, data in self.log if kind == event_type]


class Fake:
    """The injected runner: per-kind scripted behaviours, else a reply that keeps its SDK session like _reply."""

    def __init__(self):
        self.calls = []
        self.script: dict[str, list] = {"assess": [], "review": [], "message": []}

    async def __call__(self, call):
        self.calls.append(call)
        script = self.script[call.request.kind]
        if script:
            return await script.pop(0)(call)
        return await ok(call)


async def ok(call, reply="answer"):
    session_id = call.session.session_id if call.session.session_scope == call.scope else None
    session_id = session_id or f"s-{call.request.id}"
    call.on_session(session_id)
    call.session.session_id, call.session.session_scope = session_id, call.scope
    return reply, dict(USAGE)


def blocking(started, release):
    async def run(call):
        started.set()
        while not release.is_set():
            await asyncio.sleep(0.01)
        return await ok(call, "late")
    return run


def raising(exc):
    async def run(call):
        call.on_session("doomed")
        raise exc
    return run


@pytest.fixture()
def env(app, monkeypatch):  # noqa: F811
    from src.routes import agent

    setattr(app, "_INT_SCAN_FINISHED", True)
    with app.app_context():
        ids = _seed()
    deleted = []

    async def delete(token, session_id):
        deleted.append(session_id)

    monkeypatch.setattr(agent, "_delete_session", delete)
    monkeypatch.setattr(agent, "_agent_connection", agent.Conversation())

    async def logged_out(token):
        return {"authenticated": False, "login": None}

    monkeypatch.setattr(agent, "_auth_status", logged_out)
    fake, events = Fake(), Recorder()
    queue = aq.AgentQueue(app, runner=fake, events=events, autostart=False)
    yield SimpleNamespace(q=queue, fake=fake, events=events, deleted=deleted, ids=ids, app=app)
    queue.shutdown()


def _message(text="hello", **extra):
    return {"kind": "message", "text": text, **extra}


def _assess(key=None, **extra):
    return {"kind": "assess", "vuln_id": "CVE-2024-0001", **({"key": key} if key else {}), **extra}


def _custom(env, pairs):
    from src.models.assessment import Assessment

    with env.app.app_context():
        assessment = Assessment.create(status="not_affected", origin="custom", targets=[
            (uuid.UUID(env.ids[variant]), uuid.UUID(env.ids["findings"][package])) for variant, package in pairs])
        _db.session.commit()
        return str(assessment.id)


def _thread(fn, *args):
    out: dict = {}
    thread = threading.Thread(target=lambda: out.setdefault("value", fn(*args)))
    thread.start()
    return thread, out


def _wait(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.01)


def _get(queue, request_id) -> dict:
    request = queue.get_request(request_id)
    assert request is not None
    return request


def _status(env, request_id):
    return _get(env.q, request_id)["status"]


def _config(text):
    Path(os.environ["VULNSCOUT_CONFIG"]).write_text(text)


# ---------------------------------------------------------------- scheduling


def test_lanes_run_fifo_with_positions_and_record_transcripts(env):
    q = env.q
    created, skipped = q.enqueue("main", "web", [_message("one"), _message("two")], model="m")
    [action], _ = q.enqueue("per-action", "cli", [_assess()], model="m")
    assert skipped == [] and [c["conversation_id"] for c in created] == ["main", "main"]
    snapshot = q.snapshot()
    assert snapshot["epoch"] == env.events.epoch and snapshot["seq"] == env.events.seq
    assert snapshot["paused"] is None
    assert [(r["kind"], r["lane"], r["position"]) for r in snapshot["requests"]] == [
        ("message", "chat", 1), ("message", "chat", 2), ("assess", "action", 1)]
    request = q.get_request(created[1]["id"])
    assert request["position"] == 2 and request["key"] == f"message:{created[1]['id']}"
    assert request["title"] == "two" and request["timeout"] == aq.CHAT_TIMEOUT

    assert q.run_once("chat") == created[0]["id"]
    assert q.run_once("chat") == created[1]["id"]
    assert q.run_once("chat") is None
    assert q.run_once("action") == action["id"]
    first, second = env.fake.calls[:2]
    assert first.prompt == "one" and first.profile is None and first.turn is None and first.model == "m"
    assert second.session is first.session and first.scope == q._conversations["main"].session.session_scope

    transcript = q.main_transcript()
    assert [(m["role"], m["content"], m["taskId"]) for m in transcript["messages"]] == [
        ("user", "one", created[0]["id"]), ("assistant", "answer", created[0]["id"]),
        ("user", "two", created[1]["id"]), ("assistant", "answer", created[1]["id"])]
    # Each request reports its own turn's usage; the conversation adds them up.
    assert transcript["usage"] == {key: 2 * value for key, value in USAGE.items()}
    done = q.get_request(action["id"])
    assert done["status"] == "done" and done["result"]["outcome"] == "no_write" and done["result"]["reply"] == "answer"
    assert done["vuln_id"] == "CVE-2024-0001" and done["text"].startswith("Assess")
    snapshot = q.snapshot()
    assert snapshot["requests"] == [] and [r["id"] for r in snapshot["history"]] == [
        created[0]["id"], created[1]["id"], action["id"]]
    assert "reply" not in snapshot["history"][2]["result"]
    [main, conversation] = snapshot["conversations"]
    assert main["id"] == "main" and main["message_count"] == 4 and main["live"] is None
    assert conversation["kind"] == "action" and conversation["profile"] == "assess"
    assert conversation["title"].startswith("Assess CVE-2024-0001")
    assert env.events.of("conversation")[-1]["id"] == conversation["id"]
    assert q.conversation(conversation["id"])["messages"][1]["content"] == "answer"
    assert q.conversation("nope") is None and q.get_request("nope") is None


def test_a_chat_runs_while_an_action_turn_is_blocked(env):
    started, release = threading.Event(), threading.Event()
    env.fake.script["assess"].append(blocking(started, release))
    [action], _ = env.q.enqueue("per-action", "web", [_assess("k")], model="m")
    thread, out = _thread(env.q.run_once, "action")
    try:
        assert started.wait(10)
        assert env.q.run_once("action") is None
        [message], _ = env.q.enqueue("main", "web", [_message()], model="m")
        assert env.q.run_once("chat") == message["id"]
        # A running key is still active: queuing it again is skipped.
        assert env.q.enqueue("per-action", "web", [_assess("k")], model="m") == (
            [], [{"key": "k", "request_id": action["id"], "request_ids": [action["id"]]}])
        with pytest.raises(aq.QueueConflict, match="running"):
            env.q.remove(action["id"])
        with pytest.raises(aq.QueueBusy):
            env.q.reset_connection()
        with pytest.raises(aq.QueueBusy):
            with env.q.connection_change():
                pass  # pragma: no cover
        with pytest.raises(aq.QueueConflict):
            env.q.delete_conversation(action["conversation_id"])
        assert env.q.clear() == 0
    finally:
        release.set()
        thread.join(10)
    assert out["value"] == action["id"] and _status(env, action["id"]) == "done"


def test_a_follow_up_waits_for_its_action_and_reuses_its_scope_and_profile(env):
    from src.routes import agent_skills

    [action], _ = env.q.enqueue("per-action", "web", [_assess()], model="m")
    conversation = action["conversation_id"]
    [follow], _ = env.q.enqueue(conversation, "web", [_message("why?")], model="m")
    assert env.q.get_request(follow["id"])["timeout"] == agent_skills.ACTION_TIMEOUT
    assert env.q.run_once("chat") is None
    assert env.q.run_once("action") == action["id"]
    assert env.q.run_once("chat") == follow["id"]
    turn, chat = env.fake.calls
    assert chat.scope == turn.scope == turn.turn.scope and chat.profile is agent_skills.ASSESS
    assert chat.session is turn.session and chat.timeout == agent_skills.ACTION_TIMEOUT
    assert env.q.conversation(conversation)["message_count"] == 4
    assert env.deleted == []  # the follow-up resumed the action's session


def test_a_follow_up_after_batches_may_write_every_batch_target(env, monkeypatch):
    from src.controllers import ai_actions

    monkeypatch.setattr(ai_actions, "PROMPT_BUDGET", 330)
    first, second = env.q.enqueue("per-action", "web", [_assess()], model="m")[0]
    [follow], _ = env.q.enqueue(first["conversation_id"], "web", [_message("why?")], model="m")
    env.q.run_once("action"), env.q.run_once("action"), env.q.run_once("chat")
    one, two, chat = env.fake.calls
    targets = [json.loads(call.scope)["write_targets"] for call in (one, two)]
    assert targets[0] != targets[1] and json.loads(chat.scope)["write_targets"] == targets[0] + targets[1]
    # Each batch has its own session; the follow-up resumes the last one.
    assert env.deleted == [f"s-{first['id']}"] and chat.session.session_id == f"s-{second['id']}"


def test_messages_carry_their_browser_context(env):
    context = {"page": "vulnerabilities", "projectId": env.ids["demo"], "variantId": env.ids["x86"]}
    [request], _ = env.q.enqueue("main", "web", [_message("look")], model="m", context=context)
    env.q.run_once("chat")
    [call] = env.fake.calls
    assert call.prompt.startswith("look\n\nCurrent VulnScout browser view") and env.ids["x86"] in call.scope
    assert env.q.main_transcript()["messages"][0]["content"] == "look"
    assert env.q.get_request(request["id"])["context"] == context

    # Another scope starts another SDK session; the replaced one is deleted.
    env.q.enqueue("main", "web", [_message("wider")], model="m")
    env.q.run_once("chat")
    assert env.deleted == ["s-" + request["id"]]


def test_a_request_that_is_no_longer_next_does_not_start(env, monkeypatch):
    [request], _ = env.q.enqueue("main", "web", [_message()], model="m")
    load = env.q._load_credentials

    def remove_while_loading():
        env.q.remove(request["id"])
        return load()

    monkeypatch.setattr(env.q, "_load_credentials", remove_while_loading)
    assert env.q.run_once("chat") is None and env.fake.calls == []


def test_credentials_loaded_before_a_connection_change_are_not_used(env, monkeypatch):
    [request], _ = env.q.enqueue("per-action", "web", [_assess()], model="m")
    load = env.q._load_credentials

    def change_while_loading():
        loaded = load()
        with env.q.connection_change():
            pass
        monkeypatch.setattr(env.q, "_load_credentials", load)
        return loaded

    monkeypatch.setattr(env.q, "_load_credentials", change_while_loading)
    assert env.q.run_once("action") is None and env.fake.calls == []
    assert env.q.run_once("action") == request["id"]  # with the new connection's credentials


def test_dedupe_skips_active_keys_and_batches_share_a_conversation(env, monkeypatch):
    from src.controllers import ai_actions

    monkeypatch.setattr(ai_actions, "PROMPT_BUDGET", 330)
    created, skipped = env.q.enqueue("per-action", "web", [_assess(), _assess(), _assess("k"), _assess("k")],
                                     model="m", timeout=30)
    first, second, keyed, keyed_batch = created
    assert first["key"] == second["key"] and first["conversation_id"] == second["conversation_id"]
    assert keyed["conversation_id"] == keyed_batch["conversation_id"] != first["conversation_id"]
    assert skipped == [{"key": first["key"], "request_id": first["id"], "request_ids": [first["id"], second["id"]]},
                       {"key": "k", "request_id": keyed["id"], "request_ids": [keyed["id"], keyed_batch["id"]]}]
    assert env.q.get_request(first["id"])["timeout"] == 30
    titles = [r["title"] for r in env.q.snapshot()["requests"]]
    assert titles[1].endswith("batch 2 of 2")
    [summary] = [c for c in env.q.snapshot()["conversations"] if c["id"] == first["conversation_id"]]
    assert "batch" not in summary["title"]
    # Each batch reports its own turn's usage; the shared conversation adds them up.
    assert env.q.run_once("action") == first["id"]
    # Joined after its first batch finished: every batch of the action is reported, in batch order.
    assert env.q.enqueue("per-action", "web", [_assess()], model="m")[1] == [
        {"key": first["key"], "request_id": second["id"], "request_ids": [first["id"], second["id"]]}]
    assert env.q.run_once("action") == second["id"]
    assert [env.q.get_request(r["id"])["result"]["usage"] for r in (first, second)] == [USAGE, USAGE]
    [summary] = [c for c in env.q.snapshot()["conversations"] if c["id"] == first["conversation_id"]]
    assert summary["usage"] == {key: 2 * value for key, value in USAGE.items()}
    assert env.q.enqueue("per-action", "web", [_assess("k")], model="m") == (
        [], [{"key": "k", "request_id": keyed["id"], "request_ids": [keyed["id"], keyed_batch["id"]]}])

    env.fake.script["message"].append(raising(RuntimeError("boom")))
    [message], _ = env.q.enqueue("main", "web", [_message(key="ask")], model="m")
    env.q.run_once("chat")
    assert _status(env, message["id"]) == "failed"
    assert env.q.enqueue("main", "web", [_message(key="ask")], model="m")[1] == [
        {"key": "ask", "request_id": message["id"], "request_ids": [message["id"]]}]


def test_a_skipped_key_whose_holder_left_while_planning_is_still_reported(env, monkeypatch):
    [holder], _ = env.q.enqueue("per-action", "web", [_assess("k")], model="m")
    plan = env.q._plan

    def remove_after_planning(*args):
        planned = plan(*args)
        env.q.remove(holder["id"])
        return planned

    monkeypatch.setattr(env.q, "_plan", remove_after_planning)
    assert env.q.enqueue("per-action", "web", [_assess("k")], model="m") == (
        [], [{"key": "k", "request_id": holder["id"], "request_ids": [holder["id"]]}])


def test_remove_clear_and_retry(env):
    env.fake.script["message"].append(raising(RuntimeError("boom")))
    created, _ = env.q.enqueue("main", "web", [_message("a"), _message("b"), _message("c")], model="m")
    a, b, c = (item["id"] for item in created)
    assert env.q.run_once("chat") == a
    failed = env.q.get_request(a)
    assert failed["status"] == "failed" and failed["error_code"] == "failed" and failed["position"] is None
    assert failed["error"].startswith("Agent request failed. Check Copilot sign-in")
    assert env.deleted == ["doomed"]  # the failed turn's new session
    assert [r["position"] for r in env.q.snapshot()["requests"]] == [None, 1, 2]

    env.q.retry(a)
    assert [r["id"] for r in env.q.snapshot()["requests"]] == [b, c, a]
    assert env.q.get_request(a)["position"] == 3 and env.q.get_request(a)["error"] is None
    with pytest.raises(aq.QueueConflict, match="failed"):
        env.q.retry(b)
    assert env.q.run_once("chat") == b  # a failed request blocks nothing
    with pytest.raises(aq.QueueConflict, match="finished"):
        env.q.remove(b)
    with pytest.raises(LookupError):
        env.q.remove("nope")

    env.q.remove(c)
    assert env.q.get_request(c)["status"] == "cancelled" and env.q.get_request(c)["error"] == aq.REMOVED
    [action], _ = env.q.enqueue("per-action", "web", [_assess()], model="m")
    assert env.q.stop(action["id"]) == "removed"
    assert action["conversation_id"] not in {c["id"] for c in env.q.snapshot()["conversations"]}
    env.q.enqueue("per-action", "web", [_assess()], model="m")
    assert env.q.clear() == 2 and env.q.snapshot()["requests"] == []
    with pytest.raises(aq.QueueConflict):
        env.q.stop(a)


def test_stop_cancels_a_running_turn_and_keeps_its_writes(env):
    from src.models.assessment import Assessment

    started = threading.Event()

    async def write_then_hang(call):
        call.on_session("hung")
        with env.app.app_context():
            row = Assessment.create(status="not_affected", origin="ai", targets=[
                (uuid.UUID(env.ids["x86"]), uuid.UUID(env.ids["findings"]["openssl"]))])
            _db.session.commit()
            call.turn.guard.written.append(str(row.id))
        call.publish({"type": "delta", "message_id": "m1", "text": "partial"})
        started.set()
        await asyncio.sleep(3600)

    env.fake.script["assess"].append(write_then_hang)
    only_arm = [{"variant_id": env.ids["arm"], "package": "openssl@3.0"}]
    created, _ = env.q.enqueue("per-action", "web", [_assess("a"), _assess("b"), _assess("c", targets=only_arm)],
                               model="m")
    first, second, third = (item["id"] for item in created)
    assert env.q.get_request(third)["detail"] == "arm · openssl@3.0"
    assert env.q.stop(third) == "removed"
    thread, out = _thread(env.q.run_once, "action")
    assert started.wait(10)
    assert env.q.stop(first) == "stopping"
    thread.join(10)
    stopped = env.q.get_request(first)
    assert (stopped["status"], stopped["error"], stopped["error_code"]) == ("cancelled", aq.STOPPED, "stopped")
    assert stopped["result"]["outcome"] == "interrupted"
    assert sorted((t["variant"], t["package"]) for t in stopped["result"]["targets"] if t["written"]) == [
        ("x86", "openssl@3.0")] and len(stopped["result"]["targets"]) == 3
    assert env.q.conversation(created[0]["conversation_id"])["messages"] == []
    assert env.deleted == ["hung"]  # created, but the stopped turn did not keep it
    assert env.q.run_once("action") == second and _status(env, second) == "done"


def test_a_stop_before_the_turn_task_exists_cancels_it_at_once(env, monkeypatch):
    [request], _ = env.q.enqueue("main", "web", [_message()], model="m")
    real = env.q._call

    def call_then_stop(*args):
        call = real(*args)
        env.q.stop(request["id"])
        return call

    monkeypatch.setattr(env.q, "_call", call_then_stop)
    env.q.run_once("chat")
    assert _status(env, request["id"]) == "cancelled" and env.fake.calls == []


# ---------------------------------------------------------------- readiness


@pytest.mark.parametrize("config, code", [
    ("", "no_ai_config"),
    ("AI_PROVIDER=bogus\n", "invalid_config"),
    ("AI_PROVIDER=github\nAI_AUTH_CREDENTIALS=gho_test\n", "github_signed_out"),
])
def test_the_queue_pauses_without_a_usable_connection_and_wakes(env, monkeypatch, config, code):
    from src.routes import agent

    async def signed_out(token):
        return {"authenticated": False}

    _config(config)
    monkeypatch.setattr(agent, "_token_status", signed_out)
    [request], _ = env.q.enqueue("main", "web", [_message()], model="m")
    assert env.q.run_once("chat") is None
    paused = env.q.snapshot()["paused"]
    assert paused["code"] == code and env.q.paused == paused and env.q.readiness()["code"] == code
    assert env.q.run_once("chat") is None  # stays paused until woken
    with pytest.raises(aq.NotReady) as raised:
        env.q.enqueue("main", "web", [_message()], model="m", require_ready=True)
    assert raised.value.code == code and env.q.paused["code"] == code

    _config("AI_PROVIDER=github\nAI_AUTH_CREDENTIALS=gho_test\nAI_MODEL=test-model\n")

    async def signed_in(token):
        return {"authenticated": True}

    monkeypatch.setattr(agent, "_token_status", signed_in)
    env.q.wake()
    assert env.q.paused is None and env.q.run_once("chat") == request["id"]
    [created], _ = env.q.enqueue("main", "web", [_message()], require_ready=True)
    assert env.q.get_request(created["id"])["model"] == "test-model"


def test_without_a_configuration_web_turns_run_as_the_logged_in_copilot_user(env, monkeypatch):
    from src.routes import agent

    checks = []

    async def logged_in(token):
        checks.append(token)
        return {"authenticated": True, "login": "octo"}

    _config("")
    monkeypatch.setattr(agent, "_auth_status", logged_in)
    [first], _ = env.q.enqueue("main", "web", [_message()], model="m")
    [second], _ = env.q.enqueue("main", "web", [_message("again")], model="m")
    assert env.q.run_once("chat") == first["id"] and env.q.run_once("chat") == second["id"]
    assert checks == [None]  # checked once until the next wake
    credentials = env.fake.calls[0].session.credentials
    assert credentials.token is None and credentials.provider is None
    # The CLI's readiness still requires a configuration; its rejection leaves the web queue running.
    assert env.q.readiness()["code"] == "no_ai_config"
    with pytest.raises(aq.NotReady):
        env.q.enqueue("per-action", "CLI", [{"kind": "assess", "vuln_id": "CVE-2024-0001"}], require_ready=True)
    assert env.q.paused is None and env.q.snapshot()["requests"] == []
    [third], _ = env.q.enqueue("main", "web", [_message("third")], model="m")
    assert env.q.run_once("chat") == third["id"]


def test_a_failing_logged_in_user_check_pauses_the_queue(env, monkeypatch):
    from src.routes import agent

    async def unreachable(token):
        raise OSError("offline")

    _config("")
    monkeypatch.setattr(agent, "_auth_status", unreachable)
    env.q.enqueue("main", "web", [_message()], model="m")
    assert env.q.run_once("chat") is None and env.q.paused["code"] == "no_ai_config"


def test_an_inconclusive_sign_in_check_runs_the_turn(env, monkeypatch):
    from src.routes import agent

    async def unreachable(token):
        raise OSError("offline")

    monkeypatch.setattr(agent, "_token_status", unreachable)
    env.q.enqueue("main", "web", [_message()], model="m")
    assert env.q.run_once("chat") is not None


def test_a_provider_turn_uses_the_requested_model(env):
    _config("AI_PROVIDER=openai\nAI_AUTH_CREDENTIALS=key\nAI_MODEL=gpt-configured\n")
    env.fake.script["message"].append(raising(RuntimeError("boom")))
    created, _ = env.q.enqueue("main", "web", [_message(), _message()], model="other")
    env.q.run_once("chat")
    env.q.run_once("chat")
    failing, call = env.fake.calls
    provider = call.session.credentials.provider
    assert provider.model == "other" and provider.models == [{"id": "other", "name": "other"}]
    assert env.q.get_request(created[0]["id"])["error"].startswith("Agent request failed. Check the provider")


def test_requests_queued_before_setup_take_the_connected_models(env):
    used = []

    async def record(call):
        used.append(call.session.credentials.provider.model)
        return await ok(call)

    env.fake.script["message"] += [record, record]
    _config("")
    [unset], _ = env.q.enqueue("main", "web", [_message()])
    [chosen], _ = env.q.enqueue("main", "web", [_message("pinned")], model="pinned")
    assert _get(env.q, unset["id"])["model"] is None and _get(env.q, chosen["id"])["model"] == "pinned"
    with env.q.connection_change():
        _config("AI_PROVIDER=openai\nAI_AUTH_CREDENTIALS=key\nAI_MODEL=gpt-configured\n")
    env.q.run_once("chat")
    env.q.run_once("chat")
    assert [call.model for call in env.fake.calls] == used == ["gpt-configured", "pinned"]
    assert _get(env.q, unset["id"])["model"] == "gpt-configured"


def test_a_retry_takes_the_selected_model_unless_one_was_chosen(env):
    from src.routes import agent

    _config("AI_PROVIDER=openai\nAI_AUTH_CREDENTIALS=key\nAI_MODEL=first\n")
    env.fake.script["message"] += [raising(RuntimeError("boom")), raising(RuntimeError("boom"))]
    [unset], _ = env.q.enqueue("main", "web", [_message()])
    [chosen], _ = env.q.enqueue("main", "web", [_message("pinned")], model="pinned")
    env.q.run_once("chat")
    env.q.run_once("chat")
    [waiting], _ = env.q.enqueue("main", "web", [_message("waiting")])
    agent._connection().model = "second"
    env.q.model_changed()
    env.q.retry(unset["id"])
    env.q.retry(chosen["id"])
    assert _get(env.q, unset["id"])["model"] is None
    for _ in range(3):
        env.q.run_once("chat")
    # P6: the waiting request kept its model; the retried one takes the selected model.
    assert [call.model for call in env.fake.calls[2:]] == ["first", "second", "pinned"]


# ---------------------------------------------------------------- errors


@pytest.mark.parametrize("make, code, error", [
    (lambda: TimeoutError(), "timeout", f"No reply within {aq.CHAT_TIMEOUT} s."),
    (lambda: __import__("src.routes.agent", fromlist=["x"]).UnavailableModelError("Selected model is gone."),
     "unavailable_model", "Selected model is gone."),
    (lambda: __import__("src.routes.agent_skills", fromlist=["x"]).AgentSkillError("Skills missing."),
     "skills", "Skills missing."),
])
def test_turn_errors_map_to_request_errors(env, make, code, error):
    env.fake.script["message"].append(raising(make()))
    [request], _ = env.q.enqueue("main", "web", [_message()], model="m")
    env.q.run_once("chat")
    failed = env.q.get_request(request["id"])
    assert (failed["status"], failed["error_code"], failed["error"]) == ("failed", code, error)


def test_action_errors_reach_the_verified_result(env, monkeypatch):
    from src.controllers import ai_actions

    env.fake.script["assess"].append(raising(TimeoutError()))
    created, _ = env.q.enqueue("per-action", "web", [_assess("a"), _assess("b")], model="m", timeout=5)
    env.q.run_once("action")
    failed = env.q.get_request(created[0]["id"])
    assert failed["error"] == "No reply within 5 s." and failed["result"]["outcome"] == "timeout"

    def broken(*args):
        raise RuntimeError("db gone")

    monkeypatch.setattr(ai_actions, "verify", broken)
    env.q.run_once("action")
    assert env.q.get_request(created[1]["id"])["error_code"] == "verify"


def test_a_review_that_saves_nothing_fails(env):
    assessment_id = _custom(env, [("x86", "openssl"), ("arm", "openssl")])
    created, _ = env.q.enqueue("per-action", "web", [
        {"kind": "review", "assessment_id": assessment_id, "variant_id": env.ids["x86"],
         "finding_ids": [env.ids["findings"]["openssl"]]}], model="m")
    env.q.run_once("action")
    review = env.q.get_request(created[0]["id"])
    assert review["status"] == "failed" and review["error_code"] == "no_write"
    assert review["error"] == "The agent saved no review for this target." and review["assessment_id"] == assessment_id
    assert env.q.conversation(created[0]["conversation_id"])["profile"] == "review"


def test_a_review_pinned_to_older_content_reports_its_targets_changed(env):
    assessment_id = _custom(env, [("x86", "openssl")])
    [review], _ = env.q.enqueue("per-action", "web", [
        {"kind": "review", "assessment_id": assessment_id, "variant_id": env.ids["x86"], "fingerprint": "older"}],
        model="m")
    env.q.run_once("action")
    result = env.q.get_request(review["id"])["result"]
    assert [target["outcome"] for target in result["targets"]] == ["changed"]


def test_a_review_pinned_to_new_content_replaces_its_failed_request(env):
    assessment_id = _custom(env, [("x86", "openssl")])

    def review(fingerprint):
        return {"kind": "review", "assessment_id": assessment_id, "variant_id": env.ids["x86"],
                "key": "review-k", "fingerprint": fingerprint}

    env.fake.script["review"].append(raising(RuntimeError("boom")))
    [failed], _ = env.q.enqueue("per-action", "cli", [review("fp-1")], model="m")
    env.q.run_once("action")
    assert _status(env, failed["id"]) == "failed"
    # The same content: still followed (a retry can succeed).
    assert env.q.enqueue("per-action", "cli", [review("fp-1")], model="m") == (
        [], [{"key": "review-k", "request_id": failed["id"], "request_ids": [failed["id"]]}])

    [fresh], skipped = env.q.enqueue("per-action", "cli", [review("fp-2"), review("fp-2")], model="m")
    assert skipped == [{"key": "review-k", "request_id": fresh["id"], "request_ids": [fresh["id"]]}]
    assert [r["id"] for r in env.q.snapshot()["requests"]] == [fresh["id"]]
    assert fresh["conversation_id"] != failed["conversation_id"]
    assert env.q.get_request(failed["id"])["status"] == "failed"  # still found by ID
    assert env.q.get_request(fresh["id"])["status"] == "queued"
    # Not while it waits or runs: a newer pin is then followed, like any active key.
    assert env.q.enqueue("per-action", "cli", [review("fp-3")], model="m") == (
        [], [{"key": "review-k", "request_id": fresh["id"], "request_ids": [fresh["id"]]}])


def test_prepare_and_installation_errors_fail_the_request(env, monkeypatch):
    from src.models.assessment import Assessment

    assessment_id = _custom(env, [("x86", "openssl")])
    [review], _ = env.q.enqueue("per-action", "web", [{"kind": "review", "assessment_id": assessment_id}],
                                model="m")
    with env.app.app_context():
        _db.session.delete(_db.session.get(Assessment, uuid.UUID(assessment_id)))
        _db.session.commit()
    env.q.run_once("action")
    assert env.q.get_request(review["id"])["error_code"] == "prepare"

    monkeypatch.setenv("VULNSCOUT_MCP_SERVER_PATH", "/nonexistent/server.py")
    [message], _ = env.q.enqueue("main", "web", [_message()], model="m")
    env.q.run_once("chat")
    assert (env.q.get_request(message["id"])["error_code"], env.q.get_request(message["id"])["error"]) == (
        "mcp", aq.MCP_MISSING)


@pytest.mark.parametrize("conversation, actions, options, match", [
    ("", [_message()], {}, "conversation"),
    ("main", [_message()], {"source": ""}, "source"),
    ("main", [_message()], {"source": "x" * 101}, "source"),
    ("main", [_message()], {"model": "bad\nmodel"}, "model"),
    ("main", [_message()], {"timeout": 0}, "timeout"),
    ("main", [_message()], {"timeout": True}, "timeout"),
    ("main", [], {}, "between 1 and"),
    ("main", "nope", {}, "between 1 and"),
    ("main", ["nope"], {}, "object"),
    ("main", [{"kind": "explode"}], {}, "kind"),
    ("main", [_message(key="")], {}, "key"),
    ("main", [_message(context={"page": "nowhere"})], {}, "page context"),
    ("per-action", [_message()], {}, "Messages go"),
    ("main", [_message("   ")], {}, "Enter a message"),
    ("main", [_message("x" * 8001)], {}, "Enter a message"),
    ("main", [_assess()], {}, "per-action"),
    ("per-action", [{"kind": "assess", "vuln_id": "-nope"}], {}, "vulnerability ID"),
    ("per-action", [_assess(targets=[])], {}, "targets"),
    ("per-action", [_assess(targets=["x"])], {}, "variant_id and a package"),
    ("per-action", [_assess(targets=[{"package": "openssl@3.0", "variant_id": "x"}])], {}, "variant ID"),
    ("per-action", [{"kind": "review", "assessment_id": "nope"}], {}, "assessment ID"),
    ("per-action", [{"kind": "review", "assessment_id": str(uuid.uuid4()), "variant_id": 3}], {}, "variant ID"),
    ("per-action", [{"kind": "review", "assessment_id": str(uuid.uuid4()), "finding_ids": []}], {}, "finding_ids"),
    ("per-action", [{"kind": "review", "assessment_id": str(uuid.uuid4()), "finding_ids": ["x"]}], {},
     "finding ID"),
    ("per-action", [{"kind": "review", "assessment_id": str(uuid.uuid4()), "fingerprint": 3}], {}, "fingerprint"),
    ("per-action", [_assess(), {"kind": "review", "assessment_id": str(uuid.uuid4())}], {}, "."),
])
def test_enqueue_validates_every_action_before_queuing_any(env, conversation, actions, options, match):
    options = {"source": "web", "model": "m", **options}
    with pytest.raises(ValueError, match=match):
        env.q.enqueue(conversation, options.pop("source"), actions, **options)
    assert env.q.snapshot()["requests"] == [] and len(env.q.snapshot()["conversations"]) == 1


def test_enqueue_rejects_unknown_and_archived_conversations(env, monkeypatch):
    with pytest.raises(LookupError):
        env.q.enqueue("nope", "web", [_message()], model="m")
    monkeypatch.setattr(aq, "LIVE_SESSION_LIMIT", 0)
    [action], _ = env.q.enqueue("per-action", "web", [_assess()], model="m")
    env.q.run_once("action")
    with pytest.raises(aq.QueueConflict, match="archived"):
        env.q.enqueue(action["conversation_id"], "web", [_message()], model="m")


# ---------------------------------------------------------------- connection


def test_reset_connection_fails_waiting_requests_of_conversations_with_history(env):
    from src.routes import agent_skills

    env.q.enqueue("main", "web", [_message("first")], model="m")
    [done_action], _ = env.q.enqueue("per-action", "web", [_assess("done")], model="m")
    env.q.run_once("chat")
    env.q.run_once("action")
    [main_wait], _ = env.q.enqueue("main", "web", [_message("second")], model="m")
    [follow], _ = env.q.enqueue(done_action["conversation_id"], "web", [_message("why")], model="m")
    [fresh], _ = env.q.enqueue("per-action", "web", [_assess("fresh")], model="m")
    env.q.reset_connection()
    snapshot = env.q.snapshot()
    states = {r["id"]: (r["status"], r["error_code"]) for r in snapshot["requests"]}
    assert states == {main_wait["id"]: ("failed", "connection_changed"),
                      follow["id"]: ("failed", "connection_changed"), fresh["id"]: ("queued", None)}
    assert env.q.get_request(main_wait["id"])["error"] == aq.CONNECTION_CHANGED
    assert snapshot["history"] == []
    conversations = {c["id"]: c for c in snapshot["conversations"]}
    assert set(conversations) == {"main", done_action["conversation_id"], fresh["conversation_id"]}
    assert all(c["message_count"] == 0 for c in conversations.values())
    copy = env.q._conversations[done_action["conversation_id"]]
    assert copy.profile is agent_skills.ASSESS and copy.scope and copy.session.session_id is None
    env.q.retry(follow["id"])
    env.q.run_once("action")
    assert env.q.run_once("chat") == follow["id"] and env.fake.calls[-1].scope == copy.scope


def test_connection_change_holds_the_queue_and_resets_unless_aborted(env):
    env.q.enqueue("main", "web", [_message()], model="m")
    env.q.run_once("chat")
    [waiting], _ = env.q.enqueue("main", "web", [_message()], model="m")
    with env.q.connection_change() as change:
        assert env.q.run_once("chat") is None
        with pytest.raises(aq.QueueBusy):
            with env.q.connection_change():
                pass  # pragma: no cover
        change.abort()
    assert env.q.main_transcript()["messages"] and _status(env, waiting["id"]) == "queued"

    with pytest.raises(RuntimeError):
        with env.q.connection_change():
            raise RuntimeError("provider rejected")
    assert env.q.main_transcript()["messages"]

    assert env.q.snapshot()["connection_revision"] == 0  # aborted or failed: nothing changed
    with env.q.connection_change():
        pass
    assert env.q.main_transcript()["messages"] == [] and _status(env, waiting["id"]) == "failed"
    assert env.q.snapshot()["connection_revision"] == 1 == env.events.of("queue")[-1]["connection_revision"]
    env.q.model_changed()
    assert env.events.of("queue")[-1]["connection_revision"] == 2


def test_reset_sessions_reports_failures_and_keeps_those_sessions(env, monkeypatch):
    from src.routes import agent

    env.q.enqueue("main", "web", [_message()], model="m")
    [action], _ = env.q.enqueue("per-action", "web", [_assess()], model="m")
    env.q.run_once("chat")
    env.q.run_once("action")
    main_session = env.q._conversations["main"].session.session_id

    async def flaky(token, session_id):
        if session_id == main_session:
            raise OSError("offline")

    monkeypatch.setattr(agent, "_delete_session", flaky)
    assert env.q.reset_sessions() is True
    assert env.q._conversations["main"].session.session_id == main_session
    assert env.q._conversations[action["conversation_id"]].session.session_id is None
    monkeypatch.setattr(agent, "_delete_session", lambda *args: asyncio.sleep(0))
    assert env.q.reset_sessions() is False and env.q._conversations["main"].session.session_id is None


# ---------------------------------------------------------------- conversations


def test_delete_clear_finished_and_reset_main(env):
    env.q.enqueue("main", "web", [_message()], model="m")
    first, _ = env.q.enqueue("per-action", "web", [_assess("a")], model="m")
    second, _ = env.q.enqueue("per-action", "web", [_assess("b")], model="m")
    env.q.run_once("chat")
    env.q.run_once("action")
    env.q.run_once("action")
    with pytest.raises(LookupError):
        env.q.delete_conversation("nope")
    with pytest.raises(aq.QueueConflict, match="main"):
        env.q.delete_conversation("main")
    env.q.delete_conversation(first[0]["conversation_id"])
    assert env.deleted == ["s-" + first[0]["id"]]
    assert env.q.conversation(first[0]["conversation_id"]) is None
    assert first[0]["id"] not in {r["id"] for r in env.q.snapshot()["history"]}
    [queued], _ = env.q.enqueue("per-action", "web", [_assess("c")], model="m")
    assert env.q.clear_finished() == 1 and env.deleted[-1] == "s-" + second[0]["id"]
    assert {c["id"] for c in env.q.snapshot()["conversations"]} == {"main", queued["conversation_id"]}

    main_session = env.q._conversations["main"].session.session_id
    env.q.reset_main()
    empty = {"cost": None, "input_tokens": None, "output_tokens": None}
    assert env.q.main_transcript() == {"messages": [], "usage": empty}
    assert env.deleted[-1] == main_session and env.q.snapshot()["history"] == []

    started, release = threading.Event(), threading.Event()
    env.fake.script["message"].append(blocking(started, release))
    env.q.enqueue("main", "web", [_message()], model="m")
    thread, _ = _thread(env.q.run_once, "chat")
    try:
        assert started.wait(10)
        with pytest.raises(aq.QueueConflict, match="running"):
            env.q.reset_main()
    finally:
        release.set()
        thread.join(10)


def test_idle_action_sessions_and_conversations_are_capped(env, monkeypatch):
    monkeypatch.setattr(aq, "LIVE_SESSION_LIMIT", 1)
    monkeypatch.setattr(aq, "CONVERSATION_LIMIT", 2)
    first, _ = env.q.enqueue("per-action", "web", [_assess("a")], model="m")
    env.q.run_once("action")
    second, _ = env.q.enqueue("per-action", "web", [_assess("b")], model="m")
    env.q.run_once("action")
    old = env.q.conversation(first[0]["conversation_id"])
    assert old["archived"] and old["message_count"] == 2 and env.deleted == ["s-" + first[0]["id"]]
    assert not env.q.conversation(second[0]["conversation_id"])["archived"]
    third, _ = env.q.enqueue("per-action", "web", [_assess("c")], model="m")
    assert env.q.conversation(first[0]["conversation_id"]) is None  # oldest archived evicted
    assert first[0]["id"] not in {r["id"] for r in env.q.snapshot()["history"]}
    assert env.q.get_request(first[0]["id"])["status"] == "done"  # still found by ID
    env.q.run_once("action")
    assert env.q.conversation(second[0]["conversation_id"])["archived"]

    # Archived while a follow-up waits: the turn refuses to run.
    [follow], _ = env.q.enqueue(third[0]["conversation_id"], "web", [_message()], model="m")
    env.q._conversations[third[0]["conversation_id"]].archived = True
    env.q.run_once("chat")
    assert env.q.get_request(follow["id"])["error_code"] == "archived"


def test_history_and_finished_index_are_capped(env, monkeypatch):
    monkeypatch.setattr(aq, "HISTORY_LIMIT", 2)
    monkeypatch.setattr(aq, "FINISHED_LIMIT", 3)
    created, _ = env.q.enqueue("main", "web", [_message(str(n)) for n in range(4)], model="m")
    while env.q.run_once("chat"):
        pass
    ids = [item["id"] for item in created]
    assert [r["id"] for r in env.q.snapshot()["history"]] == ids[2:]
    assert env.q.get_request(ids[0]) is None and env.q.get_request(ids[1])["status"] == "done"


# ---------------------------------------------------------------- progress


def test_progress_is_coalesced_and_writes_are_announced(env, monkeypatch):
    monkeypatch.setattr(aq, "ACTIVITY_LIMIT", 2)
    snapshots = []

    async def stream(call):
        snapshots.append(env.q.conversation(call.request.conversation_id)["live"])
        for n in range(100):
            call.publish({"type": "delta", "message_id": "m1", "text": f"{n},"})
        call.publish({"type": "delta", "message_id": "m2", "text": "final"})
        call.publish({"type": "unknown"})
        await asyncio.sleep(aq.PROGRESS_INTERVAL * 2)  # the scheduled flush fires
        for n in range(3):
            call.publish({"type": "tool_start", "id": f"t{n}", "name": f"tool{n}"})
        call.publish({"type": "tool_end", "id": "t2", "success": True, "write": True})
        call.publish({"type": "tool_end", "id": "t1", "success": False, "write": False})
        return await ok(call)

    env.fake.script["message"].append(stream)
    [request], _ = env.q.enqueue("main", "web", [_message("hi")], model="m")
    env.q.run_once("chat")
    assert snapshots[0] == {"request_id": request["id"], "pending_message": "hi", "live_reply": "",
                            "activity": [], "progress": "Connecting to Copilot..."}
    progress = env.events.of("request_progress")
    assert 2 <= len(progress) <= 5
    assert any(p["live"]["live_reply"] == "final" and p["live"]["progress"] == "Writing response..."
               for p in progress)
    last = progress[-1]
    assert last["request_id"] == request["id"] and last["conversation_id"] == "main"
    assert last["live"]["activity"] == [{"id": "t1", "name": "tool1", "status": "failed"},
                                        {"id": "t2", "name": "tool2", "status": "done"}]
    assert last["live"]["progress"] == "Preparing response..."
    assert env.events.of("agent_write") == [{"tool": "tool2", "request_id": request["id"],
                                             "conversation_id": "main"}]
    assistant = env.q.main_transcript()["messages"][1]
    assert assistant["activity"] == last["live"]["activity"]
    assert env.q.conversation("main")["live"] is None

    stale = SimpleNamespace(request_id="gone", progress_pending=True, flush_scheduled=True)
    env.q._flush_progress(stale, env.q._conversations["main"])  # the turn already ended
    assert len(env.events.of("request_progress")) == len(progress)
    env.q._on_progress(SimpleNamespace(id="gone"), env.q._conversations["main"], stale, {"type": "delta"})


# ---------------------------------------------------------------- runners and workers


def test_the_default_runner_uses_reply_and_run_turn(env, monkeypatch):
    from src.routes import agent

    calls = []

    async def reply(conversation, message, path, model, scope, publish=None, **kwargs):
        calls.append((message, model, scope, kwargs))
        kwargs["on_session"]("sdk")
        return "fine", dict(USAGE)

    monkeypatch.setattr(agent, "_reply", reply)
    env.q._runner = aq.default_runner
    [action], _ = env.q.enqueue("per-action", "web", [_assess()], model="m")
    [follow], _ = env.q.enqueue(action["conversation_id"], "web", [_message("more")], model="m")
    env.q.run_once("action")
    env.q.run_once("chat")
    (prompt, model, scope, kwargs), (text, _, follow_scope, follow_kwargs) = calls
    assert model == "m" and kwargs["api_url"] == env.q._guarded.url and kwargs["ephemeral"] is False
    assert text == "more" and follow_scope == scope and follow_kwargs["profile"].action == "assess"
    assert "api_url" not in follow_kwargs and follow_kwargs["timeout"] == action_timeout()
    [main], _ = env.q.enqueue("main", "web", [_message("plain")], model="m")
    env.q.run_once("chat")
    assert "profile" not in calls[-1][3] and calls[-1][3]["timeout"] == aq.CHAT_TIMEOUT
    assert _status(env, main["id"]) == "done"


def action_timeout():
    from src.routes import agent_skills

    return agent_skills.ACTION_TIMEOUT


def test_workers_run_requests_in_threads_until_shutdown(app, env, monkeypatch):  # noqa: F811
    queue = aq.AgentQueue(runner=env.fake, events=Recorder())
    with pytest.raises(RuntimeError, match="init_app"):
        queue._app_context()
    queue.init_app(app)
    try:
        created, _ = queue.enqueue("main", "web", [_message("a"), _message("b")], model="m")
        [action], _ = queue.enqueue("per-action", "web", [_assess()], model="m")
        _wait(lambda: all(_get(queue, item["id"])["status"] == "done" for item in [*created, action]))
        queue.wake()
        queue.enqueue("main", "web", [_message("c")], model="m")
        _wait(lambda: queue.snapshot()["requests"] == [])

        def broken(lane, request_id):
            raise RuntimeError("bug")

        monkeypatch.setattr(queue, "_attempt", broken)
        queue.enqueue("main", "web", [_message("d")], model="m")
        _wait(lambda: queue.paused is not None)
        assert (queue.paused or {})["code"] == "error"
    finally:
        queue.shutdown()
    assert all(not thread.is_alive() for thread in threading.enumerate() if thread.name.startswith("agent-queue"))


def test_shutdown_cancels_a_running_turn(app, env):  # noqa: F811
    started = threading.Event()

    async def hang(call):
        started.set()
        await asyncio.sleep(3600)

    env.fake.script["message"].append(hang)
    queue = aq.AgentQueue(app, runner=env.fake, events=Recorder())
    try:
        [request], _ = queue.enqueue("main", "web", [_message()], model="m")
        assert started.wait(10)
    finally:
        queue.shutdown()
    assert _get(queue, request["id"])["status"] == "cancelled"


def test_the_module_singleton_uses_the_agent_bus():
    assert aq.agent_queue.events is aq.agent_events and aq.agent_events is not None

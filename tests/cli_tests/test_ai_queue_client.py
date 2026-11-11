# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""The web AI queue client of ``ai-assess``/``ai-review``: probe, submit, and following a run's requests."""

import dataclasses
import http.server
import json
import signal
import socket
import threading
import uuid

import click
import pytest

from src.bin import _ai_queue_client as qc
from src.bin import _ai_runner
from src.controllers.ai_actions import CHANGED, Target, TurnSpec, assess_key
from src.helpers.review_selection import ReviewTarget
from .queue_fakes import FakeQueueServer, assess_result, done, failed, review_result

VARIANT = str(uuid.uuid4())


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def _scripted(*answers):
    calls = []

    def send(method, path, body, timeout):
        calls.append((method, path, body, timeout))
        answer = answers[min(len(calls), len(answers)) - 1]
        if isinstance(answer, Exception):
            raise answer
        return answer

    return send, calls


# ---------------------------------------------------------------- QueueClient

def test_probe_returns_the_snapshot_or_none_when_nothing_serves_the_queue():
    snapshot: dict = {"requests": []}
    assert qc.QueueClient(_scripted((200, snapshot))[0]).probe() == snapshot
    assert qc.QueueClient(_scripted(qc.ServerUnavailable("refused"))[0]).probe() is None
    assert qc.QueueClient(_scripted((404, None))[0]).probe() is None
    with pytest.raises(click.ClickException, match="AI queue failed: boom"):
        qc.QueueClient(_scripted((500, {"error": "boom"}))[0]).probe()


def test_probe_waits_for_a_starting_server(capsys):
    clock = Clock()
    send, calls = _scripted((503, {"error": "Scan not finished"}), (503, None), (200, {"requests": []}))
    assert qc.QueueClient(send, sleep=clock.sleep, clock=clock).probe() == {"requests": []}
    assert clock.sleeps == [2.0, 2.0] and calls[0][3] == qc.PROBE_TIMEOUT
    assert capsys.readouterr().err.count("waiting for the web server to finish starting") == 1


def test_probe_gives_up_after_a_minute_or_runs_locally_if_the_server_goes_away():
    clock = Clock()
    with pytest.raises(click.ClickException, match="did not finish starting within 60 s"):
        qc.QueueClient(_scripted((503, None))[0], sleep=clock.sleep, clock=clock).probe()
    assert clock.now == 60.0
    send, _ = _scripted((503, None), qc.ServerUnavailable("refused"))
    assert qc.QueueClient(send, sleep=Clock().sleep, clock=Clock()).probe() is None


def test_submit_sends_a_cli_run_that_must_be_ready():
    send, calls = _scripted((202, {"requests": [], "skipped": []}))
    assert qc.QueueClient(send).submit([{"kind": "assess"}], "m", 30) == {"requests": [], "skipped": []}
    assert calls[0][:3] == ("POST", qc.QUEUE_PATH, {
        "conversation": "per-action", "source": "CLI", "require_ready": True, "actions": [{"kind": "assess"}],
        "model": "m", "timeout": 30})
    qc.QueueClient(send).submit([], None, None)
    assert "model" not in calls[1][2] and "timeout" not in calls[1][2]


@pytest.mark.parametrize("answer, message", [
    ((409, {"code": "no_ai_config", "error": "x"}), _ai_runner.NO_AI_CONFIG),
    ((409, {"code": "github_signed_out", "error": "x"}), _ai_runner.GITHUB_SIGNED_OUT),
    ((409, {"code": "invalid_config", "error": "Invalid AI provider configuration: bad"}), "bad"),
    ((400, {"error": "timeout must be at most 3600."}), "rejected this run: timeout must be at most 3600."),
    ((400, "not json"), "rejected this run: HTTP 400"),
])
def test_submit_errors(answer, message):
    with pytest.raises(click.ClickException) as error:
        qc.QueueClient(_scripted(answer)[0]).submit([], None, None)
    assert message in error.value.message


def test_submit_snapshot_and_get_report_server_failures_as_unavailable():
    with pytest.raises(qc.ServerUnavailable):
        qc.QueueClient(_scripted((503, {"error": "Scan not finished"}))[0]).submit([], None, None)
    with pytest.raises(qc.ServerUnavailable):
        qc.QueueClient(_scripted((500, None))[0]).snapshot()
    with pytest.raises(qc.ServerUnavailable):
        qc.QueueClient(_scripted((500, None))[0]).get("r")
    assert qc.QueueClient(_scripted((404, {"error": "Unknown"}))[0]).get("r") is None
    assert qc.QueueClient(_scripted((200, {"id": "r"}))[0]).get("r") == {"id": "r"}


def test_stop_and_retry_ignore_finished_or_unknown_requests():
    send, calls = _scripted((409, {"error": "Already finished."}), (404, None))
    client = qc.QueueClient(send)
    client.stop("a")
    client.retry("b")
    assert [call[:2] for call in calls] == [("POST", f"{qc.QUEUE_PATH}/requests/a/stop"),
                                            ("POST", f"{qc.QUEUE_PATH}/requests/b/retry")]


def test_base_url_targets_the_serve_port(monkeypatch):
    monkeypatch.delenv("FLASK_RUN_PORT", raising=False)
    assert qc.base_url() == "http://127.0.0.1:7275"
    monkeypatch.setenv("FLASK_RUN_PORT", "8000")
    assert qc.base_url() == "http://127.0.0.1:8000"


@pytest.fixture()
def http_server():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b"not json" if self.path == "/text" else json.dumps({"path": self.path}).encode()
            self.send_response(200 if self.path != "/missing" else 404)
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(202)
            self.end_headers()
            self.wfile.write(json.dumps({"echo": payload, "type": self.headers["Content-Type"]}).encode())

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_urllib_transport_sends_json_and_reads_errors(http_server, monkeypatch):
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")  # never used for the local server
    send = qc.urllib_transport(http_server)
    assert send("GET", "/x", None, 5) == (200, {"path": "/x"})
    assert send("POST", "/y", {"a": 1}, 5) == (202, {"echo": {"a": 1}, "type": "application/json"})
    assert send("GET", "/missing", None, 5) == (404, {"path": "/missing"})
    assert send("GET", "/text", None, 5) == (200, None)


def test_the_default_client_reports_a_closed_serve_port_as_unavailable(monkeypatch):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    monkeypatch.setenv("FLASK_RUN_PORT", str(port))
    with pytest.raises(qc.ServerUnavailable):
        qc.QueueClient().snapshot()
    assert qc.QueueClient().probe() is None


# ---------------------------------------------------------------- following a run (run_remote)

def _assess_spec(vuln_id, packages, batch=None, key=None):
    """An assess spec keyed like the server derives it (or by *key*, for the batches of one action)."""
    targets = tuple(Target(VARIANT, "x86", "p", package, f"f-{package}") for package in packages)
    key = key or assess_key(vuln_id, ((VARIANT, package) for package in packages))
    return TurnSpec(kind="assess", key=key, title=vuln_id, detail="", vuln_id=vuln_id,
                    batch=batch, assess_targets=targets, timeout=30)


def _review_spec(assessment_id, finding_ids):
    targets = tuple(ReviewTarget(assessment_id, "CVE-1", uuid.UUID(VARIANT), "x86", uuid.uuid4(), "openssl@3.0",
                                 finding_id, "missing") for finding_id in finding_ids)
    return TurnSpec(kind="review", key=f"review:{assessment_id}:{VARIANT}", title="review", detail="",
                    vuln_id="CVE-1", batch=None, assessment_id=assessment_id, review_targets=targets, timeout=30)


def _label(spec):
    return f"assess:{spec.vuln_id}" if spec.kind == "assess" else spec.key


class Recorder:
    def __init__(self):
        self.events = []

    def start(self, spec):
        self.events.append(("start", _label(spec), spec.batch))

    def done(self, spec, turn):
        self.events.append(("done", _label(spec), spec.batch, turn))

    def turns(self):
        return [event[3] for event in self.events if event[0] == "done"]


def _run(server, specs, model=None):
    recorder = Recorder()
    selected, stopped = qc.run_remote(server.client(), specs, model, recorder.start, recorder.done)
    return recorder, selected, stopped


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(qc, "POLL_INTERVAL", 0.0)
    monkeypatch.setattr(_ai_runner, "configured_model", lambda model: model or "configured")
    _ai_runner.interrupted.clear()
    yield
    _ai_runner.interrupted.clear()


def test_no_specs_submit_nothing():
    server = FakeQueueServer()
    assert _run(server, [])[1:] == ("configured", False)
    assert server.calls == []


def test_each_spec_starts_then_ends_with_its_requests_result():
    server = FakeQueueServer(lambda action, index: done(assess_result(action, written=[(VARIANT, "zlib")])))
    specs = [_assess_spec("CVE-1", ["openssl", "zlib"]), _assess_spec("CVE-2", ["curl"])]
    recorder, selected, stopped = _run(server, specs)
    assert (selected, stopped) == ("server-model", False)
    assert [event[:2] for event in recorder.events] == [
        ("start", "assess:CVE-1"), ("start", "assess:CVE-2"), ("done", "assess:CVE-1"), ("done", "assess:CVE-2")]
    first, second = recorder.turns()
    assert first["outcome"] == "partial" and [t["written"] for t in first["targets"]] == [False, True]
    assert first["targets"][1] == {"variant_id": VARIANT, "variant": "x86", "package": "zlib", "written": True,
                                   "assessment_ids": [f"a-{VARIANT}-zlib"]}
    assert second["outcome"] == "no_write" and second["usage"]["input_tokens"] == 10
    [body] = server.submitted
    assert body["actions"] == [
        {"kind": "assess", "vuln_id": "CVE-1",
         "targets": [{"variant_id": VARIANT, "package": "openssl"}, {"variant_id": VARIANT, "package": "zlib"}]},
        {"kind": "assess", "vuln_id": "CVE-2",
         "targets": [{"variant_id": VARIANT, "package": "curl"}]}]
    assert body["timeout"] == 30 and "model" not in body


def test_batches_follow_their_own_request_and_unmatched_counts_merge():
    key = assess_key("CVE-1", [(VARIANT, "openssl"), (VARIANT, "zlib")])
    specs = [_assess_spec("CVE-1", ["openssl"], (1, 2), key), _assess_spec("CVE-1", ["zlib"], (2, 2), key)]

    def finish(action, index):
        if index:
            return failed("No reply within 30 s.", "timeout", assess_result(action, [], "timeout", "No reply."))
        return done(assess_result(action))

    recorder, _, _ = _run(FakeQueueServer(finish, batches=lambda action: 2), specs, "m")
    one, two = recorder.turns()
    assert one["outcome"] == "assessed" and two["outcome"] == "timeout" and two["error"] == "No reply."
    # The server planned one request where the CLI planned two: both specs end when it does.
    recorder, _, _ = _run(FakeQueueServer(), specs)
    one, two = recorder.turns()
    assert one["outcome"] == two["outcome"] == "assessed" and one["targets"][0]["package"] == "openssl"
    recorder, _, _ = _run(FakeQueueServer(finish, batches=lambda action: 3), specs)
    assert [turn["outcome"] for turn in recorder.turns()] == ["timeout", "timeout"]
    assert recorder.turns()[0]["usage"]["input_tokens"] == 30


@pytest.mark.parametrize("final, outcome, error", [
    (failed("MCP server failed.", "mcp"), "failed", "MCP server failed."),
    (failed("The assessment changed.", "prepare"), "failed", "The assessment changed."),
    ({"status": "cancelled", "error": "Removed from the AI queue.", "error_code": "removed", "result": None},
     "interrupted", "Removed from the AI queue."),
])
def test_assess_requests_ending_without_a_result(final, outcome, error):
    recorder, _, stopped = _run(FakeQueueServer(lambda action, index: final), [_assess_spec("CVE-1", ["openssl"])])
    [turn] = recorder.turns()
    assert (turn["outcome"], turn["error"], stopped) == (outcome, error, False)
    assert turn["usage"] is None and turn["targets"][0]["written"] is False


def test_review_results_are_matched_by_finding():
    aid, kept, dropped = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

    def finish(action, index):
        return done(review_result(action, finding_ids=[str(kept)]))

    recorder, _, _ = _run(FakeQueueServer(finish), [_review_spec(aid, [kept, dropped])])
    [body] = recorder.turns()
    assert [(t["finding_id"], t["outcome"], t["error"]) for t in body["targets"]] == [
        (str(kept), "reviewed", None), (str(dropped), "changed", CHANGED)]
    assert body["outcome"] == "changed"


@pytest.mark.parametrize("final, outcome, error", [
    (failed("Not reviewable.", "prepare"), "changed", CHANGED),
    (failed("Archived.", "archived"), "failed", "Archived."),
    (done(None) | {"status": "failed", "error": None, "error_code": "mcp"}, "failed", "The AI request failed."),
])
def test_review_requests_ending_without_a_result(final, outcome, error):
    aid, finding = uuid.uuid4(), uuid.uuid4()
    server = FakeQueueServer(lambda action, index: final)
    recorder, _, _ = _run(server, [_review_spec(aid, [finding])])
    [turn] = recorder.turns()
    assert [(t["outcome"], t["error"]) for t in turn["targets"]] == [(outcome, error)]
    assert server.submitted[0]["actions"] == [{"kind": "review", "assessment_id": str(aid), "variant_id": VARIANT,
                                               "finding_ids": [str(finding)], "key": f"review:{aid}:{VARIANT}"}]


def test_a_fatal_error_stops_the_runs_other_requests_and_aborts():
    def finish(action, index):
        if action["vuln_id"] == "CVE-1":
            return failed("Model nope is not available.", "unavailable_model", assess_result(action, [], "failed"))
        return done(assess_result(action))

    server = FakeQueueServer(finish)
    recorder = Recorder()
    with pytest.raises(click.ClickException, match="Model nope is not available."):
        qc.run_remote(server.client(), [_assess_spec("CVE-1", ["a"]), _assess_spec("CVE-2", ["b"])], None,
                      recorder.start, recorder.done)
    assert server.stopped == ["req-2"] and recorder.turns() == []


def test_already_queued_actions_are_followed_and_failed_ones_retried(capsys):
    server = FakeQueueServer()
    spec = _assess_spec("CVE-1", ["openssl"])
    action = qc._action([spec])
    other = server.add(action, status="failed", error="boom", error_code="failed")
    recorder, _, _ = _run(server, [spec])
    assert server.retried == [other] and recorder.turns()[0]["outcome"] == "assessed"
    assert "CVE-1: already in the web AI queue; following it." in capsys.readouterr().err
    # The holder finished before the snapshot: follow the skipped request ID.
    server = FakeQueueServer()
    held = server.add(action)
    server.records[held]["status"] = "running"
    server.on_snapshot = lambda srv, count: srv.records[held].update(status="done", result=assess_result(action)) \
        if count == 2 else None
    assert _run(server, [spec])[0].turns()[0]["outcome"] == "assessed"


def test_joining_an_action_after_its_first_batch_finished_reports_every_batch():
    key = assess_key("CVE-1", [(VARIANT, "openssl"), (VARIANT, "zlib")])
    specs = [_assess_spec("CVE-1", ["openssl"], (1, 2), key), _assess_spec("CVE-1", ["zlib"], (2, 2), key)]
    action = qc._action(specs)
    server = FakeQueueServer(lambda action, index: done(assess_result(action, written=[(VARIANT, "zlib")])))
    server.add(action, 0, status="done", result=assess_result(action, written=[(VARIANT, "openssl")]),
               started_at=1.0, finished_at=2.0)
    server.add(action, 1)
    recorder, _, stopped = _run(server, specs)
    assert [(turn["outcome"], [t["written"] for t in turn["targets"]]) for turn in recorder.turns()] == [
        ("assessed", [True]), ("assessed", [True])]
    assert not stopped and server.stopped == [] and len(server.records) == 2


def test_an_adopted_action_partitioned_otherwise_is_matched_by_target():
    key = assess_key("CVE-1", [(VARIANT, p) for p in ("openssl", "zlib", "curl")])
    specs = [_assess_spec("CVE-1", ["openssl", "zlib"], (1, 2), key), _assess_spec("CVE-1", ["curl"], (2, 2), key)]

    def part(packages):
        return {"kind": "assess", "vuln_id": "CVE-1", "key": key,
                "targets": [{"variant_id": VARIANT, "package": package} for package in packages]}

    # Another submitter ordered the targets otherwise: its batches are [curl, zlib] then [openssl].
    server = FakeQueueServer()
    server.add(part(["curl", "zlib"]), 0)
    server.add(part(["openssl"]), 1, status="done", result=assess_result(part(["openssl"])),
               started_at=1.0, finished_at=2.0)
    recorder, _, stopped = _run(server, specs)
    turns = recorder.turns()
    assert [(turn["outcome"], [t["written"] for t in turn["targets"]]) for turn in turns] == [
        ("assessed", [True, True]), ("assessed", [True])]
    # Each result's usage is reported once.
    assert sum(turn["usage"]["input_tokens"] for turn in turns if turn["usage"]) == 20
    assert not stopped and len(server.records) == 2


def test_a_failed_adoption_still_stops_the_requests_it_created(capsys):
    server = FakeQueueServer()
    followed = _assess_spec("CVE-1", ["a"])
    held = server.add(qc._action([followed]))

    def snapshot_fails_once(srv, count):
        if count == 1:
            raise qc.ServerUnavailable("timed out")

    server.on_snapshot = snapshot_fails_once
    with pytest.raises(click.ClickException, match="web server stopped before accepting this run"):
        _run(server, [followed, _assess_spec("CVE-2", ["b"])])
    assert server.stopped == ["req-2"]
    assert server.records["req-2"]["status"] == "cancelled" and server.records[held]["status"] == "queued"
    assert "Stopped the 1 request(s) of this run" in capsys.readouterr().err


def test_ctrl_c_stops_only_this_runs_requests_and_reports_what_finished():
    server = FakeQueueServer()
    foreign = server.add({"kind": "assess", "vuln_id": "CVE-9", "key": "assess:CVE-9", "targets": []})
    specs = [_assess_spec("CVE-1", ["a"]), _assess_spec("CVE-2", ["b"])]
    server.advance = False

    def ctrl_c(srv, count):
        if count == 2:
            srv.records["req-2"].update(status="running", started_at=1.0)
        if count == 3:
            raise KeyboardInterrupt

    server.on_snapshot = ctrl_c
    recorder, _, stopped = _run(server, specs)
    assert stopped is True and server.stopped == ["req-2", "req-3"] and foreign not in server.stopped
    done_events = [event for event in recorder.events if event[0] == "done"]
    # Units that never started are reported first, so a running batch's "Interrupted." is the last word.
    assert [(event[1], event[3]["outcome"], event[3]["error"]) for event in done_events] == [
        ("assess:CVE-2", "interrupted", "Not started."), ("assess:CVE-1", "interrupted", "Interrupted.")]
    assert [event[1] for event in recorder.events if event[0] == "start"] == ["assess:CVE-1"]


def test_ctrl_c_gives_up_waiting_for_a_stuck_request(monkeypatch):
    monkeypatch.setattr(qc, "SETTLE_TIMEOUT", 0.0)
    server = FakeQueueServer()
    server.advance = False

    def ctrl_c(srv, count):
        if count == 2:
            srv.records["req-1"].update(status="running", started_at=1.0)
        if count == 3:
            raise KeyboardInterrupt

    server.on_snapshot = ctrl_c
    monkeypatch.setattr(server, "_stop", lambda record: (200, {"status": "stopping"}))  # never settles
    recorder, _, stopped = _run(server, [_assess_spec("CVE-1", ["a"])])
    assert stopped and recorder.turns()[0]["error"] == "Interrupted."


def test_ctrl_c_through_the_interrupted_flag_and_while_submitting():
    server = FakeQueueServer()
    server.on_snapshot = lambda srv, count: _ai_runner.interrupted.set()
    recorder, _, stopped = _run(server, [_assess_spec("CVE-1", ["a"])])
    assert stopped and server.stopped == ["req-1"] and recorder.turns()[0]["error"] == "Not started."

    def interrupt(method, path, body, timeout):
        raise KeyboardInterrupt

    recorder = Recorder()
    assert qc.run_remote(qc.QueueClient(interrupt), [_assess_spec("CVE-1", ["a"])], "m", recorder.start,
                         recorder.done) == ("m", True)
    assert [(e[0], e[3]["error"]) for e in recorder.events] == [("done", "Not started.")]


@pytest.mark.parametrize("how", ["down", "forget", "down_while_stopping"])
def test_a_lost_server_fails_the_unfinished_items(how, capsys):
    server = FakeQueueServer()
    specs = [_assess_spec("CVE-1", ["a"]), _assess_spec("CVE-2", ["b"])]

    def lose(srv, count):
        if count == 3:
            srv.records["req-1"].update(status="done", result=assess_result(srv.records["req-1"]["_action"]))
            if how == "down":
                srv.down = True
            elif how == "forget":
                srv.records.pop("req-2")
        if count == 4 and how == "down_while_stopping":
            srv.forget = True
            raise KeyboardInterrupt

    server.on_snapshot = lose
    recorder, _, stopped = _run(server, specs)
    turns = {event[1]: event[3] for event in recorder.events if event[0] == "done"}
    assert turns["assess:CVE-2"]["outcome"] == "failed" and turns["assess:CVE-2"]["error"] == qc.SERVER_STOPPED
    assert stopped is (how == "down_while_stopping")
    assert turns["assess:CVE-1"]["outcome"] == ("failed" if how == "down" else "assessed")
    assert "The web server stopped; reporting what finished." in capsys.readouterr().err


def test_submit_on_a_stopped_server_fails_the_run():
    server = FakeQueueServer(submit=(502, None))
    with pytest.raises(click.ClickException, match="web server stopped before accepting this run"):
        _run(server, [_assess_spec("CVE-1", ["a"])])


def test_a_review_sends_the_fingerprint_pinned_at_selection():
    aid, finding = uuid.uuid4(), uuid.uuid4()
    spec = dataclasses.replace(_review_spec(aid, [finding]), fingerprint="fp-1")
    assert qc._action([spec])["fingerprint"] == "fp-1"


def test_a_large_run_is_submitted_in_batches(monkeypatch):
    monkeypatch.setattr(qc, "SUBMIT_BATCH", 2)
    server = FakeQueueServer()
    specs = [_assess_spec(f"CVE-{n}", ["a"]) for n in range(5)]
    recorder, _, _ = _run(server, specs)
    assert [len(body["actions"]) for body in server.submitted] == [2, 2, 1]
    assert [turn["outcome"] for turn in recorder.turns()] == ["assessed"] * 5


@pytest.mark.parametrize("answer, message", [
    ((400, {"error": "bad"}), "rejected this run: bad"), ((502, None), "web server stopped before accepting")])
def test_a_rejected_batch_stops_the_accepted_ones_and_fails_the_run(monkeypatch, answer, message, capsys):
    monkeypatch.setattr(qc, "SUBMIT_BATCH", 1)
    server = FakeQueueServer()
    submit = server._submit
    monkeypatch.setattr(server, "_submit", lambda body: answer if server.records else submit(body))
    with pytest.raises(click.ClickException, match=message):
        _run(server, [_assess_spec("CVE-1", ["a"]), _assess_spec("CVE-2", ["b"])])
    assert server.stopped == ["req-1"] and server.records["req-1"]["status"] == "cancelled"
    assert "Stopped the 1 request(s) of this run" in capsys.readouterr().err


def test_ctrl_c_while_submitting_a_later_batch_stops_the_accepted_ones(monkeypatch):
    monkeypatch.setattr(qc, "SUBMIT_BATCH", 1)
    server = FakeQueueServer()
    submit = server._submit

    def second_interrupts(body):
        if server.records:
            raise KeyboardInterrupt
        return submit(body)

    monkeypatch.setattr(server, "_submit", second_interrupts)
    recorder, _, stopped = _run(server, [_assess_spec("CVE-1", ["a"]), _assess_spec("CVE-2", ["b"])])
    assert stopped and server.stopped == ["req-1"]
    assert sorted((event[1], event[3]["error"]) for event in recorder.events if event[0] == "done") == [
        ("assess:CVE-1", "Not started."), ("assess:CVE-2", "Not started.")]


def test_ctrl_c_during_a_submit_waits_for_its_answer_to_stop_its_requests(monkeypatch):
    server = FakeQueueServer()
    submit = server._submit

    def interrupted_while_posting(body):
        signal.raise_signal(signal.SIGINT)  # the server still accepts the batch
        return submit(body)

    monkeypatch.setattr(server, "_submit", interrupted_while_posting)
    handler = signal.getsignal(signal.SIGINT)
    recorder, _, stopped = _run(server, [_assess_spec("CVE-1", ["a"])])
    assert stopped and server.stopped == ["req-1"] and server.records["req-1"]["status"] == "cancelled"
    assert [event[0] for event in recorder.events] == ["done"]
    assert signal.getsignal(signal.SIGINT) is handler


def test_a_second_ctrl_c_during_a_submit_stops_at_once(monkeypatch):
    server = FakeQueueServer()
    reached = []

    def interrupted_twice(body):
        signal.raise_signal(signal.SIGINT)
        signal.raise_signal(signal.SIGINT)
        reached.append(body)

    monkeypatch.setattr(server, "_submit", interrupted_twice)
    recorder, _, stopped = _run(server, [_assess_spec("CVE-1", ["a"])])
    assert stopped and reached == [] and server.records == {}
    assert [(e[0], e[3]["error"]) for e in recorder.events] == [("done", "Not started.")]


def test_ctrl_c_never_stops_a_request_the_run_only_follows():
    server = FakeQueueServer()
    spec = _assess_spec("CVE-1", ["a"])
    held = server.add(qc._action([spec]))
    server.advance = False
    server.on_snapshot = lambda srv, count: (_ for _ in ()).throw(KeyboardInterrupt) if count == 2 else None
    recorder, _, stopped = _run(server, [spec, _assess_spec("CVE-2", ["b"])])
    assert stopped and server.stopped == ["req-2"] and server.records[held]["status"] == "queued"
    assert {event[1]: event[3]["error"] for event in recorder.events if event[0] == "done"} == {
        "assess:CVE-1": "Not started.", "assess:CVE-2": "Not started."}

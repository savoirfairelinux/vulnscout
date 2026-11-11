# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""A scripted web AI queue for the CLI's remote mode, used as ``QueueClient``'s transport."""

import itertools

from src.bin import _ai_queue_client, _ai_runner
from src.bin._ai_queue_client import QUEUE_PATH, QueueClient, ServerUnavailable
from src.controllers.ai_actions import assess_key

USAGE = {"cost": 1.0, "input_tokens": 10, "output_tokens": 5}
REVIEW = {"id": "r-1", "status": "not_affected", "verdict": "agree"}


def assess_result(action, written=None, outcome=None, error=None):
    """An assess TurnResult writing *written* ((variant_id, package) pairs; default: every target)."""
    pairs = [(t["variant_id"], t["package"]) for t in action["targets"]]
    written = pairs if written is None else written
    targets = [{"variant_id": v, "variant": "?", "package": p, "written": (v, p) in written,
                "assessment_ids": [f"a-{v}-{p}"] if (v, p) in written else []} for v, p in pairs]
    if outcome is None:
        outcome = "assessed" if len(written) == len(pairs) else "partial" if written else "no_write"
    return {"outcome": outcome, "targets": targets, "reply": "done", "usage": dict(USAGE), "error": error}


def review_result(action, outcome="reviewed", error=None, finding_ids=None):
    targets = [{"variant_id": action["variant_id"], "variant": "?", "project_id": "?", "package": "openssl@3.0",
                "outcome": outcome, "review": REVIEW if outcome == "reviewed" else None, "error": error,
                "finding_id": finding_id} for finding_id in (finding_ids or action["finding_ids"])]
    return {"outcome": outcome, "targets": targets, "reply": "done", "usage": dict(USAGE)}


def done(result):
    return {"status": "done", "error": None, "error_code": None, "result": result}


def failed(error, code, result=None):
    return {"status": "failed", "error": error, "error_code": code, "result": result}


def action_key(action):
    """The action's key: a review's explicit one, or the assess key the server derives from the targets."""
    return action.get("key") or assess_key(action["vuln_id"], ((t["variant_id"], t["package"])
                                                               for t in action["targets"]))


def default_finish(action, index):
    return done(assess_result(action) if action["kind"] == "assess" else review_result(action))


class FakeQueueServer:
    """Requests are queued at the first snapshot after they are created, running at the next, then end as
    ``finish(action, index)`` says. ``add`` puts another client's request in the queue."""

    def __init__(self, finish=default_finish, *, batches=lambda action: 1, submit=None):
        self.finish, self.batches, self.submit_reply = finish, batches, submit
        self.records = {}  # id -> record (with private "_action", "_index", "_final")
        self.calls, self.stopped, self.retried = [], [], []
        self.snapshots = 0
        self.on_snapshot = None  # hook(server, count): may raise, or set ``down``
        self.down = False
        self.forget = False
        self.advance = True  # False: ``on_snapshot`` drives the requests' states
        self._ids = (f"req-{n}" for n in itertools.count(1))
        self._conversations = itertools.count(1)

    def client(self):
        return QueueClient(self)

    def install(self, monkeypatch, poll=0.0):
        monkeypatch.setattr(_ai_runner, "queue_client", self.client)
        monkeypatch.setattr(_ai_queue_client, "POLL_INTERVAL", poll)
        return self

    @staticmethod
    def public(record, full=True):
        shown = {key: value for key, value in record.items() if not key.startswith("_")}
        if not full:
            shown.pop("result")
        return shown

    @property
    def submitted(self):
        return [body for method, path, body in self.calls if method == "POST" and path == QUEUE_PATH]

    def __call__(self, method, path, body, timeout):
        self.calls.append((method, path, body))
        if self.down:
            raise ServerUnavailable("Connection refused")
        if path == QUEUE_PATH:
            return self._snapshot() if method == "GET" else self._submit(body)
        request_id = path.split("/")[5]
        record = None if self.forget else self.records.get(request_id)
        if path.endswith("/stop"):
            self.stopped.append(request_id)
            if record is None:
                return 404, {"error": "Unknown request."}
            return self._stop(record)
        if path.endswith("/retry"):
            self.retried.append(request_id)
            assert record is not None
            record.update(status="queued", error=None, error_code=None, result=None, started_at=None)
            return 200, {"status": "queued"}
        return (404, {"error": "Unknown request."}) if record is None else (200, self.public(record))

    def _snapshot(self):
        self.snapshots += 1
        if self.on_snapshot:
            self.on_snapshot(self, self.snapshots)
            if self.down:
                raise ServerUnavailable("Connection refused")
        active = [self.public(r, full=False) for r in self.records.values()
                  if r["status"] in ("queued", "running", "failed")]
        for record in self.records.values() if self.advance else ():
            if record["status"] == "queued" and record["_seen"]:
                record.update(status="running", started_at=1.0)
            elif record["status"] == "running":
                record.update({**record["_final"], "finished_at": 2.0})
            record["_seen"] = True
        return 200, {"epoch": "e", "seq": self.snapshots, "paused": None, "requests": active,
                     "history": [], "conversations": []}

    def _submit(self, body):
        if self.submit_reply:
            return self.submit_reply
        response: dict[str, list] = {"requests": [], "skipped": []}
        held = {r["key"]: r["id"] for r in self.records.values() if r["status"] in ("queued", "running", "failed")}
        for action in body["actions"]:
            key = action_key(action)
            if key in held:
                conversation = self.records[held[key]]["conversation_id"]
                group = [r["id"] for r in self.records.values()
                         if r["key"] == key and r["conversation_id"] == conversation]
                response["skipped"].append({"key": key, "request_id": held[key], "request_ids": group})
                continue
            conversation = f"c-{next(self._conversations)}"
            for index in range(self.batches(action)):
                request_id = self.add(action, index, model=body.get("model"), conversation_id=conversation)
                response["requests"].append({"id": request_id, "key": key, "conversation_id": conversation})
        return 202, response

    def add(self, action, index=0, status="queued", model=None, conversation_id="other", **fields):
        """Queue *action*'s request number *index* (in another client's conversation by default); return its ID."""
        request_id = next(self._ids)
        self.records[request_id] = {
            "id": request_id, "key": action_key(action), "conversation_id": conversation_id, "status": status,
            "error": None, "error_code": None,
            "started_at": None, "finished_at": None, "model": model or "server-model", "result": None,
            "_action": action, "_index": index, "_seen": False, "_final": self.finish(action, index), **fields}
        return request_id

    def _stop(self, record):
        if record["status"] == "queued":
            record.update(status="cancelled", error="Removed from the AI queue.", error_code="removed")
            return 200, {"status": "removed"}
        if record["status"] == "running":
            action = record["_action"]
            result = assess_result(action, written=[], outcome="interrupted", error="Interrupted.") \
                if action["kind"] == "assess" else review_result(action, "interrupted", "Interrupted.")
            record.update(status="cancelled", error="Stopped.", error_code="stopped", result=result)
            return 200, {"status": "stopping"}
        return 409, {"error": "Already finished."}

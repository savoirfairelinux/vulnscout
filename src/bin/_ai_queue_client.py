# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Client of the web server's AI queue (``/api/agent/queue``), used by ``ai-assess`` and ``ai-review``.

When ``vulnscout serve`` runs in the container, the CLI submits its turns to the server's queue, so they
show in the web UI and wait behind the web's actions, instead of running them in its own process.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Iterable

import click

from ._console import echo

if TYPE_CHECKING:
    from ..controllers.ai_actions import TurnResult, TurnSpec

DEFAULT_PORT = "7275"
QUEUE_PATH = "/api/agent/queue"
PROBE_TIMEOUT = 2.0
REQUEST_TIMEOUT = 10.0
SUBMIT_TIMEOUT = 60.0  # the server plans the actions and checks the sign-in before answering
# Module-level so tests can shrink them.
SUBMIT_BATCH = 500  # actions per submission: the server's limit (agent_queue.MAX_ACTIONS)
START_WAIT = 60.0  # how long the CLI waits for a starting web server
START_RETRY = 2.0
WAITING = "waiting for the web server to finish starting\u2026"

# (method, path, JSON body or None, timeout in seconds) -> (HTTP status, decoded JSON body or None).
Transport = Callable[[str, str, Any, float], tuple[int, Any]]


class ServerUnavailable(Exception):
    """The web server could not be reached: refused, timed out, or closed the connection."""


def base_url() -> str:
    """The serve process in this container: ``http://127.0.0.1:${FLASK_RUN_PORT:-7275}``."""
    return f"http://127.0.0.1:{os.getenv('FLASK_RUN_PORT') or DEFAULT_PORT}"


def _decode(raw: bytes) -> Any:
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return None


def urllib_transport(url: str) -> Transport:
    """A transport sending JSON requests to *url* with urllib, bypassing any configured HTTP proxy."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def send(method: str, path: str, body: Any, timeout: float) -> tuple[int, Any]:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(f"{url}{path}", data=data, method=method,
                                         headers={"Content-Type": "application/json",
                                                  "Accept": "application/json"})
        try:
            with opener.open(request, timeout=timeout) as response:
                return response.status, _decode(response.read())
        except urllib.error.HTTPError as exc:
            try:
                payload = exc.read()
            except (OSError, http.client.HTTPException):
                payload = b""
            finally:
                exc.close()
            return exc.code, _decode(payload)
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            raise ServerUnavailable(str(getattr(exc, "reason", exc)) or type(exc).__name__) from exc

    return send


def _error(data: Any, status: int) -> str:
    if isinstance(data, dict) and isinstance(data.get("error"), str) and data["error"]:
        return data["error"]
    return f"HTTP {status}"


class QueueClient:
    """Probe, submit to, follow and stop requests of the web AI queue.

    Every call but ``probe`` raises ``ServerUnavailable`` when the server cannot be reached.
    """

    def __init__(self, transport: Transport | None = None, *, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._send = transport or urllib_transport(base_url())
        self._sleep, self._clock = sleep, clock

    def probe(self) -> dict | None:
        """The queue snapshot when the web server runs, else None (run in this process).

        A server still starting answers 503 (its "Scan not finished" gate): wait for it, printing a
        notice once, for up to ``START_WAIT`` seconds, then fail with a ``ClickException``.
        """
        deadline: float | None = None
        while True:
            try:
                status, data = self._send("GET", QUEUE_PATH, None, PROBE_TIMEOUT)
            except ServerUnavailable:
                return None
            if status == 200 and isinstance(data, dict):
                return data
            if status == 404:
                return None  # something else listens on the port, or a server without the queue
            if status != 503:
                raise click.ClickException(f"The web server's AI queue failed: {_error(data, status)}")
            now = self._clock()
            if deadline is None:
                echo(WAITING, err=True)
                deadline = now + START_WAIT
            if now >= deadline:
                raise click.ClickException(f"The web server did not finish starting within {START_WAIT:g} s. "
                                           "Try again once its scan is done.")
            self._sleep(min(START_RETRY, deadline - now))

    def snapshot(self) -> dict:
        """``GET /api/agent/queue``: the active requests (with status) and recent history."""
        status, data = self._send("GET", QUEUE_PATH, None, REQUEST_TIMEOUT)
        if status != 200 or not isinstance(data, dict):
            raise ServerUnavailable(_error(data, status))
        return data

    def submit(self, actions: list[dict], model: str | None, timeout: int | None) -> dict:
        """Queue *actions* for this CLI run; return ``{requests, skipped}``.

        The server checks the AI configuration and sign-in first (``require_ready``): when no turn could
        run, the call fails at once with today's messages instead of waiting in a paused queue.
        """
        from ._ai_runner import GITHUB_SIGNED_OUT, NO_AI_CONFIG

        body: dict[str, Any] = {"conversation": "per-action", "source": "CLI", "require_ready": True,
                                "actions": actions}
        if model:
            body["model"] = model
        if timeout is not None:
            body["timeout"] = timeout
        status, data = self._send("POST", QUEUE_PATH, body, SUBMIT_TIMEOUT)
        if status == 202 and isinstance(data, dict):
            return data
        if status == 409:
            code = data.get("code") if isinstance(data, dict) else None
            known = {"no_ai_config": NO_AI_CONFIG, "github_signed_out": GITHUB_SIGNED_OUT}
            raise click.ClickException(known.get(str(code)) or _error(data, status))
        if status >= 500:
            raise ServerUnavailable(_error(data, status))
        raise click.ClickException(f"The web AI queue rejected this run: {_error(data, status)}")

    def get(self, request_id: str) -> dict | None:
        """The request with its full result, or None when the server does not know it (it restarted)."""
        status, data = self._send("GET", f"{QUEUE_PATH}/requests/{request_id}", None, REQUEST_TIMEOUT)
        if status == 404:
            return None
        if status != 200 or not isinstance(data, dict):
            raise ServerUnavailable(_error(data, status))
        return data

    def stop(self, request_id: str) -> None:
        """Stop a running request, or remove a waiting one; a finished or unknown one is left alone."""
        self._send("POST", f"{QUEUE_PATH}/requests/{request_id}/stop", None, REQUEST_TIMEOUT)

    def retry(self, request_id: str) -> None:
        """Queue a failed request again (at the end of its lane)."""
        self._send("POST", f"{QUEUE_PATH}/requests/{request_id}/retry", None, REQUEST_TIMEOUT)


# ---------------------------------------------------------------- following a run

POLL_INTERVAL = 1.0
SETTLE_TIMEOUT = 30.0  # how long Ctrl-C waits for a stopped turn to record its outcome
FATAL_ERROR_CODES = frozenset({"unavailable_model", "skills"})
FINAL_STATUSES = frozenset({"done", "failed", "cancelled"})
SERVER_STOPPED = "web server stopped"


class _ServerLost(Exception):
    pass


@dataclass
class _Unit:
    """Local specs and the queue requests that run them: one each, or (rarely) a whole action's of both."""

    specs: list[TurnSpec]
    request_ids: list[str]
    records: dict[str, dict] = field(default_factory=dict)  # finished requests, with their full result
    started: bool = False
    folded: bool = False

    @property
    def finished(self) -> bool:
        return all(request_id in self.records for request_id in self.request_ids)


def _action(specs: list[TurnSpec]) -> dict[str, Any]:
    """The queue action of one key's specs: explicit assess targets, or a review's variant, findings and fingerprint.

    An assess action sends no key: the server derives the same canonical key, which may exceed the explicit-key limit.
    """
    first = specs[0]
    if first.kind == "assess":
        return {"kind": "assess", "vuln_id": first.vuln_id,
                "targets": [{"variant_id": target.variant_id, "package": target.package}
                            for spec in specs for target in spec.assess_targets]}
    targets = [target for spec in specs for target in spec.review_targets]
    action: dict[str, Any] = {
        "kind": "review", "assessment_id": str(first.assessment_id), "key": first.key,
        "variant_id": str(targets[0].variant_id),
        "finding_ids": list(dict.fromkeys(str(target.finding_id) for target in targets))}
    if first.fingerprint is not None:
        action["fingerprint"] = first.fingerprint
    return action


def _failure(record: dict | None) -> tuple[str, str]:
    """(outcome, error) of a request that ended without a turn result; None: the server forgot it."""
    if record is None:
        return "failed", SERVER_STOPPED
    if record["status"] == "cancelled":
        return "interrupted", record.get("error") or "Interrupted."
    if record.get("error_code") == "prepare":
        return "changed", record.get("error") or "changed"
    return "failed", record.get("error") or "The AI request failed."


def _usage(results: list[dict]) -> tuple[str | None, dict | None]:
    from ..routes import agent

    used = [result for result in results if result.get("usage") is not None]
    if not used:
        return None, None
    usage = used[0]["usage"]
    for result in used[1:]:
        usage = agent._add_usage(usage, result["usage"])
    return "\n\n".join(result.get("reply") or "" for result in used), usage


def _covers(spec: TurnSpec, result: dict) -> bool:
    """Whether the turn *result* names one of *spec*'s targets."""
    if spec.kind == "assess":
        pairs = {(target.variant_id, target.package) for target in spec.assess_targets}
        return any((item["variant_id"], item["package"]) in pairs for item in result["targets"])
    findings = {(str(target.variant_id), str(target.finding_id)) for target in spec.review_targets}
    return any((item["variant_id"], item["finding_id"]) in findings for item in result["targets"])


def _billing(specs: list[TurnSpec], records: list[dict | None]) -> list[list[dict]]:
    """Each spec's share of *records*: a result goes to the first spec it covers (else the first), once."""
    shares: list[list[dict]] = [[] for _ in specs]
    for record in records:
        if record is not None and record.get("result"):
            index = next((i for i, spec in enumerate(specs) if _covers(spec, record["result"])), 0)
            shares[index].append(record)
    return shares


def _turn_result(spec: TurnSpec, records: list[dict | None],
                 failure: Callable[[dict | None], tuple[str, str]], billed: list[dict] | None = None) -> TurnResult:
    """*spec*'s ``TurnResult`` from the requests that ran it, matched by target, as ``verify`` builds it.

    *records* may run other specs of the same action too (an adopted action, partitioned by its submitter):
    only the results naming *spec*'s targets decide its outcome, and its reply and usage come from *billed*
    (default: every result).
    """
    from ..controllers import ai_actions

    results = [record["result"] for record in records if record is not None and record.get("result")]
    failures = [failure(record) for record in records if record is None or not record.get("result")]
    billed_results = results if billed is None else [record["result"] for record in billed]
    reply, usage = _usage(billed_results)
    if spec.kind == "assess":
        written: dict[tuple[str, str], list[str]] = {}
        for result in results:
            for item in result["targets"]:
                if item["written"]:
                    written.setdefault((item["variant_id"], item["package"]), []).extend(item["assessment_ids"])
        targets = [{"variant_id": target.variant_id, "variant": target.variant, "package": target.package,
                    "written": (target.variant_id, target.package) in written,
                    "assessment_ids": sorted(set(written.get((target.variant_id, target.package), [])))}
                   for target in spec.assess_targets]
        ended = [(result["outcome"], result.get("error") or result["outcome"]) for result in results
                 if result["outcome"] in ("interrupted", "failed", "timeout") and _covers(spec, result)]
        if not all(target["written"] for target in targets):
            # A request without a result may have held this spec's unwritten targets.
            ended += [("failed", error) if outcome == "changed" else (outcome, error) for outcome, error in failures]
        stopped = [item for item in ended if item[0] == "interrupted"]
        outcome: str
        error: str | None
        if stopped or ended:
            outcome, error = (stopped or ended)[0]
        else:
            count = sum(1 for target in targets if target["written"])
            outcome, error = ("assessed" if count == len(targets) else "partial" if count else "no_write"), None
        return {"outcome": outcome, "targets": targets, "reply": reply, "usage": usage, "error": error}
    by_target = {(item["variant_id"], item["finding_id"]): item for result in results for item in result["targets"]}
    # A target missing from a result was dropped when its turn started: it is no longer the assessment's.
    fallback = failures[0] if failures else ("changed", ai_actions.CHANGED)
    if fallback[0] == "changed":
        fallback = ("changed", ai_actions.CHANGED)
    review_targets: list[dict[str, Any]] = []
    for target in spec.review_targets:
        item = by_target.get((str(target.variant_id), str(target.finding_id)))
        if item is None:
            item = {**ai_actions.TargetResult(target, *fallback[:1], None, fallback[1]).to_dict(),
                    "finding_id": str(target.finding_id)}
        review_targets.append(item)
    outcomes = {item["outcome"] for item in review_targets}
    outcome = "reviewed" if outcomes == {"reviewed"} else next(iter(sorted(outcomes - {"reviewed"})))
    return {"outcome": outcome, "targets": review_targets, "reply": reply, "usage": usage}


class _Follower:
    """One CLI run in the web AI queue: submit its specs, follow its requests, fold their results."""

    def __init__(self, client: QueueClient, specs: list[TurnSpec], model: str | None,
                 on_start: Callable[[TurnSpec], None], on_done: Callable[[TurnSpec, TurnResult], None]) -> None:
        self.client, self.model = client, model
        self.on_start, self.on_done = on_start, on_done
        self.specs = specs
        self.units: list[_Unit] = []
        self.owned: dict[str, None] = {}  # requests this run created, in order; Ctrl-C stops only these
        self.unsubmitted: list[TurnSpec] = list(specs)

    def submit(self) -> None:
        """Submit the run in batches of at most ``SUBMIT_BATCH`` actions (the server's limit per call).

        When a batch fails, the requests of the earlier batches are stopped and the run fails. A Ctrl-C
        during a batch waits for its answer, so that its requests are stopped too.
        """
        from ._ai_runner import deferred_interrupt

        groups: dict[str, list[TurnSpec]] = {}
        for spec in self.specs:
            groups.setdefault(spec.key, []).append(spec)
        items = list(groups.items())
        try:
            for start in range(0, len(items), SUBMIT_BATCH):
                batch = dict(items[start:start + SUBMIT_BATCH])
                with deferred_interrupt():
                    try:
                        response = self.client.submit([_action(group) for group in batch.values()], self.model,
                                                      self.specs[0].timeout)
                    except click.ClickException:
                        self._abandon()
                        raise
                    self._adopt(batch, response)
        except ServerUnavailable as exc:
            self._abandon()
            raise click.ClickException(f"The web server stopped before accepting this run ({exc}).") from None

    def _abandon(self) -> None:
        try:
            stopped = self._stop_own()
        except ServerUnavailable:
            return
        if stopped:
            echo(f"Stopped the {len(stopped)} request(s) of this run already in the web AI queue.", err=True)

    def _adopt(self, groups: dict[str, list[TurnSpec]], response: dict) -> None:
        created: dict[str, list[str]] = {}
        for request in response.get("requests", []):
            created.setdefault(request["key"], []).append(request["id"])
            self.owned[request["id"]] = None
        skipped = {item["key"]: item for item in response.get("skipped", [])}
        active = {request["id"]: request for request in self.client.snapshot()["requests"]} if skipped else {}
        for key, group in groups.items():
            request_ids = created.get(key, [])
            if not request_ids and key in skipped:
                # Already in the queue (another CLI or a tab): follow every request of its action, the
                # finished batches included; run the failed ones again. Its submitter partitioned the
                # targets, maybe otherwise: the whole action is one unit, its results matched by target.
                request_ids = list(skipped[key]["request_ids"])
                echo(f"{group[0].title}: already in the web AI queue; following it.", err=True)
                for request_id in request_ids:
                    if active.get(request_id, {}).get("status") == "failed":
                        self.client.retry(request_id)
                self.units.append(_Unit(group, request_ids))
            elif len(request_ids) == len(group):
                self.units += [_Unit([spec], [request_id]) for spec, request_id in zip(group, request_ids)]
            else:
                self.units.append(_Unit(group, request_ids))
        accepted = {id(spec) for group in groups.values() for spec in group}
        self.unsubmitted = [spec for spec in self.unsubmitted if id(spec) not in accepted]

    def _record(self, request_id: str, active: dict[str, dict]) -> dict:
        record = active.get(request_id)
        if record is None or record["status"] in FINAL_STATUSES:
            record = self.client.get(request_id)
            if record is None:
                raise _ServerLost
        if self.model is None:
            self.model = record.get("model")
        return record

    def _start(self, unit: _Unit) -> None:
        if not unit.started:
            unit.started = True
            for spec in unit.specs:
                self.on_start(spec)

    def _fold(self, unit: _Unit, failure: Callable[[dict | None], tuple[str, str]] = _failure) -> None:
        self._start(unit)
        unit.folded = True
        self._report(unit, [unit.records.get(request_id) for request_id in unit.request_ids], failure)

    def _report(self, unit: _Unit, records: list[dict | None],
                failure: Callable[[dict | None], tuple[str, str]]) -> None:
        for spec, billed in zip(unit.specs, _billing(unit.specs, records)):
            self.on_done(spec, _turn_result(spec, records, failure, billed))

    def _stop_own(self) -> list[str]:
        """Stop every unfinished request this run created (never one it only follows); return their IDs.

        Driven by the created IDs, not the units: a batch whose adoption failed is stopped too.
        """
        finished = {request_id for unit in self.units for request_id in unit.records}
        unfinished = [request_id for request_id in self.owned if request_id not in finished]
        for request_id in unfinished:
            self.client.stop(request_id)
        return unfinished

    def poll(self) -> bool:
        """Refresh the run's requests; fold finished units; return True once every unit is folded."""
        from ._ai_runner import interrupted

        if interrupted.is_set():
            raise KeyboardInterrupt
        active = {request["id"]: request for request in self.client.snapshot()["requests"]}
        for unit in self.units:
            if unit.folded:
                continue
            for request_id in unit.request_ids:
                if request_id in unit.records:
                    continue
                record = self._record(request_id, active)
                if record["status"] == "running" or record.get("started_at") is not None:
                    self._start(unit)
                if record["status"] in FINAL_STATUSES:
                    unit.records[request_id] = record
                    if record.get("error_code") in FATAL_ERROR_CODES:
                        with contextlib.suppress(ServerUnavailable):
                            self._stop_own()
                        raise click.ClickException(record.get("error") or record["error_code"])
            if unit.finished:
                self._fold(unit)
        return all(unit.folded for unit in self.units)

    def interrupt(self) -> None:
        """Ctrl-C: stop this run's requests, let the running one record what it wrote, report the rest."""
        stopped = self._stop_own()
        deadline = time.monotonic() + SETTLE_TIMEOUT
        waiting = set(stopped)
        while waiting and time.monotonic() < deadline:
            for request_id in list(waiting):
                record = self.client.get(request_id)
                if record is None:
                    raise _ServerLost
                if record["status"] in FINAL_STATUSES:
                    waiting.discard(request_id)
                    for unit in self.units:
                        if request_id in unit.request_ids:
                            unit.records[request_id] = record
            if waiting:
                time.sleep(POLL_INTERVAL)
        # Units that never started first: an item's "Interrupted." (its running batch) is reported last.
        for unit in sorted(self.units, key=lambda unit: unit.started):
            if unit.folded:
                continue
            label = "Interrupted." if unit.started else "Not started."
            unit.folded = True
            records: list[dict | None] = [unit.records.get(request_id) for request_id in unit.request_ids]
            # A request stopped before it started returns no result: never ran, without a progress line.
            self._report(unit, records or [None], lambda record: ("interrupted", label))

    def server_lost(self) -> None:
        echo("The web server stopped; reporting what finished.", role="error", err=True)
        for unit in self.units:
            if not unit.folded:
                self._fold(unit, lambda record: ("failed", SERVER_STOPPED))


def run_remote(client: QueueClient, specs: Iterable[TurnSpec], model: str | None,
               on_start: Callable[[TurnSpec], None],
               on_done: Callable[[TurnSpec, TurnResult], None]) -> tuple[str | None, bool]:
    """Run *specs* through the web AI queue, as ``_ai_runner.execute`` runs them in process.

    The server plans each action again from the same selection (explicit assess targets; a review's
    variant and findings), so its requests match *specs* one to one; their results are folded through
    the same callbacks. Returns the model used and whether the run was interrupted (Ctrl-C stops only
    this run's requests). Unavailable models and missing skills end the run with a ``ClickException``.
    """
    from ._ai_runner import configured_model

    planned = list(specs)
    follower = _Follower(client, planned, model, on_start, on_done)
    stopped = False
    if planned:
        try:
            follower.submit()
        except KeyboardInterrupt:
            # The batch being submitted is unknown: its specs are reported not started, with the
            # specs never submitted; the requests of the accepted batches are stopped as usual.
            if follower.unsubmitted:
                follower.units.append(_Unit(follower.unsubmitted, []))
            follower.interrupt()
            return follower.model or configured_model(model), True
        try:
            try:
                while not follower.poll():
                    time.sleep(POLL_INTERVAL)
            except KeyboardInterrupt:
                stopped = True
                follower.interrupt()
        except (_ServerLost, ServerUnavailable):
            follower.server_lost()
    return follower.model or configured_model(model), stopped

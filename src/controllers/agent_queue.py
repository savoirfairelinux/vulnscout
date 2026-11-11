# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""The AI queue of the serve process, shared by every browser tab and the CLI.

``AgentQueue`` owns the agent conversations (the ``main`` chat plus one conversation per action key)
and the requests that run turns in them. Requests run in two lanes, one turn at a time each: the
``action`` lane runs assess and review actions, the ``chat`` lane runs chat messages, so a chat never
waits behind an action. Within both lanes a request waits until the earlier requests of its own
conversation have run; a failed request blocks nothing and stays listed for retry or removal.

Each lane has one worker thread that runs a turn in its own event loop, so ``stop`` can cancel the
turn from any thread. Every change is published on ``agent_events`` (a private, localhost-only bus;
transcripts never travel on the public operations stream):

- ``queue``: ``{paused, requests, history, conversations, connection_revision}`` (request dicts and
  conversation summaries; the revision changes with the agent connection or model);
- ``request_progress``: ``{request_id, conversation_id, live}``, at most every ``PROGRESS_INTERVAL`` s;
- ``conversation``: a conversation summary, when its transcript or usage changed;
- ``agent_write``: ``{tool, request_id, conversation_id}``, when the agent saved something.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Callable, Coroutine, Iterator, Literal
from uuid import UUID

from flask import Flask

from . import ai_actions
from .event_bus import EventBus

if TYPE_CHECKING:
    from pathlib import Path

    from flask.ctx import AppContext

    from ..routes.agent import AgentCredentials, Conversation
    from ..routes.agent_skills import AgentProfile
    from .guarded_api import GuardedApi

Lane = Literal["action", "chat"]
Kind = Literal["assess", "review", "message"]
Status = Literal["queued", "running", "failed", "done", "cancelled"]

LANES: tuple[Lane, ...] = ("action", "chat")
MAIN = "main"
PER_ACTION = "per-action"
MAIN_TITLE = "Agent chat"
# Module-level so tests can shrink them.
HISTORY_LIMIT = 50  # finished requests listed in the snapshot
FINISHED_LIMIT = 1000  # finished requests still found by ID (a CLI following a long batch)
LIVE_SESSION_LIMIT = 12  # idle action conversations keeping their SDK session
CONVERSATION_LIMIT = 100  # action conversations; the oldest archived ones are evicted first
ACTIVITY_LIMIT = 50
PROGRESS_INTERVAL = 0.1
MAX_ACTIONS = 500
MAX_TARGETS = 1000
MESSAGE_LIMIT = 8000
TITLE_LIMIT = 120
CHAT_TIMEOUT = 120

BUSY = "Wait for the running AI request to finish before changing the connection."
CONNECTION_CHANGED = ("The agent connection changed. Retry to start a fresh conversation without the previous "
                      "provider history.")
ARCHIVED = "This conversation was archived. Continue in the main conversation."
NOT_AVAILABLE = "This conversation is no longer available."
MCP_MISSING = "Bundled MCP server not found. Check the installation or VULNSCOUT_MCP_SERVER_PATH override."
STOPPED = "Stopped."
REMOVED = "Removed from the AI queue."
WORKER_ERROR = "The AI queue could not start its next request; see the server logs."
LABELS = {"assess": "Assess", "review": "Review", "message": "Message"}
_BATCH_SUFFIX = re.compile(r" · batch \d+ of \d+$")

_logger = logging.getLogger(__name__)


def _agent():
    # Imported lazily: the route modules import this controller.
    from ..routes import agent

    return agent


class QueueConflict(Exception):
    """The request conflicts with the queue's state (HTTP 409)."""


class QueueBusy(QueueConflict):
    """A request is running, or the connection is already changing."""


class NotReady(QueueConflict):
    """No usable AI configuration or sign-in; ``code`` is no_ai_config, invalid_config or github_signed_out."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- records

@dataclass(kw_only=True)
class AgentRequest:
    """One queued agent turn: an action turn (assess, review) or a chat message."""

    id: str
    key: str
    kind: Kind
    lane: Lane
    conversation_id: str
    source: str
    title: str
    detail: str
    model: str | None  # None until it starts: queued without a configured connection, or re-resolved
    timeout: int
    model_explicit: bool = False  # the caller chose the model: kept on retry and connection changes
    status: Status = "queued"
    error: str | None = None
    error_code: str | None = None
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    context: dict | None = None  # validated browser context (UI matching, chat suffix)
    text: str | None = None  # the message, or the action's prompt
    spec: ai_actions.TurnSpec | None = None  # actions only; never serialized
    scope: str | None = None  # messages: the agent scope of their browser context
    vuln_id: str | None = None
    assessment_id: str | None = None
    result: dict | None = None  # actions: the turn's TurnResult

    def to_dict(self, position: int | None = None, *, full: bool = True) -> dict[str, Any]:
        """JSON-able record; without *full* the result omits the agent's reply (already in the transcript)."""
        result = self.result
        if result is not None and not full:
            result = {key: value for key, value in result.items() if key != "reply"}
        return {"id": self.id, "key": self.key, "kind": self.kind, "lane": self.lane,
                "conversation_id": self.conversation_id, "source": self.source, "title": self.title,
                "detail": self.detail, "model": self.model, "status": self.status, "error": self.error,
                "error_code": self.error_code, "position": position, "created_at": self.created_at,
                "started_at": self.started_at, "finished_at": self.finished_at, "context": self.context,
                "text": self.text, "vuln_id": self.vuln_id, "assessment_id": self.assessment_id,
                "timeout": self.timeout, "result": result}


def _new_session() -> Conversation:
    return _agent().Conversation()


def _copy_live(live: dict | None) -> dict | None:
    return None if live is None else {**live, "activity": list(live["activity"])}


@dataclass(kw_only=True)
class AgentConversationState:
    """A conversation's transcript and SDK session; ``live`` describes its running turn, if any."""

    id: str
    title: str
    kind: Literal["main", "action"]
    scope: str | None = None  # action conversations: the last action turn's scope (follow-ups reuse it)
    profile: AgentProfile | None = None
    session: Conversation = field(default_factory=_new_session)
    messages: list[dict] = field(default_factory=list)
    archived: bool = False
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    live: dict | None = None  # {request_id, pending_message, live_reply, activity, progress}

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "kind": self.kind,
                "profile": self.profile.action if self.profile else None, "archived": self.archived,
                "created_at": self.created_at, "last_used": self.last_used, "message_count": len(self.messages),
                "usage": dict(self.session.usage), "live": _copy_live(self.live)}

    def to_dict(self) -> dict[str, Any]:
        return {**self.summary(), "messages": list(self.messages)}


@dataclass
class _Running:
    request_id: str
    loop: asyncio.AbstractEventLoop | None = None
    task: asyncio.Task | None = None
    stop_requested: bool = False
    session_id: str | None = None  # the SDK session the turn created or resumed
    message_id: str | None = None
    progress_at: float = 0.0
    progress_pending: bool = False
    flush_scheduled: bool = False


@dataclass(kw_only=True)
class TurnCall:
    """Everything a runner needs for one turn."""

    request: AgentRequest
    session: Conversation  # credentials and SDK session state; ``_reply`` updates it
    prompt: str
    scope: str
    model: str
    path: Path
    publish: Callable[[dict], None]
    on_session: Callable[[str], None]
    profile: AgentProfile | None
    timeout: int
    turn: ai_actions.PreparedTurn | None = None  # actions
    api: GuardedApi | None = None  # actions: the guarded API their writes go through


Runner = Callable[[TurnCall], Coroutine[Any, Any, tuple[str, dict]]]


async def default_runner(call: TurnCall) -> tuple[str, dict]:
    """Run *call* with the agent: actions through ``ai_actions.run_turn``, messages through ``_reply``."""
    if call.turn is not None:
        assert call.api is not None
        return await ai_actions.run_turn(call.turn, call.session, call.model, call.path, call.api, call.publish,
                                         ephemeral=False, on_session=call.on_session)
    options: dict[str, Any] = {"profile": call.profile} if call.profile else {}
    return await _agent()._reply(call.session, call.prompt, call.path, call.model, call.scope, call.publish,
                                 timeout=call.timeout, on_session=call.on_session, **options)


@dataclass
class _Planned:
    kind: Kind
    key: str | None
    context: dict | None
    specs: list[ai_actions.TurnSpec] = field(default_factory=list)
    text: str | None = None
    scope: str | None = None
    skipped: str | None = None  # the active request already holding the key, when planned


class _TurnFailure(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


class ConnectionChange:
    """Yielded by ``AgentQueue.connection_change``; ``abort()`` keeps the conversations when nothing changed."""

    def __init__(self) -> None:
        self.aborted = False

    def abort(self) -> None:
        self.aborted = True


# ---------------------------------------------------------------- validation

def _bounded_text(value: Any, limit: int, error: str) -> str:
    from ..routes.config import _has_control_characters

    if not isinstance(value, str) or not value or len(value) > limit or _has_control_characters(value):
        raise ValueError(error)
    return value


def _uuid(value: Any, error: str) -> UUID:
    try:
        return UUID(value) if isinstance(value, str) else UUID("")
    except ValueError:
        raise ValueError(error) from None


def _assess_targets(value: Any) -> list[dict] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not value or len(value) > MAX_TARGETS:
        raise ValueError(f"targets must list between 1 and {MAX_TARGETS} {{variant_id, package}} pairs.")
    for target in value:
        if not isinstance(target, dict) or not isinstance(target.get("package"), str) \
                or not 0 < len(target["package"]) <= 300:
            raise ValueError("Each target needs a variant_id and a package of at most 300 characters.")
        _uuid(target.get("variant_id"), "Invalid target variant ID.")
    return value


def _finding_ids(value: Any) -> set[UUID] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not value or len(value) > MAX_TARGETS:
        raise ValueError(f"finding_ids must list between 1 and {MAX_TARGETS} finding IDs.")
    return {_uuid(item, "Invalid finding ID.") for item in value}


# ---------------------------------------------------------------- the queue

class AgentQueue:
    """Conversations, requests and the two lane workers; see the module docstring."""

    def __init__(self, app: Flask | None = None, *, runner: Runner | None = None, events: EventBus | None = None,
                 autostart: bool = True) -> None:
        self._app = app
        self._runner: Runner = runner or default_runner
        self.events = events if events is not None else agent_events
        self._autostart = autostart
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._requests: list[AgentRequest] = []  # active (queued, running, failed), in run order
        self._history: list[AgentRequest] = []
        self._finished: OrderedDict[str, AgentRequest] = OrderedDict()
        self._conversations: dict[str, AgentConversationState] = {MAIN: self._new_main()}
        self._running: dict[str, _Running | None] = {lane: None for lane in LANES}
        self._paused: dict[str, str] | None = None
        self._changing = False
        self._generation = 0  # bumped when a connection change starts; a turn's credentials must predate none
        self._revision = 0  # bumped when the connection or model changed; tabs reload their setup on a change
        self._stopping = False
        self._verified_token: str | None = None
        self._threads: dict[str, threading.Thread] = {}
        self._guarded: GuardedApi | None = None

    def init_app(self, app: Flask) -> None:
        """Bind the app whose database and API the turns use; workers start with the first request."""
        self._app = app

    @staticmethod
    def _new_main() -> AgentConversationState:
        return AgentConversationState(id=MAIN, title=MAIN_TITLE, kind="main")

    def _app_context(self) -> AppContext:
        if self._app is None:
            raise RuntimeError("AgentQueue.init_app() was not called.")
        return self._app.app_context()

    # ------------------------------------------------------------ state and events

    def _positions(self) -> dict[str, int]:
        positions: dict[str, int] = {}
        counts = dict.fromkeys(LANES, 0)
        for request in self._requests:
            if request.status == "queued":
                counts[request.lane] += 1
                positions[request.id] = counts[request.lane]
        return positions

    def _state(self) -> dict[str, Any]:
        positions = self._positions()
        conversations = sorted(self._conversations.values(), key=lambda c: (c.id != MAIN, c.created_at))
        return {"paused": dict(self._paused) if self._paused else None,
                "requests": [request.to_dict(positions.get(request.id), full=False) for request in self._requests],
                "history": [request.to_dict(full=False) for request in self._history],
                "conversations": [conversation.summary() for conversation in conversations],
                "connection_revision": self._revision}

    def snapshot(self) -> dict[str, Any]:
        """``{epoch, seq, paused, requests, history, conversations, connection_revision}``.

        ``seq`` is the last event it includes. A queued request's ``position`` counts from the next
        request to run in its lane (1 = next). ``connection_revision`` changes with the agent connection
        or model.
        """
        with self._lock:
            return {"epoch": self.events.epoch, "seq": self.events.seq, **self._state()}

    def _publish_queue(self) -> None:
        self.events.publish("queue", self._state())

    def _publish_conversation(self, conversation: AgentConversationState) -> None:
        self.events.publish("conversation", conversation.summary())

    def _pause(self, code: str, reason: str) -> None:
        if self._paused != {"code": code, "reason": reason}:
            self._paused = {"code": code, "reason": reason}
            self._publish_queue()

    @property
    def paused(self) -> dict[str, str] | None:
        with self._lock:
            return dict(self._paused) if self._paused else None

    # ------------------------------------------------------------ reads

    def get_request(self, request_id: str) -> dict[str, Any] | None:
        """An active or finished request with its full result (the last ``FINISHED_LIMIT`` are kept), or None."""
        with self._lock:
            for active in self._requests:
                if active.id == request_id:
                    return active.to_dict(self._positions().get(request_id))
            finished = self._finished.get(request_id)
            return finished.to_dict() if finished else None

    def conversation(self, conversation_id: str) -> dict[str, Any] | None:
        """A conversation with its transcript, or None."""
        with self._lock:
            conversation = self._conversations.get(conversation_id)
            return conversation.to_dict() if conversation else None

    def main_transcript(self) -> dict[str, Any]:
        """``{messages, usage}`` of the main conversation."""
        with self._lock:
            main = self._conversations[MAIN]
            return {"messages": list(main.messages), "usage": dict(main.session.usage)}

    # ------------------------------------------------------------ readiness

    def _load_credentials(self) -> tuple[AgentCredentials | None, dict[str, str] | None]:
        """The configured credentials, or why there are none ({code, error}); a GitHub token is checked once."""
        from ..bin._ai_runner import GITHUB_SIGNED_OUT, NO_AI_CONFIG

        agent = _agent()
        root = agent.Conversation()
        error = agent._load_env_credentials(root)
        if error:
            return None, {"code": "invalid_config", "error": f"Invalid AI provider configuration: {error}"}
        credentials = root.credentials
        if not credentials.token and not credentials.provider:
            return None, {"code": "no_ai_config", "error": NO_AI_CONFIG}
        token = credentials.token
        if token and not credentials.provider and token != self._verified_token:
            try:
                auth = asyncio.run(agent._token_status(token))
            except Exception:
                # Not conclusive: run the turn, which reports its own error.
                _logger.warning("Could not check the GitHub Copilot sign-in", exc_info=True)
                return credentials, None
            if not auth["authenticated"]:
                return None, {"code": "github_signed_out", "error": GITHUB_SIGNED_OUT}
            self._verified_token = token
        return credentials, None

    def readiness(self) -> dict[str, str] | None:
        """None when a request could run now, else ``{code, error}``.

        ``code`` is no_ai_config, invalid_config or github_signed_out.
        """
        return self._load_credentials()[1]

    @staticmethod
    def _configured_model() -> tuple[str, bool]:
        """The configured model, and whether a provider or GitHub token is configured (it is final then)."""
        agent = _agent()
        connection = agent._connection()
        agent._load_env_credentials_nonblocking(connection)
        return connection.model or "auto", bool(connection.credentials.token or connection.credentials.provider)

    # ------------------------------------------------------------ enqueue

    def _plan(self, action: Any, conversation: str, context: dict | None, timeout: int | None,
              active_keys: dict[str, str], failed_keys: set[str]) -> _Planned:
        agent = _agent()
        if not isinstance(action, dict):
            raise ValueError("Each action must be an object.")
        kind = action.get("kind")
        if kind not in LABELS:
            raise ValueError("Invalid action kind; use assess, review or message.")
        key = action.get("key")
        if key is not None:
            _bounded_text(key, 500, "Invalid action key (at most 500 characters).")
        if action.get("context") is not None:
            context = agent._validated_context(action["context"])
        if kind == "message":
            if conversation == PER_ACTION:
                raise ValueError("Messages go to the main conversation or to an existing conversation.")
            text = action.get("text")
            if not isinstance(text, str) or not text.strip() or len(text) > MESSAGE_LIMIT:
                raise ValueError(f"Enter a message of at most {MESSAGE_LIMIT} characters.")
            return _Planned("message", key, context, text=text.strip(), scope=agent._scope_for_context(context))
        if conversation != PER_ACTION:
            raise ValueError("Assess and review actions run in their own conversations (per-action).")
        # A failed review pinned to other content is replaced, not followed: its retry could only fail as changed.
        if key is not None and key in active_keys and not (
                kind == "review" and action.get("fingerprint") is not None and key in failed_keys):
            return _Planned(kind, key, context, skipped=active_keys[key])
        if kind == "assess":
            vuln_id = action.get("vuln_id")
            if not isinstance(vuln_id, str) or len(vuln_id) > 100 or not ai_actions.CVE_ID_PATTERN.fullmatch(vuln_id):
                raise ValueError("Invalid vulnerability ID.")
            targets = _assess_targets(action.get("targets"))
            scope = json.loads(agent._scope_for_context(context))
            resolved = ai_actions.resolve_assess_targets(vuln_id, targets, {UUID(v) for v in scope["variant_ids"]})
            specs = ai_actions.plan_assess(vuln_id, resolved, key)
        else:
            assessment_id = _uuid(action.get("assessment_id"), "Invalid assessment ID.")
            variant = action.get("variant_id")
            variant_id = None if variant is None else _uuid(variant, "Invalid variant ID.")
            fingerprint = action.get("fingerprint")
            if fingerprint is not None:
                _bounded_text(fingerprint, 200, "Invalid assessment fingerprint.")
            specs = ai_actions.plan_review(assessment_id, variant_id, _finding_ids(action.get("finding_ids")), key,
                                           per_variant=variant_id is not None)
            if fingerprint is not None:
                # Pinned by the CLI at selection: an edit since then is reported as "changed".
                specs = [replace(spec, fingerprint=fingerprint) for spec in specs]
        if timeout is not None:
            specs = [replace(spec, timeout=timeout) for spec in specs]
        return _Planned(kind, specs[0].key, context, specs=specs)

    def enqueue(self, conversation: str, source: str, actions: list[dict], *, model: str | None = None,
                context: dict | None = None, timeout: int | None = None, require_ready: bool = False
                ) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
        """Queue *actions* into *conversation*; return ``(created, skipped)``.

        *conversation* is ``"per-action"`` for assess/review actions (one new conversation per action key,
        shared by its batches), or ``"main"``/a conversation ID for messages. ``created`` lists
        ``{id, key, conversation_id}``; ``skipped`` lists ``{key, request_id, request_ids}`` (the holder and
        every request of its action, finished batches included, in batch order) for actions whose key is
        already queued, running or failed (or used earlier in the same call), except that a review pinned
        to a ``fingerprint`` replaces failed requests pinned to another one. Without *model*, a request
        takes the configured model: now if a provider or token is configured, else when it starts; a
        connection change or a retry resolves it again. *timeout* overrides the turn timeout; *context* is
        the browser context (an action's own ``context`` replaces it). Atomic: an invalid action raises
        ValueError and queues nothing. Raises LookupError for an unknown conversation, QueueConflict for an
        archived one, and NotReady when *require_ready* and no request could run now.
        """
        agent = _agent()
        if not isinstance(conversation, str) or not conversation:
            raise ValueError("Invalid conversation.")
        source = _bounded_text(source, 100, "Invalid request source (at most 100 characters).")
        if model is not None:
            _bounded_text(model, 100, "Invalid model selection.")
        if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, int)
                                    or not 1 <= timeout <= 3600):
            raise ValueError("Invalid timeout; use 1 to 3600 seconds.")
        if not isinstance(actions, list) or not 1 <= len(actions) <= MAX_ACTIONS:
            raise ValueError(f"Send between 1 and {MAX_ACTIONS} actions.")
        context = agent._validated_context(context)
        if require_ready:
            self.wake()
            if problem := self.readiness():
                with self._cond:
                    self._pause(problem["code"], problem["error"])
                raise NotReady(problem["code"], problem["error"])
        selected = model
        if selected is None:
            configured, connected = self._configured_model()
            selected = configured if connected else None
        with self._lock:
            active_keys: dict[str, str] = {}
            for request in self._requests:
                active_keys.setdefault(request.key, request.id)
            failed_keys = set(active_keys) - {r.key for r in self._requests if r.status != "failed"}
        with self._app_context():
            planned = [self._plan(action, conversation, context, timeout, active_keys, failed_keys)
                       for action in actions]
        created: list[dict[str, str]] = []
        skipped: list[dict[str, Any]] = []
        with self._cond:
            keys: dict[str, str] = {}
            for request in self._requests:
                keys.setdefault(request.key, request.id)
            target = None
            if conversation not in (MAIN, PER_ACTION):
                target = self._conversations.get(conversation)
                if target is None:
                    raise LookupError(NOT_AVAILABLE)
                if target.archived:
                    raise QueueConflict(ARCHIVED)
            added: list[AgentRequest] = []
            for plan in planned:
                if stale := self._stale_reviews(plan):
                    for request in stale:
                        self._drop(request)  # still found by ID, as failed
                    del keys[stale[0].key]
                if plan.key is not None and plan.key in keys:
                    skipped.append({"key": plan.key, "request_id": keys[plan.key]})
                    continue
                if plan.key is not None and plan.skipped is not None:
                    # Its holder finished since planning: still report it (it is found by ID).
                    skipped.append({"key": plan.key, "request_id": plan.skipped})
                    continue
                for request in self._build(plan, conversation, target, source, selected, model is not None, timeout):
                    added.append(request)
                    keys.setdefault(request.key, request.id)
            self._requests.extend(added)
            for entry in skipped:
                entry["request_ids"] = self._action_requests(entry["request_id"])
            self._discard_unstarted()
            self._evict_locked()
            self._publish_queue()
            self._cond.notify_all()
            created = [{"id": r.id, "key": r.key, "conversation_id": r.conversation_id} for r in added]
        if created:
            self._ensure_workers()
        return created, skipped

    def _action_requests(self, request_id: str) -> list[str]:
        """Every request of the action holding *request_id* (its batches, active or finished), in batch order."""
        holder = next((r for r in self._requests if r.id == request_id), None) or self._finished.get(request_id)
        if holder is None:
            return [request_id]
        group = {r.id: r for r in [*self._requests, *self._finished.values()]
                 if r.key == holder.key and r.conversation_id == holder.conversation_id}

        def number(request: AgentRequest) -> int:
            return request.spec.batch[0] if request.spec is not None and request.spec.batch else 0

        return [request.id for request in sorted(group.values(), key=number)]

    def _stale_reviews(self, plan: _Planned) -> list[AgentRequest]:
        """The failed requests holding *plan*'s review key, when every one pinned other content than *plan*."""
        fingerprint = plan.specs[0].fingerprint if plan.kind == "review" and plan.specs else None
        if fingerprint is None:
            return []
        holders = [request for request in self._requests if request.key == plan.key]
        if all(request.status == "failed" and request.spec is not None
               and request.spec.fingerprint not in (None, fingerprint) for request in holders):
            return holders
        return []

    def _build(self, plan: _Planned, conversation: str, target: AgentConversationState | None, source: str,
               model: str | None, explicit: bool, timeout: int | None) -> list[AgentRequest]:
        from ..routes import agent_skills

        if plan.kind == "message":
            owner = target or self._conversations[MAIN]
            request_id = str(uuid.uuid4())
            text = plan.text or ""
            default_timeout = agent_skills.ACTION_TIMEOUT if owner.profile else CHAT_TIMEOUT
            return [AgentRequest(id=request_id, key=plan.key or f"message:{request_id}", kind="message", lane="chat",
                                 conversation_id=owner.id, source=source, title=text[:TITLE_LIMIT], detail="",
                                 model=model, model_explicit=explicit, timeout=timeout or default_timeout,
                                 context=plan.context, text=text, scope=plan.scope)]
        first = plan.specs[0]
        owner = AgentConversationState(id=str(uuid.uuid4()), kind="action",
                                       title=f"{LABELS[plan.kind]} {_BATCH_SUFFIX.sub('', first.title)}",
                                       profile=agent_skills.PROFILES[plan.kind])
        self._conversations[owner.id] = owner
        return [AgentRequest(id=str(uuid.uuid4()), key=spec.key, kind=spec.kind, lane="action",
                             conversation_id=owner.id, source=source, title=spec.title, detail=spec.detail,
                             model=model, model_explicit=explicit, timeout=spec.timeout, context=plan.context,
                             text=spec.prompt, spec=spec,
                             vuln_id=spec.vuln_id,
                             assessment_id=str(spec.assessment_id) if spec.assessment_id else None)
                for spec in plan.specs]

    # ------------------------------------------------------------ queue mutations

    def _active(self, request_id: str) -> AgentRequest:
        for request in self._requests:
            if request.id == request_id:
                return request
        if request_id in self._finished:
            raise QueueConflict("This request already finished.")
        raise LookupError("Request not found.")

    def _index(self, request: AgentRequest) -> None:
        self._finished[request.id] = request
        self._finished.move_to_end(request.id)
        while len(self._finished) > FINISHED_LIMIT:
            self._finished.popitem(last=False)

    def _drop(self, request: AgentRequest) -> None:
        """Take a waiting request out of the queue; a queued one ends cancelled (still found by ID)."""
        self._requests.remove(request)
        if request.status == "queued":
            request.status, request.error, request.error_code = "cancelled", REMOVED, "removed"
            request.finished_at = time.time()
        self._index(request)

    def _discard_unstarted(self) -> None:
        """Drop action conversations that never ran and are referenced by no request any more."""
        used = {request.conversation_id for request in self._requests + self._history}
        for conversation in list(self._conversations.values()):
            if conversation.kind == "action" and conversation.id not in used and not conversation.messages:
                del self._conversations[conversation.id]

    def remove(self, request_id: str) -> None:
        """Remove a queued or failed request; QueueConflict while it runs, LookupError if unknown."""
        with self._cond:
            request = self._active(request_id)
            if request.status == "running":
                raise QueueConflict("This request is running; stop it instead.")
            self._drop(request)
            self._discard_unstarted()
            self._publish_queue()
            self._cond.notify_all()

    def clear(self) -> int:
        """Remove every waiting (queued or failed) request; return how many."""
        with self._cond:
            waiting = [request for request in self._requests if request.status != "running"]
            for request in waiting:
                self._drop(request)
            self._discard_unstarted()
            self._publish_queue()
            self._cond.notify_all()
            return len(waiting)

    def retry(self, request_id: str) -> None:
        """Queue a failed request again, at the end of its lane."""
        with self._cond:
            request = self._active(request_id)
            if request.status != "failed":
                raise QueueConflict("Only failed requests can be retried.")
            self._requests.remove(request)
            request.status, request.error, request.error_code, request.result = "queued", None, None, None
            request.started_at = request.finished_at = None
            if not request.model_explicit:
                request.model = None  # takes the model selected now
            self._requests.append(request)
            self._publish_queue()
            self._cond.notify_all()
        self._ensure_workers()

    def stop(self, request_id: str) -> str:
        """Stop a running request (``"stopping"``: it ends cancelled), or remove a waiting one (``"removed"``)."""
        with self._cond:
            request = self._active(request_id)
            if request.status != "running":
                self.remove(request_id)
                return "removed"
            running = self._running[request.lane]
            assert running is not None and running.request_id == request.id
            self._cancel(running)
            return "stopping"

    @staticmethod
    def _cancel(running: _Running) -> None:
        running.stop_requested = True
        if running.loop is not None and running.task is not None:
            running.loop.call_soon_threadsafe(running.task.cancel)

    # ------------------------------------------------------------ conversations

    def _sdk_session(self, conversation: AgentConversationState) -> list[tuple[AgentCredentials, str]]:
        session = conversation.session
        return [(session.credentials, session.session_id)] if session.session_id else []

    @staticmethod
    def _delete_sessions(sessions: list[tuple[AgentCredentials, str]]) -> bool:
        """Delete SDK sessions (best effort); return True if any deletion failed."""
        agent = _agent()
        failed = False
        for credentials, session_id in sessions:
            try:
                asyncio.run(agent._delete_session(credentials.token, session_id))
            except Exception:
                _logger.exception("Could not delete agent session")
                failed = True
        return failed

    def _busy_conversations(self) -> set[str]:
        return {request.conversation_id for request in self._requests}

    def _delete_locked(self, conversation: AgentConversationState) -> list[tuple[AgentCredentials, str]]:
        del self._conversations[conversation.id]
        self._history = [request for request in self._history if request.conversation_id != conversation.id]
        return [] if conversation.archived else self._sdk_session(conversation)

    def delete_conversation(self, conversation_id: str) -> None:
        """Delete a finished action conversation and its SDK session."""
        with self._cond:
            conversation = self._conversations.get(conversation_id)
            if conversation is None:
                raise LookupError(NOT_AVAILABLE)
            if conversation.kind == "main":
                raise QueueConflict("The main conversation cannot be deleted; reset it instead.")
            if conversation_id in self._busy_conversations():
                raise QueueConflict("This conversation still has requests in the AI queue.")
            sessions = self._delete_locked(conversation)
            self._publish_queue()
        self._delete_sessions(sessions)

    def clear_finished(self) -> int:
        """Delete every action conversation without requests; return how many."""
        with self._cond:
            busy = self._busy_conversations()
            finished = [c for c in self._conversations.values() if c.kind == "action" and c.id not in busy]
            sessions = [session for conversation in finished for session in self._delete_locked(conversation)]
            self._publish_queue()
        self._delete_sessions(sessions)
        return len(finished)

    def reset_main(self) -> None:
        """Start the main conversation afresh; its waiting requests stay queued."""
        with self._cond:
            if any(r.conversation_id == MAIN and r.status == "running" for r in self._requests):
                raise QueueConflict("Wait for the running message to finish before starting a new conversation.")
            old = self._conversations[MAIN]
            self._conversations[MAIN] = main = self._new_main()
            self._history = [request for request in self._history if request.conversation_id != MAIN]
            self._publish_queue()
            self._publish_conversation(main)
        self._delete_sessions(self._sdk_session(old))

    def _release_idle(self) -> None:
        """Archive idle action conversations past ``LIVE_SESSION_LIMIT`` (their SDK session is deleted)."""
        with self._cond:
            busy = self._busy_conversations()
            idle = sorted((c for c in self._conversations.values()
                           if c.kind == "action" and not c.archived and c.id not in busy),
                          key=lambda c: c.last_used, reverse=True)[LIVE_SESSION_LIMIT:]
            sessions: list[tuple[AgentCredentials, str]] = []
            for conversation in idle:
                sessions.extend(self._sdk_session(conversation))
                conversation.archived = True
                conversation.session.session_id = conversation.session.session_scope = None
            if idle:
                self._evict_locked()
                self._publish_queue()
        self._delete_sessions(sessions)

    def _evict_locked(self) -> None:
        """Keep at most ``CONVERSATION_LIMIT`` action conversations, evicting the oldest archived ones."""
        actions = [c for c in self._conversations.values() if c.kind == "action"]
        excess = len(actions) - CONVERSATION_LIMIT
        if excess <= 0:
            return
        busy = self._busy_conversations()
        for conversation in sorted((c for c in actions if c.archived and c.id not in busy),
                                   key=lambda c: c.last_used)[:excess]:
            self._delete_locked(conversation)

    # ------------------------------------------------------------ connection

    def reset_sessions(self) -> bool:
        """Delete every live SDK session; return True if any deletion failed (those sessions stay recorded)."""
        with self._cond:
            sessions = [(conversation, session) for conversation in self._conversations.values()
                        for session in self._sdk_session(conversation)]
        failed = False
        for conversation, session in sessions:
            if self._delete_sessions([session]):
                failed = True
                continue
            with self._cond:
                if conversation.session.session_id == session[1]:
                    conversation.session.session_id = conversation.session.session_scope = None
        return failed

    def _any_running(self) -> bool:
        return any(running is not None for running in self._running.values()) or any(
            request.status == "running" for request in self._requests)

    def _reset_connection_locked(self) -> None:
        previous = self._conversations
        for request in self._requests:
            if not request.model_explicit:
                request.model = None  # the new connection's model, when it starts
            owner = previous.get(request.conversation_id)
            if owner is not None and owner.messages:
                request.status, request.error, request.error_code = "failed", CONNECTION_CHANGED, "connection_changed"
        self._history = []
        fresh = {MAIN: self._new_main()}
        for request in self._requests:
            old = previous.get(request.conversation_id)
            if old is not None and old.id not in fresh:
                fresh[old.id] = AgentConversationState(id=old.id, title=old.title, kind=old.kind, scope=old.scope,
                                                       profile=old.profile, created_at=old.created_at)
        self._conversations = fresh
        self._publish_queue()
        for conversation in fresh.values():
            self._publish_conversation(conversation)
        self._cond.notify_all()

    def reset_connection(self) -> None:
        """Forget every conversation after a connection change, as the per-tab queue did.

        Waiting requests of conversations with history fail (``connection_changed``); the history is
        cleared; the conversations become an empty main one plus empty copies of those still referenced
        by requests. Raises QueueBusy while a request runs.
        """
        with self._cond:
            if self._any_running():
                raise QueueBusy(BUSY)
            self._reset_connection_locked()

    @contextmanager
    def connection_change(self) -> Iterator[ConnectionChange]:
        """Hold the queue while the caller changes the agent connection.

        Raises QueueBusy if a request runs (or another change is in progress); otherwise no request starts
        until the block exits, which resets the conversations and wakes the queue, unless ``abort()`` was
        called. An exception leaves the conversations untouched.
        """
        with self._cond:
            if self._changing or self._any_running():
                raise QueueBusy(BUSY)
            self._changing = True
            self._generation += 1
        change = ConnectionChange()
        try:
            yield change
        except BaseException:
            with self._cond:
                self._changing = False
                self._cond.notify_all()
            raise
        with self._cond:
            if not change.aborted:
                self._revision += 1
                self._reset_connection_locked()
            self._changing = False
            self._cond.notify_all()
        if not change.aborted:
            self.wake()

    def model_changed(self) -> None:
        """The selected model changed: tell every tab (``connection_revision``) and resume a paused queue."""
        with self._cond:
            self._revision += 1
            self._publish_queue()
        self.wake()

    def wake(self) -> None:
        """Resume a paused queue (after sign-in, a provider or model change): requests are retried."""
        with self._cond:
            self._verified_token = None
            if self._paused is not None:
                self._paused = None
                self._publish_queue()
            self._cond.notify_all()
            waiting = any(request.status == "queued" for request in self._requests)
        if waiting:
            self._ensure_workers()

    # ------------------------------------------------------------ scheduling

    def _next(self, lane: Lane) -> AgentRequest | None:
        """The lane's first eligible request (P12): queued, and no earlier request of its conversation waits or runs."""
        if self._paused or self._changing or self._stopping or self._running[lane] is not None:
            return None
        busy = {request.conversation_id for request in self._requests if request.status == "running"}
        for request in self._requests:
            if request.status != "queued":
                continue
            if request.lane == lane and request.conversation_id not in busy:
                return request
            busy.add(request.conversation_id)
        return None

    def run_once(self, lane: Lane) -> str | None:
        """Run the lane's next eligible request in this thread; return its ID, or None if none could start."""
        with self._cond:
            request = self._next(lane)
        if request is None:
            return None
        return request.id if self._attempt(lane, request.id) else None

    def _attempt(self, lane: Lane, request_id: str) -> bool:
        with self._cond:
            generation = self._generation
            unresolved = any(request.id == request_id and request.model is None for request in self._requests)
        credentials, problem = self._load_credentials()
        model = self._configured_model()[0] if unresolved else None
        with self._cond:
            if self._generation != generation:
                return False  # the connection changed while loading: the worker reloads them
            if problem is not None:
                self._pause(problem["code"], problem["error"])
                return False
            request = self._next(lane)
            if request is None or request.id != request_id or (request.model is None and model is None):
                return False
            assert credentials is not None
            conversation = self._conversations[request.conversation_id]
            running = _Running(request.id)
            self._running[lane] = running
            request.status, request.started_at = "running", time.time()
            if request.model is None:
                request.model = model
            conversation.live = {"request_id": request.id, "pending_message": request.text or "", "live_reply": "",
                                 "activity": [], "progress": "Connecting to Copilot..."}
            self._publish_queue()
        try:
            self._execute(request, conversation, credentials, running)
        finally:
            with self._cond:
                self._running[lane] = None
                self._cond.notify_all()
        return True

    def _ensure_workers(self) -> None:
        if self._autostart:
            self.start()

    def start(self) -> None:
        """Start the lane workers (once); the first enqueue does it unless ``autostart`` is off."""
        with self._cond:
            for lane in LANES:
                thread = self._threads.get(lane)
                if thread is None or not thread.is_alive():
                    thread = threading.Thread(target=self._work, args=(lane,), name=f"agent-queue-{lane}",
                                              daemon=True)
                    self._threads[lane] = thread
                    thread.start()

    def _work(self, lane: Lane) -> None:
        while True:
            with self._cond:
                while not self._stopping and (request := self._next(lane)) is None:
                    self._cond.wait()
                if self._stopping or request is None:
                    return
            try:
                self._attempt(lane, request.id)
            except Exception:
                _logger.exception("The AI queue worker failed")
                with self._cond:
                    self._pause("error", WORKER_ERROR)

    def shutdown(self, timeout: float = 10) -> None:
        """Stop the running turns and the workers, and the guarded API; the queue keeps its state."""
        with self._cond:
            self._stopping = True
            for running in self._running.values():
                if running is not None:
                    self._cancel(running)
            self._cond.notify_all()
            threads, self._threads = list(self._threads.values()), {}
        for thread in threads:
            thread.join(timeout)
        with self._cond:
            guarded, self._guarded = self._guarded, None
            self._stopping = False
        if guarded is not None:
            guarded.stop()

    # ------------------------------------------------------------ one turn

    def _guarded_api(self) -> GuardedApi:
        from .guarded_api import GuardedApi

        with self._lock:
            if self._guarded is None:
                assert self._app is not None
                self._guarded = GuardedApi(self._app)
                self._guarded.start()
            return self._guarded

    @staticmethod
    def _with_model(credentials: AgentCredentials, model: str) -> AgentCredentials:
        provider = credentials.provider
        if provider and provider.model and model != provider.model:
            # A configured AI_MODEL is the provider's only choice; a request's model replaces it for its turn.
            return replace(credentials, provider=replace(provider, model=model, models=[{"id": model, "name": model}]))
        return credentials

    def _call(self, request: AgentRequest, conversation: AgentConversationState, path: Path,
              running: _Running) -> TurnCall:
        def publish(event: dict) -> None:
            self._on_progress(request, conversation, running, event)

        def on_session(session_id: str) -> None:
            running.session_id = session_id

        common: dict[str, Any] = {"request": request, "session": conversation.session, "model": request.model,
                                  "path": path, "publish": publish, "on_session": on_session}
        if request.spec is None:
            return TurnCall(**common, prompt=_agent().chat_prompt(request.text, request.context),
                            scope=conversation.scope or request.scope or "", profile=conversation.profile,
                            timeout=request.timeout)
        with self._app_context():
            try:
                turn = ai_actions.prepare(request.spec)
            except ValueError as exc:
                raise _TurnFailure("prepare", str(exc)) from None
        with self._lock:
            # Follow-ups may write what any of the conversation's batches could.
            conversation.scope = ai_actions.merge_scopes(conversation.scope, turn.scope)
            request.text = turn.prompt
            if conversation.live is not None:
                conversation.live["pending_message"] = turn.prompt
        return TurnCall(**common, prompt=turn.prompt, scope=turn.scope, profile=turn.profile,
                        timeout=turn.spec.timeout, turn=turn, api=self._guarded_api())

    def _run(self, call: TurnCall, running: _Running) -> tuple[str, dict]:
        """Run the turn in an event loop owned by this thread, so ``stop`` can cancel its task."""
        with asyncio.Runner() as runner:
            loop = runner.get_loop()
            task: asyncio.Task[tuple[str, dict]] = loop.create_task(self._runner(call))
            with self._lock:
                running.loop, running.task = loop, task
                if running.stop_requested:
                    task.cancel()
            try:
                return loop.run_until_complete(task)
            finally:
                with self._lock:
                    running.loop = running.task = None

    def _execute(self, request: AgentRequest, conversation: AgentConversationState, credentials: AgentCredentials,
                 running: _Running) -> None:
        from ..routes import agent_skills

        agent = _agent()
        assert request.model is not None  # resolved when it started
        conversation.session.credentials = self._with_model(credentials, request.model)
        previous = conversation.session.session_id
        call: TurnCall | None = None
        reply: str | None = None
        usage: dict | None = None
        failure: tuple[str, str] | None = None  # (error_code, error) of the request
        turn_error: tuple[str, str] | None = None  # (outcome, message) for ai_actions.verify
        try:
            path = agent._mcp_path()
            if path is None or not path.is_file():
                raise _TurnFailure("mcp", MCP_MISSING)
            if conversation.archived:
                raise _TurnFailure("archived", ARCHIVED)
            call = self._call(request, conversation, path, running)
            reply, usage = self._run(call, running)
        except _TurnFailure as exc:
            failure = (exc.code, exc.message)
        except asyncio.CancelledError:
            running.stop_requested = True
        except TimeoutError:
            failure = turn_error = ("timeout", f"No reply within {call.timeout if call else request.timeout} s.")
        except (agent.UnavailableModelError, agent_skills.AgentSkillError) as exc:
            code = "unavailable_model" if isinstance(exc, agent.UnavailableModelError) else "skills"
            failure, turn_error = (code, str(exc)), ("failed", str(exc))
        except Exception as exc:
            _logger.exception("Agent request failed")
            failure = ("failed", "Agent request failed. Check the provider model, key, endpoint, and backend logs."
                       if credentials.provider else
                       "Agent request failed. Check Copilot sign-in, MCP server, and backend logs.")
            turn_error = ("failed", str(exc) or type(exc).__name__)
        result: dict | None = None
        if call is not None and call.turn is not None:
            try:
                with self._app_context():
                    result = ai_actions.verify(call.turn, turn_error, running.stop_requested, reply, usage)
            except Exception:
                _logger.exception("Could not verify the AI action")
                failure = failure or ("verify", "Could not verify the result of this request; see the server logs.")
        stale = self._finish(request, conversation, running, previous, reply, usage, failure, result)
        self._delete_sessions(stale)
        self._release_idle()

    def _finish(self, request: AgentRequest, conversation: AgentConversationState, running: _Running,
                previous: str | None, reply: str | None, usage: dict | None, failure: tuple[str, str] | None,
                result: dict | None) -> list[tuple[AgentCredentials, str]]:
        """Record the turn's outcome; return the SDK sessions it left behind (to delete)."""
        with self._cond:
            if running.progress_pending:
                self._emit_progress(running, conversation)
            activity = list(conversation.live["activity"]) if conversation.live else []
            conversation.live = None
            now = time.time()
            if reply is not None:
                if request.spec is not None and conversation.session.session_scope is not None:
                    # The batch's session also fits the conversation's wider scope: follow-ups resume it.
                    conversation.session.session_scope = conversation.scope
                conversation.messages.extend((
                    {"role": "user", "content": request.text or "", "taskId": request.id},
                    {"role": "assistant", "content": reply, "activity": activity, "taskId": request.id}))
                if usage is not None:
                    conversation.session.usage = _agent()._add_usage(conversation.session.usage, usage)
                conversation.last_used = now
            request.result, request.finished_at = result, now
            if running.stop_requested:
                request.status, request.error, request.error_code = "cancelled", STOPPED, "stopped"
            elif failure is not None:
                request.status, (request.error_code, request.error) = "failed", failure
            elif request.kind == "review" and result is not None and result["outcome"] != "reviewed":
                errors = [target["error"] for target in result["targets"] if target["outcome"] != "reviewed"]
                request.status, request.error_code = "failed", result["outcome"]
                request.error = next((error for error in errors if error), "Not every target was reviewed.")
            else:
                request.status = "done"
            if request.status != "failed":
                self._requests.remove(request)
                self._history = [*self._history, request][-HISTORY_LIMIT:]
                self._index(request)
            self._publish_queue()
            self._publish_conversation(conversation)
            session = conversation.session
            stale = []
            if running.session_id and running.session_id not in (session.session_id, previous):
                stale.append((session.credentials, running.session_id))  # created, but the turn did not keep it
            if previous and session.session_id != previous:
                stale.append((session.credentials, previous))  # replaced by the turn's new session
            return stale

    # ------------------------------------------------------------ progress

    def _on_progress(self, request: AgentRequest, conversation: AgentConversationState, running: _Running,
                     event: dict) -> None:
        with self._lock:
            live = conversation.live
            if live is None or live["request_id"] != request.id:
                return
            kind = event.get("type")
            if kind == "delta":
                if running.message_id != event.get("message_id"):
                    running.message_id, live["live_reply"] = event.get("message_id"), ""
                live["live_reply"] += event.get("text") or ""
                live["progress"] = "Writing response..."
            elif kind == "tool_start":
                live["activity"] = [*live["activity"], {"id": event.get("id"), "name": event.get("name"),
                                                        "status": "running"}][-ACTIVITY_LIMIT:]
                live["progress"] = "Checking VulnScout..."
            elif kind == "tool_end":
                status = "done" if event.get("success") else "failed"
                tool = next((item["name"] for item in live["activity"] if item["id"] == event.get("id")), None)
                live["activity"] = [{**item, "status": status} if item["id"] == event.get("id") else item
                                    for item in live["activity"]]
                live["progress"] = "Preparing response..."
                if event.get("success") and event.get("write"):
                    self.events.publish("agent_write", {"tool": tool, "request_id": request.id,
                                                        "conversation_id": conversation.id})
            else:
                return
            elapsed = time.monotonic() - running.progress_at
            if elapsed >= PROGRESS_INTERVAL:
                self._emit_progress(running, conversation)
                return
            running.progress_pending = True
            if not running.flush_scheduled and running.loop is not None:
                running.flush_scheduled = True
                running.loop.call_soon_threadsafe(running.loop.call_later, PROGRESS_INTERVAL - elapsed,
                                                  self._flush_progress, running, conversation)

    def _emit_progress(self, running: _Running, conversation: AgentConversationState) -> None:
        running.progress_at, running.progress_pending = time.monotonic(), False
        self.events.publish("request_progress", {"request_id": running.request_id,
                                                 "conversation_id": conversation.id,
                                                 "live": _copy_live(conversation.live)})

    def _flush_progress(self, running: _Running, conversation: AgentConversationState) -> None:
        with self._lock:
            running.flush_scheduled = False
            live = conversation.live
            if running.progress_pending and live is not None and live["request_id"] == running.request_id:
                self._emit_progress(running, conversation)


# The agent stream's bus: separate from operation_events, whose stream any client may read.
agent_events = EventBus(replay_size=64)
agent_queue = AgentQueue()

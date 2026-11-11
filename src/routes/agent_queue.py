# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""HTTP and SSE access to the process-wide AI queue (``controllers.agent_queue``).

Like the other agent routes, these are available only on localhost, to same-origin requests. Unlike
the agent blueprint, they are registered on the app, so the "Scan not finished" gate applies to all
but the stream (the CLI waits on that 503 while the web server starts).
"""

from __future__ import annotations

from typing import Any

from flask import Flask, make_response, request
from flask.typing import ResponseReturnValue

from ..controllers import agent_queue as queue_module
from . import agent, events

QUEUE_STREAM_PATH = "/api/agent/queue/stream"
UNKNOWN_REQUEST = "This AI request is no longer available."


def _queue() -> queue_module.AgentQueue:
    # Looked up per call, so tests can replace the process-wide queue.
    return queue_module.agent_queue


def _guarded(handler) -> ResponseReturnValue:
    """Run *handler* after the localhost checks; map queue exceptions to JSON errors."""
    if error := agent._access_error():
        response = make_response(error)
        response.headers["Cache-Control"] = "no-store"
        return response
    try:
        return handler()
    except queue_module.NotReady as exc:
        return agent._response({"code": exc.code, "error": str(exc)}, 409)
    except queue_module.QueueConflict as exc:
        return agent._response({"error": str(exc)}, 409)
    except LookupError as exc:
        return agent._response({"error": str(exc.args[0]) if exc.args else UNKNOWN_REQUEST}, 404)
    except ValueError as exc:
        return agent._response({"error": str(exc)}, 400)


def _actions(value: Any) -> Any:
    """The actions with assess ``vuln_id`` uppercased, as vulnerabilities are stored; the queue validates the rest."""
    if not isinstance(value, list):
        return value
    return [{**action, "vuln_id": action["vuln_id"].upper()}
            if isinstance(action, dict) and action.get("kind") == "assess" and isinstance(action.get("vuln_id"), str)
            else action for action in value]


def queue_snapshot():
    """Return the AI queue: waiting and running requests, recent history, conversations and pause state.

    OpenAPI:
    response 200 AgentQueueSnapshot Queue snapshot; seq is the last queue event it includes.
    """
    return _guarded(lambda: agent._response(_queue().snapshot()))


def queue_stream():
    """Stream AI queue updates over server-sent events.

    Frames are ``snapshot`` (the queue snapshot, sent first), ``queue`` (requests, history, conversations
    and pause state), ``request_progress``, ``conversation``, ``agent_write`` (an AI request saved an
    assessment or review), ``heartbeat`` every 15 seconds, and ``bye`` on shutdown. Reconnecting clients
    that send ``Last-Event-ID`` are replayed from the buffer, or resnapshotted when the gap is too wide.
    Available before the scan finishes.

    OpenAPI:
    header Last-Event-ID string optional Resume from this instance-scoped cursor.
    response 200 sse Server-sent event frames (see above).
    response 503 Error Too many concurrent streams.
    """
    def stream():
        queue = _queue()

        def snapshot() -> tuple[dict, int]:
            data = queue.snapshot()
            return data, data["seq"]

        response = make_response(events.stream_response(queue.events, snapshot))
        response.headers["Cache-Control"] = "no-store, no-transform"
        return response
    return _guarded(stream)


def queue_submit():
    """Queue agent actions or a chat message.

    Assess and review actions go to ``per-action`` (one new conversation per action key); a message goes
    to ``main`` or to an existing conversation. Actions whose key is already queued, running or failed are
    reported in ``skipped`` with the request holding that key. With ``require_ready``, the call fails with
    409 and a ``code`` (no_ai_config, invalid_config or github_signed_out) when no request could run now.

    OpenAPI:
    body AgentQueueSubmit required Actions and where to queue them.
    response 202 AgentQueueSubmitted Created requests and skipped duplicates.
    response 404 Error Unknown conversation.
    response 409 Error Not ready (with code), or the conversation is archived.
    """
    def submit():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ValueError("Send a JSON object.")
        require_ready = data.get("require_ready", False)
        if not isinstance(require_ready, bool):
            raise ValueError("require_ready must be a boolean.")
        # enqueue() validates the types of the untrusted values.
        conversation: Any = data.get("conversation")
        source: Any = data.get("source")
        created, skipped = _queue().enqueue(
            conversation, source, _actions(data.get("actions")),
            model=data.get("model"), context=data.get("context"), timeout=data.get("timeout"),
            require_ready=require_ready)
        return agent._response({"requests": created, "skipped": skipped}, 202)
    return _guarded(submit)


def queue_clear():
    """Remove every waiting (queued or failed) request; running requests continue.

    OpenAPI:
    response 200 AgentQueueRemoved Number of removed requests.
    """
    return _guarded(lambda: agent._response({"removed": _queue().clear()}))


def queue_request(request_id):
    """Return one AI request, with its full result, while it is active or recently finished.

    OpenAPI:
    response 200 AgentQueueRequest The request.
    response 404 Error Unknown or forgotten request.
    """
    def get():
        record = _queue().get_request(request_id)
        if record is None:
            raise LookupError(UNKNOWN_REQUEST)
        return agent._response(record)
    return _guarded(get)


def queue_remove(request_id):
    """Remove a queued or failed request.

    OpenAPI:
    response 200 AgentQueueRequestStatus The request was removed.
    response 404 Error Unknown request.
    response 409 Error The request is running; stop it instead.
    """
    def remove():
        _queue().remove(request_id)
        return agent._response({"status": "removed"})
    return _guarded(remove)


def queue_stop(request_id):
    """Stop a running request (it ends cancelled, keeping what it saved), or remove a waiting one.

    OpenAPI:
    response 200 AgentQueueRequestStatus stopping, or removed for a request that was not running.
    response 404 Error Unknown request.
    """
    return _guarded(lambda: agent._response({"status": _queue().stop(request_id)}))


def queue_retry(request_id):
    """Queue a failed request again, at the end of its lane.

    OpenAPI:
    response 200 AgentQueueRequestStatus The request is queued.
    response 404 Error Unknown request.
    response 409 Error Only failed requests can be retried.
    """
    def retry():
        _queue().retry(request_id)
        return agent._response({"status": "queued"})
    return _guarded(retry)


def conversation_get(conversation_id):
    """Return a conversation's transcript, usage and live turn.

    OpenAPI:
    response 200 AgentConversation The conversation.
    response 404 Error Unknown conversation.
    """
    def get():
        conversation = _queue().conversation(conversation_id)
        if conversation is None:
            raise LookupError(queue_module.NOT_AVAILABLE)
        return agent._response(conversation)
    return _guarded(get)


def conversation_delete(conversation_id):
    """Delete a finished action conversation and its stored Copilot session.

    OpenAPI:
    response 200 AgentConversationsDeleted One deleted conversation.
    response 404 Error Unknown conversation.
    response 409 Error The conversation still has requests, or is the main conversation.
    """
    def delete():
        _queue().delete_conversation(conversation_id)
        return agent._response({"deleted": 1})
    return _guarded(delete)


def conversations_clear():
    """Delete every action conversation without requests.

    OpenAPI:
    response 200 AgentConversationsDeleted Number of deleted conversations.
    """
    return _guarded(lambda: agent._response({"deleted": _queue().clear_finished()}))


def conversation_reset_main():
    """Start the main conversation afresh; its waiting messages stay queued.

    OpenAPI:
    response 200 AgentConversation The new, empty main conversation.
    response 409 Error A main conversation message is running.
    """
    def reset():
        queue = _queue()
        queue.reset_main()
        return agent._response(queue.conversation(queue_module.MAIN))
    return _guarded(reset)


ROUTES = (
    ("/api/agent/queue", "GET", queue_snapshot),
    (QUEUE_STREAM_PATH, "GET", queue_stream),
    ("/api/agent/queue", "POST", queue_submit),
    ("/api/agent/queue", "DELETE", queue_clear),
    ("/api/agent/queue/requests/<request_id>", "GET", queue_request),
    ("/api/agent/queue/requests/<request_id>", "DELETE", queue_remove),
    ("/api/agent/queue/requests/<request_id>/stop", "POST", queue_stop),
    ("/api/agent/queue/requests/<request_id>/retry", "POST", queue_retry),
    ("/api/agent/conversations/<conversation_id>", "GET", conversation_get),
    ("/api/agent/conversations/<conversation_id>", "DELETE", conversation_delete),
    ("/api/agent/conversations", "DELETE", conversations_clear),
    ("/api/agent/conversations/main/reset", "POST", conversation_reset_main),
)


def init_app(app: Flask) -> None:
    for rule, method, view in ROUTES:
        app.route(rule, methods=[method])(view)

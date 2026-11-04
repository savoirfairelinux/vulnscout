# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Helpers shared by the CLI commands that run the embedded AI agent (``ai-assess``, ``ai-review``)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import threading
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Iterator

import click
from flask import Response, abort, current_app, request_finished, request_started

# Set by entrypoint.sh (ai-assess and ai-review) so the host wrapper can forward Ctrl-C to this process.
PID_FILE_ENV = "VULNSCOUT_AI_ASSESS_PID_FILE"
# Set by SIGINT so an interrupt is reported even when cancellation cleanup raises another exception.
interrupted = threading.Event()

NO_AI_CONFIG = ("No AI provider configured. Connect an AI provider in the web UI Agent panel "
                "or set AI_* with `vulnscout config`.")
GITHUB_SIGNED_OUT = ("GitHub Copilot rejected the configured token (expired or invalid). Reconnect in the "
                     "web UI Agent panel or update AI_AUTH_CREDENTIALS with `vulnscout config`.")

Guard = Callable[[], "Response | None"]  # runs in request_started; may abort
Recorder = Callable[["Response"], None]  # runs in request_finished


def empty_usage() -> dict[str, Any]:
    return {"cost": None, "input_tokens": None, "output_tokens": None}


def load_agent(model: str | None):
    """Return (credentials, model, MCP server path) from config.env, or fail like the web Agent would
    (including missing skills)."""
    from ..routes import agent, agent_skills

    root = agent.Conversation()
    error = agent._load_env_credentials(root)
    if error:
        raise click.ClickException(f"Invalid AI provider configuration: {error}")
    if not root.credentials.token and not root.credentials.provider:
        raise click.ClickException(NO_AI_CONFIG)
    selected = model or root.model
    if not selected:
        raise click.ClickException("No AI model configured. Set AI_MODEL with `vulnscout config` or pass --model.")
    provider = root.credentials.provider
    if provider and provider.model and selected != provider.model:
        # A configured AI_MODEL is the provider's only choice; --model replaces it for this run only.
        root.credentials.provider = replace(provider, model=selected, models=[{"id": selected, "name": selected}])
    path = agent._mcp_path()
    if path is None or not path.is_file():
        raise click.ClickException(
            "Bundled MCP server not found. Check the installation or VULNSCOUT_MCP_SERVER_PATH override.")
    if agent_skills.skills_path() is None:
        raise click.ClickException(agent_skills.SKILLS_MISSING_ERROR)
    return root.credentials, selected, path


def check_github_sign_in(token: str) -> None:
    """Fail once up front instead of once per vulnerability when the GitHub token is unusable."""
    from ..routes import agent

    try:
        auth = asyncio.run(agent._token_status(token))
    except Exception as exc:
        raise click.ClickException(f"Could not check the GitHub Copilot sign-in: {exc}") from exc
    if not auth["authenticated"]:
        raise click.ClickException(GITHUB_SIGNED_OUT)


def configured_model(model: str | None) -> str | None:
    """--model, else AI_MODEL as configured, without validating the provider."""
    from ..routes import agent

    try:
        return model or agent._agent_environment().get("AI_MODEL") or None
    except (OSError, ValueError):
        return model


def _on_sigint(signum, frame) -> None:
    interrupted.set()
    signal.default_int_handler(signum, frame)


@contextmanager
def interrupt_signals() -> Iterator[None]:
    """Replace webapp.py's stop handler (prints and exits 0) for this command.

    The host wrapper forwards the first Ctrl-C as SIGINT (stop and report) and any further one as
    SIGTERM, which must stop at once.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
    interrupted.clear()
    signal.signal(signal.SIGINT, _on_sigint)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    try:
        yield
    finally:
        for signum, handler in previous.items():
            if handler is not None:
                signal.signal(signum, handler)


def release_pid_file() -> None:
    """Remove the entrypoint's pidfile if it still names this process (it ``exec``s into flask)."""
    path = os.environ.get(PID_FILE_ENV)
    if not path:
        return
    with contextlib.suppress(OSError):
        if Path(path).read_text().strip() == str(os.getpid()):
            Path(path).unlink()


@contextmanager
def private_api(guard: Guard, recorder: Recorder) -> Iterator[str]:
    """Serve the app on 127.0.0.1:<free port> for one run; yield its base URL.

    ``guard`` is called before every request and may return a Response to reject it;
    ``recorder`` sees every finished response, including guard rejections.
    """
    from werkzeug.serving import make_server

    app = current_app._get_current_object()  # type: ignore[attr-defined]
    # This process never runs the boot scan that normally opens the /api gate.
    setattr(app, "_INT_SCAN_FINISHED", True)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    def on_started(sender, **extra) -> None:
        rejection = guard()
        if rejection is not None:
            abort(rejection)

    def on_finished(sender, response, **extra) -> None:
        recorder(response)

    request_started.connect(on_started, app, weak=False)
    request_finished.connect(on_finished, app, weak=False)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        request_finished.disconnect(on_finished, app)
        request_started.disconnect(on_started, app)

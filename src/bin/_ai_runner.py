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
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator

import click
from flask import current_app

from ..helpers.env_vars import get_bool_env

if TYPE_CHECKING:
    from ..controllers.ai_actions import TurnResult, TurnSpec
    from ..controllers.guarded_api import GuardedApi

# Set by entrypoint.sh (ai-assess and ai-review) so the host wrapper can forward Ctrl-C to this process.
PID_FILE_ENV = "VULNSCOUT_AI_ASSESS_PID_FILE"
# Set by SIGINT so an interrupt is reported even when cancellation cleanup raises another exception.
interrupted = threading.Event()

NO_AI_CONFIG = ("No AI provider configured. Connect an AI provider in the web UI Agent panel "
                "or set AI_* with `vulnscout config`.")
GITHUB_SIGNED_OUT = ("GitHub Copilot rejected the configured token (expired or invalid). Reconnect in the "
                     "web UI Agent panel or update AI_AUTH_CREDENTIALS with `vulnscout config`.")


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
def guarded_api() -> Iterator[GuardedApi]:
    """Serve the app on 127.0.0.1:<free port> for one run (see ``GuardedApi``), started and disarmed.

    Each turn arms it with its own guard (``ai_actions.run_turn``); requests that do not come through
    this port are not guarded.
    """
    from ..controllers.guarded_api import GuardedApi

    api = GuardedApi(current_app._get_current_object())  # type: ignore[attr-defined]
    api.start()
    try:
        yield api
    finally:
        api.stop()


def execute(specs: Iterable[TurnSpec], model: str | None, on_start: Callable[[TurnSpec], None],
            on_done: Callable[[TurnSpec, TurnResult], None]) -> tuple[str, bool]:
    """Run each of *specs* as one agent turn in this process; return the model used and whether the run was
    interrupted.

    *specs* is consumed lazily, one spec per turn, so a command can plan each item when it is reached.
    ``on_start(spec)`` runs before the turn and ``on_done(spec, result)`` after it with its ``TurnResult``;
    a completed turn's result carries its ``usage``. An unavailable model or missing skills ends the run with
    a ``ClickException``; Ctrl-C stops it after recording what the current turn wrote.
    """
    from ..controllers import ai_actions
    from ..routes import agent, agent_skills

    # This process never runs the boot scan that normally opens the /api gate.
    setattr(current_app, "_INT_SCAN_FINISHED", True)
    credentials, selected, path = load_agent(model)
    if not get_bool_env("VERBOSE_MODE"):
        # The SDK logs every failed request with a traceback; the summary already reports the error.
        logging.getLogger("copilot").setLevel(logging.ERROR)
    if credentials.token and not credentials.provider:
        check_github_sign_in(credentials.token)
    with guarded_api() as api:
        try:
            for spec in specs:
                on_start(spec)
                turn = ai_actions.prepare(spec)
                reply: str | None = None
                usage: dict | None = None
                error: tuple[str, str] | None = None
                stopped = False
                try:
                    reply, usage = asyncio.run(ai_actions.run_turn(
                        turn, agent.Conversation(credentials=credentials), selected, path, api))
                except (agent.UnavailableModelError, agent_skills.AgentSkillError):
                    raise
                except KeyboardInterrupt:
                    # SIGINT forwarded by the host wrapper: asyncio.run cancels the turn (the SDK session is
                    # disconnected and deleted in _reply's finally); still record what it already wrote.
                    stopped = True
                except asyncio.TimeoutError:
                    error = ("timeout", f"No reply within {spec.timeout} s.")
                except Exception as exc:
                    error = ("failed", str(exc) or type(exc).__name__)
                # A cleanup error raised while the turn was being cancelled replaces the KeyboardInterrupt.
                stopped = stopped or interrupted.is_set()
                on_done(spec, ai_actions.verify(turn, error, stopped, reply, usage))
                if stopped or interrupted.is_set():
                    raise KeyboardInterrupt
        except KeyboardInterrupt:
            return selected, True
        except (agent.UnavailableModelError, agent_skills.AgentSkillError) as exc:
            raise click.ClickException(str(exc)) from exc
    return selected, False

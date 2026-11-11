# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""``flask ai-assess``: assess selected vulnerabilities with the embedded AI agent."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field, replace
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import click
from flask import current_app
from flask.cli import with_appcontext

from ..controllers import ConditionParser, ControllersCache, ai_actions
# MESSAGE_LIMIT and build_prompts are re-exported for the CLI tests.
from ..controllers.ai_actions import (  # noqa: F401
    CVE_ID_PATTERN, MESSAGE_LIMIT, Target, active_targets, build_prompts)
from ..controllers.guarded_api import GuardedApi
from ..helpers.env_vars import get_bool_env
from ..helpers.export_scope import compute_export_scope
from . import _ai_runner
from ._common import resolve_project_variant
from ._console import Command, echo
from .cmd_process import _condition_scope, condition_data, newest_assessment

FAILING_OUTCOMES = frozenset({"partial", "no_write", "failed", "timeout", "not_found", "interrupted"})


@dataclass
class Result:
    id: str
    targets: list[Target]
    outcome: str = "pending"
    written: set[Target] = field(default_factory=set)
    assessment_ids: dict[Target, list[str]] = field(default_factory=dict)
    replies: list[str] = field(default_factory=list)
    usage: dict[str, Any] = field(default_factory=_ai_runner.empty_usage)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "outcome": self.outcome,
            "targets": [{"variant_id": target.variant_id, "variant": target.variant,
                         "package": target.package, "written": target in self.written,
                         "assessment_ids": self.assessment_ids.get(target, [])}
                        for target in self.targets],
            "reply": "\n\n".join(self.replies) or None,
            "usage": self.usage,
            "error": self.error,
        }


# One assessment per state a filter can tell apart (None: unassessed; "": any other status).
_STATUS_SAMPLES = (None, *(SimpleNamespace(status=status)
                           for status in ("fixed", "not_affected", "affected", "under_investigation", "")))


def _filter_targets(scope, condition: str) -> dict[str, list[Target]]:
    """Vulnerability ID -> its active targets in *scope* that match *condition*.

    Each target is evaluated with its own newest assessment, so an assessment of a removed version or of
    another package never decides whether a current target is selected.
    """
    parser = ConditionParser()

    def matches(data: dict) -> bool:
        try:
            return parser.evaluate(condition, data)
        except Exception as exc:  # ConditionParser raises bare Exception for invalid expressions.
            raise click.ClickException(f"Invalid filter: {exc}") from exc

    targets_by_vuln: dict[str, list[Target]] = {}
    selected: dict[str, list[Target]] = {}
    for variant_id in sorted(scope.variant_ids, key=str):
        controllers = ControllersCache(scope=compute_export_scope(variant_id=variant_id))
        for vuln_id, vuln in controllers.vulnerabilities.vulnerabilities.items():
            # Skip the target lookup when no assessment state can make the vulnerability match.
            if not any(matches(condition_data(vuln_id, vuln, sample)) for sample in _STATUS_SAMPLES):
                continue
            if vuln_id not in targets_by_vuln:
                targets_by_vuln[vuln_id] = active_targets(vuln_id, set(scope.variant_ids))
            assessments = controllers.assessments.gets_by_vuln(vuln_id)
            for target in targets_by_vuln[vuln_id]:
                if target.variant_id != str(variant_id):
                    continue
                pair = (UUID(target.variant_id), UUID(target.finding_id))
                newest = newest_assessment(a for a in assessments if pair in getattr(a, "targets", []))
                if matches(condition_data(vuln_id, vuln, newest)):
                    selected.setdefault(vuln_id, []).append(target)
    return selected


def _report(results: list[Result], model: str | None, project: str | None, variants: list[str],
            as_json: bool) -> None:
    scope = {"project": project or "default", "variants": variants or (None if project else ["default"])}
    if as_json:
        click.echo(json.dumps({"model": model, "scope": scope,
                               "results": [result.to_dict() for result in results]}, indent=2))
        return
    if not results:
        echo("No vulnerabilities matched.")
        return
    for result in results:
        count = (str(len(result.targets)) if result.outcome in ("planned", "not_found")
                 else f"{len(result.written)}/{len(result.targets)}")
        echo(f"{result.id}  {result.outcome}  {count} targets" + (f"  {result.error}" if result.error else ""),
             role="success" if result.outcome in ("assessed", "planned") else "error")
        if result.outcome == "planned":
            for variant_name in dict.fromkeys(target.variant for target in result.targets):
                packages = ", ".join(t.package for t in result.targets if t.variant == variant_name)
                echo(f"    {variant_name}: {packages}")
        else:
            for target in result.targets:
                if target in result.written:
                    echo(f"    {target.variant} / {target.package}  written  "
                         + ", ".join(result.assessment_ids.get(target, [])))
                else:
                    echo(f"    {target.variant} / {target.package}  not written", role="error")
    if model:
        echo(f"Model: {model}")


@click.command("ai-assess", cls=Command)
@click.option("--project", "project_name", default=None, help="Project (all its variants without --variant).")
@click.option("--variant", "variant_names", multiple=True, help="Variant (repeatable); requires --project.")
@click.option("--cve", "cve_ids", multiple=True, help="Vulnerability ID to assess (repeatable); not with --filter.")
@click.option("--filter", "condition", default=None,
              help="Match-condition expression selecting vulnerabilities; not with --cve. "
                   "Use \"id == <id>\" to combine IDs with other conditions.")
@click.option("--model", default=None, help="Model to use instead of AI_MODEL.")
@click.option("--timeout", type=click.IntRange(min=1), default=600, show_default=True,
              help="Seconds allowed for each agent turn.")
@click.option("--dry-run", is_flag=True, help="Show the selection and targets without calling the AI.")
@click.option("--json", "as_json", is_flag=True, help="Print the summary as JSON on stdout.")
@with_appcontext
def ai_assess_command(project_name, variant_names, cve_ids, condition, model, timeout, dry_run, as_json):
    """Assess vulnerabilities with the embedded AI agent; results are pending AI assessments."""
    try:
        with _ai_runner.interrupt_signals():
            _ai_assess(project_name, variant_names, cve_ids, condition, model, timeout, dry_run, as_json)
    finally:
        _ai_runner.release_pid_file()


def _scope(project_name: str | None, variant_names: list[str]):
    if project_name and variant_names:
        return compute_export_scope(
            variant_ids=[resolve_project_variant(project_name, name)[1].id for name in variant_names])
    return _condition_scope(project_name, None)


def _ai_assess(project_name, variant_names, cve_ids, condition, model, timeout, dry_run, as_json):
    if cve_ids and condition:
        raise click.UsageError(
            "Use exactly one of --cve or --filter; to combine them, list the IDs in the filter, "
            'e.g. --filter "(id == CVE-2024-3094 or id == CVE-2023-4863) and pending".')
    if not cve_ids and not condition:
        raise click.UsageError("Use exactly one of --cve or --filter.")
    variants = list(dict.fromkeys(variant_names))
    if variants and not project_name:
        raise click.UsageError("--variant requires --project.")
    invalid = [cve for cve in cve_ids if not CVE_ID_PATTERN.fullmatch(cve)]
    if invalid:
        raise click.UsageError(f"Invalid vulnerability ID: {invalid[0]}")
    # Vulnerability IDs are stored uppercase: canonical IDs deduplicate the selection and match the agent's writes.
    cve_ids = tuple(cve.upper() for cve in cve_ids)
    scope = _scope(project_name, variants)
    if cve_ids:
        results = [Result(vuln_id, active_targets(vuln_id, set(scope.variant_ids)))
                   for vuln_id in dict.fromkeys(cve_ids)]
    else:
        # Only matching active targets are selected: a match through a finding seen only by an older scan,
        # or by another project sharing the package, yields none. Only explicitly requested IDs report
        # not_found.
        results = [Result(vuln_id, targets) for vuln_id, targets in _filter_targets(scope, condition).items()]
    for result in results:
        if not result.targets:
            result.outcome, result.error = "not_found", "No active targets in scope."
        elif dry_run:
            result.outcome = "planned"
    if dry_run:
        for result in results:
            if result.outcome == "planned":
                try:
                    ai_actions.plan_assess(result.id, result.targets)
                except ValueError as exc:
                    result.outcome, result.error = "failed", str(exc)
    else:
        model = _run(results, model, timeout)
    _report(results, model, project_name, variants, as_json)
    if any(result.outcome in FAILING_OUTCOMES for result in results):
        raise SystemExit(1)


def _assess(result: Result, label: str, credentials, model: str, path, api: GuardedApi, timeout: int) -> None:
    from ..routes import agent, agent_skills

    try:
        specs = ai_actions.plan_assess(result.id, result.targets)
    except ValueError as exc:
        result.outcome, result.error = "failed", str(exc)
        return
    errors: list[tuple[str, str]] = []
    for spec in specs:
        part = f", batch {spec.batch[0]} of {spec.batch[1]}" if spec.batch else ""
        echo(f"{label} Assessing {result.id} ({len(spec.assess_targets)} targets{part})...", err=True)
        turn = ai_actions.prepare(replace(spec, timeout=timeout))
        error: tuple[str, str] | None = None
        interrupted = False
        try:
            reply, usage = asyncio.run(ai_actions.run_turn(
                turn, agent.Conversation(credentials=credentials), model, path, api))
            result.replies.append(reply)
            result.usage = agent._add_usage(result.usage, usage)
        except agent.UnavailableModelError:
            raise
        except agent_skills.AgentSkillError as exc:
            raise click.ClickException(str(exc)) from exc
        except KeyboardInterrupt:
            # SIGINT forwarded by the host wrapper: asyncio.run cancels the turn (the SDK session is
            # disconnected and deleted in _reply's finally); still record what it already wrote.
            interrupted = True
        except asyncio.TimeoutError:
            error = ("timeout", f"No reply within {timeout} s.")
        except Exception as exc:
            error = ("failed", str(exc) or type(exc).__name__)
        if error is not None:
            errors.append(error)
        # A cleanup error raised while the turn was being cancelled replaces the KeyboardInterrupt.
        interrupted = interrupted or _ai_runner.interrupted.is_set()
        outcome = ai_actions.verify(turn, error, interrupted)
        for target, item in zip(spec.assess_targets, outcome["targets"]):
            if item["written"]:
                result.written.add(target)
                result.assessment_ids[target] = item["assessment_ids"]
        if interrupted:
            result.outcome, result.error = "interrupted", "Interrupted."
            raise KeyboardInterrupt
    if errors:
        result.outcome, result.error = errors[0][0], "; ".join(message for _, message in errors)
    elif len(result.written) == len(result.targets):
        result.outcome = "assessed"
    else:
        result.outcome = "partial" if result.written else "no_write"
    echo(f"{label} {result.id}: {result.outcome}", role="success" if result.outcome == "assessed" else "error",
         err=True)


def _run(results: list[Result], model: str | None, timeout: int) -> str | None:
    from ..routes import agent

    # This process never runs the boot scan that normally opens the /api gate.
    setattr(current_app, "_INT_SCAN_FINISHED", True)

    pending = [result for result in results if result.outcome == "pending"]
    if not pending:
        return _ai_runner.configured_model(model)
    credentials, selected, path = _ai_runner.load_agent(model)
    if not get_bool_env("VERBOSE_MODE"):
        # The SDK logs every failed request with a traceback; the summary already reports the error.
        logging.getLogger("copilot").setLevel(logging.ERROR)
    if credentials.token and not credentials.provider:
        _ai_runner.check_github_sign_in(credentials.token)
    with _ai_runner.guarded_api() as api:
        try:
            for number, result in enumerate(pending, 1):
                try:
                    _assess(result, f"[{number}/{len(pending)}]", credentials, selected, path, api, timeout)
                except KeyboardInterrupt:
                    if result.outcome == "pending":
                        result.outcome, result.error = "interrupted", "Interrupted."
                    raise
                if _ai_runner.interrupted.is_set():
                    raise KeyboardInterrupt
        except KeyboardInterrupt:
            echo("Interrupted; reporting completed assessments.", role="warning", err=True)
            for result in pending:
                if result.outcome == "pending":
                    result.outcome, result.error = "interrupted", "Not started."
        except agent.UnavailableModelError as exc:
            raise click.ClickException(str(exc)) from exc
    return selected

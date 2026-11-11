# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""``flask ai-assess``: assess selected vulnerabilities with the embedded AI agent."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Iterator
from uuid import UUID

import click
from flask import Response, current_app, make_response, request
from flask.cli import with_appcontext

from ..controllers import ConditionParser, ControllersCache
from ..extensions import db
from ..helpers.active_scans import active_scan_ids_for_variant
from ..helpers.active_targets import variant_active_packages
from ..helpers.env_vars import get_bool_env
from ..helpers.export_scope import compute_export_scope
from ..models.observation import Observation
from ..models.variant import Variant
from . import _ai_runner
from ._common import resolve_project_variant
from ._console import Command, echo
from .cmd_process import _condition_scope, condition_data, newest_assessment

CVE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*")
MESSAGE_LIMIT = 8000
PROMPT_BUDGET = MESSAGE_LIMIT - len(" (batch 9999 of 9999)")
FAILING_OUTCOMES = frozenset({"partial", "no_write", "failed", "timeout", "not_found", "interrupted"})


@dataclass(frozen=True)
class Target:
    variant_id: str
    variant: str
    project_id: str
    package: str
    finding_id: str


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


def active_targets(vuln_id: str, variant_ids: set[UUID]) -> list[Target]:
    """Active (variant, package) pairs of *vuln_id* within *variant_ids*, as the web UI resolves them.

    Like the web UI (``packages_current_by_variant``), a target's exact package (supplier included) must be
    in the variant's active SBOM and the vulnerability must be observed on it by one of the variant's active
    scans.
    """
    targets: dict[tuple[str, str], Target] = {}
    for entry in variant_active_packages(vuln_id):
        variant = db.session.get(Variant, UUID(entry["variant_id"]))
        if variant is None or variant.id not in variant_ids:
            continue
        active = set(entry["active_packages"])
        current = {str(finding_id) for finding_id in db.session.scalars(
            db.select(Observation.finding_id)
            .where(Observation.scan_id.in_(active_scan_ids_for_variant(variant.id)))
            .where(Observation.finding_id.in_([UUID(f["finding_id"]) for f in entry["findings"]])))}
        for finding in entry["findings"]:
            # "outdated" compares only (name, version); a supplier change must not keep the old package.
            if finding["package"] in active and finding["finding_id"] in current:
                targets.setdefault((entry["variant_id"], finding["package"]), Target(
                    entry["variant_id"], variant.name, str(variant.project_id),
                    finding["package"], finding["finding_id"]))
    return list(targets.values())


def build_prompts(vuln_id: str, targets: list[Target]) -> list[tuple[str, list[Target]]]:
    """Port of the web UI's ``buildAiAssessmentMessages``: whole variants per batch, under the message limit."""
    groups: dict[str, list[Target]] = {}
    for target in targets:
        groups.setdefault(target.variant_id, []).append(target)
    variant_groups = list(groups.values())
    lines = [f'- variant "{group[0].variant}" (variant_id {group[0].variant_id}): '
             + ", ".join(target.package for target in group) for group in variant_groups]

    def prompt(batch_lines: list[str], label: str = "") -> str:
        return (f"Assess {vuln_id}{label} for exactly these targets (packages listed per variant):\n"
                + "\n".join(batch_lines) + "\n"
                "Retrieve the vulnerability details and each variant's merged context with VulnScout MCP first, "
                "then record the result with write_assessment for these targets only.")

    oversized = [group[0].variant for group, line in zip(variant_groups, lines)
                 if len(prompt([line])) > PROMPT_BUDGET]
    if oversized:
        raise ValueError(f"Too many packages for variant {', '.join(oversized)} to assess in one request.")
    batches: list[list[int]] = []
    for index, line in enumerate(lines):
        if batches and len(prompt([lines[i] for i in batches[-1]] + [line])) <= PROMPT_BUDGET:
            batches[-1].append(index)
        else:
            batches.append([index])
    return [
        (prompt([lines[i] for i in batch], f" (batch {number} of {len(batches)})" if len(batches) > 1 else ""),
         [target for i in batch for target in variant_groups[i]])
        for number, batch in enumerate(batches, 1)
    ]


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
                    build_prompts(result.id, result.targets)
                except ValueError as exc:
                    result.outcome, result.error = "failed", str(exc)
    else:
        model = _run(results, model, timeout)
    _report(results, model, project_name, variants, as_json)
    if any(result.outcome in FAILING_OUTCOMES for result in results):
        raise SystemExit(1)


OUTSIDE_TURN = ("Write rejected: this assessment run may only write AI assessments for its listed targets "
                "and revise those its current turn wrote.")


class TurnTargets:
    """The vulnerability and (variant_id, package) targets the current agent turn may write.

    ``created`` holds the IDs of the AI assessments this turn wrote: the only rows it may revise.
    """

    def __init__(self) -> None:
        self.current: tuple[str, frozenset[tuple[str, str]]] | None = None
        self.created: set[str] = set()

    @contextmanager
    def allow(self, vuln_id: str, targets: list[Target]) -> Iterator[None]:
        self.current = (vuln_id, frozenset((target.variant_id, target.package) for target in targets))
        self.created = set()
        try:
            yield
        finally:
            self.current = None
            self.created = set()


def _write_target_pairs(payload: Any) -> list[tuple[Any, Any]]:
    """The (package, variant_id) pairs an assessment-create payload writes, read as the route reads them."""
    if not isinstance(payload, dict):
        return []
    targets = payload.get("targets")
    if targets is not None:
        if not isinstance(targets, list):
            return []
        return [(t.get("package"), t.get("variant_id")) if isinstance(t, dict) else (None, None) for t in targets]
    packages, variant_ids = payload.get("packages"), payload.get("variant_ids")
    if not (isinstance(variant_ids, list) and variant_ids):
        variant_ids = [payload.get("variant_id")]
    return [(p, v) for p in packages for v in variant_ids] if isinstance(packages, list) else []


def _turn_allows(turn: tuple[str, frozenset[tuple[str, str]]] | None, vuln_id: Any, payload: Any) -> bool:
    from ..routes._assessment_write import resolve_package

    pairs = _write_target_pairs(payload)
    if turn is None or vuln_id != turn[0] or not pairs:
        return False
    for package, variant_id in pairs:
        if not isinstance(package, str) or not isinstance(variant_id, str):
            return False
        try:
            variant = str(UUID(variant_id))
        except ValueError:
            return False
        # Compare canonical package IDs, so another spelling of a selected package is still accepted.
        resolved = resolve_package(package)
        if resolved is None or (variant, resolved.string_id) not in turn[1]:
            return False
    return True


def _turn_allows_update(turns: TurnTargets, assessment_id: Any) -> bool:
    """Whether the current turn wrote AI assessment *assessment_id* and all its targets are still the turn's."""
    from ..models.assessment import Assessment
    from ..models.assessment_target import AssessmentTarget

    turn = turns.current
    try:
        row_id = UUID(assessment_id)
    except (TypeError, ValueError):
        return False
    if turn is None or str(row_id) not in turns.created:
        return False
    # Lock the row and its targets until the update commits, so another writer cannot widen them in between.
    row = db.session.execute(
        db.select(Assessment).where(Assessment.id == row_id).with_for_update()).scalar_one_or_none()
    targets = db.session.execute(
        db.select(AssessmentTarget).where(AssessmentTarget.assessment_id == row_id).with_for_update()).scalars().all()
    return row is not None and row.origin == "ai" and bool(targets) and all(
        target.finding.vulnerability_id == turn[0]
        and (str(target.variant_id), target.finding.package.string_id) in turn[1] for target in targets)


@contextmanager
def _private_api() -> Iterator[tuple[str, list[str], TurnTargets]]:
    """Serve this app's API on an ephemeral loopback port for the agent's MCP server.

    Also yields the IDs of the assessments created through it, in order: only this run's agent uses
    this API, so they are exactly its writes, unlike rows the web agent or another run creates meanwhile.
    The API only accepts creating AI assessments on the targets of the current turn (see ``TurnTargets``)
    and revising the AI assessments that turn created while all their targets remain the turn's;
    every other write is rejected, whatever the agent asks.
    """
    written: list[str] = []
    turns = TurnTargets()

    def guard_write() -> Response | None:
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None
        if request.endpoint == "add_assessment" and _turn_allows(
                turns.current, (request.view_args or {}).get("vuln_id"), request.get_json(silent=True)):
            return None
        if request.endpoint == "update_assessment" and _turn_allows_update(
                turns, (request.view_args or {}).get("assessment_id")):
            return None
        return make_response({"error": OUTSIDE_TURN}, 403)

    def record_write(response: Response) -> None:
        if request.endpoint == "add_assessment" and response.status_code == 200:
            body = response.get_json(silent=True) or {}
            row_ids = [str(row["id"]) for row in body.get("assessments") or [] if row.get("id")]
            written.extend(row_ids)
            if turns.current is not None:
                turns.created.update(row_ids)

    with _ai_runner.private_api(guard_write, record_write) as url:
        yield url, written, turns


def _ai_targets(row_ids: list[str]) -> dict[str, set[tuple[str, str]]]:
    """Those of *row_ids* still saved as AI assessments -> their (variant_id, finding_id) targets.

    A later write in the same turn may have replaced or trimmed an earlier one.
    """
    from ..models.assessment import Assessment

    rows = {str(row.id): {(str(target.variant_id), str(target.finding_id)) for target in row.target_rows}
            for row in db.session.scalars(db.select(Assessment).where(
                Assessment.id.in_([UUID(row_id) for row_id in row_ids])))
            if row.origin == "ai"} if row_ids else {}
    # End the read transaction: the private API threads write while the agent runs.
    db.session.rollback()
    return rows


def _assess(result: Result, label: str, credentials, model: str, path, api_url: str, written: list[str],
            turns: TurnTargets, timeout: int) -> None:
    from ..routes import agent, agent_skills

    try:
        batches = build_prompts(result.id, result.targets)
    except ValueError as exc:
        result.outcome, result.error = "failed", str(exc)
        return
    errors: list[tuple[str, str]] = []
    for number, (prompt, batch) in enumerate(batches, 1):
        part = f", batch {number} of {len(batches)}" if len(batches) > 1 else ""
        echo(f"{label} Assessing {result.id} ({len(batch)} targets{part})...", err=True)
        start = len(written)
        scope = json.dumps({"project_ids": sorted({target.project_id for target in batch}),
                            "variant_ids": sorted({target.variant_id for target in batch}),
                            "write_targets": [{"vuln_id": result.id, "variant_id": target.variant_id,
                                               "package": target.package} for target in batch]},
                           separators=(",", ":"))
        interrupted = False
        try:
            with turns.allow(result.id, batch):
                reply, usage = asyncio.run(agent._reply(
                    agent.Conversation(credentials=credentials), prompt, path, model, scope,
                    profile=agent_skills.ASSESS, timeout=timeout, api_url=api_url, ephemeral=True))
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
            errors.append(("timeout", f"No reply within {timeout} s."))
        except Exception as exc:
            errors.append(("failed", str(exc) or type(exc).__name__))
        # A cleanup error raised while the turn was being cancelled replaces the KeyboardInterrupt.
        interrupted = interrupted or _ai_runner.interrupted.is_set()
        created = _ai_targets(written[start:])
        for target in batch:
            row_ids = sorted(row_id for row_id, pairs in created.items()
                             if (target.variant_id, target.finding_id) in pairs)
            if row_ids:
                result.written.add(target)
                result.assessment_ids[target] = row_ids
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
    with _private_api() as (api_url, written, turns):
        try:
            for number, result in enumerate(pending, 1):
                try:
                    _assess(result, f"[{number}/{len(pending)}]", credentials, selected, path, api_url, written,
                            turns, timeout)
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

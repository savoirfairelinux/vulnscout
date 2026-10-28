# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""``flask ai-assess``: assess selected vulnerabilities with the embedded AI agent."""

from __future__ import annotations

import contextlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

import click
from flask.cli import with_appcontext

from ..extensions import db
from ..helpers.active_scans import active_scan_ids_for_variant
from ..helpers.active_targets import variant_active_packages
from ..helpers.export_scope import compute_export_scope
from ..models.observation import Observation
from ..models.variant import Variant
from ._common import resolve_project_variant
from ._console import Command, echo
from .cmd_process import _condition_scope, _evaluate_condition_in_scope

CVE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*")
MESSAGE_LIMIT = 8000
PROMPT_BUDGET = MESSAGE_LIMIT - len(" (batch 9999 of 9999)")
FAILING_OUTCOMES = frozenset({"partial", "no_write", "failed", "timeout", "not_found", "interrupted"})
# Set by entrypoint.sh (cmd_ai_assess) so the host wrapper can forward Ctrl-C to this process.
PID_FILE_ENV = "VULNSCOUT_AI_ASSESS_PID_FILE"


@dataclass(frozen=True)
class Target:
    variant_id: str
    variant: str
    project_id: str
    package: str
    finding_id: str


def _empty_usage() -> dict[str, Any]:
    return {"cost": None, "input_tokens": None, "output_tokens": None}


@dataclass
class Result:
    id: str
    targets: list[Target]
    outcome: str = "pending"
    written: set[Target] = field(default_factory=set)
    replies: list[str] = field(default_factory=list)
    usage: dict[str, Any] = field(default_factory=_empty_usage)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "outcome": self.outcome,
            "targets": [{"variant_id": target.variant_id, "variant": target.variant,
                         "package": target.package, "written": target in self.written}
                        for target in self.targets],
            "reply": "\n\n".join(self.replies) or None,
            "usage": self.usage,
            "error": self.error,
        }


def active_targets(vuln_id: str, variant_ids: set[UUID]) -> list[Target]:
    """Active (variant, package) pairs of *vuln_id* within *variant_ids*, as the web UI resolves them.

    Like the web UI (``packages_current_by_variant``), a target's package must be in the variant's active
    SBOM and the vulnerability must be observed on it by one of the variant's active scans.
    """
    targets: dict[tuple[str, str], Target] = {}
    for entry in variant_active_packages(vuln_id):
        variant = db.session.get(Variant, UUID(entry["variant_id"]))
        if variant is None or variant.id not in variant_ids:
            continue
        current = {str(finding_id) for finding_id in db.session.scalars(
            db.select(Observation.finding_id)
            .where(Observation.scan_id.in_(active_scan_ids_for_variant(variant.id)))
            .where(Observation.finding_id.in_([UUID(f["finding_id"]) for f in entry["findings"]])))}
        for finding in entry["findings"]:
            if not finding["outdated"] and finding["finding_id"] in current:
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


def _select(scope, cve_ids: tuple[str, ...], condition: str | None) -> list[str]:
    if cve_ids:
        return list(dict.fromkeys(cve_ids))
    try:
        return _evaluate_condition_in_scope(scope, condition or "", quiet=True)
    except Exception as exc:  # ConditionParser raises bare Exception for invalid expressions.
        raise click.ClickException(f"Invalid filter: {exc}") from exc


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
        _ai_assess(project_name, variant_names, cve_ids, condition, model, timeout, dry_run, as_json)
    finally:
        _release_pid_file()


def _release_pid_file() -> None:
    """Remove the entrypoint's pidfile if it still names this process (it ``exec``s into flask)."""
    path = os.environ.get(PID_FILE_ENV)
    if not path:
        return
    with contextlib.suppress(OSError):
        if Path(path).read_text().strip() == str(os.getpid()):
            Path(path).unlink()


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
    scope = _scope(project_name, variants)
    results = [Result(vuln_id, active_targets(vuln_id, scope.variant_ids))
               for vuln_id in _select(scope, cve_ids, condition)]
    if condition:
        # The filter matches findings on in-scope packages, including ones seen only by older scans or
        # by another project sharing the package; only explicitly requested IDs report not_found.
        results = [result for result in results if result.targets]
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


def _run(results: list[Result], model: str | None, timeout: int) -> str:
    raise NotImplementedError  # Task 5

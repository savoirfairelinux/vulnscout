# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""``flask ai-review``: AI review of custom assessments, one ephemeral agent turn per target batch."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Any, Iterator
from uuid import UUID

import click
from flask.cli import with_appcontext

from ..controllers import ai_actions
# build_review_prompts is re-exported for the CLI tests.
from ..controllers.ai_actions import CVE_ID_PATTERN, TargetResult, build_review_prompts  # noqa: F401
from ..helpers.review_selection import ReviewSelection, select_by_cve, select_by_ids
from . import _ai_runner
from ..helpers.export_scope import compute_export_scope
from ._console import Command, _CommandError, echo

FAILING_TARGET_OUTCOMES = frozenset({"changed", "no_write", "failed", "timeout", "interrupted"})


@dataclass
class ReviewResult:
    selection: ReviewSelection
    targets: list[TargetResult]
    replies: list[str] = field(default_factory=list)
    usage: dict[str, Any] = field(default_factory=_ai_runner.empty_usage)

    @property
    def outcome(self) -> str:
        outcomes = {t.outcome for t in self.targets}
        if "planned" in outcomes and outcomes <= {"planned", "skipped_fresh"}:
            return "planned"
        if outcomes == {"skipped_fresh"}:
            return "skipped"
        if outcomes <= {"reviewed", "skipped_fresh"}:
            return "reviewed"
        return "partial" if "reviewed" in outcomes else "failed"

    def to_dict(self) -> dict[str, Any]:
        s = self.selection
        return {"assessment_id": str(s.assessment_id), "vuln_id": s.vuln_id, "outcome": self.outcome,
                "excluded_targets": s.excluded_targets, "targets": [t.to_dict() for t in self.targets],
                "reply": "\n\n".join(self.replies) or None, "usage": self.usage}


def _plan(result: ReviewResult, timeout: int) -> list[ai_actions.TurnSpec]:
    """One turn per variant of *result*'s pending targets; targets no turn covers are reported as changed."""
    by_variant: dict[UUID, list[TargetResult]] = {}
    for item in result.targets:
        if item.outcome == "pending":
            by_variant.setdefault(item.target.variant_id, []).append(item)
    specs: list[ai_actions.TurnSpec] = []
    for variant_id, items in by_variant.items():
        try:
            specs += ai_actions.plan_review(result.selection.assessment_id, variant_id,
                                            {item.target.finding_id for item in items}, per_variant=True)
        except ValueError:
            pass  # changed since the selection: reported below
    planned = {(t.variant_id, t.finding_id) for spec in specs for t in spec.review_targets}
    for items in by_variant.values():
        for item in items:
            if (item.target.variant_id, item.target.finding_id) not in planned:
                item.outcome, item.error = "changed", ai_actions.CHANGED
    # Pinned at selection, so an edit since then is reported as "changed".
    return [replace(spec, fingerprint=result.selection.fingerprint, timeout=timeout) for spec in specs]


def _fold(result: ReviewResult, turn: ai_actions.TurnResult) -> None:
    from ..routes import agent

    if turn["usage"] is not None:
        result.replies.append(turn["reply"])
        result.usage = agent._add_usage(result.usage, turn["usage"])
    items = {(item.target.variant_id, item.target.finding_id): item for item in result.targets}
    for target in turn["targets"]:
        item = items[(UUID(target["variant_id"]), UUID(target["finding_id"]))]
        item.outcome, item.review, item.error = target["outcome"], target["review"], target["error"]


def _run(results: list[ReviewResult], model: str | None, timeout: int) -> tuple[str | None, bool]:
    """Review every pending target; returns the model used and whether the run was interrupted."""
    pending = [r for r in results if any(t.outcome == "pending" for t in r.targets)]
    if not pending:
        return _ai_runner.configured_model(model), False
    owners: dict[int, tuple[ai_actions.TurnSpec, str, ReviewResult]] = {}

    def specs() -> Iterator[ai_actions.TurnSpec]:
        for number, result in enumerate(pending, 1):
            for spec in _plan(result, timeout):
                owners[id(spec)] = (spec, f"[{number}/{len(pending)}]", result)
                yield spec

    def on_start(spec: ai_actions.TurnSpec) -> None:
        _, label, result = owners[id(spec)]
        batch = spec.review_targets
        echo(f"{label} Reviewing {str(result.selection.assessment_id)[:8]}\u2026 {result.selection.vuln_id} "
             f"on {batch[0].variant} "
             f"({len(batch)} target{'s' if len(batch) != 1 else ''})...", err=True)

    # Run-level: an interrupt after the last turn saved its reviews leaves no failing target.
    selected, interrupted = _ai_runner.execute(specs(), model, on_start,
                                               lambda spec, turn: _fold(owners[id(spec)][2], turn))
    if interrupted:
        echo("Interrupted; reporting completed reviews.", role="warning", err=True)
        for result in pending:
            for item in result.targets:
                if item.outcome == "pending":
                    item.outcome, item.error = "interrupted", "Not started."
    return selected, interrupted


def _report(results: list[ReviewResult], model: str | None, scope: dict[str, Any], ignored: int,
            interrupted: bool, as_json: bool) -> None:
    targets = [t for r in results for t in r.targets]
    counts = {"reviewed": sum(t.outcome == "reviewed" for t in targets),
              "skipped": sum(t.outcome == "skipped_fresh" for t in targets),
              "failed": sum(t.outcome in FAILING_TARGET_OUTCOMES for t in targets)}
    if as_json:
        click.echo(json.dumps({"model": model, "scope": scope, "ignored_non_custom": ignored,
                               "interrupted": interrupted, "results": [r.to_dict() for r in results],
                               "counts": counts}, indent=2))
        return
    for r in results:
        done = sum(t.outcome in ("reviewed", "skipped_fresh") for t in r.targets)
        excluded = r.selection.excluded_targets
        outside = f"  ({excluded} target{'s' if excluded != 1 else ''} outside scope)" if excluded else ""
        echo(f"{r.selection.assessment_id}  {r.selection.vuln_id}  {r.outcome}  {done}/{len(r.targets)} targets"
             + outside,
             role="error" if r.outcome in ("partial", "failed") else "success")
        for t in r.targets:
            review = f"  {t.review['status']} ({t.review['verdict']})" if t.review else ""
            echo(f"    {t.target.variant} / {t.target.package}  {t.outcome}{review}"
                 + (f"  {t.error}" if t.error else ""),
                 role="error" if t.outcome in FAILING_TARGET_OUTCOMES else "info")
    if ignored:
        echo(f"Ignored {ignored} non-custom assessment(s).")
    echo(f"Reviewed {counts['reviewed']}, skipped {counts['skipped']}, failed {counts['failed']}.")
    if interrupted:
        echo("Interrupted.", role="error")
    if model:
        echo(f"Model: {model}")


class ReviewCommand(Command):
    """Report parser errors with exit code 1, like every other usage error of this command."""

    def make_context(self, *args: Any, **kwargs: Any) -> click.Context:
        try:
            return super().make_context(*args, **kwargs)
        except _CommandError as exc:
            setattr(exc, "exit_code", 1)
            raise


def _scope(project_name: str, variants: list[str]):
    """Resolve the review scope, reporting unknown projects and variants on stderr (stdout carries --json)."""
    from ..controllers.projects import ProjectController
    from ..models.variant import Variant

    project = ProjectController.get_by_name(project_name)
    if not project:
        raise click.ClickException(f"Project not found: {project_name}")
    if not variants:
        return compute_export_scope(project_id=project.id)
    variant_ids = []
    for name in variants:
        variant = Variant.get_by_name_and_project(name, project.id)
        if not variant:
            raise click.ClickException(f"Variant not found: {name}")
        variant_ids.append(variant.id)
    return compute_export_scope(variant_ids=variant_ids)


@click.command("ai-review", cls=ReviewCommand)
@click.option("--assessment-id", "assessment_ids", multiple=True,
              help="Custom assessment to review (repeatable); reviews all its targets.")
@click.option("--cve", "cve_ids", multiple=True, help="Review the custom assessments of this CVE (repeatable).")
@click.option("--project", "project_name", default=None, help="Project whose targets are reviewed (required).")
@click.option("--variant", "variant_names", multiple=True,
              help="Variant (repeatable, --cve only); default all of the project.")
@click.option("--re-review", is_flag=True, help="Also review targets whose review is still fresh.")
@click.option("--model", default=None, help="Model to use instead of AI_MODEL.")
@click.option("--timeout", type=click.IntRange(min=1), default=600, show_default=True,
              help="Seconds allowed for each agent turn.")
@click.option("--dry-run", is_flag=True, help="Show the selected targets without calling the AI.")
@click.option("--json", "as_json", is_flag=True, help="Print the summary as JSON on stdout.")
@with_appcontext
def ai_review_command(assessment_ids, cve_ids, project_name, variant_names, re_review, model, timeout,
                      dry_run, as_json):
    """Review custom assessments with the embedded AI agent; the assessments are never modified."""
    try:
        with _ai_runner.interrupt_signals():
            _ai_review(assessment_ids, cve_ids, project_name, variant_names, re_review, model, timeout,
                       dry_run, as_json)
    finally:
        _ai_runner.release_pid_file()


def _ai_review(assessment_ids, cve_ids, project_name, variant_names, re_review, model, timeout, dry_run,
               as_json):
    if not project_name:
        raise click.ClickException("--project is required.")
    if bool(assessment_ids) == bool(cve_ids):
        raise click.ClickException("Use exactly one of --assessment-id or --cve.")
    variants = list(dict.fromkeys(variant_names))
    if assessment_ids and variants:
        raise click.ClickException(
            "--variant cannot be used with --assessment-id, which reviews every target in the project.")
    ids: list[UUID] = []
    for raw in assessment_ids:
        try:
            ids.append(UUID(raw))
        except ValueError:
            raise click.ClickException(f"Invalid assessment ID: {raw}") from None
    invalid = [cve for cve in cve_ids if not CVE_ID_PATTERN.fullmatch(cve)]
    if invalid:
        raise click.ClickException(f"Invalid vulnerability ID: {invalid[0]}")
    scope = _scope(project_name, variants)
    variant_ids = set(scope.variant_ids)
    label = f"project {project_name} " + (f"(variants: {', '.join(variants)})" if variants else "(all variants)")
    report_scope = {"project": project_name, "variants": variants or None}
    ignored = 0
    if ids:
        selections, errors = select_by_ids(ids, variant_ids, label)
    else:
        selections, ignored, errors = select_by_cve(list(cve_ids), variant_ids, label)
    if errors:
        for message in errors:
            echo(message, role="error", err=True)
        raise SystemExit(1)
    results = [ReviewResult(s, [TargetResult(t, "skipped_fresh" if t.review_state == "fresh" and not re_review
                                             else ("planned" if dry_run else "pending"))
                                for t in s.targets]) for s in selections]
    interrupted = False
    if dry_run:
        model = _ai_runner.configured_model(model)
    else:
        model, interrupted = _run(results, model, timeout)
    _report(results, model, report_scope, ignored, interrupted, as_json)
    if interrupted or any(t.outcome in FAILING_TARGET_OUTCOMES for r in results for t in r.targets):
        raise SystemExit(1)

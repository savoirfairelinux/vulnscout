# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""``flask ai-review``: AI review of custom assessments, one ephemeral agent turn per target batch."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import click
from flask.cli import with_appcontext

from ..helpers.review_selection import ReviewSelection, ReviewTarget, select_by_cve, select_by_ids
from . import _ai_runner
from ._console import Command, echo
from .cmd_ai_assess import CVE_ID_PATTERN, _scope

FAILING_TARGET_OUTCOMES = frozenset({"changed", "no_write", "failed", "timeout", "interrupted"})


@dataclass
class TargetResult:
    target: ReviewTarget
    outcome: str = "pending"
    review: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        t = self.target
        return {"variant_id": str(t.variant_id), "variant": t.variant, "project_id": str(t.project_id),
                "package": t.package, "outcome": self.outcome, "review": self.review, "error": self.error}


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


def _run(results: list[ReviewResult], model: str | None, timeout: int) -> str | None:
    """Review every pending target; returns the model used."""
    if not any(t.outcome == "pending" for r in results for t in r.targets):
        return _ai_runner.configured_model(model)
    raise NotImplementedError


def _report(results: list[ReviewResult], model: str | None, scope: dict[str, Any], ignored: int,
            as_json: bool) -> None:
    targets = [t for r in results for t in r.targets]
    counts = {"reviewed": sum(t.outcome == "reviewed" for t in targets),
              "skipped": sum(t.outcome == "skipped_fresh" for t in targets),
              "failed": sum(t.outcome in FAILING_TARGET_OUTCOMES for t in targets)}
    if as_json:
        click.echo(json.dumps({"model": model, "scope": scope, "ignored_non_custom": ignored,
                               "results": [r.to_dict() for r in results], "counts": counts}, indent=2))
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
    if model:
        echo(f"Model: {model}")


@click.command("ai-review", cls=Command)
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
    if dry_run:
        model = _ai_runner.configured_model(model)
    else:
        model = _run(results, model, timeout)
    _report(results, model, report_scope, ignored, as_json)
    if any(t.outcome in FAILING_TARGET_OUTCOMES for r in results for t in r.targets):
        raise SystemExit(1)

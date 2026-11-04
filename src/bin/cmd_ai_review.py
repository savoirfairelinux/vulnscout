# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""``flask ai-review``: AI review of custom assessments, one ephemeral agent turn per target batch."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import click
from flask import Response, make_response, request
from flask.cli import with_appcontext

from ..helpers.env_vars import get_bool_env
from ..helpers.review_selection import ReviewSelection, ReviewTarget, select_by_cve, select_by_ids
from . import _ai_runner
from ..helpers.export_scope import compute_export_scope
from ._console import Command, _CommandError, echo
from .cmd_ai_assess import CVE_ID_PATTERN, MESSAGE_LIMIT

FAILING_TARGET_OUTCOMES = frozenset({"changed", "no_write", "failed", "timeout", "interrupted"})
OUTSIDE_RUN = "Write rejected: this review run may only save reviews for its listed targets."
PROMPT_BUDGET = MESSAGE_LIMIT - len(" (batch 9999 of 9999)")  # module-level so tests can shrink it
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


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


class ReviewTurn:
    """Write policy and record of the current turn, shared with the private API threads."""

    def __init__(self) -> None:
        self.armed: tuple[ReviewSelection, list[ReviewTarget]] | None = None
        self.saved: set[tuple[str, str, str]] = set()  # (assessment_id, variant_id, package) answered 200
        self.rejections: list[str] = []

    def arm(self, selection: ReviewSelection, batch: list[ReviewTarget]) -> None:
        self.armed, self.saved, self.rejections = (selection, batch), set(), []

    def disarm(self) -> None:
        self.armed = None

    def guard(self) -> Response | None:
        if request.method in SAFE_METHODS:
            return None
        armed = self.armed
        if request.endpoint == "put_assessment_review" and armed is not None:
            selection, batch = armed
            body = request.get_json(silent=True)
            body = body if isinstance(body, dict) else {}
            assessment_id = str((request.view_args or {}).get("assessment_id", "")).lower()
            if assessment_id == str(selection.assessment_id) and any(_lists(t, body) for t in batch):
                if body.get("expected_assessment_fingerprint") != selection.fingerprint:
                    return make_response({"error": "The assessment changed since this run selected it.",
                                          "code": "assessment_changed"}, 409)
                return None
        return make_response({"error": OUTSIDE_RUN}, 403)

    def record(self, response: Response) -> None:
        if request.method in SAFE_METHODS:
            return
        body = response.get_json(silent=True)
        body = body if isinstance(body, dict) else {}
        if request.endpoint == "put_assessment_review" and response.status_code == 200:
            review = body.get("review") or {}
            self.saved.add((str(review.get("assessment_id", "")).lower(), str(review.get("variant_id", "")).lower(),
                            review.get("package", "")))
        elif response.status_code >= 400:
            self.rejections.append(body.get("error") or f"HTTP {response.status_code}")


def _lists(target: ReviewTarget, body: dict[str, Any]) -> bool:
    """Whether a review body names *target*: its variant, plus finding_id and/or package (both must match)."""
    if str(body.get("variant_id", "")).lower() != str(target.variant_id):
        return False
    finding_id, package = body.get("finding_id"), body.get("package")
    if not finding_id and not package:
        return False
    return ((not finding_id or str(finding_id).lower() == str(target.finding_id))
            and (not package or package == target.package))


def build_review_prompts(selection: ReviewSelection, targets: list[ReviewTarget]
                         ) -> list[tuple[str, list[ReviewTarget]]]:
    """One variant's targets -> prompts under PROMPT_BUDGET, splitting packages into batches."""
    def prompt(batch: list[ReviewTarget]) -> str:
        lines = "\n".join(f"- variant {t.variant} ({t.variant_id}), package {t.package} (finding {t.finding_id})"
                          for t in batch)
        return (f"Review the user assessment {selection.assessment_id} for {selection.vuln_id}. Retrieve it with "
                f"get_custom_assessment, independently re-derive the verdict for each of the targets below using "
                f"VulnScout MCP data, and record one review per target with write_assessment_review, passing "
                f"expected_assessment_fingerprint=`{selection.fingerprint}`. Review only these targets. These "
                f"targets were selected for review: write a review for each even if one already exists. Do not "
                f"modify the assessment itself.\n{lines}")

    batches: list[list[ReviewTarget]] = []
    for target in targets:
        if batches and len(prompt(batches[-1] + [target])) <= PROMPT_BUDGET:
            batches[-1].append(target)
        else:
            batches.append([target])
    if len(batches) == 1:
        return [(prompt(batches[0]), batches[0])]
    return [(prompt(b) + f" (batch {n} of {len(batches)})", b) for n, b in enumerate(batches, 1)]


def _verify(selection: ReviewSelection, batch: list[TargetResult], turn: ReviewTurn,
            error: tuple[str, str] | None, interrupted: bool) -> None:
    """Set each target's outcome from what the database holds after its turn, not from the agent's reply."""
    from ..extensions import db
    from ..models.assessment import Assessment
    from ..models.assessment_review import AssessmentReview, fingerprint_assessment

    db.session.expire_all()
    assessment = Assessment.get_by_id(selection.assessment_id)
    current = (assessment is not None and assessment.origin == "custom"
               and fingerprint_assessment(assessment) == selection.fingerprint)
    pairs = set(assessment.targets) if assessment is not None else set()
    for item in batch:
        t = item.target
        review = AssessmentReview.get_for_target(t.assessment_id, t.variant_id, t.finding_id) if current else None
        if not current or (t.variant_id, t.finding_id) not in pairs:
            item.outcome, item.error = "changed", "The assessment changed during the review; run it again."
        elif review is not None and (str(t.assessment_id), str(t.variant_id), t.package) in turn.saved \
                and review.reviewed_fingerprint == selection.fingerprint:
            item.outcome, item.review = "reviewed", {"id": str(review.id), "status": review.status,
                                                     "verdict": review.verdict()}
        elif interrupted:
            item.outcome, item.error = "interrupted", "Interrupted."
        elif error is not None:
            item.outcome, item.error = error
        else:
            item.outcome = "no_write"
            item.error = turn.rejections[-1] if turn.rejections else "The agent saved no review for this target."
    db.session.rollback()  # end the read transaction: the private API threads write during the next turn


def _review(result: ReviewResult, label: str, credentials, model: str, path, api_url: str, turn: ReviewTurn,
            timeout: int) -> None:
    from ..routes import agent, agent_skills

    by_variant: dict[UUID, list[TargetResult]] = {}
    for item in result.targets:
        if item.outcome == "pending":
            by_variant.setdefault(item.target.variant_id, []).append(item)
    for items in by_variant.values():
        lookup = {item.target: item for item in items}
        for prompt, batch in build_review_prompts(result.selection, [item.target for item in items]):
            echo(f"{label} Reviewing {str(result.selection.assessment_id)[:8]}\u2026 {result.selection.vuln_id} "
                 f"on {batch[0].variant} "
                 f"({len(batch)} target{'s' if len(batch) != 1 else ''})...", err=True)
            review_targets = [{"assessment_id": str(t.assessment_id), "variant_id": str(t.variant_id),
                               "package": t.package, "finding_id": str(t.finding_id)} for t in batch]
            scope = json.dumps({"project_ids": [str(batch[0].project_id)],
                                "variant_ids": [str(batch[0].variant_id)], "review_targets": review_targets},
                               separators=(",", ":"))
            error: tuple[str, str] | None = None
            interrupted = False
            turn.arm(result.selection, batch)
            try:
                reply, usage = asyncio.run(agent._reply(
                    agent.Conversation(credentials=credentials), prompt, path, model, scope,
                    profile=agent_skills.REVIEW, timeout=timeout, api_url=api_url, ephemeral=True))
                result.replies.append(reply)
                result.usage = agent._add_usage(result.usage, usage)
            except (agent.UnavailableModelError, agent_skills.AgentSkillError):
                raise
            except KeyboardInterrupt:
                # SIGINT forwarded by the host wrapper: asyncio.run cancels the turn.
                interrupted = True
            except asyncio.TimeoutError:
                error = ("timeout", f"No reply within {timeout} s.")
            except Exception as exc:
                error = ("failed", str(exc) or type(exc).__name__)
            finally:
                turn.disarm()
            # A cleanup error raised while the turn was being cancelled replaces the KeyboardInterrupt.
            interrupted = interrupted or _ai_runner.interrupted.is_set()
            _verify(result.selection, [lookup[t] for t in batch], turn, error, interrupted)
            if interrupted:
                raise KeyboardInterrupt


def _run(results: list[ReviewResult], model: str | None, timeout: int) -> str | None:
    """Review every pending target; returns the model used."""
    from ..routes import agent, agent_skills

    pending = [r for r in results if any(t.outcome == "pending" for t in r.targets)]
    if not pending:
        return _ai_runner.configured_model(model)
    credentials, selected, path = _ai_runner.load_agent(model)
    if not get_bool_env("VERBOSE_MODE"):
        # The SDK logs every failed request with a traceback; the summary already reports the error.
        logging.getLogger("copilot").setLevel(logging.ERROR)
    if credentials.token and not credentials.provider:
        _ai_runner.check_github_sign_in(credentials.token)
    turn = ReviewTurn()
    with _ai_runner.private_api(turn.guard, turn.record) as api_url:
        try:
            for number, result in enumerate(pending, 1):
                _review(result, f"[{number}/{len(pending)}]", credentials, selected, path, api_url, turn, timeout)
                if _ai_runner.interrupted.is_set():
                    raise KeyboardInterrupt
        except KeyboardInterrupt:
            echo("Interrupted; reporting completed reviews.", role="warning", err=True)
            for result in pending:
                for item in result.targets:
                    if item.outcome == "pending":
                        item.outcome, item.error = "interrupted", "Not started."
        except (agent.UnavailableModelError, agent_skills.AgentSkillError) as exc:
            raise click.ClickException(str(exc)) from exc
    return selected


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
    if dry_run:
        model = _ai_runner.configured_model(model)
    else:
        model = _run(results, model, timeout)
    _report(results, model, report_scope, ignored, as_json)
    if any(t.outcome in FAILING_TARGET_OUTCOMES for r in results for t in r.targets):
        raise SystemExit(1)

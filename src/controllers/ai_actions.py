# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""AI actions (assess, review) shared by the CLI commands and the agent queue.

An action is planned into ``TurnSpec`` s, one per agent turn (``plan_assess``, ``plan_review``). Each
spec is prepared just before its turn (``prepare``), run through a ``GuardedApi`` armed with the
turn's guard (``run_turn``), and checked against the database afterwards (``verify``): the outcome
never relies on the agent's reply.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, Literal, Union
from uuid import UUID

from flask import Response, make_response, request

from ..extensions import db
from ..helpers.active_scans import active_scan_ids_for_variant
from ..helpers.active_targets import variant_active_packages
from ..helpers.review_selection import ReviewSelection, ReviewTarget, _selection
from ..models.observation import Observation
from ..models.variant import Variant

if TYPE_CHECKING:
    from pathlib import Path

    from ..routes import agent
    from ..routes.agent_skills import AgentProfile
    from .guarded_api import GuardedApi

CVE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*")
MESSAGE_LIMIT = 8000
PROMPT_BUDGET = MESSAGE_LIMIT - len(" (batch 9999 of 9999)")  # module-level so tests can shrink it
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
OUTSIDE_TURN = ("Write rejected: this assessment run may only write AI assessments for its listed targets "
                "and revise those its current turn wrote.")
OUTSIDE_RUN = "Write rejected: this review run may only save reviews for its listed targets."
CHANGED = "The assessment changed during the review; run it again."

# JSON-able outcome of one turn, as stored by the agent queue (see ``verify``).
TurnResult = dict[str, Any]


# ---------------------------------------------------------------- assess: targets and prompts

@dataclass(frozen=True)
class Target:
    variant_id: str
    variant: str
    project_id: str
    package: str
    finding_id: str


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


# ---------------------------------------------------------------- assess: write guard

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


def _turn_allows_update(turns: AssessGuard, assessment_id: Any) -> bool:
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


class AssessGuard:
    """The vulnerability and (variant_id, package) targets one assess turn may write (a ``TurnGuard``).

    It accepts only creating AI assessments on the turn's targets and revising the AI assessments this
    turn created (``created``) while all their targets remain the turn's; every other write is rejected,
    whatever the agent asks. ``written`` lists the IDs of the assessments created through it, in order:
    only this turn's agent uses its API, so they are exactly its writes, unlike rows the web agent or
    another run creates meanwhile.
    """

    def __init__(self, vuln_id: str, targets: Iterable[Target]) -> None:
        self.current: tuple[str, frozenset[tuple[str, str]]] | None = (
            vuln_id, frozenset((target.variant_id, target.package) for target in targets))
        self.created: set[str] = set()
        self.written: list[str] = []

    def allow(self) -> Response | None:
        if request.method in SAFE_METHODS:
            return None
        if request.endpoint == "add_assessment" and _turn_allows(
                self.current, (request.view_args or {}).get("vuln_id"), request.get_json(silent=True)):
            return None
        if request.endpoint == "update_assessment" and _turn_allows_update(
                self, (request.view_args or {}).get("assessment_id")):
            return None
        return make_response({"error": OUTSIDE_TURN}, 403)

    def record(self, response: Response) -> None:
        if request.endpoint == "add_assessment" and response.status_code == 200:
            body = response.get_json(silent=True) or {}
            row_ids = [str(row["id"]) for row in body.get("assessments") or [] if row.get("id")]
            self.written.extend(row_ids)
            self.created.update(row_ids)


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


# ---------------------------------------------------------------- review: guard, prompts, verification

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


class ReviewGuard(ReviewTurn):
    """A ``ReviewTurn`` armed for one turn's (selection, batch), as a ``TurnGuard``."""

    def __init__(self, selection: ReviewSelection, batch: list[ReviewTarget]) -> None:
        super().__init__()
        self.selection, self.batch = selection, batch
        self.arm(selection, batch)

    def allow(self) -> Response | None:
        return self.guard()


def _lists(target: ReviewTarget, body: dict[str, Any]) -> bool:
    """Whether a review body names *target*: its variant, plus finding_id and/or package (both must match)."""
    if str(body.get("variant_id", "")).lower() != str(target.variant_id):
        return False
    finding_id, package = body.get("finding_id"), body.get("package")
    if not finding_id and not package:
        return False
    return ((not finding_id or str(finding_id).lower() == str(target.finding_id))
            and (not package or package == target.package))


def _review_prompt(selection: ReviewSelection, batch: list[ReviewTarget]) -> str:
    lines = "\n".join(f"- variant {t.variant} ({t.variant_id}), package {t.package} (finding {t.finding_id})"
                      for t in batch)
    return (f"Review the user assessment {selection.assessment_id} for {selection.vuln_id}. Retrieve it with "
            f"get_custom_assessment, independently re-derive the verdict for each of the targets below using "
            f"VulnScout MCP data, and record one review per target with write_assessment_review, passing "
            f"expected_assessment_fingerprint=`{selection.fingerprint}`. Review only these targets. These "
            f"targets were selected for review: write a review for each even if one already exists. Do not "
            f"modify the assessment itself.\n{lines}")


def build_review_prompts(selection: ReviewSelection, targets: list[ReviewTarget]
                         ) -> list[tuple[str, list[ReviewTarget]]]:
    """Targets -> prompts under PROMPT_BUDGET, splitting packages into batches."""
    batches: list[list[ReviewTarget]] = []
    for target in targets:
        if batches and len(_review_prompt(selection, batches[-1] + [target])) <= PROMPT_BUDGET:
            batches[-1].append(target)
        else:
            batches.append([target])
    if len(batches) == 1:
        return [(_review_prompt(selection, batches[0]), batches[0])]
    return [(_review_prompt(selection, b) + f" (batch {n} of {len(batches)})", b) for n, b in enumerate(batches, 1)]


def _verify(selection: ReviewSelection, batch: list[TargetResult], turn: ReviewTurn,
            error: tuple[str, str] | None, interrupted: bool) -> None:
    """Set each target's outcome from what the database holds after its turn, not from the agent's reply."""
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
            item.outcome, item.error = "changed", CHANGED
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


# ---------------------------------------------------------------- turns

def _action_timeout() -> int:
    from ..routes import agent_skills

    return agent_skills.ACTION_TIMEOUT


@dataclass(frozen=True)
class TurnSpec:
    """One planned agent turn of an action; JSON-free but hashable and safe to keep while queued."""

    kind: Literal["assess", "review"]
    key: str
    title: str
    detail: str
    vuln_id: str
    batch: tuple[int, int] | None  # (number, total) when split
    assess_targets: tuple[Target, ...] = ()
    assessment_id: UUID | None = None
    review_targets: tuple[ReviewTarget, ...] = ()
    fingerprint: str | None = None  # review: pinned by the caller; None pins it in prepare (A3)
    prompt: str = ""  # assess: final; review: rebuilt by prepare
    timeout: int = field(default_factory=_action_timeout)


@dataclass
class PreparedTurn:
    spec: TurnSpec
    prompt: str
    scope: str  # VULNSCOUT_AGENT_SCOPE JSON (project_ids, variant_ids, write/review targets)
    profile: AgentProfile
    guard: Union[AssessGuard, ReviewGuard]
    fingerprint: str | None  # review: pinned at prepare unless the spec pins it


def _unique(values: Iterable[str]) -> str:
    return ", ".join(dict.fromkeys(values))


def _batch_label(number: int, total: int) -> tuple[int, int] | None:
    return (number, total) if total > 1 else None


def plan_assess(vuln_id: str, targets: list[Target], key: str | None = None) -> list[TurnSpec]:
    """Turns assessing *targets*; raises ValueError when there are none or a variant cannot fit one prompt."""
    if not targets:
        raise ValueError(f"No active assessment targets for {vuln_id}.")
    batches = build_prompts(vuln_id, targets)
    # The web UI's assessmentKey: one key for every batch of the action.
    key = key or f"assess:{vuln_id}:" + ",".join(sorted(f"{t.variant_id}|{t.package}" for t in targets))
    specs = []
    for number, (prompt, batch) in enumerate(batches, 1):
        part = f" · batch {number} of {len(batches)}" if len(batches) > 1 else ""
        specs.append(TurnSpec(
            kind="assess", key=key, title=f"{vuln_id} · {len(batch)} target{'' if len(batch) == 1 else 's'}{part}",
            detail=f"{_unique(t.variant for t in batch)} · {_unique(t.package for t in batch)}",
            vuln_id=vuln_id, batch=_batch_label(number, len(batches)), assess_targets=tuple(batch), prompt=prompt))
    return specs


def resolve_assess_targets(vuln_id: str, pairs: list[dict] | None, variant_ids: set[UUID]) -> list[Target]:
    """The active targets named by *pairs* ({variant_id, package}), or all those of *variant_ids* when None.

    Packages are compared by canonical ID, so another spelling of an active package is accepted. Raises
    ValueError for malformed pairs, variants outside *variant_ids*, and pairs that are not active targets.
    """
    if pairs is None:
        return active_targets(vuln_id, variant_ids)
    from ..routes._assessment_write import resolve_package

    if not isinstance(pairs, list) or not pairs:
        raise ValueError("targets must be a non-empty list of {variant_id, package}.")
    wanted: list[tuple[str, str]] = []
    for pair in pairs:
        variant, package = (pair.get("variant_id"), pair.get("package")) if isinstance(pair, dict) else (None, None)
        if not isinstance(variant, str) or not isinstance(package, str):
            raise ValueError("Each target needs a variant_id and a package.")
        try:
            variant_id = UUID(variant)
        except ValueError:
            raise ValueError(f"Invalid variant ID: {variant}") from None
        if variant_id not in variant_ids:
            raise ValueError(f"Variant {variant_id} is not in scope.")
        resolved = resolve_package(package)
        if resolved is None:
            raise ValueError(f"Package not found: {package}")
        wanted.append((str(variant_id), resolved.string_id))
    active = {(t.variant_id, t.package): t for t in active_targets(vuln_id, {UUID(v) for v, _ in wanted})}
    for variant, package in wanted:
        if (variant, package) not in active:
            raise ValueError(f"{package} on variant {variant} is not an active target of {vuln_id}.")
    return list(dict.fromkeys(active[pair] for pair in wanted))


def plan_review(assessment_id: UUID, variant_id: UUID | None = None, finding_ids: set[UUID] | None = None,
                key: str | None = None, per_variant: bool = False) -> list[TurnSpec]:
    """Turns reviewing the targets of custom assessment *assessment_id*.

    Optionally restricted to *variant_id* and *finding_ids*. Without *per_variant* (web) every target
    goes in one prompt, split only past PROMPT_BUDGET; with it (CLI) each variant gets its own turns.
    Raises ValueError for unknown or non-custom assessments, no target left, or targets in several projects.
    """
    from ..models.assessment import Assessment

    assessment = Assessment.get_by_id(assessment_id)
    if assessment is None:
        raise ValueError(f"Assessment {assessment_id} not found.")
    if assessment.origin != "custom":
        raise ValueError(f"Assessment {assessment_id} has origin '{assessment.origin}'; "
                         "only custom assessments can be reviewed.")
    variant_ids = {row.variant_id for row in assessment.target_rows} if variant_id is None else {variant_id}
    selection = _selection(assessment, variant_ids)
    targets = [t for t in selection.targets if finding_ids is None or t.finding_id in finding_ids]
    if not targets:
        raise ValueError(f"Assessment {assessment_id} has no target to review.")
    if len({t.project_id for t in targets}) > 1:
        raise ValueError(f"Assessment {assessment_id} targets more than one project.")
    groups: dict[UUID | None, list[ReviewTarget]] = {}
    for target in targets:
        groups.setdefault(target.variant_id if per_variant else None, []).append(target)
    specs = []
    for group_variant, group in groups.items():
        group_key = key or f"review:{assessment_id}" + (f":{group_variant}" if group_variant else "")
        batches = build_review_prompts(selection, group)
        for number, (prompt, batch) in enumerate(batches, 1):
            specs.append(TurnSpec(
                kind="review", key=group_key, title=f"assessment {str(assessment_id)[:8]}",
                detail=" · ".join([selection.vuln_id, *dict.fromkeys(t.package for t in batch)]),
                vuln_id=selection.vuln_id, batch=_batch_label(number, len(batches)),
                assessment_id=assessment.id, review_targets=tuple(batch), prompt=prompt))
    return specs


def _review_selection(spec: TurnSpec) -> ReviewSelection:
    """The spec's targets with the fingerprint pinned now, unless the spec pins one."""
    from ..models.assessment import Assessment

    assert spec.assessment_id is not None
    if spec.fingerprint is not None:
        return ReviewSelection(spec.assessment_id, spec.vuln_id, spec.fingerprint, list(spec.review_targets))
    assessment = Assessment.get_by_id(spec.assessment_id)
    if assessment is None or assessment.origin != "custom":
        raise ValueError(f"Assessment {spec.assessment_id} is no longer a reviewable custom assessment.")
    wanted = {(t.variant_id, t.finding_id) for t in spec.review_targets}
    current = _selection(assessment, {t.variant_id for t in spec.review_targets})
    targets = [t for t in current.targets if (t.variant_id, t.finding_id) in wanted]
    if not targets:
        raise ValueError(f"Assessment {spec.assessment_id} no longer has any of the targets to review.")
    return ReviewSelection(current.assessment_id, current.vuln_id, current.fingerprint, targets)


def prepare(spec: TurnSpec) -> PreparedTurn:
    """The prompt, agent scope and guard of *spec*'s turn, right before it runs.

    A review re-selects its targets that are still the assessment's and pins the assessment fingerprint
    now (unless the spec pins it), so a queued review judges the latest content. Raises ValueError when
    a review has nothing left to review.
    """
    from ..routes import agent_skills

    if spec.kind == "assess":
        batch = list(spec.assess_targets)
        scope = json.dumps({"project_ids": sorted({target.project_id for target in batch}),
                            "variant_ids": sorted({target.variant_id for target in batch}),
                            "write_targets": [{"vuln_id": spec.vuln_id, "variant_id": target.variant_id,
                                               "package": target.package} for target in batch]},
                           separators=(",", ":"))
        return PreparedTurn(spec, spec.prompt, scope, agent_skills.ASSESS, AssessGuard(spec.vuln_id, batch), None)
    selection = _review_selection(spec)
    targets = selection.targets
    prompt = _review_prompt(selection, targets) + (f" (batch {spec.batch[0]} of {spec.batch[1]})" if spec.batch else "")
    review_targets = [{"assessment_id": str(t.assessment_id), "variant_id": str(t.variant_id),
                       "package": t.package, "finding_id": str(t.finding_id)} for t in targets]
    scope = json.dumps({"project_ids": sorted({str(t.project_id) for t in targets}),
                        "variant_ids": sorted({str(t.variant_id) for t in targets}),
                        "review_targets": review_targets}, separators=(",", ":"))
    return PreparedTurn(spec, prompt, scope, agent_skills.REVIEW, ReviewGuard(selection, targets),
                        selection.fingerprint)


async def run_turn(turn: PreparedTurn, conversation: agent.Conversation, model: str, path: Path,
                   api: GuardedApi, publish=None, ephemeral: bool = True,
                   on_session=None) -> tuple[str, dict]:
    """Run *turn* as one agent turn whose writes go through *api*, armed with the turn's guard.

    *on_session* receives the SDK session ID as soon as the session exists.
    """
    from ..routes import agent

    api.arm(turn.guard)
    try:
        return await agent._reply(conversation, turn.prompt, path, model, turn.scope, publish,
                                  profile=turn.profile, timeout=turn.spec.timeout, api_url=api.url,
                                  ephemeral=ephemeral, on_session=on_session)
    finally:
        api.arm(None)


def verify(turn: PreparedTurn, error: tuple[str, str] | None, interrupted: bool,
           reply: str | None = None, usage: dict | None = None) -> TurnResult:
    """The turn's outcome from what the database holds after it, not from the agent's reply.

    *error* is ``(outcome, message)`` when the turn failed (``"failed"``, ``"timeout"``); *interrupted*
    when it was stopped.
    """
    if isinstance(turn.guard, AssessGuard):
        return _verify_assess(turn.spec, turn.guard, error, interrupted, reply, usage)
    return _verify_review(turn.guard, error, interrupted, reply, usage)


def _verify_assess(spec: TurnSpec, guard: AssessGuard, error: tuple[str, str] | None, interrupted: bool,
                   reply: str | None, usage: dict | None) -> TurnResult:
    created = _ai_targets(guard.written)
    targets: list[dict[str, Any]] = []
    for target in spec.assess_targets:
        row_ids = sorted(row_id for row_id, pairs in created.items() if (target.variant_id, target.finding_id) in pairs)
        targets.append({"variant_id": target.variant_id, "variant": target.variant, "package": target.package,
                        "written": bool(row_ids), "assessment_ids": row_ids})
    message: str | None = None
    if interrupted:
        outcome, message = "interrupted", "Interrupted."
    elif error is not None:
        outcome, message = error
    else:
        written = sum(target["written"] for target in targets)
        outcome = "assessed" if written == len(targets) else ("partial" if written else "no_write")
    return {"outcome": outcome, "targets": targets, "reply": reply, "usage": usage, "error": message}


def _verify_review(guard: ReviewGuard, error: tuple[str, str] | None, interrupted: bool,
                   reply: str | None, usage: dict | None) -> TurnResult:
    items = [TargetResult(target) for target in guard.batch]
    _verify(guard.selection, items, guard, error, interrupted)
    outcomes = {item.outcome for item in items}
    if outcomes == {"reviewed"}:
        outcome = "reviewed"
    elif interrupted:
        outcome = "interrupted"
    elif error is not None:
        outcome = error[0]
    else:
        outcome = "changed" if "changed" in outcomes else "no_write"
    return {"outcome": outcome,
            "targets": [{**item.to_dict(), "finding_id": str(item.target.finding_id)} for item in items],
            "reply": reply, "usage": usage}

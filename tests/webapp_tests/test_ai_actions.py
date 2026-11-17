# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""The AI action domain shared by the CLI and the agent queue: planning, prepare, run_turn, verify."""

import asyncio
import json
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

from src.extensions import db as _db
from ..cli_tests.test_cmd_ai_assess import _seed, app  # noqa: F401


@pytest.fixture()
def ctx(app):  # noqa: F811
    with app.app_context():
        ids = _seed()
        yield ids


def _custom(ids, pairs, origin="custom"):
    from src.models.assessment import Assessment

    assessment = Assessment.create(status="not_affected", origin=origin, targets=[
        (uuid.UUID(ids[variant]), uuid.UUID(ids["findings"][package])) for variant, package in pairs])
    _db.session.commit()
    return assessment


def _fingerprint(assessment):
    from src.models.assessment_review import fingerprint_assessment

    return fingerprint_assessment(assessment)


# ---------------------------------------------------------------- assess planning


def test_plan_assess_uses_the_web_key_titles_and_batches(ctx, monkeypatch):
    from src.controllers import ai_actions

    targets = ai_actions.active_targets("CVE-2024-0001", {uuid.UUID(ctx["x86"]), uuid.UUID(ctx["arm"])})
    [spec] = ai_actions.plan_assess("CVE-2024-0001", targets)
    pairs = sorted(f"{t.variant_id}|{t.package}" for t in targets)
    assert spec.key == "assess:CVE-2024-0001:" + ",".join(pairs)
    assert spec.kind == "assess" and spec.batch is None and spec.title == "CVE-2024-0001 · 3 targets"
    assert spec.prompt == ai_actions.build_prompts("CVE-2024-0001", targets)[0][0]
    assert ai_actions.plan_assess("CVE-2024-0001", targets, key="k")[0].key == "k"

    monkeypatch.setattr(ai_actions, "PROMPT_BUDGET", 330)
    first, second = ai_actions.plan_assess("CVE-2024-0001", targets)
    assert first.key == second.key == spec.key
    assert (first.batch, second.batch) == ((1, 2), (2, 2))
    assert second.title == "CVE-2024-0001 · 1 target · batch 2 of 2"
    assert first.detail == "x86 · openssl@3.0, zlib@1.2" and second.detail == "arm · openssl@3.0"
    with pytest.raises(ValueError, match="No active assessment targets"):
        ai_actions.plan_assess("CVE-2024-0001", [])


def test_resolve_assess_targets(ctx):
    from src.controllers.ai_actions import resolve_assess_targets

    x86, arm = uuid.UUID(ctx["x86"]), uuid.UUID(ctx["arm"])
    scope = {x86, arm}
    [target] = resolve_assess_targets("CVE-2024-0001", [{"variant_id": ctx["arm"], "package": "openssl@3.0::"}],
                                      scope)
    assert (target.variant_id, target.package, target.finding_id) == (
        ctx["arm"], "openssl@3.0", ctx["findings"]["openssl"])
    twice = [{"variant_id": ctx["x86"], "package": "zlib@1.2"}] * 2
    assert [t.package for t in resolve_assess_targets("CVE-2024-0001", twice, scope)] == ["zlib@1.2"]
    assert {(t.variant_id, t.package) for t in resolve_assess_targets("CVE-2024-0001", None, {arm})} == {
        (ctx["arm"], "openssl@3.0")}
    cases: list[tuple[list, str]] = [
        ([], "non-empty list"),
        ([{"variant_id": ctx["x86"]}], "needs a variant_id and a package"),
        (["x"], "needs a variant_id and a package"),
        ([{"variant_id": "nope", "package": "zlib@1.2"}], "Invalid variant ID"),
        ([{"variant_id": ctx["default"], "package": "zlib@1.2"}], "not in scope"),
        ([{"variant_id": ctx["x86"], "package": "zlib@9"}], "Package not found"),
        ([{"variant_id": ctx["arm"], "package": "zlib@1.2"}], "not an active target"),
    ]
    for pairs, message in cases:
        with pytest.raises(ValueError, match=message):
            resolve_assess_targets("CVE-2024-0001", pairs, scope)
    with pytest.raises(ValueError, match="not an active target"):  # busybox is outdated on x86
        resolve_assess_targets("CVE-2024-0002", [{"variant_id": ctx["x86"], "package": "busybox@1.36"}], scope)


# ---------------------------------------------------------------- review planning


def test_plan_review_lists_every_target_in_one_prompt_or_one_spec_per_variant(ctx):
    from src.controllers import ai_actions

    assessment = _custom(ctx, [("x86", "openssl"), ("arm", "openssl"), ("x86", "zlib")])
    aid = assessment.id
    [spec] = ai_actions.plan_review(aid)
    assert spec.key == f"review:{aid}" and spec.title == f"assessment {str(aid)[:8]}"
    assert spec.detail == "CVE-2024-0001 · openssl@3.0 · zlib@1.2"
    assert [(t.variant, t.package) for t in spec.review_targets] == [
        ("arm", "openssl@3.0"), ("x86", "openssl@3.0"), ("x86", "zlib@1.2")]
    assert f"expected_assessment_fingerprint=`{_fingerprint(assessment)}`" in spec.prompt
    assert all(f"variant {t.variant} ({t.variant_id}), package {t.package}" in spec.prompt
               for t in spec.review_targets)

    arm, x86 = ai_actions.plan_review(aid, per_variant=True)
    assert (arm.key, x86.key) == (f"review:{aid}:{ctx['arm']}", f"review:{aid}:{ctx['x86']}")
    assert [len(arm.review_targets), len(x86.review_targets)] == [1, 2]
    [only] = ai_actions.plan_review(aid, uuid.UUID(ctx["x86"]), {uuid.UUID(ctx["findings"]["zlib"])},
                                    key="k", per_variant=True)
    assert only.key == "k" and [t.package for t in only.review_targets] == ["zlib@1.2"]
    x86_id, zlib, openssl = (uuid.UUID(value)
                             for value in (ctx["x86"], ctx["findings"]["zlib"], ctx["findings"]["openssl"]))
    [one] = ai_actions.plan_review(aid, x86_id, {zlib}, per_variant=True)
    [both] = ai_actions.plan_review(aid, x86_id, {zlib, openssl}, per_variant=True)
    [again] = ai_actions.plan_review(aid, x86_id, {openssl, zlib}, per_variant=True)
    # The selected findings are part of the key: a run selecting more never follows one selecting fewer.
    assert one.key.startswith(f"review:{aid}:{x86_id}:") and one.key != both.key == again.key


def test_plan_review_rejects_unreviewable_assessments(ctx):
    from src.controllers.ai_actions import plan_review

    with pytest.raises(ValueError, match="not found"):
        plan_review(uuid.uuid4())
    with pytest.raises(ValueError, match="only custom assessments"):
        plan_review(_custom(ctx, [("x86", "openssl")], origin="ai").id)
    with pytest.raises(ValueError, match="no target to review"):
        plan_review(_custom(ctx, [("x86", "openssl")]).id, finding_ids={uuid.uuid4()})
    from src.models.variant import Variant

    spread = _custom(ctx, [("x86", "openssl"), ("arm", "openssl")])
    # The model refuses cross-project assessments; a variant moved to another project yields one.
    arm, default = _db.session.get(Variant, uuid.UUID(ctx["arm"])), _db.session.get(Variant, uuid.UUID(ctx["default"]))
    assert arm is not None and default is not None
    arm.project_id = default.project_id
    _db.session.commit()
    with pytest.raises(ValueError, match="more than one project"):
        plan_review(spread.id)


def test_prepare_pins_the_review_fingerprint_when_the_turn_starts(ctx):
    from src.controllers import ai_actions
    from src.routes import agent_skills

    assessment = _custom(ctx, [("x86", "openssl"), ("arm", "openssl")])
    planned = _fingerprint(assessment)
    [spec] = ai_actions.plan_review(assessment.id)
    assessment.status_notes = "edited while queued"
    _db.session.commit()
    edited = _fingerprint(assessment)
    assert edited != planned

    turn = ai_actions.prepare(spec)
    assert isinstance(turn.guard, ai_actions.ReviewGuard)
    assert turn.fingerprint == edited and turn.guard.selection.fingerprint == edited
    assert f"`{edited}`" in turn.prompt and planned not in turn.prompt
    assert turn.profile is agent_skills.REVIEW
    scope = json.loads(turn.scope)
    assert scope["project_ids"] == [ctx["demo"]] and scope["variant_ids"] == sorted([ctx["x86"], ctx["arm"]])
    assert len(scope["review_targets"]) == 2

    from dataclasses import replace

    pinned = ai_actions.prepare(replace(spec, fingerprint=planned))
    assert pinned.fingerprint == planned and f"`{planned}`" in pinned.prompt

    for row in list(assessment.target_rows):
        if str(row.variant_id) == ctx["arm"]:
            _db.session.delete(row)
    _db.session.commit()
    guard = ai_actions.prepare(spec).guard
    assert isinstance(guard, ai_actions.ReviewGuard) and [t.variant for t in guard.batch] == ["x86"]
    for row in list(assessment.target_rows):
        _db.session.delete(row)
    _db.session.commit()
    with pytest.raises(ValueError, match="no longer has any of the targets"):
        ai_actions.prepare(spec)
    assessment.origin = "ai"
    _db.session.commit()
    with pytest.raises(ValueError, match="no longer a reviewable custom assessment"):
        ai_actions.prepare(spec)


def test_prepare_keeps_the_batch_label_of_a_split_review(ctx, monkeypatch):
    from src.controllers import ai_actions

    assessment = _custom(ctx, [("x86", "openssl"), ("x86", "zlib")])
    monkeypatch.setattr(ai_actions, "PROMPT_BUDGET", 650)
    first, second = ai_actions.plan_review(assessment.id)
    assert (first.batch, second.batch) == ((1, 2), (2, 2))
    assert ai_actions.prepare(second).prompt == second.prompt and second.prompt.endswith("(batch 2 of 2)")


# ---------------------------------------------------------------- verify


@pytest.mark.parametrize("error, interrupted, outcome, message", [
    (None, False, "no_write", None),
    (("timeout", "No reply within 5 s."), False, "timeout", "No reply within 5 s."),
    (("failed", "boom"), False, "failed", "boom"),
    (("failed", "boom"), True, "interrupted", "Interrupted."),
    (None, True, "interrupted", "Interrupted."),
])
def test_verify_maps_errors_like_the_cli(ctx, error, interrupted, outcome, message):
    from src.controllers import ai_actions

    targets = ai_actions.active_targets("CVE-2024-0001", {uuid.UUID(ctx["x86"])})
    [spec] = ai_actions.plan_assess("CVE-2024-0001", targets)
    turn = ai_actions.prepare(spec)
    result = ai_actions.verify(turn, error, interrupted, reply="r", usage={"cost": 1})
    assert result == {"outcome": outcome, "error": message, "reply": "r", "usage": {"cost": 1}, "targets": [
        {"variant_id": t.variant_id, "variant": t.variant, "package": t.package, "written": False,
         "assessment_ids": []} for t in targets]}

    [review_spec] = ai_actions.plan_review(_custom(ctx, [("x86", "openssl")]).id)
    review = ai_actions.verify(ai_actions.prepare(review_spec), error, interrupted)
    assert review["outcome"] == outcome and review["reply"] is None
    [target] = review["targets"]
    assert target["outcome"] == outcome and target["finding_id"] == ctx["findings"]["openssl"]
    assert target["error"] == (message or "The agent saved no review for this target.")


def test_verify_reports_written_and_changed_targets(ctx):
    from src.controllers import ai_actions
    from src.models.assessment import Assessment

    targets = ai_actions.active_targets("CVE-2024-0001", {uuid.UUID(ctx["x86"])})
    turn = ai_actions.prepare(ai_actions.plan_assess("CVE-2024-0001", targets)[0])
    row = Assessment.create(status="not_affected", origin="ai",
                            targets=[(uuid.UUID(ctx["x86"]), uuid.UUID(ctx["findings"]["openssl"]))])
    _db.session.commit()
    assert isinstance(turn.guard, ai_actions.AssessGuard)
    turn.guard.written.append(str(row.id))
    result = ai_actions.verify(turn, None, False)
    assert result["outcome"] == "partial"
    assert [(t["package"], t["assessment_ids"]) for t in result["targets"]] == [
        ("openssl@3.0", [str(row.id)]), ("zlib@1.2", [])]

    assessment = _custom(ctx, [("x86", "openssl")])
    review_turn = ai_actions.prepare(ai_actions.plan_review(assessment.id)[0])
    assessment.status_notes = "edited during the turn"
    _db.session.commit()
    review = ai_actions.verify(review_turn, None, False)
    assert review["outcome"] == "changed" and review["targets"][0]["error"] == ai_actions.CHANGED


# ---------------------------------------------------------------- run_turn


def _post(url, path, payload):
    request = urllib.request.Request(f"{url}{path}", data=json.dumps(payload).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_run_turn_arms_the_guard_for_the_turn_only(app, ctx, monkeypatch):  # noqa: F811
    from src.controllers import ai_actions
    from src.controllers.guarded_api import NO_TURN, GuardedApi
    from src.routes import agent

    setattr(app, "_INT_SCAN_FINISHED", True)
    targets = ai_actions.active_targets("CVE-2024-0001", {uuid.UUID(ctx["arm"])})
    turn = ai_actions.prepare(ai_actions.plan_assess("CVE-2024-0001", targets)[0])
    payload = {"status": "not_affected", "justification": "component_not_present", "ai_generated": True,
               "targets": [{"package": "openssl@3.0", "variant_id": ctx["arm"]}]}
    calls = []

    async def fake(conversation, message, path, model, scope, publish=None, **kwargs):
        calls.append((message, scope, publish, kwargs))
        outside = dict(payload, targets=[{"package": "zlib@1.2", "variant_id": ctx["x86"]}])
        answers = [await asyncio.to_thread(_post, kwargs["api_url"], path_, body) for path_, body in [
            ("/api/vulnerabilities/CVE-2024-0001/assessments", payload),
            ("/api/vulnerabilities/CVE-2024-0001/assessments", outside)]]
        return json.dumps([status for status, _ in answers]), {"cost": None}

    monkeypatch.setattr(agent, "_reply", fake)
    api = GuardedApi(app)
    api.start()
    try:
        publish, on_session = object(), object()
        reply, _ = asyncio.run(ai_actions.run_turn(turn, agent.Conversation(), "m", Path("mcp"), api, publish,
                                                   ephemeral=False, on_session=on_session))
        assert json.loads(reply) == [200, 403]
        [(message, scope, published, kwargs)] = calls
        assert (message, scope, published) == (turn.prompt, turn.scope, publish)
        assert kwargs == {"profile": turn.profile, "timeout": turn.spec.timeout, "api_url": api.url,
                          "ephemeral": False, "on_session": on_session}
        assert isinstance(turn.guard, ai_actions.AssessGuard) and len(turn.guard.written) == 1
        assert _post(api.url, "/api/vulnerabilities/CVE-2024-0001/assessments", payload) == (403, {"error": NO_TURN})
    finally:
        api.stop()
    assert ai_actions.verify(turn, None, False)["outcome"] == "assessed"

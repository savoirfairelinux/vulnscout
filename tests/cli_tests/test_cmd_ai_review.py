# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Tests for ``flask ai-review``: validation, selection, skip policy, dry-run and report."""

import json
import uuid

import pytest

from src.bin.webapp import create_app
from src.extensions import db as _db


def _seed():
    """demo/{x86, arm} plus an empty default/default.

    CVE-2024-0001: openssl@3.0 on x86 and arm, zlib@1.2 on x86 (all active).
    CVE-2024-0002: busybox@1.36 on x86, outdated (observed, absent from the active SBOM).
    CVE-2024-0003: curl@8.0 on x86 (active), already assessed "affected" by a human.
    CVE-2024-0004: libxml2@2.9 on x86 (active).
    """
    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.project import Project
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.scan import Scan
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability

    demo = Project.create("demo")
    x86 = Variant.create("x86", demo.id)
    arm = Variant.create("arm", demo.id)
    default = Project.create("default")
    default_variant = Variant.create("default", default.id)
    for vuln_id in ("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"):
        Vulnerability.create_record(id=vuln_id, description=vuln_id)
    _db.session.commit()

    findings = {}

    def observe(variant, observed, active):
        scan = Scan.create(f"{variant.name}-scan", variant.id, scan_type="sbom")
        document = SBOMDocument.create(path=f"/sbom/{variant.name}.json", source_name="cdx", scan_id=scan.id)
        for vuln_id, name, version in observed:
            package = Package.find_or_create(name, version, [], [], "")
            _db.session.commit()
            finding = Finding.get_or_create(package.id, vuln_id)
            Observation.create(finding.id, scan.id)
            if (name, version) in active:
                SBOMPackage.create(document.id, package.id)
            findings[name] = finding

    observe(x86, [
        ("CVE-2024-0001", "openssl", "3.0"), ("CVE-2024-0001", "zlib", "1.2"),
        ("CVE-2024-0002", "busybox", "1.36"), ("CVE-2024-0003", "curl", "8.0"),
        ("CVE-2024-0004", "libxml2", "2.9"),
    ], active={("openssl", "3.0"), ("zlib", "1.2"), ("curl", "8.0"), ("libxml2", "2.9")})
    observe(arm, [("CVE-2024-0001", "openssl", "3.0")], active={("openssl", "3.0")})
    Assessment.create(status="affected", origin="custom", targets=[(x86.id, findings["curl"].id)])
    _db.session.commit()
    return {
        "demo": str(demo.id), "x86": str(x86.id), "arm": str(arm.id), "default": str(default_variant.id),
        "findings": {name: str(finding.id) for name, finding in findings.items()},
    }


@pytest.fixture()
def app(tmp_path, monkeypatch):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    config = tmp_path / "config.env"
    config.write_text("AI_PROVIDER=github\nAI_AUTH_CREDENTIALS=gho_test\nAI_MODEL=test-model\n")
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("VULNSCOUT_CONFIG", str(config))
    for key in ("AI_PROVIDER", "AI_AUTH_CREDENTIALS", "AI_MODEL", "AI_BASE_URL", "VULNSCOUT_MCP_SERVER_PATH"):
        monkeypatch.delenv(key, raising=False)
    from src.routes import agent

    async def signed_in(token):
        return {"authenticated": True, "login": "tester"}

    monkeypatch.setattr(agent, "_token_status", signed_in)
    application = create_app()
    application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
    with application.app_context():
        _db.drop_all()
        _db.create_all()
    return application


@pytest.fixture()
def ids(app):
    with app.app_context():
        return _seed()


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    from src.bin import _ai_runner
    from src.routes import agent

    async def reply(*args, **kwargs):
        pytest.fail("the AI must not be called")

    monkeypatch.setattr(agent, "_reply", reply)
    monkeypatch.setattr(_ai_runner, "load_agent", lambda model: pytest.fail("the agent must not be loaded"))


def _custom(ids, variants, package="openssl", status="not_affected", vuln_id="CVE-2024-0001", origin="custom"):
    from src.models.assessment import Assessment

    assessment = Assessment.create(
        status=status, origin=origin,
        targets=[(uuid.UUID(ids[name]), uuid.UUID(ids["findings"][package])) for name in variants])
    _db.session.commit()
    return str(assessment.id)


def _mark_reviewed(assessment_id, variants, ids, package="openssl"):
    from src.models.assessment import Assessment
    from src.models.assessment_review import AssessmentReview, fingerprint_assessment

    assessment = Assessment.get_by_id(uuid.UUID(assessment_id))
    for name in variants:
        AssessmentReview.upsert(assessment.id, uuid.UUID(ids[name]), uuid.UUID(ids["findings"][package]),
                                fingerprint_assessment(assessment), "agree", "ok")


def _invoke(app, *args):
    return app.test_cli_runner().invoke(args=["ai-review", *args])


@pytest.mark.parametrize("args, message", [
    (["--assessment-id", str(uuid.uuid4())], "--project is required."),
    (["--cve", "CVE-2024-0001"], "--project is required."),
    (["--variant", "x86", "--cve", "CVE-2024-0001"], "--project is required."),
    (["--project", "demo"], "Use exactly one of --assessment-id or --cve."),
    (["--project", "demo", "--assessment-id", str(uuid.uuid4()), "--cve", "CVE-2024-0001"],
     "Use exactly one of --assessment-id or --cve."),
    (["--project", "demo", "--variant", "x86", "--assessment-id", str(uuid.uuid4())],
     "--variant cannot be used with --assessment-id, which reviews every target in the project."),
    (["--project", "demo", "--assessment-id", "X"], "Invalid assessment ID: X"),
    (["--project", "demo", "--cve", "bad id"], "Invalid vulnerability ID: bad id"),
])
def test_usage_errors(app, ids, args, message):
    result = _invoke(app, *args)
    assert result.exit_code == 1
    assert message in result.stderr


@pytest.mark.parametrize("args", [
    ["--project", "demo", "--cve", "CVE-2024-0001", "--timeout", "0"],
    ["--project", "demo", "--cve", "CVE-2024-0001", "--timeout"],
    ["--project", "demo", "--cve", "CVE-2024-0001", "--unknown"],
])
def test_parser_errors_exit_one(app, ids, args):
    result = _invoke(app, *args)
    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr.startswith(("Usage:", "Error:"))


@pytest.mark.parametrize("args, message", [
    (["--project", "nonexistent", "--cve", "CVE-2024-0001"], "Project not found: nonexistent"),
    (["--project", "demo", "--variant", "nope", "--cve", "CVE-2024-0001"], "Variant not found: nope"),
])
@pytest.mark.parametrize("flags", [[], ["--json"]])
def test_unknown_scope_is_reported_on_stderr_only(app, ids, args, message, flags):
    result = _invoke(app, *args, *flags)
    assert result.exit_code == 1
    assert result.stdout == ""
    assert message in result.stderr


def test_resolution_errors_are_all_listed_and_nothing_runs(app, ids):
    first, second = str(uuid.uuid4()), str(uuid.uuid4())
    result = _invoke(app, "--project", "demo", "--assessment-id", first, "--assessment-id", second)
    assert result.exit_code == 1
    assert f"Assessment {first} not found." in result.stderr
    assert f"Assessment {second} not found." in result.stderr


def test_dry_run_by_assessment_id_plans_every_target(app, ids):
    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])
    text = _invoke(app, "--project", "demo", "--assessment-id", aid, "--dry-run")
    assert text.exit_code == 0, text.stderr
    assert f"{aid}  CVE-2024-0001  planned" in text.stdout
    assert "x86 / openssl@3.0  planned" in text.stdout
    assert "arm / openssl@3.0  planned" in text.stdout
    assert "Reviewed 0, skipped 0, failed 0." in text.stdout

    report = json.loads(_invoke(app, "--project", "demo", "--assessment-id", aid, "--dry-run", "--json").stdout)
    assert report["scope"] == {"project": "demo", "variants": None}
    assert report["model"] == "test-model"
    [entry] = report["results"]
    assert entry["outcome"] == "planned"
    assert [(t["variant"], t["outcome"]) for t in entry["targets"]] == [("arm", "planned"), ("x86", "planned")]


def test_dry_run_by_cve_restricts_variants_and_counts_ignored(app, ids):
    with app.app_context():
        _custom(ids, ["x86", "arm"])
        _custom(ids, ["x86"], origin="sbom")
    result = _invoke(app, "--cve", "CVE-2024-0001", "--project", "demo", "--variant", "x86", "--dry-run", "--json")
    assert result.exit_code == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["scope"] == {"project": "demo", "variants": ["x86"]}
    assert report["ignored_non_custom"] == 1
    [entry] = report["results"]
    assert entry["excluded_targets"] == 1
    assert [t["variant"] for t in entry["targets"]] == ["x86"]

    text = _invoke(app, "--cve", "CVE-2024-0001", "--project", "demo", "--dry-run")
    assert "Ignored 1 non-custom assessment(s)." in text.stdout

    one = _invoke(app, "--cve", "CVE-2024-0001", "--project", "demo", "--variant", "x86", "--dry-run")
    assert "planned  0/1 targets  (1 target outside scope)" in one.stdout


def test_fresh_targets_are_skipped_without_loading_the_agent(app, ids):
    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])
        _mark_reviewed(aid, ["x86", "arm"], ids)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--json")
    assert result.exit_code == 0, result.stderr
    report = json.loads(result.stdout)
    [entry] = report["results"]
    assert entry["outcome"] == "skipped"
    assert {t["outcome"] for t in entry["targets"]} == {"skipped_fresh"}
    assert report["counts"] == {"reviewed": 0, "skipped": 2, "failed": 0}
    assert "Reviewed 0, skipped 2, failed 0." in _invoke(app, "--project", "demo", "--assessment-id", aid).stdout


def test_re_review_plans_fresh_targets(app, ids):
    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])
        _mark_reviewed(aid, ["x86"], ids)
    report = json.loads(_invoke(app, "--project", "demo", "--assessment-id", aid, "--dry-run", "--json").stdout)
    assert {t["variant"]: t["outcome"] for t in report["results"][0]["targets"]} == {
        "arm": "planned", "x86": "skipped_fresh"}
    assert report["results"][0]["outcome"] == "planned"
    forced = json.loads(_invoke(app, "--project", "demo", "--assessment-id", aid, "--re-review", "--dry-run",
                                "--json").stdout)
    assert {t["outcome"] for t in forced["results"][0]["targets"]} == {"planned"}


def test_many_assessments_are_not_paginated(app, ids):
    with app.app_context():
        for _ in range(60):
            _custom(ids, ["x86"])
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--dry-run", "--json")
    assert result.exit_code == 0, result.stderr
    assert len(json.loads(result.stdout)["results"]) == 60


# ---------------------------------------------------------------- run path

from src.bin import _ai_runner  # noqa: E402

REAL_LOAD_AGENT = _ai_runner.load_agent
OUTSIDE_RUN = "Write rejected: this review run may only save reviews for its listed targets."


def _fake_reply(monkeypatch, behaviour):
    """Replace agent._reply (overriding ``no_ai``); *behaviour(call)* may call the API, raise, or return."""
    from src.routes import agent

    calls = []

    async def fake(conversation, message, path, model, scope, publish=None, **kwargs):
        call = {"message": message, "model": model, "scope": json.loads(scope), **kwargs}
        calls.append(call)
        behaviour(call)
        return "done", {"cost": 1.0, "input_tokens": 10, "output_tokens": 5}

    monkeypatch.setattr(agent, "_reply", fake)
    monkeypatch.setattr(_ai_runner, "load_agent", REAL_LOAD_AGENT)
    return calls


def _http(call, method, path, payload=None):
    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        f"{call['api_url']}{path}", method=method, headers={"Content-Type": "application/json"},
        data=None if payload is None else json.dumps(payload).encode())
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _fingerprint(call):
    return call["message"].split("expected_assessment_fingerprint=`")[1].split("`")[0]


def _put_review(call, target, **overrides):
    payload = {"variant_id": target["variant_id"], "finding_id": target["finding_id"],
               "package": target["package"], "status": "not_affected",
               "justification": "component_not_present", "rationale": "Independent analysis.",
               "expected_assessment_fingerprint": _fingerprint(call), **overrides}
    payload = {key: value for key, value in payload.items() if value is not None}
    return _http(call, "PUT", f"/api/assessments/{target['assessment_id']}/review", payload)


def _write_all(call):
    for target in call["scope"]["review_targets"]:
        status, body = _put_review(call, target)
        assert status == 200, body


def _report(result):
    assert result.exit_code in (0, 1), result.stderr
    return json.loads(result.stdout)


def _outcomes(report, index=0):
    return {t["variant"] + "/" + t["package"]: t["outcome"] for t in report["results"][index]["targets"]}


def test_one_turn_per_variant_with_scoped_review_targets(app, ids, monkeypatch):
    from src.routes import agent_skills

    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])
        _mark_reviewed(aid, ["x86"], ids)
    seen = []

    def behaviour(call):
        [target] = call["scope"]["review_targets"]
        status, body = _put_review(call, target)
        assert status == 200
        # the recorder relies on these two fields of the 200 body
        assert body["review"]["variant_id"] == target["variant_id"]
        assert body["review"]["package"] == target["package"]
        seen.append(target)
        status, _ = _http(call, "GET", f"/api/assessments/{aid}/review?variant_id={target['variant_id']}"
                          f"&finding_id={target['finding_id']}")
        assert status == 200

    calls = _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--re-review", "--timeout", "30", "--json")
    assert result.exit_code == 0, result.stderr
    assert len(calls) == 2
    for call in calls:
        assert call["profile"] is agent_skills.REVIEW and call["ephemeral"] is True
        [variant_id] = call["scope"]["variant_ids"]
        assert call["scope"]["project_ids"] == [ids["demo"]]
        [target] = call["scope"]["review_targets"]
        assert target == {"assessment_id": aid, "variant_id": variant_id, "package": "openssl@3.0",
                          "finding_id": ids["findings"]["openssl"]}
        assert "(batch" not in call["message"]
    assert {c["scope"]["variant_ids"][0] for c in calls} == {ids["x86"], ids["arm"]}
    report = json.loads(result.stdout)
    [entry] = report["results"]
    assert entry["outcome"] == "reviewed"
    for item in entry["targets"]:
        assert item["outcome"] == "reviewed" and set(item["review"]) == {"id", "status", "verdict"}
    assert report["counts"] == {"reviewed": 2, "skipped": 0, "failed": 0}
    assert report["interrupted"] is False
    assert report["model"] == "test-model" and entry["usage"]["input_tokens"] == 20


def test_review_leaves_the_assessment_untouched(app, ids, monkeypatch):
    from src.models.assessment import Assessment
    from src.models.assessment_review import fingerprint_assessment

    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])
        before = Assessment.get_by_id(uuid.UUID(aid))
        snapshot = (fingerprint_assessment(before), before.status, set(before.targets))
    _fake_reply(monkeypatch, _write_all)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid)
    assert result.exit_code == 0, result.stdout + result.stderr
    with app.app_context():
        after = Assessment.get_by_id(uuid.UUID(aid))
        assert (fingerprint_assessment(after), after.status, set(after.targets)) == snapshot
        assert not [a for a in Assessment.get_by_vulnerability("CVE-2024-0001") if a.origin == "ai"]


def test_text_report_roles_of_reviewed_and_failed(app, ids, monkeypatch):
    monkeypatch.setenv("_VULNSCOUT_COLOR_STDOUT", "1")
    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])

    def behaviour(call):
        [target] = call["scope"]["review_targets"]
        if target["variant_id"] == ids["arm"]:
            raise RuntimeError("boom")
        _put_review(call, target)

    _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid)
    assert result.exit_code == 1
    red, green = "\x1b[31m", "\x1b[32m"
    assert f"{red}{aid}  CVE-2024-0001  partial  1/2 targets" in result.stdout
    assert f"[1/1] Reviewing {aid[:8]}\u2026 CVE-2024-0001 on arm (1 target)..." in result.stderr
    assert f"{red}    arm / openssl@3.0  failed  boom" in result.stdout
    assert "x86 / openssl@3.0  reviewed  " in result.stdout
    assert "Reviewed 1, skipped 0, failed 1." in result.stdout

    _fake_reply(monkeypatch, _write_all)
    ok = _invoke(app, "--project", "demo", "--assessment-id", aid, "--re-review")
    assert ok.exit_code == 0
    assert f"{green}{aid}  CVE-2024-0001  reviewed  2/2 targets" in ok.stdout

    def always_fails(call):
        raise RuntimeError("boom")

    _fake_reply(monkeypatch, always_fails)
    failed = _invoke(app, "--project", "demo", "--assessment-id", aid, "--re-review")
    assert failed.exit_code == 1
    assert f"{red}{aid}  CVE-2024-0001  failed  0/2 targets" in failed.stdout


def test_guard_rejects_writes_outside_the_turn(app, ids, monkeypatch):
    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])
        other = _custom(ids, ["x86"], package="zlib")
    attempts = []

    def behaviour(call):
        [target] = call["scope"]["review_targets"]
        if target["variant_id"] != ids["x86"]:
            return
        zlib = {**target, "assessment_id": other, "finding_id": ids["findings"]["zlib"], "package": "zlib@1.2"}
        attempts.append(_put_review(call, zlib))
        attempts.append(_http(call, "POST", "/api/vulnerabilities/CVE-2024-0001/assessments",
                              {"status": "affected", "targets": [
                                  {"package": "openssl@3.0", "variant_id": target["variant_id"]}]}))
        attempts.append(_put_review(call, {**target, "variant_id": ids["arm"]}))
        # a finding and a package that name different targets
        attempts.append(_put_review(call, {**target, "package": "zlib@1.2"}))
        attempts.append(_put_review(call, target, variant_id=None))
        attempts.append(_put_review(call, target, finding_id=None, package=None))
        attempts.append(_http(call, "PUT", f"/api/assessments/{aid}/review", ["not", "an", "object"]))

    _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--json")
    assert result.exit_code == 1
    assert attempts == [(403, {"error": OUTSIDE_RUN})] * 7
    [entry] = _report(result)["results"]
    assert entry["outcome"] == "failed"
    [item] = [t for t in entry["targets"] if t["variant"] == "x86" and t["package"] == "openssl@3.0"]
    assert item["outcome"] == "no_write" and item["error"] == OUTSIDE_RUN
    with app.app_context():
        from src.models.assessment_review import AssessmentReview
        assert AssessmentReview.get_all_for_assessment(uuid.UUID(other)) == []


def test_guard_accepts_one_identifier_in_any_uuid_case(app, ids, monkeypatch):
    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])
    by_package = []

    def behaviour(call):
        [target] = call["scope"]["review_targets"]
        if target["variant_id"] == ids["x86"]:
            by_package.append(_put_review(call, target, finding_id=None, variant_id=target["variant_id"].upper()))
        else:
            by_package.append(_put_review(call, target, package=None, finding_id=target["finding_id"].upper()))

    _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--json")
    assert result.exit_code == 0, result.stderr
    assert [status for status, _ in by_package] == [200, 200]


def test_guard_rejects_a_stale_fingerprint(app, ids, monkeypatch):
    with app.app_context():
        aid = _custom(ids, ["x86"])
    answers = []

    def behaviour(call):
        [target] = call["scope"]["review_targets"]
        answers.append(_put_review(call, target, expected_assessment_fingerprint="0" * 64))

    _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--json")
    assert result.exit_code == 1
    [(status, body)] = answers
    assert status == 409 and body["code"] == "assessment_changed"
    [item] = _report(result)["results"][0]["targets"]
    assert item["outcome"] == "no_write"
    assert item["error"] == "The assessment changed since this run selected it."


def test_no_write_without_any_rejection(app, ids, monkeypatch):
    with app.app_context():
        aid = _custom(ids, ["x86"])
    _fake_reply(monkeypatch, lambda call: None)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--json")
    assert result.exit_code == 1
    [item] = _report(result)["results"][0]["targets"]
    assert item == {**item, "outcome": "no_write", "error": "The agent saved no review for this target."}


def test_failed_write_without_error_message_is_recorded_by_status(app, ids, monkeypatch):
    with app.app_context():
        aid = _custom(ids, ["x86"])

    def behaviour(call):
        [target] = call["scope"]["review_targets"]
        assert _put_review(call, target, rationale="  ")[0] == 400

    _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--json")
    [item] = _report(result)["results"][0]["targets"]
    assert item["outcome"] == "no_write" and item["error"] == "rationale is required"


def _edit_assessment(app, aid, edit):
    from src.models.assessment import Assessment

    with app.app_context():
        edit(Assessment.get_by_id(uuid.UUID(aid)))
        _db.session.commit()


def test_concurrent_edit_during_the_turn_is_reported_as_changed(app, ids, monkeypatch):
    with app.app_context():
        aid = _custom(ids, ["x86"])

    def behaviour(call):
        _write_all(call)
        _edit_assessment(app, aid, lambda a: setattr(a, "status_notes", "edited meanwhile"))

    _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--json")
    assert result.exit_code == 1
    [item] = _report(result)["results"][0]["targets"]
    assert item["outcome"] == "changed"
    assert item["error"] == "The assessment changed during the review; run it again."
    assert item["review"] is None


def test_target_removed_during_the_turn_is_reported_as_changed(app, ids, monkeypatch):
    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])

    def behaviour(call):
        def drop(assessment):
            for row in list(assessment.target_rows):
                if str(row.variant_id) == call["scope"]["variant_ids"][0]:
                    _db.session.delete(row)

        _edit_assessment(app, aid, drop)

    _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--json")
    assert result.exit_code == 1
    assert set(_outcomes(_report(result)).values()) == {"changed"}


def test_assessment_no_longer_custom_when_reached_is_reported_as_changed_without_a_turn(app, ids, monkeypatch):
    with app.app_context():
        first, second = _custom(ids, ["x86"]), _custom(ids, ["x86"])

    def behaviour(call):
        _write_all(call)
        other = second if first in call["message"] else first
        _edit_assessment(app, other, lambda assessment: setattr(assessment, "origin", "ai"))

    calls = _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--json")
    assert result.exit_code == 1 and len(calls) == 1
    report = _report(result)
    assert sorted(entry["targets"][0]["outcome"] for entry in report["results"]) == ["changed", "reviewed"]
    assert "[2/2] Reviewing" not in result.stderr


def test_stale_targets_are_reprocessed_and_fresh_ones_skipped(app, ids, monkeypatch):
    from src.models.assessment import Assessment
    from src.models.assessment_review import AssessmentReview

    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])
        _mark_reviewed(aid, ["arm"], ids)
        AssessmentReview.upsert(uuid.UUID(aid), uuid.UUID(ids["x86"]), uuid.UUID(ids["findings"]["openssl"]),
                                "an-older-fingerprint", "agree", "old")
        _db.session.commit()
        assert Assessment.get_by_id(uuid.UUID(aid))
    calls = _fake_reply(monkeypatch, _write_all)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--json")
    assert result.exit_code == 0, result.stderr
    assert len(calls) == 1 and calls[0]["scope"]["variant_ids"] == [ids["x86"]]
    report = json.loads(result.stdout)
    assert _outcomes(report) == {"arm/openssl@3.0": "skipped_fresh", "x86/openssl@3.0": "reviewed"}
    assert report["results"][0]["outcome"] == "reviewed"


def test_re_review_replaces_fresh_reviews(app, ids, monkeypatch):
    from src.models.assessment_review import AssessmentReview

    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])
        _mark_reviewed(aid, ["x86", "arm"], ids)
        _db.session.commit()
    calls = _fake_reply(monkeypatch, _write_all)
    assert _invoke(app, "--project", "demo", "--assessment-id", aid).exit_code == 0
    assert calls == []
    assert _invoke(app, "--project", "demo", "--assessment-id", aid, "--re-review").exit_code == 0
    assert len(calls) == 2
    with app.app_context():
        reviews = AssessmentReview.get_all_for_assessment(uuid.UUID(aid))
        assert {r.rationale for r in reviews} == {"Independent analysis."}


@pytest.mark.parametrize("error, outcome, message", [
    (__import__("asyncio").TimeoutError(), "timeout", "No reply within 30 s."),
    (RuntimeError("boom"), "failed", "boom"),
    (RuntimeError(), "failed", "RuntimeError"),
])
def test_turn_errors_do_not_stop_the_next_variant(app, ids, monkeypatch, error, outcome, message):
    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])

    def behaviour(call):
        if call["scope"]["variant_ids"] == [ids["arm"]]:
            raise error
        _write_all(call)

    calls = _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--timeout", "30", "--json")
    assert result.exit_code == 1
    assert len(calls) == 2
    report = json.loads(result.stdout)
    assert report["results"][0]["outcome"] == "partial"
    arm, x86 = report["results"][0]["targets"]
    assert (arm["outcome"], arm["error"]) == (outcome, message)
    assert x86["outcome"] == "reviewed"
    assert report["counts"] == {"reviewed": 1, "skipped": 0, "failed": 1}


def test_interrupt_stops_and_reports_the_rest_as_not_started(app, ids, monkeypatch):
    with app.app_context():
        first = _custom(ids, ["x86"])
        second = _custom(ids, ["x86"])

    def behaviour(call):
        raise KeyboardInterrupt

    calls = _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--json")
    assert result.exit_code == 1
    assert len(calls) == 1
    entries = _report(result)["results"]
    assert {e["assessment_id"] for e in entries} == {first, second}
    interrupted = sorted((e["targets"][0]["error"] for e in entries))
    assert interrupted == ["Interrupted.", "Not started."]
    assert {e["targets"][0]["outcome"] for e in entries} == {"interrupted"}
    assert "Interrupted; reporting completed reviews." in result.stderr


def test_interrupt_signal_after_a_finished_turn_stops_the_run(app, ids, monkeypatch):
    with app.app_context():
        _custom(ids, ["x86"])
        _custom(ids, ["x86"])

    def behaviour(call):
        _write_all(call)
        _ai_runner.interrupted.set()

    calls = _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--json")
    assert result.exit_code == 1
    assert len(calls) == 1
    # the finished turn's review is saved and verified; the interrupt only stops what comes next
    assert sorted(e["targets"][0]["outcome"] for e in _report(result)["results"]) == ["interrupted", "reviewed"]


def test_interrupt_signal_between_assessments_marks_the_rest_not_started(app, ids, monkeypatch):
    from src.bin import cmd_ai_review

    with app.app_context():
        _custom(ids, ["x86"])
        _custom(ids, ["x86"])
    original = cmd_ai_review._fold

    def review_then_signal(*args, **kwargs):
        original(*args, **kwargs)
        _ai_runner.interrupted.set()

    monkeypatch.setattr(cmd_ai_review, "_fold", review_then_signal)
    calls = _fake_reply(monkeypatch, _write_all)
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--json")
    assert result.exit_code == 1 and len(calls) == 1
    assert sorted(e["targets"][0]["outcome"] for e in _report(result)["results"]) == ["interrupted", "reviewed"]


def test_interrupt_after_the_last_turn_saved_its_reviews_still_fails(app, ids, monkeypatch):
    with app.app_context():
        aid = _custom(ids, ["x86"])

    def write_then_interrupt(call):
        _write_all(call)
        raise KeyboardInterrupt

    _fake_reply(monkeypatch, write_then_interrupt)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--json")
    assert result.exit_code == 1
    report = _report(result)
    assert report["interrupted"] is True
    assert _outcomes(report) == {"x86/openssl@3.0": "reviewed"}
    assert report["counts"] == {"reviewed": 1, "skipped": 0, "failed": 0}
    assert "Interrupted; reporting completed reviews." in result.stderr

    text = _invoke(app, "--project", "demo", "--assessment-id", aid, "--re-review")
    assert text.exit_code == 1
    assert "Reviewed 1, skipped 0, failed 0.\nInterrupted." in text.stdout


def test_long_target_lists_are_split_into_labelled_batches(app, ids, monkeypatch):
    from src.controllers import ai_actions
    from src.models.assessment import Assessment

    with app.app_context():
        assessment = Assessment.create(status="not_affected", origin="custom", targets=[
            (uuid.UUID(ids["x86"]), uuid.UUID(ids["findings"]["openssl"])),
            (uuid.UUID(ids["x86"]), uuid.UUID(ids["findings"]["zlib"]))])
        _db.session.commit()
        aid = str(assessment.id)
    monkeypatch.setattr(ai_actions, "PROMPT_BUDGET", 650)
    calls = _fake_reply(monkeypatch, _write_all)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--json")
    assert result.exit_code == 0, result.stderr
    assert len(calls) == 2
    assert calls[0]["message"].endswith("(batch 1 of 2)") and calls[1]["message"].endswith("(batch 2 of 2)")
    assert [len(c["scope"]["review_targets"]) for c in calls] == [1, 1]
    assert set(_outcomes(json.loads(result.stdout)).values()) == {"reviewed"}


def test_prompt_names_the_targets_and_pins_the_fingerprint(app, ids):
    from src.bin.cmd_ai_review import build_review_prompts
    from src.helpers.review_selection import select_by_ids

    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])
        [selection], errors = select_by_ids([uuid.UUID(aid)], {uuid.UUID(ids["x86"]), uuid.UUID(ids["arm"])}, "x")
        [(prompt, batch)] = build_review_prompts(selection, selection.targets)
    assert batch == selection.targets
    assert f"user assessment {aid} for CVE-2024-0001" in prompt
    assert f"expected_assessment_fingerprint=`{selection.fingerprint}`" in prompt
    sentence = "These targets were selected for review: write a review for each even if one already exists."
    assert sentence in prompt
    assert prompt.index(sentence) < prompt.index("Do not modify the assessment itself.")
    assert f"- variant x86 ({ids['x86']}), package openssl@3.0 (finding {ids['findings']['openssl']})" in prompt


def test_unavailable_model_and_skill_errors_abort(app, ids, monkeypatch):
    from src.routes import agent, agent_skills

    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])
    for error, text in ((agent.UnavailableModelError("Selected model is not available."), "not available"),
                        (agent_skills.AgentSkillError("skill missing"), "skill missing")):
        def behaviour(call, error=error):
            raise error

        calls = _fake_reply(monkeypatch, behaviour)
        result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--model", "nope")
        assert result.exit_code == 1 and text in result.stderr
        assert len(calls) == 1


def test_signed_out_github_token_aborts_before_any_turn(app, ids, monkeypatch):
    from src.routes import agent

    with app.app_context():
        aid = _custom(ids, ["x86"])

    async def signed_out(token):
        return {"authenticated": False, "login": None}

    monkeypatch.setattr(agent, "_token_status", signed_out)
    calls = _fake_reply(monkeypatch, _write_all)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid)
    assert result.exit_code == 1 and "GitHub Copilot rejected the configured token" in result.stderr
    assert calls == []


def test_sdk_logging_is_quiet_unless_verbose(app, ids, monkeypatch):
    import logging

    with app.app_context():
        aid = _custom(ids, ["x86"])
    monkeypatch.setenv("VERBOSE_MODE", "true")
    logger = logging.getLogger("copilot")
    logger.setLevel(logging.NOTSET)
    _fake_reply(monkeypatch, _write_all)
    assert _invoke(app, "--project", "demo", "--assessment-id", aid).exit_code == 0
    assert logger.level == logging.NOTSET
    monkeypatch.delenv("VERBOSE_MODE")
    assert _invoke(app, "--project", "demo", "--assessment-id", aid, "--re-review").exit_code == 0
    assert logger.level == logging.ERROR
    logger.setLevel(logging.NOTSET)


# ---------------------------------------------------------------- remote mode: through the web AI queue

def test_remote_review_submits_one_action_per_variant_and_folds_results_by_target(app, ids, monkeypatch):
    """The ``no_ai`` fixture proves nothing runs in this process: the web server's queue runs the turns."""
    from .queue_fakes import FakeQueueServer, done, failed, review_result

    with app.app_context():
        aid = _custom(ids, ["x86", "arm"])

    def finish(action, index):
        if action["variant_id"] == ids["arm"]:
            return failed("Not reviewable.", "prepare")
        return done(review_result(action))

    server = FakeQueueServer(finish).install(monkeypatch)
    result = _invoke(app, "--project", "demo", "--assessment-id", aid, "--timeout", "30", "--json")
    assert result.exit_code == 1, result.stderr
    [body] = server.submitted
    assert body["source"] == "CLI" and body["timeout"] == 30
    assert sorted((a["kind"], a["assessment_id"], a["variant_id"], tuple(a["finding_ids"]), a["key"].rsplit(":", 1)[0])
                  for a in body["actions"]) == sorted(
        ("review", aid, ids[name], (ids["findings"]["openssl"],), f"review:{aid}:{ids[name]}")
        for name in ("x86", "arm"))
    # The content pinned at selection, so the server reports an edit made since then as "changed".
    with app.app_context():
        from src.models.assessment import Assessment
        from src.models.assessment_review import fingerprint_assessment
        pinned = fingerprint_assessment(_db.session.get(Assessment, uuid.UUID(aid)))
    assert {action["fingerprint"] for action in body["actions"]} == {pinned}
    report = _report(result)
    assert _outcomes(report) == {"x86/openssl@3.0": "reviewed", "arm/openssl@3.0": "changed"}
    assert report["model"] == "server-model" and report["results"][0]["usage"]["input_tokens"] == 10
    assert "Reviewing" in result.stderr and "note: web server not running" not in result.stderr


def test_remote_review_ctrl_c_reports_unfinished_targets(app, ids, monkeypatch):
    from .queue_fakes import FakeQueueServer

    with app.app_context():
        _custom(ids, ["x86"])
        _custom(ids, ["x86"])
    server = FakeQueueServer().install(monkeypatch)
    server.on_snapshot = lambda srv, count: _ai_runner.interrupted.set() if count == 2 else None
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--json")
    assert result.exit_code == 1
    assert sorted(server.stopped) == ["req-1", "req-2"]
    entries = _report(result)["results"]
    assert [(e["targets"][0]["outcome"], e["targets"][0]["error"]) for e in entries] == [
        ("interrupted", "Not started.")] * 2
    assert _report(result)["interrupted"] is True

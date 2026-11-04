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

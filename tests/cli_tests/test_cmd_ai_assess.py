# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Tests for ``flask ai-assess`` and its helpers."""

import asyncio
import json
import os
import signal
import time

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


def test_variant_active_packages_matches_route_and_flags_outdated(app, ids):
    from src.helpers.active_targets import variant_active_packages

    with app.app_context():
        entries = variant_active_packages("CVE-2024-0002")
    assert [(entry["variant_id"], [(f["package"], f["outdated"]) for f in entry["findings"]])
            for entry in entries] == [(ids["x86"], [("busybox@1.36", True)])]
    route = app.test_client().get("/api/vulnerabilities/CVE-2024-0002/variant-active-packages")
    assert route.get_json() == entries


def _invoke(app, *args):
    # Click >= 8.2 (venv: 8.5) keeps result.stderr separate; it has no mix_stderr argument.
    return app.test_cli_runner().invoke(args=["ai-assess", *args])


@pytest.mark.parametrize("args, message", [
    ([], "exactly one of --cve or --filter"),
    (["--cve", "CVE-2024-0001", "--filter", "pending"], "to combine them, list the IDs in the filter"),
    (["--cve", "bad id"], "Invalid vulnerability ID: bad id"),
    (["--variant", "x86", "--cve", "CVE-2024-0001"], "--variant requires --project"),
    (["--cve", "CVE-2024-0001", "--timeout", "0"], "--timeout"),
])
def test_usage_errors(app, ids, args, message):
    result = _invoke(app, *args)
    assert result.exit_code != 0
    assert message in result.stderr


def test_unknown_project_exits_1(app, ids):
    result = _invoke(app, "--project", "nope", "--cve", "CVE-2024-0001", "--dry-run")
    assert result.exit_code == 1


def test_dry_run_plans_active_targets_per_scope(app, ids):
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--cve", "CVE-2024-0001",
                     "--dry-run", "--json")
    assert result.exit_code == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["model"] is None
    assert report["scope"] == {"project": "demo", "variants": None}
    [entry] = report["results"]
    assert entry["outcome"] == "planned"
    assert sorted((t["variant"], t["package"]) for t in entry["targets"]) == [
        ("arm", "openssl@3.0"), ("x86", "openssl@3.0"), ("x86", "zlib@1.2")]
    assert not any(t["written"] or t["assessment_ids"] for t in entry["targets"])

    one_variant = json.loads(_invoke(app, "--project", "demo", "--variant", "arm",
                                     "--cve", "CVE-2024-0001", "--dry-run", "--json").stdout)
    assert one_variant["scope"] == {"project": "demo", "variants": ["arm"]}
    assert [t["variant"] for t in one_variant["results"][0]["targets"]] == ["arm"]

    default_scope = json.loads(_invoke(app, "--cve", "CVE-2024-0001", "--dry-run", "--json").stdout)
    assert default_scope["scope"] == {"project": "default", "variants": ["default"]}


def test_repeated_variants_select_only_those_variants(app, ids):
    from src.models.project import Project
    from src.models.variant import Variant

    with app.app_context():
        Variant.create("riscv", Project.get_by_name("demo").id)
        _db.session.commit()
    result = _invoke(app, "--project", "demo", "--variant", "arm", "--variant", "x86", "--variant", "arm",
                     "--cve", "CVE-2024-0001", "--cve", "CVE-2024-0004", "--dry-run", "--json")
    assert result.exit_code == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["scope"] == {"project": "demo", "variants": ["arm", "x86"]}
    first, second = report["results"]
    assert sorted((t["variant"], t["package"]) for t in first["targets"]) == [
        ("arm", "openssl@3.0"), ("x86", "openssl@3.0"), ("x86", "zlib@1.2")]
    assert [(t["variant"], t["package"]) for t in second["targets"]] == [("x86", "libxml2@2.9")]

    only_arm = json.loads(_invoke(app, "--project", "demo", "--variant", "arm", "--variant", "riscv",
                                  "--cve", "CVE-2024-0004", "--dry-run", "--json").stdout)
    assert only_arm["results"][0]["outcome"] == "not_found"


def test_unknown_variant_among_several_exits_1(app, ids):
    result = _invoke(app, "--project", "demo", "--variant", "x86", "--variant", "nope",
                     "--cve", "CVE-2024-0001", "--dry-run")
    assert result.exit_code == 1
    assert "variant not found: nope" in result.stdout


def test_not_found_for_absent_or_outdated_cves(app, ids):
    default_scope = _invoke(app, "--cve", "CVE-2024-0001", "--dry-run", "--json")
    assert default_scope.exit_code == 1
    assert json.loads(default_scope.stdout)["results"][0]["outcome"] == "not_found"

    outdated = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0002", "--dry-run", "--json")
    assert outdated.exit_code == 1
    assert json.loads(outdated.stdout)["results"][0]["outcome"] == "not_found"


def test_targets_require_an_observation_in_the_variants_current_scans(app, ids):
    """Like the web UI: a package still in the active SBOM is not a target if only an older scan found the CVE."""
    from datetime import datetime, timedelta, timezone
    from uuid import UUID

    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.scan import Scan
    from src.models.vulnerability import Vulnerability

    with app.app_context():
        now = datetime.now(timezone.utc)
        for vuln_id, name, age in (("CVE-2024-0005", "openssl", 2), ("CVE-2024-0006", "zlib", 1)):
            Vulnerability.create_record(id=vuln_id, description=vuln_id)
            scan = Scan.create(f"grype-{age}", UUID(ids["x86"]), scan_type="tool", scan_source="grype")
            scan.timestamp = now - timedelta(hours=age)
            package = Package.find_or_create(name, {"openssl": "3.0", "zlib": "1.2"}[name], [], [], "")
            _db.session.commit()
            Observation.create(Finding.get_or_create(package.id, vuln_id).id, scan.id)
        _db.session.commit()

    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0005", "--cve", "CVE-2024-0006",
                     "--dry-run", "--json")
    historical, current = json.loads(result.stdout)["results"]
    assert historical["outcome"] == "not_found" and historical["targets"] == []
    assert current["outcome"] == "planned"
    assert [(t["variant"], t["package"]) for t in current["targets"]] == [("x86", "zlib@1.2")]


def test_targets_require_the_exact_package_in_the_active_sbom(app, ids):
    """A finding on lib@1::VendorA is not a target when the active SBOM only holds lib@1::VendorB."""
    from uuid import UUID

    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.scan import Scan
    from src.models.vulnerability import Vulnerability

    with app.app_context():
        Vulnerability.create_record(id="CVE-2024-0005", description="CVE-2024-0005")
        vendor_a = Package.find_or_create("lib", "1", [], [], "", "VendorA")
        vendor_b = Package.find_or_create("lib", "1", [], [], "", "VendorB")
        _db.session.commit()
        document = _db.session.scalars(_db.select(SBOMDocument).join(Scan, Scan.id == SBOMDocument.scan_id)
                                       .where(Scan.variant_id == UUID(ids["x86"]))).one()
        SBOMPackage.create(document.id, vendor_b.id)
        scan = Scan.create("grype", UUID(ids["x86"]), scan_type="tool", scan_source="grype")
        _db.session.commit()
        Observation.create(Finding.get_or_create(vendor_a.id, "CVE-2024-0005").id, scan.id)
        _db.session.commit()

    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0005", "--dry-run", "--json")
    assert result.exit_code == 1, result.stdout + result.stderr
    [entry] = json.loads(result.stdout)["results"]
    assert entry["outcome"] == "not_found" and entry["targets"] == []


def test_filter_selects_quietly(app, ids):
    result = _invoke(app, "--project", "demo", "--variant", "arm", "--filter", "pending", "--dry-run")
    assert result.exit_code == 0, result.stderr
    assert "CVE-2024-0001" in result.stdout and "planned" in result.stdout
    assert "triggered fail condition" not in result.stdout


def test_filter_without_matches_succeeds(app, ids):
    result = _invoke(app, "--project", "demo", "--filter", "cvss >= 9", "--dry-run")
    assert result.exit_code == 0, result.stderr
    assert "No vulnerabilities matched." in result.stdout


def test_filter_skips_vulnerabilities_without_active_targets_in_scope(app, ids):
    """A finding seen only by an older scan, or only by another project sharing the package, is not selected."""
    from datetime import datetime, timedelta, timezone
    from uuid import UUID

    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.project import Project
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.scan import Scan
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability

    with app.app_context():
        for vuln_id in ("CVE-2024-0005", "CVE-2024-0007"):
            Vulnerability.create_record(id=vuln_id, description=vuln_id)
        openssl = Package.find_or_create("openssl", "3.0", [], [], "")
        _db.session.commit()
        now = datetime.now(timezone.utc)
        for age in (2, 1):
            scan = Scan.create(f"grype-{age}", UUID(ids["x86"]), scan_type="tool", scan_source="grype")
            scan.timestamp = now - timedelta(hours=age)
            if age == 2:
                Observation.create(Finding.get_or_create(openssl.id, "CVE-2024-0005").id, scan.id)
        other = Variant.create("main", Project.create("other").id)
        scan = Scan.create("other-scan", other.id, scan_type="sbom")
        document = SBOMDocument.create(path="/sbom/other.json", source_name="cdx", scan_id=scan.id)
        SBOMPackage.create(document.id, openssl.id)
        Observation.create(Finding.get_or_create(openssl.id, "CVE-2024-0007").id, scan.id)
        _db.session.commit()

    result = _invoke(app, "--project", "demo", "--filter", "pending", "--dry-run", "--json")
    assert result.exit_code == 0, result.stdout + result.stderr
    selected = [entry["id"] for entry in json.loads(result.stdout)["results"]]
    assert "CVE-2024-0001" in selected
    assert "CVE-2024-0005" not in selected and "CVE-2024-0007" not in selected


def test_filter_assesses_only_the_variants_that_matched(app, ids):
    """x86 matches only through a historical finding; arm's active finding is fixed, so nothing is selected."""
    from datetime import datetime, timedelta, timezone
    from uuid import UUID

    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.scan import Scan
    from src.models.vulnerability import Vulnerability

    with app.app_context():
        Vulnerability.create_record(id="CVE-2024-0005", description="CVE-2024-0005")
        finding = Finding.get_or_create(Package.find_or_create("openssl", "3.0", [], [], "").id, "CVE-2024-0005")
        now = datetime.now(timezone.utc)
        for age in (2, 1):
            scan = Scan.create(f"grype-{age}", UUID(ids["x86"]), scan_type="tool", scan_source="grype")
            scan.timestamp = now - timedelta(hours=age)
            if age == 2:
                Observation.create(finding.id, scan.id)
        arm_scan = _db.session.scalars(_db.select(Scan).where(Scan.variant_id == UUID(ids["arm"]))).one()
        Observation.create(finding.id, arm_scan.id)
        Assessment.create(status="fixed", origin="custom", targets=[(UUID(ids["arm"]), finding.id)])
        _db.session.commit()

    planned = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0005", "--dry-run", "--json")
    assert [(t["variant"], t["package"]) for t in json.loads(planned.stdout)["results"][0]["targets"]] == [
        ("arm", "openssl@3.0")]
    result = _invoke(app, "--project", "demo", "--filter", "pending", "--dry-run", "--json")
    assert result.exit_code == 0, result.stdout + result.stderr
    assert "CVE-2024-0005" not in [entry["id"] for entry in json.loads(result.stdout)["results"]]
    fixed = json.loads(_invoke(app, "--project", "demo", "--filter", "fixed", "--dry-run", "--json").stdout)
    assert [(entry["id"], [t["variant"] for t in entry["targets"]]) for entry in fixed["results"]] == [
        ("CVE-2024-0005", ["arm"])]


def test_invalid_filter_exits_1(app, ids):
    result = _invoke(app, "--project", "demo", "--filter", "pending and", "--dry-run")
    assert result.exit_code == 1
    assert "Invalid filter" in result.stderr


def test_prompt_matches_web_wording():
    from src.bin.cmd_ai_assess import Target, build_prompts

    targets = [Target("v1", "x86", "p", "openssl@3.0", "f1"), Target("v1", "x86", "p", "zlib@1.2", "f2"),
               Target("v2", "arm", "p", "openssl@3.0", "f1")]
    [(prompt, batch)] = build_prompts("CVE-2024-0001", targets)
    assert prompt == (
        "Assess CVE-2024-0001 for exactly these targets (packages listed per variant):\n"
        '- variant "x86" (variant_id v1): openssl@3.0, zlib@1.2\n'
        '- variant "arm" (variant_id v2): openssl@3.0\n'
        "Retrieve the vulnerability details and each variant's merged context with VulnScout MCP first, "
        "then record the result with write_assessment for these targets only.")
    assert batch == targets


def test_prompts_batch_whole_variants_under_the_limit():
    from src.bin.cmd_ai_assess import MESSAGE_LIMIT, Target, build_prompts

    targets = [Target(f"v{v}", f"variant{v}", "p", f"pkg{v}-{i}@1.0", f"f{v}-{i}")
               for v in range(4) for i in range(150)]
    prompts = build_prompts("CVE-2024-0001", targets)
    assert len(prompts) > 1
    assert all(len(prompt) <= MESSAGE_LIMIT for prompt, _ in prompts)
    assert prompts[0][0].startswith(f"Assess CVE-2024-0001 (batch 1 of {len(prompts)}) for")
    assert [t for _, batch in prompts for t in batch] == targets
    batch_of = {}
    for number, (_, batch) in enumerate(prompts):
        for target in batch:
            assert batch_of.setdefault(target.variant_id, number) == number  # variants are never split


def test_oversized_variant_is_rejected():
    from src.bin.cmd_ai_assess import Target, build_prompts

    targets = [Target("v1", "huge", "p", f"package-{i}@1.0", f"f{i}") for i in range(1000)]
    with pytest.raises(ValueError, match="Too many packages for variant huge"):
        build_prompts("CVE-2024-0001", targets)


@pytest.mark.parametrize("owner, removed", [("self", True), ("other", False)])
def test_pid_file_is_removed_only_when_it_names_this_process(app, ids, monkeypatch, tmp_path, owner, removed):
    import os

    pid_file = tmp_path / "vulnscout-ai-assess-run.pid"
    pid_file.write_text(f"{os.getpid() if owner == 'self' else 1}\n")
    monkeypatch.setenv("VULNSCOUT_AI_ASSESS_PID_FILE", str(pid_file))
    _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--dry-run")
    assert pid_file.exists() is not removed


def test_dry_run_reports_model_and_unbatchable_variants(app, ids, monkeypatch):
    from src.bin import cmd_ai_assess

    monkeypatch.setattr(cmd_ai_assess, "PROMPT_BUDGET", 10)
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--dry-run", "--model", "m1")
    assert result.exit_code == 1
    assert "failed" in result.stdout and "Too many packages for variant" in result.stdout
    assert "Model: m1" in result.stdout


def _fake_reply(monkeypatch, behaviour):
    """Replace agent._reply; *behaviour(call)* may write assessments, raise, or return a reply string."""
    from src.routes import agent

    calls = []

    async def fake(conversation, message, path, model, scope, publish=None, **kwargs):
        call = {"message": message, "model": model, "scope": json.loads(scope), "token": conversation.credentials.token,
                "provider": conversation.credentials.provider, **kwargs}
        calls.append(call)
        reply = behaviour(call)
        return reply or "done", {"cost": 1.0, "input_tokens": 10, "output_tokens": 5}

    monkeypatch.setattr(agent, "_reply", fake)
    return calls


PACKAGES = {"openssl": "openssl@3.0", "zlib": "zlib@1.2", "curl": "curl@8.0", "libxml2": "libxml2@2.9"}


def _write_ai(call, variant_id, name):
    """Write an AI assessment as the agent does: write_assessment through this run's private API."""
    import urllib.request

    vuln_id = call["message"].split()[1]
    payload = {"status": "not_affected", "justification": "component_not_present", "ai_generated": True,
               "targets": [{"package": PACKAGES[name], "variant_id": variant_id}]}
    request = urllib.request.Request(
        f"{call['api_url']}/api/vulnerabilities/{vuln_id}/assessments",
        data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        assert response.status == 200


def _store_ai(variant_id, finding_id):
    """An AI assessment saved outside this run, e.g. by the web agent."""
    from uuid import UUID
    from src.models.assessment import Assessment

    Assessment.create(status="not_affected", origin="ai", targets=[(UUID(variant_id), UUID(finding_id))])
    _db.session.commit()


def test_run_assesses_every_target_with_assess_tools(app, ids, monkeypatch):
    from src.routes import agent

    def write_all(call):
        for target_variant in call["scope"]["variant_ids"]:
            _write_ai(call, target_variant, "openssl")
        if ids["x86"] in call["scope"]["variant_ids"]:
            _write_ai(call, ids["x86"], "zlib")

    calls = _fake_reply(monkeypatch, write_all)
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--timeout", "30", "--json")

    assert result.exit_code == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["model"] == "test-model"
    [entry] = report["results"]
    assert entry["outcome"] == "assessed" and entry["error"] is None
    assert all(target["written"] for target in entry["targets"])
    with app.app_context():
        from src.models.assessment import Assessment

        saved = {str(row.id) for row in Assessment.get_by_vulnerability("CVE-2024-0001") if row.origin == "ai"}
    reported = {row_id for target in entry["targets"] for row_id in target["assessment_ids"]}
    assert reported == saved and all(len(target["assessment_ids"]) == 1 for target in entry["targets"])
    assert entry["usage"] == {"cost": 1.0, "input_tokens": 10, "output_tokens": 5}
    [call] = calls
    assert call["message"].startswith("Assess CVE-2024-0001 for exactly these targets")
    assert call["tools"] == agent.ASSESS_TOOLS and call["timeout"] == 30 and call["ephemeral"] is True
    assert call["api_url"].startswith("http://127.0.0.1:")
    assert call["token"] == "gho_test" and call["model"] == "test-model"
    assert call["scope"]["project_ids"] == [ids["demo"]]
    assert call["scope"]["variant_ids"] == sorted([ids["x86"], ids["arm"]])
    assert sorted((t["vuln_id"], t["variant_id"], t["package"]) for t in call["scope"]["write_targets"]) == sorted([
        ("CVE-2024-0001", ids["x86"], "openssl@3.0"), ("CVE-2024-0001", ids["arm"], "openssl@3.0"),
        ("CVE-2024-0001", ids["x86"], "zlib@1.2")])
    assert "Assessing CVE-2024-0001" in result.stderr


def test_mixed_case_cve_ids_are_assessed_once_under_the_canonical_id(app, ids, monkeypatch):
    statuses = []

    def write_canonical(call):
        for target in call["scope"]["write_targets"]:
            statuses.append(_request(call, "POST", "/api/vulnerabilities/CVE-2024-0001/assessments", {
                "status": "not_affected", "justification": "component_not_present", "ai_generated": True,
                "targets": [{"package": target["package"], "variant_id": target["variant_id"]}]})[0])

    calls = _fake_reply(monkeypatch, write_canonical)
    result = _invoke(app, "--project", "demo", "--cve", "cve-2024-0001", "--cve", "CVE-2024-0001", "--json")

    assert result.exit_code == 0, result.stdout + result.stderr
    [entry] = json.loads(result.stdout)["results"]
    assert entry["id"] == "CVE-2024-0001" and entry["outcome"] == "assessed"
    [call] = calls
    assert call["message"].startswith("Assess CVE-2024-0001 ")
    assert statuses == [200, 200, 200]
    with app.app_context():
        from src.models.assessment import Assessment

        saved = {str(row.id) for row in Assessment.get_by_vulnerability("CVE-2024-0001") if row.origin == "ai"}
    assert {row_id for target in entry["targets"] for row_id in target["assessment_ids"]} == saved


def _request(call, method, path, payload):
    """Send *payload* to this run's private API as the agent's MCP server would; return (status, body)."""
    import urllib.error
    import urllib.request

    request = urllib.request.Request(f"{call['api_url']}{path}", data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_private_api_rejects_writes_outside_the_turns_targets(app, ids, monkeypatch):
    """Only the selected (variant, package) targets of the turn's vulnerability can be written."""
    from datetime import datetime, timedelta, timezone
    from uuid import UUID

    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.scan import Scan

    with app.app_context():
        # An unselected historical package, observed by an older x86 SBOM scan for the selected vulnerability.
        old = Scan.create("x86-old", UUID(ids["x86"]), scan_type="sbom")
        old.timestamp = datetime.now(timezone.utc) - timedelta(days=1)
        package = Package.find_or_create("openssl", "1.1", [], [], "")
        _db.session.commit()
        Observation.create(Finding.get_or_create(package.id, "CVE-2024-0004").id, old.id)
        _db.session.commit()
        _store_ai(ids["x86"], ids["findings"]["openssl"])
    responses = []

    def write(call):
        def post(vuln_id, payload):
            responses.append(_request(call, "POST", f"/api/vulnerabilities/{vuln_id}/assessments", {
                "status": "not_affected", "justification": "component_not_present", "ai_generated": True,
                **payload}))

        post("CVE-2024-0001", {"targets": [{"package": "openssl@3.0", "variant_id": ids["x86"]}]})
        post("CVE-2024-0004", {"targets": [{"package": "openssl@1.1", "variant_id": ids["x86"]}]})
        post("CVE-2024-0004", {"packages": ["libxml2@2.9", "openssl@1.1"], "variant_id": ids["x86"]})
        responses.append(_request(call, "PUT", f"/api/variants/{ids['x86']}/context", {"description": "x"}))
        post("CVE-2024-0004", {"targets": [{"package": "libxml2@2.9", "variant_id": ids["x86"]}]})

    _fake_reply(monkeypatch, write)
    result = _invoke(app, "--project", "demo", "--variant", "x86", "--cve", "CVE-2024-0004", "--json")

    assert result.exit_code == 0, result.stdout + result.stderr
    assert [status for status, _body in responses] == [403, 403, 403, 403, 200]
    assert "only write AI assessments for its listed targets" in responses[0][1]["error"]
    with app.app_context():
        def ai_findings(vuln_id):
            return [{str(target.finding_id) for target in row.target_rows}
                    for row in Assessment.get_by_vulnerability(vuln_id) if row.origin == "ai"]

        assert ai_findings("CVE-2024-0001") == [{ids["findings"]["openssl"]}]
        assert ai_findings("CVE-2024-0004") == [{ids["findings"]["libxml2"]}]


@pytest.mark.parametrize("writes, outcome", [("some", "partial"), ("none", "no_write")])
def test_missing_writes_fail_the_run(app, ids, monkeypatch, writes, outcome):
    def write(call):
        if writes == "some":
            _write_ai(call, ids["arm"], "openssl")

    _fake_reply(monkeypatch, write)
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--json")
    assert result.exit_code == 1
    [entry] = json.loads(result.stdout)["results"]
    assert entry["outcome"] == outcome
    assert {(t["variant"], t["package"], t["written"], bool(t["assessment_ids"])) for t in entry["targets"]} == {
        ("arm", "openssl@3.0", writes == "some", writes == "some"),
        ("x86", "openssl@3.0", False, False), ("x86", "zlib@1.2", False, False)}


def test_text_summary_lists_saved_ids_and_unwritten_targets(app, ids, monkeypatch):
    from src.models.assessment import Assessment

    _fake_reply(monkeypatch, lambda call: _write_ai(call, ids["arm"], "openssl"))
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001")
    assert result.exit_code == 1
    with app.app_context():
        [saved] = [str(row.id) for row in Assessment.get_by_vulnerability("CVE-2024-0001") if row.origin == "ai"]
    assert "CVE-2024-0001  partial  1/3 targets" in result.stdout
    assert f"    arm / openssl@3.0  written  {saved}" in result.stdout
    assert "    x86 / openssl@3.0  not written" in result.stdout
    assert "    x86 / zlib@1.2  not written" in result.stdout


def test_concurrent_ai_assessment_does_not_count_as_written(app, ids, monkeypatch):
    """Another writer (web agent, other run) saving the same target during the turn is not this run's write."""
    def outside_write(call):
        _store_ai(ids["arm"], ids["findings"]["openssl"])

    _fake_reply(monkeypatch, outside_write)
    result = _invoke(app, "--project", "demo", "--variant", "arm", "--cve", "CVE-2024-0001", "--json")
    assert result.exit_code == 1
    [entry] = json.loads(result.stdout)["results"]
    assert entry["outcome"] == "no_write" and entry["targets"][0]["assessment_ids"] == []


def test_replaced_write_in_the_same_turn_reports_the_saved_row(app, ids, monkeypatch):
    def write_twice(call):
        _write_ai(call, ids["arm"], "openssl")
        _write_ai(call, ids["arm"], "openssl")

    _fake_reply(monkeypatch, write_twice)
    result = _invoke(app, "--project", "demo", "--variant", "arm", "--cve", "CVE-2024-0001", "--json")
    assert result.exit_code == 0, result.stdout + result.stderr
    from src.models.assessment import Assessment
    with app.app_context():
        [saved] = [str(row.id) for row in Assessment.get_by_vulnerability("CVE-2024-0001") if row.origin == "ai"]
    assert json.loads(result.stdout)["results"][0]["targets"][0]["assessment_ids"] == [saved]


def test_earlier_ai_assessment_does_not_count_as_written(app, ids, monkeypatch):
    with app.app_context():
        _store_ai(ids["arm"], ids["findings"]["openssl"])
    _fake_reply(monkeypatch, lambda call: None)
    result = _invoke(app, "--project", "demo", "--variant", "arm", "--cve", "CVE-2024-0001", "--json")
    assert result.exit_code == 1
    assert json.loads(result.stdout)["results"][0]["outcome"] == "no_write"


@pytest.mark.parametrize("error, outcome", [
    (__import__("asyncio").TimeoutError(), "timeout"),
    (RuntimeError("provider down"), "failed"),
])
def test_turn_errors_continue_with_next_cve(app, ids, monkeypatch, error, outcome):
    def behaviour(call):
        if "CVE-2024-0001" in call["message"]:
            raise error
        _write_ai(call, ids["x86"], "curl")

    _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--variant", "x86",
                     "--cve", "CVE-2024-0001", "--cve", "CVE-2024-0003", "--json")
    assert result.exit_code == 1
    first, second = json.loads(result.stdout)["results"]
    assert first["outcome"] == outcome and first["error"]
    assert second["outcome"] == "assessed"


def test_unavailable_model_aborts(app, ids, monkeypatch):
    from src.routes import agent

    def unavailable(call):
        raise agent.UnavailableModelError("Selected model is not available for this account.")

    calls = _fake_reply(monkeypatch, unavailable)
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--cve", "CVE-2024-0003",
                     "--model", "nope")
    assert result.exit_code == 1
    assert "not available" in result.stderr
    assert len(calls) == 1


@pytest.mark.parametrize("status, message", [
    ({"authenticated": False, "login": None}, "GitHub Copilot rejected the configured token"),
    (RuntimeError("CLI exited"), "Could not check the GitHub Copilot sign-in: CLI exited"),
])
def test_unusable_github_token_aborts_before_any_turn(app, ids, monkeypatch, status, message):
    from src.routes import agent

    async def token_status(token):
        if isinstance(status, Exception):
            raise status
        return status

    monkeypatch.setattr(agent, "_token_status", token_status)
    calls = _fake_reply(monkeypatch, lambda call: None)
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--cve", "CVE-2024-0004")
    assert result.exit_code == 1
    assert message in result.stderr
    assert calls == []


@pytest.fixture()
def production_signals():
    """Install webapp.py's stop handler, as importing it does for `flask --app src.bin.webapp ai-assess`."""
    from src.bin import webapp

    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
    for signum in previous:
        signal.signal(signum, webapp.stop_handler)
    yield webapp.stop_handler
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def _ctrl_c():
    """Deliver a real SIGINT, as the host wrapper forwards Ctrl-C to the pidfile's process."""
    os.kill(os.getpid(), signal.SIGINT)
    time.sleep(5)
    raise AssertionError("SIGINT did not interrupt")


def test_sigint_stops_the_run_and_reports(app, ids, monkeypatch, production_signals):
    sigterm_handlers = []

    def behaviour(call):
        sigterm_handlers.append(signal.getsignal(signal.SIGTERM))
        if "CVE-2024-0003" in call["message"]:
            _write_ai(call, ids["x86"], "curl")  # written before Ctrl-C arrived
            _ctrl_c()
        if "CVE-2024-0004" in call["message"]:
            raise AssertionError("no turn may start after an interrupt")
        _write_ai(call, ids["x86"], "openssl")
        _write_ai(call, ids["x86"], "zlib")

    _fake_reply(monkeypatch, behaviour)
    result = _invoke(app, "--project", "demo", "--variant", "x86",
                     "--cve", "CVE-2024-0001", "--cve", "CVE-2024-0003", "--cve", "CVE-2024-0004", "--json")
    assert result.exit_code == 1
    assert "Stopping Flask server" not in result.stdout
    first, second, third = json.loads(result.stdout)["results"]
    assert first["outcome"] == "assessed"
    assert second["outcome"] == "interrupted" and second["error"] == "Interrupted."
    assert [t["written"] for t in second["targets"]] == [True]
    assert third["outcome"] == "interrupted" and third["error"] == "Not started."
    assert "Interrupted" in result.stderr
    # The wrapper's second Ctrl-C arrives as SIGTERM and must stop at once.
    assert sigterm_handlers == [signal.SIG_DFL, signal.SIG_DFL]
    assert signal.getsignal(signal.SIGINT) is production_signals


def test_sigint_is_reported_when_cancellation_cleanup_fails(app, ids, monkeypatch, production_signals):
    from src.routes import agent

    calls = []

    async def fake(conversation, message, *args, **kwargs):
        calls.append(message)
        try:
            os.kill(os.getpid(), signal.SIGINT)
            await asyncio.sleep(5)
        finally:
            raise RuntimeError("disconnect failed")

    monkeypatch.setattr(agent, "_reply", fake)
    result = _invoke(app, "--project", "demo", "--variant", "x86",
                     "--cve", "CVE-2024-0001", "--cve", "CVE-2024-0003", "--json")
    assert result.exit_code == 1
    first, second = json.loads(result.stdout)["results"]
    assert first["outcome"] == "interrupted" and first["error"] == "Interrupted."
    assert second["outcome"] == "interrupted" and second["error"] == "Not started."
    assert len(calls) == 1


def test_sigint_after_a_turn_marks_its_cve_interrupted(app, ids, monkeypatch, production_signals):
    from src.bin import cmd_ai_assess

    snapshots = []

    def interrupting(row_ids):
        snapshots.append(row_ids)
        if len(snapshots) == 1:  # the first CVE's post-turn check
            _ctrl_c()
        return original(row_ids)

    original = cmd_ai_assess._ai_targets
    monkeypatch.setattr(cmd_ai_assess, "_ai_targets", interrupting)
    calls = _fake_reply(monkeypatch, lambda call: None)
    result = _invoke(app, "--project", "demo", "--variant", "x86",
                     "--cve", "CVE-2024-0001", "--cve", "CVE-2024-0003", "--json")
    assert result.exit_code == 1
    first, second = json.loads(result.stdout)["results"]
    assert first["outcome"] == "interrupted" and first["error"] == "Interrupted."
    assert second["outcome"] == "interrupted" and second["error"] == "Not started."
    assert len(calls) == 1


@pytest.mark.parametrize("config, message", [
    ("", "Connect an AI provider"),
    ("AI_PROVIDER=github\n", "AI_AUTH_CREDENTIALS is required"),
    ("AI_PROVIDER=openai\nAI_AUTH_CREDENTIALS=sk-test\n", "No AI model configured"),
])
def test_ai_configuration_errors(app, ids, monkeypatch, tmp_path, config, message):
    from src.routes import agent

    (tmp_path / "config.env").write_text(config)
    monkeypatch.setattr(agent, "_fetch_provider_models",
                        lambda connection, base_url: b'{"data": [{"id": "gpt-x"}]}')
    calls = _fake_reply(monkeypatch, lambda call: None)
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001")
    assert result.exit_code == 1
    assert message in result.stderr
    assert calls == []


def test_private_api_write_replaces_pending_ai_assessment(app, ids, monkeypatch):
    """End to end through the private API: the second run replaces the first pending AI assessment."""
    import urllib.request

    def post(call):
        payload = {"status": "not_affected", "justification": "component_not_present", "ai_generated": True,
                   "targets": [{"package": "openssl@3.0", "variant_id": ids["arm"]}]}
        request = urllib.request.Request(
            f"{call['api_url']}/api/vulnerabilities/CVE-2024-0001/assessments",
            data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=10) as response:
            assert response.status in (200, 201)

    _fake_reply(monkeypatch, post)
    for _ in range(2):
        result = _invoke(app, "--project", "demo", "--variant", "arm", "--cve", "CVE-2024-0001", "--json")
        assert result.exit_code == 0, result.stdout + result.stderr
        assert json.loads(result.stdout)["results"][0]["outcome"] == "assessed"

    from src.models.assessment import Assessment
    with app.app_context():
        ai_rows = [row for row in Assessment.get_by_vulnerability("CVE-2024-0001") if row.origin == "ai"]
    assert len(ai_rows) == 1


def test_missing_mcp_server_aborts(app, ids, monkeypatch, tmp_path):
    monkeypatch.setenv("VULNSCOUT_MCP_SERVER_PATH", str(tmp_path / "missing.py"))
    calls = _fake_reply(monkeypatch, lambda call: None)
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001")
    assert result.exit_code == 1
    assert "Bundled MCP server not found" in result.stderr
    assert calls == []


def test_run_without_turns_still_reports_the_model(app, ids, monkeypatch):
    calls = _fake_reply(monkeypatch, lambda call: None)
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0002", "--json")
    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["model"] == "test-model"
    assert report["results"][0]["outcome"] == "not_found"
    assert calls == []


def test_run_without_matches_needs_no_ai_configuration(app, ids, monkeypatch, tmp_path):
    (tmp_path / "config.env").write_text("")
    calls = _fake_reply(monkeypatch, lambda call: None)
    result = _invoke(app, "--project", "demo", "--filter", "cvss >= 9", "--json")
    assert result.exit_code == 0, result.stderr
    assert json.loads(result.stdout) == {"model": None, "scope": {"project": "demo", "variants": None},
                                         "results": []}
    assert calls == []


def test_model_override_applies_to_a_configured_provider_model(app, ids, monkeypatch, tmp_path):
    from src.routes import agent

    config = tmp_path / "config.env"
    config.write_text("AI_PROVIDER=openai\nAI_AUTH_CREDENTIALS=sk-test\nAI_MODEL=gpt-configured\n")
    monkeypatch.setattr(agent, "_fetch_provider_models", lambda connection, base_url: pytest.fail("listed models"))
    calls = _fake_reply(monkeypatch, lambda call: _write_ai(call, ids["arm"], "openssl"))
    result = _invoke(app, "--project", "demo", "--variant", "arm", "--cve", "CVE-2024-0001",
                     "--model", "gpt-other", "--json")
    assert result.exit_code == 0, result.stderr
    assert json.loads(result.stdout)["model"] == "gpt-other"
    [call] = calls
    assert call["model"] == "gpt-other"
    assert call["provider"].model == "gpt-other"
    assert [choice["id"] for choice in call["provider"].models] == ["gpt-other"]
    assert "AI_MODEL=gpt-configured" in config.read_text()


def test_unbatchable_variant_fails_without_a_turn(app, ids, monkeypatch):
    from src.bin import cmd_ai_assess

    monkeypatch.setattr(cmd_ai_assess, "PROMPT_BUDGET", 10)
    calls = _fake_reply(monkeypatch, lambda call: None)
    result = _invoke(app, "--project", "demo", "--cve", "CVE-2024-0001", "--json")
    assert result.exit_code == 1
    [entry] = json.loads(result.stdout)["results"]
    assert entry["outcome"] == "failed" and "Too many packages for variant" in entry["error"]
    assert calls == []


def test_variant_active_packages_filters_by_project(app, ids):
    from uuid import UUID, uuid4

    from src.helpers.active_targets import variant_active_packages

    with app.app_context():
        demo = variant_active_packages("CVE-2024-0001", project_uuid=UUID(ids["demo"]))
        other = variant_active_packages("CVE-2024-0001", project_uuid=uuid4())
    assert sorted(entry["variant_id"] for entry in demo) == sorted([ids["x86"], ids["arm"]])
    assert other == []

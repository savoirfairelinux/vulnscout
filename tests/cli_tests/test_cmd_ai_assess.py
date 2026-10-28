# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Tests for ``flask ai-assess`` and its helpers."""

import json

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
    assert not any(t["written"] for t in entry["targets"])

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

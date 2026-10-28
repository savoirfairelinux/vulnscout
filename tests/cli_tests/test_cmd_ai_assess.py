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

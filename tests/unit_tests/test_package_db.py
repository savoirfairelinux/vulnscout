# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""DB-backed tests for Package supplier identity."""

import pytest
from src.bin.webapp import create_app
from src.extensions import db as _db
from src.models.package import Package
from src.models.project import Project
from src.models.variant import Variant
from src.models.scan import Scan


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("SCAN_FILE", "/dev/null")
    application = create_app()
    application.config.update({"TESTING": True})
    with application.app_context():
        _db.create_all()
        yield application
        _db.drop_all()


def test_find_or_create_different_supplier_creates_new_row(app):
    pkg_a = Package.find_or_create("foo", "1.0", supplier="Organization: Acme Corp")
    pkg_b = Package.find_or_create("foo", "1.0", supplier="Organization: Bar Inc")
    pkg_none = Package.find_or_create("foo", "1.0")
    _db.session.flush()
    assert pkg_a.id != pkg_b.id
    assert pkg_a.id != pkg_none.id
    assert pkg_b.id != pkg_none.id


def test_find_or_create_same_supplier_returns_same_row(app):
    pkg_a = Package.find_or_create("foo", "1.0", supplier="Organization: Acme Corp")
    _db.session.flush()
    pkg_b = Package.find_or_create("foo", "1.0", supplier="Organization: Acme Corp")
    assert pkg_a.id == pkg_b.id


def test_get_by_string_id_with_supplier(app):
    Package.find_or_create("foo", "1.0", supplier="Organization: Acme Corp (x@a.com)")
    _db.session.flush()
    found = Package.get_by_string_id("foo@1.0::Organization: Acme Corp (x@a.com)")
    assert found is not None
    assert found.supplier == "Organization: Acme Corp (x@a.com)"


def test_get_by_string_id_email_at_sign_doesnt_corrupt(app):
    """@ in supplier email must not corrupt name/version split."""
    Package.find_or_create("foo", "1.0", supplier="Organization: Acme Corp (contact@acme.com)")
    _db.session.flush()
    found = Package.get_by_string_id("foo@1.0::Organization: Acme Corp (contact@acme.com)")
    assert found is not None
    assert found.name == "foo"
    assert found.version == "1.0"


def test_get_by_string_id_backward_compat(app):
    """Old name@version string_ids (no ::) still resolve correctly."""
    Package.find_or_create("foo", "1.0")
    _db.session.flush()
    found = Package.get_by_string_id("foo@1.0")
    assert found is not None
    assert found.name == "foo"
    assert found.supplier == ""


def test_bulk_find_or_create_with_suppliers(app):
    items = [
        {"name": "foo", "version": "1.0", "supplier": "Organization: Acme Corp"},
        {"name": "foo", "version": "1.0", "supplier": "Organization: Bar Inc"},
        {"name": "bar", "version": "2.0"},
    ]
    result = Package.bulk_find_or_create(items)
    assert len(result) == 3
    acme_key = "foo@1.0::Organization: Acme Corp"
    bar_key = "foo@1.0::Organization: Bar Inc"
    plain_key = "bar@2.0"
    assert acme_key in result
    assert bar_key in result
    assert plain_key in result
    assert result[acme_key].id != result[bar_key].id


@pytest.mark.parametrize("versions", [
    ("1_1.0.0", "1.0.0"),
    ("1.0.0", "1_1.0.0"),
])
def test_same_sbom_epoch_and_bare_version_share_package(app, versions):
    from src.controllers.packages import PackagesController
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("epoch-project")
    variant = Variant.create("epoch-variant", project.id)
    scan = Scan.create("epoch-scan", variant.id, scan_type="sbom")
    document = SBOMDocument.create("epoch.spdx.json", "spdx", scan.id)
    ctrl = PackagesController()
    ctrl.current_sbom_document = document
    for version in versions:
        ctrl.add(Package("mesa", version))

    linked = _db.session.query(SBOMPackage).filter_by(sbom_document_id=document.id).all()
    assert len(linked) == 1
    assert linked[0].package.version == "1_1.0.0"
    assert ctrl.get("mesa@1.0.0").id == linked[0].package_id
    assert ctrl.get_or_resolve_db_id("mesa@1.0.0") == linked[0].package_id


def test_epoch_versions_and_suppliers_remain_distinct(app):
    from src.controllers.packages import PackagesController
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("epochs-project")
    variant = Variant.create("epochs-variant", project.id)
    scan = Scan.create("epochs-scan", variant.id, scan_type="sbom")
    document = SBOMDocument.create("epochs.spdx.json", "spdx", scan.id)
    ctrl = PackagesController()
    ctrl.current_sbom_document = document
    for name, version, supplier in [
        ("pixman", "1_1.0.0", ""),
        ("pixman", "2_1.0.0", ""),
        ("pixman", "1.0.0", ""),
        ("pixman", "3_1.0.0", ""),
        ("pixman", "1_1.0.0", "Organization: Other"),
        ("pixman", "1_1.1.0", ""),
        ("pixman", "1_1.0.0-rc1", ""),
    ]:
        ctrl.add(Package(name, version, supplier=supplier))

    linked = SBOMPackage.get_by_document(document.id)
    assert {link.package.string_id for link in linked} == {
        "pixman@1_1.0.0", "pixman@2_1.0.0", "pixman@3_1.0.0", "pixman@1.0.0",
        "pixman@1_1.0.0::Organization: Other", "pixman@1_1.1.0",
        "pixman@1_1.0.0-rc1",
    }


def test_bare_version_stops_aliasing_when_multiple_epochs_match(app):
    from src.controllers.packages import PackagesController
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("ambiguous-project")
    variant = Variant.create("ambiguous-variant", project.id)
    scan = Scan.create("ambiguous-scan", variant.id, scan_type="sbom")
    document = SBOMDocument.create("ambiguous.spdx.json", "spdx", scan.id)
    ctrl = PackagesController()
    ctrl.current_sbom_document = document
    ctrl.add(Package("mesa", "1.0.0"))
    ctrl.add(Package("mesa", "1_1.0.0"))
    ctrl.add(Package("mesa", "2_1.0.0"))
    restored_id = ctrl.get_or_resolve_db_id("mesa@1.0.0")
    assert restored_id is not None
    bare = ctrl.add(Package("mesa", "1.0.0"))

    linked = {link.package.string_id: link.package_id for link in SBOMPackage.get_by_document(document.id)}
    assert set(linked) == {"mesa@1_1.0.0", "mesa@2_1.0.0", "mesa@1.0.0"}
    assert bare.id == restored_id
    assert bare.id == linked["mesa@1.0.0"]
    assert ctrl.get("mesa@1.0.0").id == bare.id
    assert ctrl.get_or_resolve_db_id("mesa@1.0.0") == bare.id


@pytest.mark.parametrize("versions", [
    ("1.0.0", "1_1.0.0", "2_1.0.0"),
    ("1_1.0.0", "1.0.0", "2_1.0.0"),
    ("2_1.0.0", "1_1.0.0", "1.0.0"),
])
def test_ambiguous_bare_version_survives_without_readding(app, versions):
    from src.controllers.packages import PackagesController
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("ambiguous-order-project")
    variant = Variant.create("ambiguous-order-variant", project.id)
    scan = Scan.create("ambiguous-order-scan", variant.id, scan_type="sbom")
    document = SBOMDocument.create("ambiguous-order.spdx.json", "spdx", scan.id)
    ctrl = PackagesController()
    ctrl.current_sbom_document = document
    for version in versions:
        ctrl.add(Package(
            "mesa", version, [f"cpe:2.3:a:mesa:mesa:{version}:*:*:*:*:*:*:*"],
            [f"pkg:generic/mesa@{version}"], "MIT" if version == "1.0.0" else "Apache-2.0",
        ))
        if version == "1_1.0.0":
            ctrl.add(Package(
                "mesa", version, ["cpe:2.3:a:mesa:mesa:1_1.0.0:extra:*:*:*:*:*:*"],
                ["pkg:generic/mesa-extra@1_1.0.0"],
            ))

    linked = {link.package.string_id: link.package for link in SBOMPackage.get_by_document(document.id)}
    assert set(linked) == {"mesa@1.0.0", "mesa@1_1.0.0", "mesa@2_1.0.0"}
    for version in versions:
        package = linked[f"mesa@{version}"]
        expected_cpe = [f"cpe:2.3:a:mesa:mesa:{version}:*:*:*:*:*:*:*"]
        expected_purl = [f"pkg:generic/mesa@{version}"]
        if version == "1_1.0.0":
            expected_cpe.append("cpe:2.3:a:mesa:mesa:1_1.0.0:extra:*:*:*:*:*:*")
            expected_purl.append("pkg:generic/mesa-extra@1_1.0.0")
        assert package.cpe == expected_cpe
        assert package.purl == expected_purl
        assert package.licences == ("MIT" if version == "1.0.0" else "Apache-2.0")
    assert ctrl.get_or_resolve_db_id("mesa@1.0.0") is not None


def test_ambiguous_document_preserves_existing_epoch_metadata(app):
    from src.controllers.packages import PackagesController
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("shared-epoch-project")
    variant = Variant.create("shared-epoch-variant", project.id)
    scan = Scan.create("shared-epoch-scan", variant.id, scan_type="sbom")
    older = SBOMDocument.create("older.spdx.json", "spdx", scan.id)
    newer = SBOMDocument.create("newer.spdx.json", "spdx", scan.id)
    ctrl = PackagesController()
    ctrl.current_sbom_document = older
    epoch = ctrl.add(Package(
        "mesa", "1_1.0.0", ["cpe:2.3:a:mesa:mesa:1_1.0.0:*:*:*:*:*:*:*"],
        ["pkg:generic/mesa@1_1.0.0"], "Apache-2.0",
    ))
    ctrl.current_sbom_document = newer
    ctrl.add(Package("mesa", "1_1.0.0"))
    ctrl.add(Package(
        "mesa", "1.0.0", ["cpe:2.3:a:mesa:mesa:1.0.0:*:*:*:*:*:*:*"],
        ["pkg:generic/mesa@1.0.0"], "MIT",
    ))
    ctrl.add(Package("mesa", "2_1.0.0"))

    assert {link.package_id for link in SBOMPackage.get_by_document(older.id)} == {epoch.id}
    assert {link.package.version for link in SBOMPackage.get_by_document(newer.id)} == {
        "1.0.0", "1_1.0.0", "2_1.0.0",
    }
    assert epoch.cpe == ["cpe:2.3:a:mesa:mesa:1_1.0.0:*:*:*:*:*:*:*"]
    assert epoch.purl == ["pkg:generic/mesa@1_1.0.0"]
    assert epoch.licences == "Apache-2.0"


def test_ambiguous_document_restores_metadata_to_shared_bare_row(app):
    from src.controllers.packages import PackagesController
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("shared-ambiguity-project")
    variant = Variant.create("shared-ambiguity-variant", project.id)
    scan = Scan.create("shared-ambiguity-scan", variant.id, scan_type="sbom")
    older = SBOMDocument.create("older.spdx.json", "spdx", scan.id)
    newer = SBOMDocument.create("newer.spdx.json", "spdx", scan.id)
    ctrl = PackagesController()
    ctrl.current_sbom_document = older
    bare = ctrl.add(Package("mesa", "1.0.0"))
    ctrl.current_sbom_document = newer
    ctrl.add(Package("mesa", "1_1.0.0"))
    ctrl.add(Package("mesa", "1.0.0", purl=["pkg:generic/mesa@1.0.0"], licences="MIT"))
    ctrl.add(Package("mesa", "2_1.0.0"))

    linked = {link.package.string_id for link in SBOMPackage.get_by_document(newer.id)}
    assert linked == {"mesa@1.0.0", "mesa@1_1.0.0", "mesa@2_1.0.0"}
    assert {link.package_id for link in SBOMPackage.get_by_document(older.id)} == {bare.id}
    assert bare.licences == "MIT"
    assert "pkg:generic/mesa@1.0.0" in bare.purl


def test_epoch_upgrade_does_not_change_package_in_another_document(app):
    from src.controllers.packages import PackagesController
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("shared-project")
    variant = Variant.create("shared-variant", project.id)
    scan = Scan.create("shared-scan", variant.id, scan_type="sbom")
    first = SBOMDocument.create("first.spdx.json", "spdx", scan.id)
    second = SBOMDocument.create("second.spdx.json", "spdx", scan.id)
    ctrl = PackagesController()
    ctrl.current_sbom_document = first
    bare = ctrl.add(Package("mesa", "1.0.0"))
    ctrl.current_sbom_document = second
    ctrl.add(Package("mesa", "1.0.0"))
    epoch = ctrl.add(Package("mesa", "1_1.0.0"))

    assert bare.version == "1.0.0"
    assert epoch.version == "1_1.0.0"
    assert {link.package_id for link in SBOMPackage.get_by_document(first.id)} == {bare.id}
    assert {link.package_id for link in SBOMPackage.get_by_document(second.id)} == {epoch.id}


def test_epoch_upgrade_reuses_existing_epoch_row(app):
    from src.controllers.packages import PackagesController
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("reuse-project")
    variant = Variant.create("reuse-variant", project.id)
    scan = Scan.create("reuse-scan", variant.id, scan_type="sbom")
    first = SBOMDocument.create("epoch.spdx.json", "spdx", scan.id)
    second = SBOMDocument.create("mixed.spdx.json", "spdx", scan.id)
    ctrl = PackagesController()
    ctrl.current_sbom_document = first
    epoch = ctrl.add(Package("mesa", "1_1.0.0"))
    ctrl.current_sbom_document = second
    ctrl.add(Package("mesa", "1.0.0"))
    assert ctrl.add(Package("mesa", "1_1.0.0")).id == epoch.id
    assert {link.package_id for link in SBOMPackage.get_by_document(second.id)} == {epoch.id}
    assert Package.get_by_string_id("mesa@1_1.0.0").id == epoch.id


@pytest.mark.parametrize("shared_bare", [False, True])
def test_existing_epoch_row_retains_bare_metadata_across_documents(app, shared_bare):
    from src.controllers.packages import PackagesController
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("reuse-metadata-project")
    variant = Variant.create("reuse-metadata-variant", project.id)
    scan = Scan.create("reuse-metadata-scan", variant.id, scan_type="sbom")
    older = SBOMDocument.create("older.spdx.json", "spdx", scan.id)
    shared = SBOMDocument.create("shared.spdx.json", "spdx", scan.id) if shared_bare else None
    newer = SBOMDocument.create("newer.spdx.json", "spdx", scan.id)
    ctrl = PackagesController()
    ctrl.current_sbom_document = older
    epoch = ctrl.add(Package("mesa", "1_1.0.0"))
    if shared is not None:
        ctrl.current_sbom_document = shared
        bare = ctrl.add(Package("mesa", "1.0.0"))
    ctrl.current_sbom_document = newer
    ctrl.add(Package(
        "mesa", "1.0.0", ["cpe:2.3:a:mesa:mesa:1.0.0:*:*:*:*:*:*:*"],
        ["pkg:generic/mesa@1.0.0"], "MIT",
    ))
    ctrl.add(Package("mesa", "1_1.0.0"))

    assert {link.package_id for link in SBOMPackage.get_by_document(newer.id)} == {epoch.id}
    if shared is not None:
        assert {link.package_id for link in SBOMPackage.get_by_document(shared.id)} == {bare.id}
        assert bare.version == "1.0.0"
    assert "pkg:generic/mesa@1.0.0" in epoch.purl
    assert "cpe:2.3:a:mesa:mesa:1.0.0:*:*:*:*:*:*:*" in epoch.cpe
    assert epoch.licences == "MIT"


@pytest.mark.parametrize("format_name", ["spdx3", "cdx"])
@pytest.mark.parametrize("versions", [
    ("1.0.0", "1_1.0.0"),
    ("1.0.0", "1_1.0.0", "2_1.0.0"),
    ("1_1.0.0", "1.0.0", "2_1.0.0"),
])
def test_bare_first_sbom_keeps_cve_and_vex_targets(app, format_name, versions):
    from src.controllers.cache import ControllersCache
    from src.models.assessment_target import AssessmentTarget
    from src.models.finding import Finding
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.views.cyclonedx import CycloneDx
    from src.views.fast_spdx3 import FastSPDX3

    project = Project.create(f"{format_name}-cve-project")
    variant = Variant.create("cve-variant", project.id)
    scan = Scan.create("cve-scan", variant.id, scan_type="sbom")
    document = SBOMDocument.create(f"{format_name}.json", format_name, scan.id)
    controllers = ControllersCache()
    controllers.packages.current_sbom_document = document
    controllers.assessments.current_variant_id = variant.id
    controllers.vulnerabilities.current_variant_id = variant.id
    if format_name == "spdx3":
        FastSPDX3(controllers).parse_from_dict({"@graph": [
            {"type": "CreationInfo", "specVersion": "3.0.1"},
            *({"type": "software_Package", "spdxId": f"pkg:{version}",
                "name": "mesa", "software_packageVersion": version}
                            for version in versions),
            {"type": "security_Vulnerability", "spdxId": "vuln:CVE-2024-12345",
             "externalIdentifier": [{"externalIdentifierType": "cve",
                                     "identifier": "CVE-2024-12345"}]},
            {"type": "Relationship", "relationshipType": "hasAssociatedVulnerability",
             "from": "pkg:1.0.0", "to": ["vuln:CVE-2024-12345"]},
            {"type": "security_VexNotAffectedVulnAssessmentRelationship",
             "relationshipType": "doesNotAffect", "from": "vuln:CVE-2024-12345",
             "to": ["pkg:1.0.0"]},
        ]})
    else:
        parser = CycloneDx(controllers)
        parser.load_from_dict({
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [
                {"type": "library", "bom-ref": f"mesa-{version}",
                 "name": "mesa", "version": version}
                for version in versions
            ],
            "vulnerabilities": [{
                "id": "CVE-2024-12345", "bom-ref": "CVE-2024-12345",
                "analysis": {"state": "exploitable"},
                "affects": [{"ref": "mesa-1.0.0"}],
            }],
        })
        parser.parse_and_merge()

    linked = SBOMPackage.get_by_document(document.id)
    expected_version = "1_1.0.0" if len(versions) == 2 else "1.0.0"
    assert len(linked) == (1 if len(versions) == 2 else 3)
    target = next(link for link in linked if link.package.version == expected_version)
    findings = _db.session.execute(_db.select(Finding).where(
        Finding.package_id == target.package_id,
        Finding.vulnerability_id == "CVE-2024-12345",
    )).scalars().all()
    assert len(findings) == 1
    assert _db.session.execute(_db.select(AssessmentTarget).where(
        AssessmentTarget.finding_id == findings[0].id,
        AssessmentTarget.variant_id == variant.id,
    )).scalar_one_or_none() is not None


@pytest.mark.parametrize("parser_class", ["YoctoVulns", "YoctoVex"])
@pytest.mark.parametrize("historical", [False, True])
def test_yocto_issue_before_epoch_keeps_scan_target(app, parser_class, historical):
    from src.bin.cmd_process import populate_observations
    from src.controllers.cache import ControllersCache
    from src.models.assessment_target import AssessmentTarget
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_observation import SBOMObservation
    from src.models.sbom_package import SBOMPackage
    from src.views.yocto_vex import YoctoVex
    from src.views.yocto_vulns import YoctoVulns

    project = Project.create("yocto-epoch-project")
    variant = Variant.create("yocto-epoch-variant", project.id)
    scan = Scan.create("yocto-epoch-scan", variant.id, scan_type="sbom")
    document = SBOMDocument.create("yocto-epoch.json", "yocto", scan.id)
    controllers = ControllersCache()
    controllers.packages.current_sbom_document = document
    controllers.assessments.current_variant_id = variant.id
    controllers.vulnerabilities.current_variant_id = variant.id
    parser = {"YoctoVulns": YoctoVulns, "YoctoVex": YoctoVex}[parser_class](controllers)
    issue = {"id": "CVE-2024-12345", "status": "Unpatched", "description": "Affected"}
    bare = {"name": "mesa", "version": "1.0.0", "issue": [issue]}
    epoch = {"name": "mesa", "version": "1_1.0.0", "issue": []}

    if historical:
        older_scan = Scan.create("yocto-older-scan", variant.id, scan_type="sbom")
        older_document = SBOMDocument.create("yocto-older.json", "yocto", older_scan.id)
        controllers.packages.current_sbom_document = older_document
        parser.load_from_dict({"package": [bare]})
        populate_observations(older_scan, controllers.vulnerabilities)
        older_link = SBOMPackage.get_by_document(older_document.id)[0]
        older_finding = Finding.get_by_package_and_vulnerability(older_link.package_id, issue["id"])
        controllers.packages.current_sbom_document = document

    parser.load_from_dict({"package": [bare, epoch]})
    populate_observations(scan, controllers.vulnerabilities)

    links = SBOMPackage.get_by_document(document.id)
    assert len(links) == 1
    assert links[0].package.version == "1_1.0.0"
    finding = Finding.get_by_package_and_vulnerability(links[0].package_id, issue["id"])
    assert finding is not None
    assert any(row.finding_id == finding.id for row in Observation.get_by_scan(scan.id))
    assert _db.session.execute(_db.select(AssessmentTarget).where(
        AssessmentTarget.finding_id == finding.id,
        AssessmentTarget.variant_id == variant.id,
    )).scalar_one_or_none() is not None
    assert any(row.sbom_document_id == document.id and row.package_id == links[0].package_id
               for row in SBOMObservation.get_by_vuln(issue["id"]))
    if historical:
        assert older_link.package_id != links[0].package_id
        assert Finding.get_by_id(older_finding.id) is not None
        assert any(row.finding_id == older_finding.id for row in Observation.get_by_scan(older_scan.id))
        assert _db.session.execute(_db.select(AssessmentTarget).where(
            AssessmentTarget.finding_id == older_finding.id,
            AssessmentTarget.variant_id == variant.id,
        )).scalar_one_or_none() is not None


@pytest.mark.parametrize("reverse", [False, True])
def test_fast_spdx_epoch_ingestion_keeps_identifiers_and_other_versions(app, reverse):
    from src.controllers.cache import ControllersCache
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.views.cyclonedx import CycloneDx
    from src.views.fast_spdx import FastSPDX
    from cyclonedx.model.bom import Bom

    project = Project.create("spdx-epoch-project")
    variant = Variant.create("spdx-epoch-variant", project.id)
    scan = Scan.create("spdx-epoch-scan", variant.id, scan_type="sbom")
    document = SBOMDocument.create("versions.spdx.json", "spdx", scan.id)
    controllers = ControllersCache()
    controllers.packages.current_sbom_document = document
    mesa = [
        {"name": "mesa", "versionInfo": version, "externalRefs": [
            {"referenceType": "purl", "referenceLocator": f"pkg:generic/mesa@{version}"},
            {"referenceType": "cpe23Type", "referenceLocator": f"cpe:2.3:a:mesa:mesa:{version}:*:*:*:*:*:*:*"},
        ]}
        for version in ("1_1.0.0", "1.0.0")
    ]
    if reverse:
        mesa.reverse()
    FastSPDX(controllers).parse_from_dict({
        "spdxVersion": "SPDX-2.3",
        "packages": mesa + [
            {"name": "mesa", "versionInfo": "1_1.1.0"},
            {"name": "pixman", "versionInfo": "1_6.4"},
        ],
    })

    linked = {link.package.string_id: link.package for link in SBOMPackage.get_by_document(document.id)}
    assert set(linked) == {"mesa@1_1.0.0", "mesa@1_1.1.0", "pixman@1_6.4"}
    assert {"pkg:generic/mesa@1_1.0.0", "pkg:generic/mesa@1.0.0"} <= set(
        linked["mesa@1_1.0.0"].purl
    )
    assert {
        "cpe:2.3:a:mesa:mesa:1_1.0.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:mesa:mesa:1.0.0:*:*:*:*:*:*:*",
    } <= set(linked["mesa@1_1.0.0"].cpe)
    assert controllers.packages.get("mesa@1.0.0").id == linked["mesa@1_1.0.0"].id
    export = CycloneDx(controllers)
    export.sbom = Bom()
    export.register_components()
    component = next(component for component in export.sbom.components if component.name == "mesa"
                     and component.version == "1_1.0.0")
    assert str(component.bom_ref) == "pkg:generic/mesa@1_1.0.0"
    assert str(component.purl) == "pkg:generic/mesa@1_1.0.0"
    assert component.cpe == "cpe:2.3:a:mesa:mesa:1_1.0.0:*:*:*:*:*:*:*"


def test_controller_from_dict_roundtrip_preserves_supplier(app):
    from src.controllers.packages import PackagesController
    ctrl = PackagesController()
    ctrl.add(Package("foo", "1.0", supplier="Organization: Acme Corp"))
    serialised = ctrl.to_dict()
    ctrl2 = PackagesController.from_dict(serialised)
    key = "foo@1.0::Organization: Acme Corp"
    assert key in ctrl2.packages
    assert ctrl2.packages[key].supplier == "Organization: Acme Corp"


def test_controller_current_sbom_document_defaults_to_none(app):
    from src.controllers.packages import PackagesController
    ctrl = PackagesController()
    assert ctrl.current_sbom_document is None


def test_controller_reprocesses_populated_document_in_one_select(app):
    from sqlalchemy import event
    from src.controllers.packages import PackagesController
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("reprocess-proj")
    variant = Variant.create("reprocess-variant", project.id)
    scan = Scan.create("sbom", variant.id, scan_type="sbom")
    document = SBOMDocument.create("sbom.json", "test", scan.id)
    for name in ("first", "second", "third"):
        package = Package.create(name, "1.0.0")
        SBOMPackage.create(document.id, package.id)
    _db.session.flush()
    document_id = document.id
    _db.session.expunge_all()
    document = _db.session.get(SBOMDocument, document_id)
    assert document is not None

    statements = []

    def count_select(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    event.listen(_db.engine, "before_cursor_execute", count_select)
    try:
        controller = PackagesController()
        controller.current_sbom_document = document
    finally:
        event.remove(_db.engine, "before_cursor_execute", count_select)

    assert len(statements) == 1
    assert {package.name for peers in controller._document_packages.values() for package in peers} == {
        "first", "second", "third",
    }


def test_active_package_ids_for_scans_returns_empty_for_non_sbom_scan(app):
    from src.helpers.active_scans import active_package_ids_for_scans

    project = Project.create("active-scan-proj")
    variant = Variant.create("active-scan-variant", project.id)
    tool_scan = Scan.create("tool-only", variant.id, scan_type="tool", scan_source="osv")

    assert active_package_ids_for_scans([tool_scan.id]) == set()


def test_active_package_ids_for_scans_returns_empty_for_empty_input(app):
    from src.helpers.active_scans import active_package_ids_for_scans
    assert active_package_ids_for_scans([]) == set()


def test_active_package_ids_for_scans_restrict_filters_to_requested(app):
    """restrict_to_package_ids narrows the result to the requested package ids."""
    from src.helpers.active_scans import active_package_ids_for_scans
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("restrict-proj")
    variant = Variant.create("restrict-variant", project.id)
    sbom_scan = Scan.create("sbom", variant.id, scan_type="sbom")
    document = SBOMDocument.create("sbom.json", "test", sbom_scan.id)
    pkg_a = Package.create("pkg-a", "1.0.0")
    pkg_b = Package.create("pkg-b", "2.0.0")
    SBOMPackage.create(document.id, pkg_a.id)
    SBOMPackage.create(document.id, pkg_b.id)
    _db.session.flush()

    # Without restriction: both packages are active.
    assert active_package_ids_for_scans([sbom_scan.id]) == {pkg_a.id, pkg_b.id}

    # With restriction: only the requested (present) package is returned.
    assert active_package_ids_for_scans(
        [sbom_scan.id], restrict_to_package_ids={pkg_a.id}
    ) == {pkg_a.id}

    # A restriction listing a package absent from the SBOM yields an empty set.
    absent = Package.create("pkg-c", "3.0.0")
    assert active_package_ids_for_scans(
        [sbom_scan.id], restrict_to_package_ids={absent.id}
    ) == set()


def test_active_package_ids_for_scans_restrict_empty_returns_empty(app):
    """An empty restriction set short-circuits to an empty result."""
    from src.helpers.active_scans import active_package_ids_for_scans
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    project = Project.create("restrict-empty-proj")
    variant = Variant.create("restrict-empty-variant", project.id)
    sbom_scan = Scan.create("sbom", variant.id, scan_type="sbom")
    document = SBOMDocument.create("sbom.json", "test", sbom_scan.id)
    pkg = Package.create("pkg-x", "1.0.0")
    SBOMPackage.create(document.id, pkg.id)
    _db.session.flush()

    assert active_package_ids_for_scans(
        [sbom_scan.id], restrict_to_package_ids=set()
    ) == set()



def test_find_or_create_openembedded_collapses_into_blank_supplier(app):
    """An OpenEmbedded supplier resolves to the same row as the blank one."""
    pkg_oe = Package.find_or_create("busybox", "1.36.1", supplier="OpenEmbedded ()")
    _db.session.flush()
    pkg_blank = Package.find_or_create("busybox", "1.36.1")
    assert pkg_oe.supplier == ""
    assert pkg_oe.id == pkg_blank.id


def test_exists_normalizes_openembedded_supplier(app):
    """exists() must match the cleaned (blank) row for an OpenEmbedded query."""
    Package.find_or_create("busybox", "1.36.1")
    _db.session.flush()
    assert Package.exists("busybox", "1.36.1", supplier="OpenEmbedded ()") is True


def test_get_by_string_id_normalizes_openembedded_supplier(app):
    """A string_id carrying an OpenEmbedded supplier resolves to the blank row."""
    Package.find_or_create("busybox", "1.36.1")
    _db.session.flush()
    found = Package.get_by_string_id("busybox@1.36.1::OpenEmbedded ()")
    assert found is not None
    assert found.supplier == ""


def test_bulk_find_or_create_collapses_openembedded_supplier(app):
    """bulk_find_or_create() deduplicates OpenEmbedded with the blank supplier."""
    result = Package.bulk_find_or_create([
        {"name": "busybox", "version": "1.36.1", "supplier": "OpenEmbedded ()"},
        {"name": "busybox", "version": "1.36.1", "supplier": ""},
    ])
    _db.session.flush()
    ids = {pkg.id for pkg in result.values()}
    assert len(ids) == 1
    assert "busybox@1.36.1" in result
    assert result["busybox@1.36.1"].supplier == ""

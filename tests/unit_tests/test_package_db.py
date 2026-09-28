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


def test_document_evidence_sorts_once_per_package_field(app, monkeypatch):
    from unittest.mock import Mock
    from src.models import SBOMDocument, SBOMPackage
    from src.models import sbom_package as sbom_package_module

    project = Project.create("evidence-aggregation")
    variant = Variant.create("default", project.id)
    scan = Scan.create("SBOM", variant.id)
    package = Package.create("lib", "1.0")
    ordinary = Package.create("ordinary", "1.0")
    document_ids = set()
    for index in range(24):
        document = SBOMDocument.create(f"{index}.json", str(index), scan.id)
        document_ids.add(document.id)
        _db.session.add_all([
            SBOMPackage(
                sbom_document_id=document.id, package_id=package.id,
                cpe=[f"cpe:{index % 3}", "cpe:shared", f"cpe:{index % 3}"],
                purl=[f"pkg:generic/lib@{index % 4}", "pkg:generic/lib@shared"],
                source_urls=[f"https://example.org/{index % 5}"],
                source_revisions=[str(index % 2) * 40],
                type=("normal", "workspace", "built")[index % 3],
            ),
            SBOMPackage(sbom_document_id=document.id, package_id=ordinary.id),
        ])
    excluded = SBOMDocument.create("excluded.json", "excluded", scan.id)
    _db.session.add(SBOMPackage(
        sbom_document_id=excluded.id, package_id=package.id,
        cpe=["unselected"], purl=["unselected"], source_urls=["unselected"],
        source_revisions=["unselected"],
    ))
    _db.session.commit()
    sort = Mock(wraps=sorted)
    monkeypatch.setattr(sbom_package_module, "sorted", sort, raising=False)
    evidence = SBOMPackage.evidence_for_documents(document_ids)
    assert sort.call_count == 8
    assert evidence == {
        package.id: {
            "cpe": ["cpe:0", "cpe:1", "cpe:2", "cpe:shared"],
            "purl": ["pkg:generic/lib@0", "pkg:generic/lib@1", "pkg:generic/lib@2",
                     "pkg:generic/lib@3", "pkg:generic/lib@shared"],
            "source_urls": [f"https://example.org/{index}" for index in range(5)],
            "source_revisions": ["0" * 40, "1" * 40],
            "component_types": ["built", "normal", "workspace"],
        },
        ordinary.id: {"cpe": [], "purl": [], "source_urls": []},
    }


@pytest.mark.parametrize("cpe,purl", [(None, None), (None, []), ([], None), ([], [])])
def test_scanner_snapshots_require_recorded_identifiers_not_global_fallback(app, cpe, purl):
    from src.helpers.active_scans import package_snapshots_for_sbom_scans
    from src.models import SBOMDocument, SBOMPackage
    from src.models.sbom_package import SBOMReimportRequiredError

    project = Project.create("recorded-evidence")
    variant = Variant.create("default", project.id)
    scan = Scan.create("SBOM", variant.id)
    document = SBOMDocument.create("lib.json", "lib", scan.id)
    package = Package.create("lib", "1.0", purl=["pkg:generic/lib@1.0"])
    _db.session.add(SBOMPackage(
        sbom_document_id=document.id, package_id=package.id, cpe=cpe, purl=purl,
    ))
    _db.session.commit()
    if cpe is None or purl is None:
        with pytest.raises(SBOMReimportRequiredError, match="Reimport"):
            package_snapshots_for_sbom_scans([scan.id])
    else:
        snapshots = package_snapshots_for_sbom_scans([scan.id])
        assert len(snapshots) == 1
        assert snapshots[0].id == package.id
        assert snapshots[0].cpe == snapshots[0].purl == []
    assert package.purl == ["pkg:generic/lib@1.0"]


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
    assert ctrl.get_or_resolve_db_id("mesa@1.0.0") is None
    bare = ctrl.add(Package("mesa", "1.0.0"))

    linked = {link.package.string_id: link.package_id for link in SBOMPackage.get_by_document(document.id)}
    assert set(linked) == {"mesa@1_1.0.0", "mesa@2_1.0.0", "mesa@1.0.0"}
    assert bare.id == linked["mesa@1.0.0"]
    assert ctrl.get("mesa@1.0.0").id == bare.id
    assert ctrl.get_or_resolve_db_id("mesa@1.0.0") == bare.id


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


@pytest.mark.parametrize("reverse", [False, True])
def test_fast_spdx_epoch_ingestion_keeps_identifiers_and_other_versions(app, reverse):
    from src.controllers.cache import ControllersCache
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.views.fast_spdx import FastSPDX

    project = Project.create("spdx-epoch-project")
    variant = Variant.create("spdx-epoch-variant", project.id)
    scan = Scan.create("spdx-epoch-scan", variant.id, scan_type="sbom")
    document = SBOMDocument.create("versions.spdx.json", "spdx", scan.id)
    controllers = ControllersCache()
    controllers.packages.current_sbom_document = document
    mesa = [
        {"name": "mesa", "versionInfo": version, "externalRefs": [{
            "referenceType": "purl", "referenceLocator": f"pkg:generic/mesa@{version}",
        }]}
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
    assert controllers.packages.get("mesa@1.0.0").id == linked["mesa@1_1.0.0"].id


def test_controller_from_dict_roundtrip_preserves_supplier(app):
    from src.controllers.packages import PackagesController
    ctrl = PackagesController()
    ctrl.add(Package("foo", "1.0", supplier="Organization: Acme Corp"))
    serialised = ctrl.to_dict()
    ctrl2 = PackagesController.from_dict(serialised)
    key = "foo@1.0::Organization: Acme Corp"
    assert key in ctrl2.packages
    assert ctrl2.packages[key].supplier == "Organization: Acme Corp"


def test_source_urls_remain_transient_through_package_crud_and_roundtrip(app):
    from src.controllers.packages import PackagesController
    urls = [f"git+https://example.org/repo-{i}.git@{str(i) * 40}" for i in range(1, 5)]
    package = Package.create("lib", "1.0", source_urls=[urls[0]])
    package_id = package.id
    Package.find_or_create("lib", "1.0", source_urls=[urls[0], urls[1], "NOASSERTION"])
    Package.bulk_find_or_create([{"name": "lib", "version": "1.0", "source_urls": [urls[2]]},
                                {"name": "new", "version": "1", "source_urls": [urls[0]]}])
    ctrl = PackagesController()
    ctrl.add(Package("lib", "1.0", source_urls=[urls[3]]))
    ctrl.add(Package("lib", "1.0", source_urls=[urls[0]]))
    assert ctrl.to_dict()["lib@1.0"]["source_urls"] == urls
    data = PackagesController.from_dict(ctrl.to_dict()).to_dict()
    assert data["lib@1.0"]["source_urls"] == urls
    _db.session.commit()
    _db.session.remove()
    restored = _db.session.get(Package, package_id)
    assert restored.source_urls == []
    assert not restored.version_info["revision_conflict"]
    assert _db.session.query(Package).count() == 2


def test_adding_to_preloaded_snapshots_still_persists_package_identifiers(app):
    from src.controllers.packages import PackagesController

    Package.create("lib", "1.0")
    ctrl = PackagesController()
    ctrl._preload_cache()
    purl = "pkg:generic/lib@1.0"
    cpe = "cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*"
    ctrl.add(Package("lib", "1.0", cpe=[cpe], purl=[purl]))
    _db.session.commit()
    _db.session.remove()
    restored = Package.get_by_string_id("lib@1.0")
    assert restored.cpe == [cpe]
    assert restored.purl == [purl]


@pytest.mark.parametrize("evidence_location", ["document", "legacy"])
def test_sbom_evidence_downgrade_rejects_source_url_loss_without_changing_evidence(app, evidence_location):
    import importlib
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    import sqlalchemy as sa
    from src.models import SBOMDocument, SBOMPackage

    migration = importlib.import_module("src.migrations.versions.c83e91ab402d_add_sbom_package_evidence")
    project = Project.create("downgrade")
    variant = Variant.create("default", project.id)
    scan = Scan.create("SBOM", variant.id)
    document = SBOMDocument.create("lib.json", "lib", scan.id)
    purl = "pkg:generic/lib@1.0"
    url = f"git+https://example.org/lib@{'a' * 40}"
    package = Package.create("lib", "1.0")
    link = SBOMPackage.create(document.id, package.id)
    link.purl = [purl]
    link.source_urls = [url] if evidence_location == "document" else []
    # Legacy evidence can belong to a package with no document link.
    legacy = Package.create("legacy-only", "1.0")
    legacy._legacy_source_urls = [url] if evidence_location == "legacy" else []
    _db.session.commit()
    with _db.engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            with pytest.raises(RuntimeError, match="previous schema cannot retain"):
                migration.downgrade()
            assert {"source_urls", "purl", "cpe"} <= {
                c["name"] for c in sa.inspect(connection).get_columns("sbom_packages")
            }
    _db.session.expire_all()
    assert package.purl == []
    assert link.purl == [purl]
    assert link.source_urls == ([url] if evidence_location == "document" else [])
    assert legacy._legacy_source_urls == ([url] if evidence_location == "legacy" else [])


def test_sbom_evidence_migration_excludes_global_evidence_and_preserves_identifiers_on_downgrade(app):
    import importlib
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    import sqlalchemy as sa
    from src.models import SBOMDocument, SBOMPackage

    migration = importlib.import_module("src.migrations.versions.c83e91ab402d_add_sbom_package_evidence")
    project = Project.create("identifier-migration")
    variant = Variant.create("default", project.id)
    scan = Scan.create("SBOM", variant.id)
    documents = [SBOMDocument.create(f"{i}.json", str(i), scan.id) for i in range(2)]
    cpes = [f"cpe:2.3:a:vendor:lib:{i}.0:*:*:*:*:*:*:*" for i in (1, 2, 3)]
    purls = [f"pkg:generic/lib@{i}.0" for i in (1, 2, 3)]
    package = Package.create("lib", "1.0", cpe=[cpes[0]], purl=[purls[0]])
    fresh = Package.create("fresh", "1.0")
    for document in documents:
        for pkg in (package, fresh):
            SBOMPackage.create(document.id, pkg.id)
    with _db.engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            migration.downgrade()
            assert not {"source_urls", "purl", "cpe"} & {
                c["name"] for c in sa.inspect(connection).get_columns("sbom_packages")
            }
            assert "legacy_source_urls" not in {
                c["name"] for c in sa.inspect(connection).get_columns("packages")
            }
            migration.upgrade()
            links = sa.table("sbom_packages", sa.column("cpe", sa.JSON()),
                             sa.column("purl", sa.JSON()), sa.column("source_urls", sa.JSON()))
            assert connection.execute(sa.select(links.c.cpe, links.c.purl, links.c.source_urls)).all() == [
                (None, None, None),
            ] * 4
            packages = sa.table("packages", sa.column("name"), sa.column("version"),
                                sa.column("legacy_source_urls", sa.JSON()))
            assert connection.execute(sa.select(packages.c.name, packages.c.version, packages.c.legacy_source_urls)
                                      .order_by(packages.c.name)).all() == [
                ("fresh", "1.0", None), ("lib", "1.0", None),
            ]
    assert SBOMPackage.evidence_for_documents({document.id for document in documents})[package.id] == {
        "cpe": [], "purl": [], "source_urls": [],
    }
    for i, document in enumerate(documents, 1):
        link = SBOMPackage.get(document.id, package.id)
        link.cpe = cpes[i:i + 1]
        link.purl = purls[i:i + 1]
        link = SBOMPackage.get(document.id, fresh.id)
        link.cpe = cpes[1:]
        link.purl = purls[1:]
    _db.session.commit()
    with _db.engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            migration.downgrade()
            packages = sa.table("packages", sa.column("name"),
                                sa.column("cpe", sa.JSON()), sa.column("purl", sa.JSON()))
            assert connection.execute(sa.select(packages.c.name, packages.c.cpe, packages.c.purl)
                                      .order_by(packages.c.name)).all() == [
                ("fresh", cpes[1:], purls[1:]), ("lib", cpes, purls),
            ]
            migration.upgrade()


def test_already_upgraded_pr_database_remains_compatible_with_consolidated_migration(app, monkeypatch):
    from src.models import SBOMDocument, SBOMPackage

    project = Project.create("already-upgraded")
    variant = Variant.create("default", project.id)
    scan = Scan.create("SBOM", variant.id)
    document = SBOMDocument.create("lib.json", "lib", scan.id)
    url = f"git+https://example.org/lib@{'a' * 40}"
    package = Package.create("lib", "1.0")
    package._legacy_source_urls = [url]
    link = SBOMPackage.create(document.id, package.id)
    link.source_urls = [url]
    link.purl = ["pkg:generic/lib@1.0"]
    _db.session.commit()
    # Alembic's logging configuration must not disable other tests' loggers.
    monkeypatch.setattr("logging.config.fileConfig", lambda _filename: None)
    runner = app.test_cli_runner()
    result = runner.invoke(args=["db", "stamp", "c83e91ab402d"])
    assert result.exit_code == 0, result.output
    result = runner.invoke(args=["db", "upgrade"])
    assert result.exit_code == 0, result.output
    _db.session.expire_all()
    assert link.source_urls == [url]
    assert link.purl == ["pkg:generic/lib@1.0"]
    assert package._legacy_source_urls == [url]


def test_controller_current_sbom_document_defaults_to_none(app):
    from src.controllers.packages import PackagesController
    ctrl = PackagesController()
    assert ctrl.current_sbom_document is None


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

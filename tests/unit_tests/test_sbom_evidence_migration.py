# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Exercise the consolidated evidence migration through real Alembic upgrades."""

from pathlib import Path
from uuid import uuid4

from alembic.script import ScriptDirectory
import pytest
from sqlalchemy import JSON, String, Uuid, column, inspect, table, text

from src.bin.webapp import create_app
from src.controllers.packages import PackagesController
from src.extensions import db
from src.models import Package, Project, SBOMDocument, SBOMPackage, Scan, Variant


HEAD_REVISION = ScriptDirectory(
    str(Path(__file__).resolve().parents[2] / "src" / "migrations"),
).get_current_head()


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("SCAN_FILE", "/dev/null")
    # Alembic must not replace pytest's logging configuration.
    monkeypatch.setattr("logging.config.fileConfig", lambda _filename: None)
    application = create_app()
    application.config["TESTING"] = True
    with application.app_context():
        yield application
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


def _upgrade(app, revision="head"):
    result = app.test_cli_runner().invoke(args=["db", "upgrade", revision])
    assert result.exit_code == 0, result.output


def test_fresh_database_reaches_the_evidence_schema_and_can_use_its_links(app):
    _upgrade(app)
    assert db.session.execute(text("SELECT version_num FROM alembic_version")).scalar() == HEAD_REVISION
    inspector = inspect(db.engine)
    for table in ("packages", "sbom_packages"):
        assert {column["name"] for column in inspector.get_columns(table)} == set(
            db.metadata.tables[table].columns.keys()
        )

    project = Project.create("fresh-schema")
    variant = Variant.create("default", project.id)
    scan = Scan.create("SBOM", variant.id)
    document = SBOMDocument.create("lib.json", "lib", scan.id)
    url = f"git+https://example.org/lib@{'a' * 40}"
    ctrl = PackagesController()
    ctrl.current_sbom_document = document
    package = ctrl.add(Package("lib", "1.0", purl=["pkg:generic/lib@1.0"], source_urls=[url]))
    ctrl.flush_spdx_sources()
    db.session.commit()
    document_id, package_id = document.id, package.id
    db.session.remove()

    _upgrade(app)
    link = SBOMPackage.get(document_id, package_id)
    assert link.purl == ["pkg:generic/lib@1.0"]
    assert link.source_urls == [url]
    assert link.type == "normal"
    assert link.source_revisions is None
    assert db.session.get(Package, package_id)._legacy_source_urls is None


def test_populated_pre_pr_database_upgrades_without_inventing_document_evidence(app):
    _upgrade(app, "cc5359c88dd2")
    project = Project.create("old-schema")
    variant = Variant.create("default", project.id)
    scan = Scan.create("SBOM", variant.id)
    scan_id = scan.id
    document_id, package_id = uuid4(), uuid4()
    cpe = "cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*"
    purl = "pkg:generic/lib@1.0"
    db.session.remove()
    documents = table(
        "sbom_documents", column("id", Uuid), column("path", String),
        column("source_name", String), column("scan_id", Uuid),
    )
    packages = table(
        "packages", column("id", Uuid), column("name", String), column("version", String),
        column("supplier", String), column("licences", String), column("cpe", JSON), column("purl", JSON),
    )
    links = table(
        "sbom_packages", column("sbom_document_id", Uuid), column("package_id", Uuid),
    )
    with db.engine.begin() as connection:
        connection.execute(documents.insert().values(
            id=document_id, path="lib.json", source_name="lib", scan_id=scan_id,
        ))
        connection.execute(packages.insert().values(
            id=package_id, name="lib", version="1.0", supplier="", licences="", cpe=[cpe], purl=[purl],
        ))
        connection.execute(links.insert().values(
            sbom_document_id=document_id, package_id=package_id,
        ))

    _upgrade(app)
    package = db.session.get(Package, package_id)
    assert (package.name, package.version, package.cpe, package.purl) == ("lib", "1.0", [cpe], [purl])
    assert package._legacy_source_urls is None
    link = SBOMPackage.get(document_id, package_id)
    assert (link.cpe, link.purl, link.source_urls) == (None, None, None)
    assert link.type == "normal"
    assert link.source_revisions is None
    assert db.session.get(SBOMDocument, document_id).jsonld_groups is None
    assert SBOMPackage.evidence_for_documents({document_id})[package_id] == {
        "cpe": [], "purl": [], "source_urls": [],
    }


def test_empty_evidence_schema_can_downgrade_to_an_older_schema_and_upgrade_again(app):
    _upgrade(app)
    expected_columns = {
        table: {column["name"] for column in inspect(db.engine).get_columns(table)}
        for table in inspect(db.engine).get_table_names()
    }
    result = app.test_cli_runner().invoke(args=["db", "downgrade", "c8748f805850"])
    assert result.exit_code == 0, result.output
    assert db.session.execute(text("SELECT version_num FROM alembic_version")).scalar() == "c8748f805850"
    assert {"source_urls", "cpe", "purl", "source_revisions", "type"}.isdisjoint(
        column["name"] for column in inspect(db.engine).get_columns("sbom_packages")
    )
    assert "legacy_source_urls" not in {
        column["name"] for column in inspect(db.engine).get_columns("packages")
    }
    db.session.remove()

    _upgrade(app)
    assert {
        table: {column["name"] for column in inspect(db.engine).get_columns(table)}
        for table in inspect(db.engine).get_table_names()
    } == expected_columns
    assert db.session.execute(text("SELECT version_num FROM alembic_version")).scalar() == HEAD_REVISION

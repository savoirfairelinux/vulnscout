# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
from pathlib import Path
import pytest

from src.bin.cmd_process import read_inputs
from src.bin.webapp import create_app
from src.controllers import ControllersCache
from src.controllers.scc_adapter import build_comp_build
from src.extensions import db
from src.helpers.active_scans import package_snapshots_for_sbom_scans
from src.models import Package, PackageSourceFile, Project, SBOMDocument, SBOMFile, Scan, Variant


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    application = create_app()
    status = tmp_path / "status.txt"
    status.write_text("__END_OF_SCAN_SCRIPT__")
    application.config.update(TESTING=True, SCAN_FILE=str(status))
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


def _graph(items):
    return {"@graph": [
        {"type": "CreationInfo", "specVersion": "3.0.1"},
        {"type": "SoftwareAgent", "name": "West SPDX Generator"},
        *items,
    ]}


def _documents(path="src/enabled.c", extra=False, unresolved=False):
    prefix = "https://example.org/evidence/"

    def ref(name):
        return prefix + name

    def relation(kind, source, *targets):
        return {"type": "Relationship", "relationshipType": kind,
                "from": ref(source), "to": [ref(target) for target in targets]}

    files = [
        {"type": "software_Package", "spdxId": ref("source"), "name": "lib-sources",
         "software_primaryPurpose": "source", "software_packageVersion": "1.0"},
        {"type": "software_File", "spdxId": ref("file"), "name": path,
         "verifiedUsing": [{"type": "Hash", "algorithm": "sha256", "hashValue": "a" * 64}]},
        relation("contains", "source", "file"),
    ]
    if extra:
        files.extend([
            {"type": "software_File", "spdxId": ref("listed"), "name": "src/listed.c"},
            relation("contains", "source", "listed"),
        ])
    builds = [
        {"type": "software_Package", "spdxId": ref("package"), "name": "lib",
         "software_packageVersion": "1.0"},
        {"type": "software_File", "spdxId": ref("output"), "name": "build/lib.a"},
        {"type": "build_Build", "spdxId": ref("build"), "build_buildType": "urn:compile",
         "build_parameter": [{"key": "flags", "value": "-DCONFIG_FEATURE=1"}]},
        relation("contains", "package", "output"),
        relation("hasInput", "build", "file", *(["missing"] if unresolved else [])),
        relation("hasOutput", "build", "output"),
    ]
    # Lexical ordering deliberately imports the build before its source document.
    return {"a-build.jsonld": _graph(builds), "z-source.jsonld": _graph(files)}


def _import(tmp_path, documents, variant=None):
    if variant is None:
        project = Project.create("source-test")
        variant = Variant.create("default", project.id)
    scan = Scan.create("file inventory", variant.id, scan_type="sbom")
    directory = tmp_path / str(scan.id)
    directory.mkdir()
    for name, content in documents.items():
        path = directory / name
        path.write_text(json.dumps(content))
        SBOMDocument.create(str(path), name, scan.id, format="spdx")
    read_inputs(ControllersCache(), scan.id)
    return variant, scan


def _package(app, variant, name="lib"):
    rows = app.test_client().get("/api/packages", query_string={
        "variant_id": str(variant.id), "include_source_files": "true",
    }).get_json()
    return next(row for row in rows if row["name"] == name)


def test_companion_files_builds_and_properties_survive_input_cleanup(app, tmp_path):
    variant, scan = _import(tmp_path, _documents())
    assert db.session.query(SBOMFile).count() == 2
    row = _package(app, variant)
    assert row["source_file_count"] == 1
    assert row["compiled_sources_complete"]
    assert row["compiled_source_file_count"] == 1
    file = row["source_files"][0]
    assert file["path"] == "src/enabled.c"
    assert file["document_name"] == "z-source.jsonld"
    assert file["properties"]["verifiedUsing"][0]["algorithm"] == "sha256"
    assert file["builds"][0]["parameters"] == [{"key": "flags", "value": "-DCONFIG_FEATURE=1"}]
    assert file["builds"][0]["outputs"] == ["https://example.org/evidence/output"]
    snapshots = package_snapshots_for_sbom_scans([scan.id])
    built = next(package for package in snapshots if package.name == "lib")
    assert build_comp_build(built).compiled_sources == {"src/enabled.c"}
    for document in SBOMDocument.get_by_scan(scan.id):
        Path(document.path).unlink()
    assert _package(app, variant)["source_files"] == row["source_files"]
    ordinary = app.test_client().get("/api/packages", query_string={"variant_id": str(variant.id)}).get_json()
    assert all("source_files" not in package for package in ordinary)


def test_reimport_replaces_instead_of_duplicating_files(app, tmp_path):
    variant, scan = _import(tmp_path, _documents())
    count = db.session.query(PackageSourceFile).count()
    read_inputs(ControllersCache(), scan.id)
    assert db.session.query(SBOMFile).count() == 2
    assert db.session.query(PackageSourceFile).count() == count
    assert _package(app, variant)["source_file_count"] == 1


def test_intermediate_objects_are_retained_but_not_used_as_source_files(app, tmp_path):
    documents = _documents()
    graph = documents["a-build.jsonld"]["@graph"]
    graph.extend([
        {"type": "software_File", "spdxId": "https://example.org/evidence/object", "name": "build/enabled.c.obj"},
        {"type": "Relationship", "relationshipType": "hasInput",
         "from": "https://example.org/evidence/build", "to": "https://example.org/evidence/object"},
        {"type": "Relationship", "relationshipType": "contains",
         "from": "https://example.org/evidence/package", "to": "https://example.org/evidence/object"},
    ])
    variant, scan = _import(tmp_path, documents)
    assert db.session.query(SBOMFile).count() == 3
    assert _package(app, variant)["source_file_count"] == 1
    assert all(package.compiled_sources == {"src/enabled.c"}
               for package in package_snapshots_for_sbom_scans([scan.id]))


def test_generated_source_is_still_a_source_when_consumed_by_another_build(app, tmp_path):
    documents = _documents()
    documents["z-source.jsonld"]["@graph"].extend([
        {"type": "build_Build", "spdxId": "https://example.org/evidence/generator"},
        {"type": "Relationship", "relationshipType": "hasOutput",
         "from": "https://example.org/evidence/generator", "to": "https://example.org/evidence/file"},
    ])
    variant, scan = _import(tmp_path, documents)
    assert _package(app, variant)["source_file_count"] == 1
    assert all(package.compiled_sources == {"src/enabled.c"}
               for package in package_snapshots_for_sbom_scans([scan.id]))


@pytest.mark.parametrize("malformed", ["file", "input", "conflicting"])
def test_malformed_or_conflicting_evidence_disables_refinement(app, tmp_path, malformed, caplog):
    documents = _documents()
    graph = documents["z-source.jsonld"]["@graph"]
    if malformed == "file":
        graph.append({"type": "software_File", "spdxId": "https://example.org/evidence/invalid"})
    elif malformed == "input":
        graph.append({"type": "Relationship", "relationshipType": "hasInput",
                      "from": "https://example.org/evidence/build", "to": [7]})
    else:
        documents["a-build.jsonld"]["@graph"].append({
            "type": "software_File", "spdxId": "https://example.org/evidence/file", "name": "conflicting.c",
        })
    variant, scan = _import(tmp_path, documents)
    assert not _package(app, variant)["compiled_sources_complete"]
    assert all(not package.compiled_sources for package in package_snapshots_for_sbom_scans([scan.id]))
    assert "compiled-source refinement disabled" in caplog.text


def test_namespace_prefixes_resolve_only_within_the_import(app, tmp_path):
    documents = _documents()
    graph = documents["a-build.jsonld"]["@graph"]
    graph.append({"type": "SpdxDocument", "spdxId": "https://example.org/document",
                  "namespaceMap": [{"prefix": "src", "namespace": "https://example.org/evidence/"}]})
    for node in graph:
        if node.get("relationshipType") == "hasInput":
            node["to"] = ["src:file"]
    variant, _ = _import(tmp_path, documents)
    assert _package(app, variant)["compiled_sources_complete"]
    assert _package(app, variant)["source_files"][0]["path"] == "src/enabled.c"


def test_deleting_a_companion_disables_remaining_compilation_evidence(app, tmp_path):
    variant, scan = _import(tmp_path, _documents())
    source = next(document for document in SBOMDocument.get_by_scan(scan.id)
                  if document.source_name == "z-source.jsonld")
    source.delete()
    assert _package(app, variant)["source_file_count"] == 0
    assert not _package(app, variant)["compiled_sources_complete"]
    assert all(not package.compiled_sources for package in package_snapshots_for_sbom_scans([scan.id]))


def test_project_details_keep_variant_and_scan_provenance(app, tmp_path):
    variant, first_scan = _import(tmp_path, _documents("src/first.c"))
    other = Variant.create("other", variant.project_id)
    _, other_scan = _import(tmp_path, _documents("src/other.c"), other)
    rows = app.test_client().get("/api/packages", query_string={
        "project_id": str(variant.project_id), "package_id": "lib@1.0", "include_source_files": "true",
    }).get_json()
    assert len(rows) == 1
    assert rows[0]["source_file_count"] == 2
    assert {(file["variant_name"], file["scan_id"]) for file in rows[0]["source_files"]} == {
        ("default", str(first_scan.id)), ("other", str(other_scan.id)),
    }


@pytest.mark.parametrize("unresolved,extra", [(True, False), (False, True)])
def test_partial_or_listed_only_evidence_cannot_trim_cves(app, tmp_path, unresolved, extra):
    variant, scan = _import(tmp_path, _documents(unresolved=unresolved, extra=extra))
    source = _package(app, variant, "lib-sources")
    assert not source["compiled_sources_complete"]
    snapshot = next(package for package in package_snapshots_for_sbom_scans([scan.id])
                    if package.name == "lib-sources")
    assert build_comp_build(snapshot).compiled_sources == set()
    assert source["source_files"][0]["builds"]
    if extra:
        assert source["source_file_count"] == 2
        assert source["source_files"][1]["builds"] == []


def test_variants_and_superseded_scans_do_not_share_file_evidence(app, tmp_path):
    first, first_scan = _import(tmp_path, _documents("src/first.c"))
    other = Variant.create("other", first.project_id)
    _, other_scan = _import(tmp_path, _documents("src/other.c"), other)
    assert _package(app, first)["source_files"][0]["path"] == "src/first.c"
    assert _package(app, other)["source_files"][0]["path"] == "src/other.c"
    _, latest = _import(tmp_path, _documents("src/latest.c"), first)
    assert _package(app, first)["source_files"][0]["path"] == "src/latest.c"
    snapshots = package_snapshots_for_sbom_scans([other_scan.id])
    assert {tuple(sorted(package.compiled_sources)) for package in snapshots} == {("src/other.c",)}
    assert db.session.query(SBOMFile).count() == 6
    latest.delete()
    assert _package(app, first)["source_files"][0]["path"] == "src/first.c"
    first_scan.delete()
    other_scan.delete()
    assert db.session.query(SBOMFile).count() == 0
    assert db.session.query(PackageSourceFile).count() == 0


def test_companion_references_never_resolve_from_another_scan(app, tmp_path):
    variant, _ = _import(tmp_path, _documents())
    other = Variant.create("incomplete", variant.project_id)
    _, scan = _import(tmp_path, {"a-build.jsonld": _documents()["a-build.jsonld"]}, other)
    assert not _package(app, other)["compiled_sources_complete"]
    assert _package(app, other)["source_file_count"] == 0
    assert all(package.compiled_sources == set() for package in package_snapshots_for_sbom_scans([scan.id]))


def test_checked_in_zephyr_example_retains_canonical_lz4_source(app, tmp_path):
    example = Path(__file__).resolve().parents[2] / "example" / "zephyr"
    documents = {path.name: json.loads(path.read_text()) for path in example.glob("*.jsonld")}
    variant, scan = _import(tmp_path, documents)
    assert db.session.query(SBOMFile).count() == 316
    row = _package(app, variant, "lz4")
    assert row["source_file_count"] == 1
    assert row["source_files"][0]["path"] == "lib/lz4.c"
    assert row["source_files"][0]["builds"]
    assert row["compiled_sources_complete"]
    snapshot = next(package for package in package_snapshots_for_sbom_scans([scan.id]) if package.name == "lz4")
    assert snapshot.compiled_sources == {"lib/lz4.c"}
    # A Git revision alone must not be invented into a release version.
    assert snapshot.version == ""
    assert build_comp_build(snapshot) is None
    mbedtls = next(package for package in package_snapshots_for_sbom_scans([scan.id]) if package.name == "mbedtls")
    assert mbedtls.version == "4.1.1"
    assert build_comp_build(mbedtls).compiled_sources == mbedtls.compiled_sources
    assert mbedtls.compiled_sources
    assert not any(path.endswith((".a", ".obj", ".elf")) for package in package_snapshots_for_sbom_scans([scan.id])
                   for path in package.compiled_sources)


def test_old_imports_are_unknown_not_zero_and_file_filter_is_scoped(app, tmp_path):
    variant, _ = _import(tmp_path, _documents())
    other = Variant.create("old-import", variant.project_id)
    scan = Scan.create("old", other.id)
    document = SBOMDocument.create("gone", "old", scan.id)
    from src.models import SBOMPackage
    package = Package.create("old", "1")
    SBOMPackage.create(document.id, package.id)
    companion = SBOMDocument.create("gone-too", "legacy-companion", scan.id)
    companion.delete()
    row = _package(app, other, "old")
    assert row["source_file_count"] is None
    assert row["source_files"] is None
    response = app.test_client().get("/api/packages", query_string={
        "variant_id": str(variant.id), "package_id": package.string_id, "include_source_files": "true",
    })
    assert response.get_json() == []


def test_upstream_engine_uses_proven_sources_without_suppressing_matching_files(app, tmp_path):
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from sbom_cve_check.analysis.computed_vuln import vex_assessment_from_compiled_sources
    from sbom_cve_check.vuln.vex import VexStatus

    _, scan = _import(tmp_path, _documents())
    package = next(package for package in package_snapshots_for_sbom_scans([scan.id]) if package.name == "lib")
    build = build_comp_build(package)
    now = datetime.now(timezone.utc)
    entry = SimpleNamespace(affected_sources={"src/disabled.c"})
    assessment = vex_assessment_from_compiled_sources(build, (entry,), now)
    assert assessment.status == VexStatus.NOT_AFFECTED
    entry.affected_sources = {"src/enabled.c"}
    assert vex_assessment_from_compiled_sources(build, (entry,), now) is None
    package._compiled_sources_complete = False
    assert vex_assessment_from_compiled_sources(build_comp_build(package), (entry,), now) is None


def test_source_migration_roundtrip_is_idempotent_and_keeps_existing_packages(app, tmp_path):
    import importlib
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import inspect

    variant, _ = _import(tmp_path, _documents())
    package_count = db.session.query(Package).count()
    migration = importlib.import_module("src.migrations.versions.a70c2d94e618_add_sbom_source_files")
    with db.engine.begin() as connection, Operations.context(MigrationContext.configure(connection)):
        migration.downgrade()
        assert not inspect(connection).has_table("sbom_files")
        migration.upgrade()
        migration.upgrade()
        assert inspect(connection).has_table("package_source_files")
    db.session.expire_all()
    assert db.session.query(Package).count() == package_count
    assert _package(app, variant)["source_file_count"] is None

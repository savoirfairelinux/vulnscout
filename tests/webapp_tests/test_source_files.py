# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import io
import subprocess
import tarfile
from pathlib import Path
import pytest

from src.bin.cmd_process import read_inputs
from src.bin.webapp import create_app
from src.controllers import ControllersCache
from src.controllers.scc_adapter import build_comp_build
from src.extensions import db
from src.helpers.active_scans import package_snapshots_for_sbom_scans
from src.models.sbom_file import has_compilation_evidence
from src.models import (
    Package, PackageSourceFile, Project, SBOMBuild, SBOMDocument, SBOMFile, SBOMFileBuild, Scan, Variant,
)


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
        {"type": "build_Build", "spdxId": ref("build"), "build_buildType": "urn:spdx.dev:zephyr-cmake",
         "build_parameter": [{"key": "compile:flags:C", "value": "-DCONFIG_FEATURE=1"}]},
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


def _assert_no_source_exclusion(scan, name="lib"):
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from sbom_cve_check.analysis.computed_vuln import vex_assessment_from_compiled_sources

    package = next(package for package in package_snapshots_for_sbom_scans([scan.id]) if package.name == name)
    assert not package.compiled_sources
    advisory = SimpleNamespace(affected_sources={"src/vulnerable.c"})
    assert vex_assessment_from_compiled_sources(
        build_comp_build(package), (advisory,), datetime.now(timezone.utc),
    ) is None


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
    assert file["builds"][0]["parameters"] == [{"key": "compile:flags:C", "value": "-DCONFIG_FEATURE=1"}]
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
    files = _package(app, variant)["source_files"]
    read_inputs(ControllersCache(), scan.id)
    assert db.session.query(SBOMFile).count() == 2
    assert db.session.query(PackageSourceFile).count() == count
    assert db.session.query(SBOMBuild).count() == 1
    assert db.session.query(SBOMFileBuild).count() == 1
    assert _package(app, variant)["source_file_count"] == 1
    assert _package(app, variant)["source_files"] == files


def test_build_metadata_is_stored_once_for_many_output_packages(app, tmp_path):
    from sqlalchemy import inspect
    from src.models import SBOMPackage

    documents = _documents()
    prefix = "https://example.org/evidence/"
    source_graph = documents["z-source.jsonld"]["@graph"]
    source_refs = [prefix + "file"]
    for index in range(1, 7):
        ref = prefix + f"file-{index}"
        source_refs.append(ref)
        source_graph.extend([
            {"type": "software_File", "spdxId": ref, "name": f"src/enabled-{index}.c"},
            {"type": "Relationship", "relationshipType": "contains", "from": prefix + "source", "to": [ref]},
        ])
    build_graph = documents["a-build.jsonld"]["@graph"]
    targets = [prefix + "output"]
    for index in range(1, 820):
        ref = prefix + f"package-{index}"
        targets.append(ref)
        build_graph.append({"type": "software_Package", "spdxId": ref,
                            "name": f"lib-output-{index}", "software_packageVersion": "1.0"})
    for node in build_graph:
        if node.get("relationshipType") == "hasInput":
            node["to"] = source_refs
        elif node.get("relationshipType") == "hasOutput":
            node["to"] = targets
        elif node.get("type") == "build_Build":
            node["build_parameter"] = [{"key": "compile:flags:C", "value": "x" * 8192}]
    variant, scan = _import(tmp_path, documents)
    assert db.session.query(PackageSourceFile).count() == 7 * 821
    assert db.session.query(SBOMBuild).count() == 1
    assert db.session.query(SBOMFileBuild).count() == 7
    assert "builds" not in {column["name"] for column in inspect(db.engine).get_columns("package_source_files")}
    build = db.session.scalars(db.select(SBOMBuild)).one()
    assert build.outputs == sorted(targets)
    assert build.parameters == [{"key": "compile:flags:C", "value": "x" * 8192}]
    page_count = db.session.execute(db.text("PRAGMA page_count")).scalar_one()
    page_size = db.session.execute(db.text("PRAGMA page_size")).scalar_one()
    assert page_count * page_size < 10 * 1024 * 1024
    row = app.test_client().get("/api/packages", query_string={
        "variant_id": str(variant.id), "package_id": "lib@1.0", "include_source_files": "true",
    }).get_json()[0]
    assert row["source_file_count"] == 7
    assert row["compiled_sources_complete"]
    assert row["source_files"][0]["builds"][0]["outputs"] == sorted(targets)
    evidence = SBOMPackage.evidence_for_documents(
        {doc.id for doc in SBOMDocument.get_by_scan(scan.id)}, include_source_files=True,
    )
    builds = [item["source_files"][0]["builds"][0] for item in evidence.values()]
    assert len(builds) == 821
    assert all(value is builds[0] for value in builds)


def test_multiple_builds_of_a_file_preserve_distinct_evidence(app, tmp_path):
    documents = _documents()
    prefix = "https://example.org/evidence/"
    documents["a-build.jsonld"]["@graph"].extend([
        {"type": "build_Build", "spdxId": prefix + "other-build", "build_buildType": "urn:spdx.dev:zephyr-cmake",
         "build_parameter": [{"key": "compile:flags:CXX", "value": "-DOTHER=1"}]},
        {"type": "Relationship", "relationshipType": "hasInput",
         "from": prefix + "other-build", "to": [prefix + "file"]},
        {"type": "Relationship", "relationshipType": "hasOutput",
         "from": prefix + "other-build", "to": [prefix + "output"]},
    ])
    variant, _ = _import(tmp_path, documents)
    assert db.session.query(SBOMBuild).count() == 2
    assert db.session.query(SBOMFileBuild).count() == 2
    builds = _package(app, variant)["source_files"][0]["builds"]
    assert {build["parameters"][0]["key"] for build in builds} == {"compile:flags:C", "compile:flags:CXX"}
    assert all(build["compiled"] for build in builds)


def test_deleting_a_build_document_removes_its_file_evidence(app, tmp_path):
    variant, scan = _import(tmp_path, _documents())
    build_document = next(document for document in SBOMDocument.get_by_scan(scan.id)
                          if document.source_name == "a-build.jsonld")
    build_document.delete()
    assert db.session.query(SBOMBuild).count() == 0
    assert db.session.query(SBOMFileBuild).count() == 0
    row = _package(app, variant, "lib-sources")
    assert row["source_file_count"] == 1
    assert row["source_files"][0]["builds"] == []
    assert not row["compiled_sources_complete"]


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
    snapshots = package_snapshots_for_sbom_scans([scan.id])
    assert next(package for package in snapshots if package.name == "lib-sources").compiled_sources == {"src/enabled.c"}
    assert not _package(app, variant)["compiled_sources_complete"]
    _assert_no_source_exclusion(scan)


@pytest.mark.parametrize("build_type,parameters", [
    (None, [{"key": "compile:flags:C", "value": "-O2"}]),
    ("urn:packaging", [{"key": "compile:flags:C", "value": "-O2"}]),
    ("urn:copy", []),
    ("urn:generator", []),
    ("urn:spdx.dev:zephyr-cmake", [{"key": "cmake:generator", "value": "Ninja"}]),
    ("urn:spdx.dev:zephyr-cmake", None),
    ("urn:spdx.dev:zephyr-cmake", [{"key": ["compile:flags:C"], "value": "-O2"}]),
])
def test_unproven_builds_cannot_exclude_cves(app, tmp_path, build_type, parameters):
    documents = _documents(path="manifest.json")
    build = next(node for node in documents["a-build.jsonld"]["@graph"] if node.get("type") == "build_Build")
    build["build_buildType"] = build_type
    build["build_parameter"] = parameters
    variant, scan = _import(tmp_path, documents)
    row = _package(app, variant)
    assert row["source_file_count"] == 1
    assert row["compiled_source_file_count"] == 0
    assert not row["source_files"][0]["builds"][0]["compiled"]
    assert not row["compiled_sources_complete"]
    _assert_no_source_exclusion(scan)


@pytest.mark.parametrize("compiled", [False, True])
def test_compilation_flags_cannot_make_an_unknown_build_type_compilation(compiled):
    assert not has_compilation_evidence([{
        "build_type": "urn:packaging", "compiled": compiled,
        "parameters": [{"key": "compile:flags:C", "value": "-O2"}],
    }])


@pytest.mark.parametrize("relation", [
    {"from": "source", "to": ["missing"]},
    {"from": "source", "to": [7]},
    {"from": "source", "to": None},
    {"from": "source"},
    {"from": None, "to": ["file"]},
    {"from": "missing", "to": ["file"]},
])
def test_unresolved_or_malformed_containment_disables_refinement(app, tmp_path, relation, caplog):
    documents = _documents()
    prefix = "https://example.org/evidence/"
    edge = {"type": "Relationship", "relationshipType": "contains", **relation}
    if isinstance(edge.get("from"), str):
        edge["from"] = prefix + edge["from"]
    if isinstance(edge.get("to"), list):
        edge["to"] = [prefix + value if isinstance(value, str) else value for value in edge["to"]]
    documents["z-source.jsonld"]["@graph"].append(edge)
    variant, scan = _import(tmp_path, documents)
    row = _package(app, variant)
    assert row["source_file_count"] == 1
    assert row["compiled_source_file_count"] == 1
    assert not row["compiled_sources_complete"]
    assert "containment references" in caplog.text
    _assert_no_source_exclusion(scan)


def test_unresolved_nested_containment_disables_refinement(app, tmp_path):
    documents = _documents()
    prefix = "https://example.org/evidence/"
    documents["z-source.jsonld"]["@graph"].extend([
        {"type": "ElementCollection", "spdxId": prefix + "collection"},
        {"type": "Relationship", "relationshipType": "contains",
         "from": prefix + "source", "to": [prefix + "collection"]},
        {"type": "Relationship", "relationshipType": "contains",
         "from": prefix + "collection", "to": [prefix + "missing"]},
    ])
    variant, scan = _import(tmp_path, documents)
    assert not _package(app, variant)["compiled_sources_complete"]
    _assert_no_source_exclusion(scan)


@pytest.mark.parametrize("package_input", [False, True])
@pytest.mark.parametrize("direct_source", [False, True])
def test_multistage_inputs_cannot_hide_source_contributions(app, tmp_path, package_input, direct_source):
    documents = _documents(path="src/vulnerable.c")
    prefix = "https://example.org/evidence/"
    graph = documents["a-build.jsonld"]["@graph"]
    graph[:] = [node for node in graph if node.get("relationshipType") != "contains"]
    input_ref = prefix + "output"
    if package_input:
        input_ref = prefix + "intermediate-package"
        graph.extend([
            {"type": "software_Package", "spdxId": input_ref, "name": "intermediate", "software_packageVersion": "1.0"},
            {"type": "Relationship", "relationshipType": "contains", "from": input_ref, "to": [prefix + "output"]},
        ])
    documents["z-source.jsonld"]["@graph"].extend([
        {"type": "software_File", "spdxId": prefix + "main", "name": "src/main.c"},
        {"type": "Relationship", "relationshipType": "contains",
         "from": prefix + "source", "to": [prefix + "main"]},
    ])
    graph.extend([
        {"type": "software_File", "spdxId": prefix + "executable", "name": "build/main.elf"},
        {"type": "build_Build", "spdxId": prefix + "final-build", "build_buildType": "urn:spdx.dev:zephyr-cmake",
         "build_parameter": [{"key": "compile:flags:C", "value": "-O2"}]},
        {"type": "Relationship", "relationshipType": "hasInput", "from": prefix + "final-build",
         "to": [input_ref, *([prefix + "main"] if direct_source else [])]},
        {"type": "Relationship", "relationshipType": "hasOutput",
         "from": prefix + "final-build", "to": [prefix + "executable"]},
        {"type": "Relationship", "relationshipType": "contains",
         "from": prefix + "package", "to": [prefix + "executable"]},
    ])
    variant, scan = _import(tmp_path, documents)
    row = _package(app, variant)
    assert row["source_file_count"] == int(direct_source)
    assert not row["compiled_sources_complete"]
    _assert_no_source_exclusion(scan)


def test_package_lists_count_files_without_loading_json_evidence(app, tmp_path):
    variant, _ = _import(tmp_path, _documents(extra=True))
    # Invalid JSON makes any accidental loading of full evidence fail the request.
    db.session.execute(db.text("UPDATE sbom_files SET properties = 'invalid JSON'"))
    db.session.execute(db.text("UPDATE sbom_builds SET parameters = 'invalid JSON', outputs = 'invalid JSON'"))
    db.session.commit()
    response = app.test_client().get("/api/packages", query_string={"variant_id": str(variant.id)})
    assert response.status_code == 200
    rows = {row["name"]: row for row in response.get_json()}
    assert rows["lib"]["source_file_count"] == 1
    assert rows["lib"]["compiled_source_file_count"] == 1
    assert rows["lib"]["compiled_sources_complete"]
    assert rows["lib-sources"]["source_file_count"] == 2
    assert not rows["lib-sources"]["compiled_sources_complete"]
    assert all("source_files" not in row for row in rows.values())


def test_file_details_do_not_load_unrelated_package_files(app, tmp_path):
    variant, _ = _import(tmp_path, _documents(extra=True))
    db.session.execute(db.text("UPDATE sbom_files SET properties = 'invalid JSON' WHERE spdx_id = :ref"),
                       {"ref": "https://example.org/evidence/listed"})
    db.session.commit()
    response = app.test_client().get("/api/packages", query_string={
        "variant_id": str(variant.id), "package_id": "lib@1.0", "include_source_files": "true",
    })
    assert response.status_code == 200
    row, = response.get_json()
    assert row["source_file_count"] == 1
    assert row["source_files"][0]["path"] == "src/enabled.c"


def test_count_queries_deduplicate_file_records_and_compiled_paths(app, tmp_path):
    from src.models import SBOMPackage

    variant, first_scan = _import(tmp_path, _documents())
    other = Variant.create("other", variant.project_id)
    _import(tmp_path, _documents(), other)
    source_document = next(doc for doc in SBOMDocument.get_by_scan(first_scan.id)
                           if doc.source_name == "z-source.jsonld")
    package = Package.get_by_string_id("lib@1.0")
    link = SBOMPackage.create(source_document.id, package.id)
    link.compiled_sources_complete = True
    db.session.add(PackageSourceFile(
        sbom_document_id=source_document.id, package_id=package.id,
        file_document_id=source_document.id, spdx_id="https://example.org/evidence/file",
    ))
    db.session.commit()
    response = app.test_client().get("/api/packages", query_string={
        "project_id": str(variant.project_id), "package_id": "lib@1.0",
    })
    row, = response.get_json()
    assert row["source_file_count"] == 2
    assert row["compiled_source_file_count"] == 1
    documents = {doc.id for doc in SBOMDocument.get_by_scan(first_scan.id)}
    assert PackageSourceFile.counts_for_documents(set()) == {}
    assert PackageSourceFile.counts_for_documents(documents, set()) == {}
    assert PackageSourceFile.evidence_for_documents(documents, set()) == {}


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
    assert db.session.query(SBOMBuild).count() == 0
    assert db.session.query(SBOMFileBuild).count() == 0


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
    # Older stored recipe inputs may lack the explicit compilation flag.
    package._compiled_sources_complete = True
    package.source_files[0]["builds"] = [{"build_type": "http://openembedded.org/bitbake/do_create_spdx/recipe"}]
    entry.affected_sources = {"src/disabled.c"}
    assert package.to_dict()["compiled_source_file_count"] == 0
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
        assert not inspect(connection).has_table("sbom_builds")
        assert not inspect(connection).has_table("sbom_file_builds")
        migration.upgrade()
        migration.upgrade()
        assert inspect(connection).has_table("package_source_files")
        assert inspect(connection).has_table("sbom_builds")
        assert inspect(connection).has_table("sbom_file_builds")
    db.session.expire_all()
    assert db.session.query(Package).count() == package_count
    assert _package(app, variant)["source_file_count"] is None


def _spdx2_documents():
    def document(namespace, packages, files, relationships):
        return {
            "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": namespace, "documentNamespace": "https://example.org/" + namespace,
            "creationInfo": {"creators": ["Tool: source-tests"], "created": "2026-01-01T00:00:00Z"},
            "packages": packages, "files": files, "relationships": relationships,
        }

    source = {"SPDXID": "SPDXRef-source", "fileName": "src/enabled.c", "fileTypes": ["SOURCE"],
              "checksums": [{"algorithm": "SHA256", "checksumValue": "a" * 64}],
              "licenseConcluded": "MIT", "licenseInfoInFiles": ["MIT"], "copyrightText": "NOASSERTION"}
    package = {"SPDXID": "SPDXRef-package", "name": "lib", "versionInfo": "1.0",
               "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "licenseDeclared": "MIT"}
    built = document("built", [package], [], [])
    built["externalDocumentRefs"] = [{
        "externalDocumentId": "DocumentRef-sources", "spdxDocument": "https://example.org/sources",
        "checksum": {"algorithm": "SHA1", "checksumValue": "b" * 40},
    }]
    built["relationships"] = [{
        "spdxElementId": "SPDXRef-package", "relationshipType": "CONTAINS",
        "relatedSpdxElement": "DocumentRef-sources:SPDXRef-source",
    }]
    sources = document("sources", [], [source], [])
    return {"a-built.spdx.json": built, "z-source.spdx.json": sources}


@pytest.mark.parametrize("fast", [False, True])
@pytest.mark.parametrize("containment", ["CONTAINS", "CONTAINED_BY", "hasFiles"])
def test_spdx2_companion_source_files_preserve_properties_without_claiming_compilation(
    app, tmp_path, monkeypatch, fast, containment,
):
    monkeypatch.setenv("IGNORE_PARSING_ERRORS", str(fast).lower())
    documents = _spdx2_documents()
    built = documents["a-built.spdx.json"]
    if containment == "hasFiles":
        built["packages"][0]["hasFiles"] = ["DocumentRef-sources:SPDXRef-source"]
        built["relationships"] = []
    elif containment == "CONTAINED_BY":
        built["relationships"] = [{
            "spdxElementId": "DocumentRef-sources:SPDXRef-source", "relationshipType": containment,
            "relatedSpdxElement": "SPDXRef-package",
        }]
    variant, scan = _import(tmp_path, documents)
    row = _package(app, variant)
    assert row["source_file_count"] == 1
    assert row["compiled_source_file_count"] == 0
    assert not row["compiled_sources_complete"]
    file = row["source_files"][0]
    assert file["path"] == "src/enabled.c"
    assert file["spdx_id"] == "https://example.org/sources#SPDXRef-source"
    assert file["properties"] == documents["z-source.spdx.json"]["files"][0]
    assert not file["builds"]
    assert all(not package.compiled_sources for package in package_snapshots_for_sbom_scans([scan.id]))
    read_inputs(ControllersCache(), scan.id)
    assert db.session.query(SBOMFile).count() == 1


def test_spdx2_external_file_references_never_use_a_different_scan(app, tmp_path):
    documents = _spdx2_documents()
    variant, _ = _import(tmp_path, documents)
    other = Variant.create("missing-source-companion", variant.project_id)
    _, scan = _import(tmp_path, {"a-built.spdx.json": documents["a-built.spdx.json"]}, other)
    assert _package(app, other)["source_file_count"] is None
    assert all(not package.compiled_sources for package in package_snapshots_for_sbom_scans([scan.id]))


@pytest.mark.parametrize("fast", [False, True])
def test_checked_in_yocto_spdx2_retains_binary_inventory_without_compiled_sources(app, tmp_path, monkeypatch, fast):
    monkeypatch.setenv("IGNORE_PARSING_ERRORS", str(fast).lower())
    path = (Path(__file__).resolve().parents[2] / "example" / "yocto-scarthgap-spdx2"
            / "core-image-minimal-stm32mp25-eval.spdx.tar.zst")
    uncompressed = subprocess.run(["unzstd", "-c", str(path)], check=True, capture_output=True)
    with tarfile.open(fileobj=io.BytesIO(uncompressed.stdout)) as archive:
        documents = {
            member.name: json.load(archive.extractfile(member))
            for member in archive if member.isfile() and member.name.endswith(".spdx.json")
        }
    variant, scan = _import(tmp_path, documents)
    assert len(documents) == 203
    assert db.session.query(SBOMFile).count() == 162
    binary = db.session.scalars(db.select(SBOMFile).where(SBOMFile.path == "bin/busybox.suid")).one()
    assert binary.properties["fileTypes"] == ["BINARY"]
    assert _package(app, variant, "busybox")["source_file_count"] == 0
    assert all(not package.compiled_sources for package in package_snapshots_for_sbom_scans([scan.id]))


def test_checked_in_yocto_spdx3_recipe_inputs_do_not_exclude_cves(app, tmp_path):
    path = (Path(__file__).resolve().parents[2] / "example" / "yocto-wrynose-spdx3"
            / "core-image-minimal-qemux86-64.rootfs.spdx.json")
    variant, scan = _import(tmp_path, {path.name: json.loads(path.read_text())})
    assert db.session.query(SBOMFile).count() == 859
    row = _package(app, variant, "libacl1")
    assert row["source_file_count"] == 3
    assert not row["compiled_sources_complete"]
    assert row["compiled_source_file_count"] == 0
    assert all(file["builds"] and not file["builds"][0]["compiled"] for file in row["source_files"])
    assert not any(file["path"].startswith("usr/lib/") for file in row["source_files"])
    assert all(not package.compiled_sources for package in package_snapshots_for_sbom_scans([scan.id]))


def _export_files(variant, version):
    from src.helpers.export_scope import compute_export_scope
    from src.views.spdx import SPDX
    from src.views.spdx3 import SPDX3

    controllers = ControllersCache(compute_export_scope(variant_id=variant.id))
    controllers.packages._preload_cache()
    view = SPDX(controllers) if version == 2 else SPDX3(controllers)
    output = json.loads(view.output_as_json())
    if version == 2:
        import jsonschema
        from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
        schema = Path(__file__).resolve().parents[1] / "schemas" / "spdx" / "spdx-schema-2.3.json"
        jsonschema.validate(output, json.loads(schema.read_text()))
        parser = SPDX(ControllersCache())
        parser.load_from_dict(output)
        assert validate_full_spdx_document(parser.sbom) == []
    return output


def _exported_file_records(output, version):
    from src.helpers.export_files import spdx2_annotation_inventory

    if version == 2:
        annotated, _ = spdx2_annotation_inventory(output)
        return [*output.get("files", []), *annotated]
    return [item for item in output["@graph"] if item.get("type") == "software_File"]


@pytest.mark.parametrize("version", [2, 3])
@pytest.mark.parametrize("fast", [False, True])
def test_file_exports_roundtrip_companion_identity_shared_records_and_active_scope(
    app, tmp_path, monkeypatch, version, fast,
):
    monkeypatch.setenv("IGNORE_PARSING_ERRORS", str(fast).lower())
    documents = _spdx2_documents()
    documents["z-source.spdx.json"]["files"][0]["checksums"].append({
        "algorithm": "SHA1", "checksumValue": "c" * 40,
    })
    built = documents["a-built.spdx.json"]
    built["packages"].append({**built["packages"][0], "SPDXID": "SPDXRef-shared", "name": "shared"})
    built["relationships"].append({**built["relationships"][0], "spdxElementId": "SPDXRef-shared"})
    duplicate = json.loads(json.dumps(documents["z-source.spdx.json"]))
    duplicate["documentNamespace"] = "https://example.org/duplicate"
    # Same local SPDX ID and same path, but a distinct companion-document record.
    duplicate["files"][0].pop("checksums")
    duplicate["files"][0]["fileContent"] = "FILE CONTENT MUST NOT BE EXPORTED"
    documents["duplicate.spdx.json"] = duplicate
    built["externalDocumentRefs"].append({
        **built["externalDocumentRefs"][0], "externalDocumentId": "DocumentRef-duplicate",
        "spdxDocument": duplicate["documentNamespace"],
    })
    built["relationships"].append({
        **built["relationships"][0], "relatedSpdxElement": "DocumentRef-duplicate:SPDXRef-source",
    })
    variant, _ = _import(tmp_path, _spdx2_documents())
    old_file = db.session.scalars(db.select(SBOMFile)).one()
    old_file.path = "old-scan-only.c"
    db.session.commit()
    _import(tmp_path, documents, variant)
    other = Variant.create("other", variant.project_id)
    _, other_scan = _import(tmp_path, _spdx2_documents(), other)
    for file in db.session.scalars(db.select(SBOMFile).join(SBOMDocument).where(
        SBOMDocument.scan_id == other_scan.id,
    )):
        file.path = "other-variant-only.c"
    db.session.commit()
    output = _export_files(variant, version)
    encoded = json.dumps(output)
    assert "old-scan-only.c" not in encoded
    assert "other-variant-only.c" not in encoded
    assert "FILE CONTENT MUST NOT BE EXPORTED" not in encoded
    files = _exported_file_records(output, version)
    assert len(files) == 2
    id_field = "SPDXID" if version == 2 else "spdxId"
    assert len({file[id_field] for file in files}) == 2
    hash_field = "checksums" if version == 2 else "verifiedUsing"
    assert sum(hash_field in file for file in files) == 1
    if version == 2:
        from src.helpers.export_files import spdx2_annotation_inventory
        _, annotated_relationships = spdx2_annotation_inventory(output)
        assert len(output["files"]) == 1
        relationships = [*output["relationships"], *annotated_relationships]
    else:
        relationships = output["@graph"]
    assert sum(item.get("relationshipType") == ("OTHER" if version == 2 else "contains")
               for item in relationships) == 3
    restored = Variant.create("restored", variant.project_id)
    name = "export.spdx.json" if version == 2 else "export.jsonld"
    _, scan = _import(tmp_path, {name: output}, restored)
    lib = _package(app, restored)
    shared = _package(app, restored, "shared")
    assert lib["source_file_count"] == 2
    assert shared["source_file_count"] == 1
    assert lib["compiled_source_file_count"] == shared["compiled_source_file_count"] == 0
    assert len({item["spdx_id"] for item in lib["source_files"]}) == 2
    assert shared["source_files"][0]["spdx_id"] in {item["spdx_id"] for item in lib["source_files"]}
    assert not any(package.compiled_sources for package in package_snapshots_for_sbom_scans([scan.id]))
    again = _export_files(restored, version)
    assert len(_exported_file_records(again, version)) == 2


@pytest.mark.parametrize("version", [2, 3])
@pytest.mark.parametrize("fast", [False, True])
def test_file_exports_preserve_recorded_compilation_without_fabricating_graph_completeness(
    app, tmp_path, monkeypatch, version, fast,
):
    monkeypatch.setenv("IGNORE_PARSING_ERRORS", str(fast).lower())
    documents = _documents(extra=True)
    variant, _ = _import(tmp_path, documents)
    output = _export_files(variant, version)
    files = _exported_file_records(output, version)
    assert len(files) == 3  # Includes the recorded binary output, not just source counts.
    if version == 3:
        identifiers = [node.get("spdxId", node.get("@id")) for node in output["@graph"]]
        assert len(identifiers) == len(set(identifiers))
        assert not any(node.get("type") == "build_Build" for node in output["@graph"])
    restored = Variant.create("restored", variant.project_id)
    name = "export.spdx.json" if version == 2 else "export.jsonld"
    _, scan = _import(tmp_path, {name: output}, restored)
    source = _package(app, restored, "lib-sources")
    built = _package(app, restored)
    assert source["source_file_count"] == 2
    assert source["compiled_source_file_count"] == built["compiled_source_file_count"] == 1
    assert not source["compiled_sources_complete"]
    assert not built["compiled_sources_complete"]
    compiled, listed = source["source_files"]
    assert compiled["path"] == "src/enabled.c"
    assert compiled["builds"][0]["compiled"] is True
    assert compiled["builds"][0]["parameters"] == [{"key": "compile:flags:C", "value": "-DCONFIG_FEATURE=1"}]
    assert compiled["builds"][0]["outputs"] == ["https://example.org/evidence/output"]
    assert listed["path"] == "src/listed.c"
    assert listed["builds"] == []
    assert not any(package.compiled_sources for package in package_snapshots_for_sbom_scans([scan.id]))
    read_inputs(ControllersCache(), scan.id)
    assert _package(app, restored, "lib-sources")["compiled_source_file_count"] == 1


@pytest.mark.parametrize("version", [2, 3])
def test_file_exports_do_not_invent_inventory_for_unrecorded_packages(app, tmp_path, version):
    from src.models import SBOMPackage

    project = Project.create("source-test")
    variant = Variant.create("default", project.id)
    scan = Scan.create("legacy inventory", variant.id, scan_type="sbom")
    document = SBOMDocument.create("gone", "legacy", scan.id)
    package = Package.create("lib", "1.0")
    SBOMPackage.create(document.id, package.id)
    output = _export_files(variant, version)
    assert not output.get("files")
    assert not any(node.get("type") == "software_File" for node in output.get("@graph", []))
    restored = Variant.create("restored", project.id)
    name = "export.spdx.json" if version == 2 else "export.jsonld"
    _import(tmp_path, {name: output}, restored)
    row = _package(app, restored)
    assert row["source_file_count"] is None
    assert not row["compiled_sources_complete"]


@pytest.mark.parametrize("version", [2, 3])
def test_file_exports_do_not_upgrade_recipe_input_observations_to_compilation(app, tmp_path, version):
    documents = _documents()
    build = next(node for node in documents["a-build.jsonld"]["@graph"] if node.get("type") == "build_Build")
    build["build_buildType"] = "http://openembedded.org/bitbake/do_create_spdx/recipe"
    variant, _ = _import(tmp_path, documents)
    output = _export_files(variant, version)
    restored = Variant.create("restored", variant.project_id)
    name = "export.spdx.json" if version == 2 else "export.jsonld"
    _import(tmp_path, {name: output}, restored)
    file = _package(app, restored)["source_files"][0]
    assert file["builds"]
    assert file["builds"][0]["compiled"] is False
    assert _package(app, restored)["compiled_source_file_count"] == 0


def test_spdx2_xml_exports_recorded_files_and_shared_containment(app, tmp_path):
    from xml.etree import ElementTree
    from src.helpers.export_scope import compute_export_scope
    from src.views.spdx import SPDX

    documents = _documents(extra=True)
    source = next(node for node in documents["z-source.jsonld"]["@graph"] if node.get("type") == "software_File")
    source["verifiedUsing"].append({"type": "Hash", "algorithm": "sha1", "hashValue": "c" * 40})
    variant, _ = _import(tmp_path, documents)
    controllers = ControllersCache(compute_export_scope(variant_id=variant.id))
    controllers.packages._preload_cache()
    output = SPDX(controllers).output_as_xml()
    root = ElementTree.fromstring(output)
    path = tmp_path / "export.spdx.xml"
    path.write_text(output)
    parser = SPDX(ControllersCache())
    parser.load_from_file(str(path))
    from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
    assert validate_full_spdx_document(parser.sbom) == []
    files = root.findall("files")
    assert len(files) == 1
    assert len({file.findtext("SPDXID") for file in files}) == 1
    assert sum(file.find("checksums") is not None for file in files) == 1
    associations = [relation for relation in root.findall("relationships")
                    if relation.findtext("relationshipType") == "OTHER"]
    assert len(associations) == 2
    from src.helpers.export_files import SPDX2_INVENTORY_PREFIX
    annotation = root.findtext("annotations/comment")
    assert annotation.startswith(SPDX2_INVENTORY_PREFIX)
    inventory = json.loads(annotation[len(SPDX2_INVENTORY_PREFIX):])
    assert len(inventory["files"]) == 2
    assert len(inventory["relationships"]) == 1


@pytest.mark.parametrize("absolute_path", [False, True])
def test_spdx2_hashless_and_sha256_only_records_are_valid_annotation_evidence(app, tmp_path, absolute_path):
    from src.helpers.export_files import spdx2_annotation_inventory

    documents = _documents(extra=True)
    if absolute_path:
        source = next(node for node in documents["z-source.jsonld"]["@graph"] if node.get("type") == "software_File")
        source["name"] = "/recorded/source.c"
        source["verifiedUsing"].append({"type": "Hash", "algorithm": "sha1", "hashValue": "c" * 40})
    variant, _ = _import(tmp_path, documents)
    output = _export_files(variant, 2)
    # Even a recorded SHA256 alone cannot satisfy SPDX2's normative SHA1 requirement.
    assert not output.get("files")
    files, relationships = spdx2_annotation_inventory(output)
    assert len(files) == 3
    hashed = next(file for file in files if file["fileName"] == (
        "/recorded/source.c" if absolute_path else "src/enabled.c"
    ))
    expected_hashes = [{"algorithm": "SHA256", "checksumValue": "a" * 64}]
    if absolute_path:
        expected_hashes.append({"algorithm": "SHA1", "checksumValue": "c" * 40})
    assert hashed["checksums"] == expected_hashes
    assert all(not file.get("checksums") for file in files if file is not hashed)
    private_ids = {file["SPDXID"] for file in files}
    assert all(relation["relatedSpdxElement"] not in private_ids for relation in output["relationships"])
    assert len(relationships) == 3

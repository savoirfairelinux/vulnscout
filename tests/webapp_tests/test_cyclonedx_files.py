# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Recorded evidence tests; only the checked-in MBOM is an upstream example."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from src.bin.cmd_process import read_inputs
from src.bin.webapp import create_app
from src.controllers import ControllersCache
from src.extensions import db
from src.helpers.active_scans import package_snapshots_for_sbom_scans
from src.models import (
    Package, PackageSourceFile, Project, SBOMBuild, SBOMDocument, SBOMFile, SBOMFileBuild, Scan, Variant,
)


FIXTURE = Path(__file__).parents[1] / "integration_tests/data/helloworld-c-mbom.json"


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


def _validate(data):
    directory = Path(__file__).parents[1] / "schemas/cyclonedx"
    registry = Registry().with_resources(
        (f"http://cyclonedx.org/schema/{path.name}", Resource.from_contents(json.loads(path.read_text())))
        for path in directory.glob("*.json")
    )
    schema = json.loads((directory / f"bom-{data['specVersion']}.schema.json").read_text())
    Draft7Validator(schema, registry=registry).validate(data)


def _import(tmp_path, documents, variant=None):
    if variant is None:
        project = Project.create("cyclonedx-files")
        variant = Variant.create("default", project.id)
    scan = Scan.create("recorded files", variant.id, scan_type="sbom")
    directory = tmp_path / str(scan.id)
    directory.mkdir()
    for name, data in documents.items():
        path = directory / name
        path.write_text(json.dumps(data))
        SBOMDocument.create(str(path), name, scan.id, format="cdx")
    read_inputs(ControllersCache(), scan.id)
    return variant, scan


def _packages(app, variant):
    return app.test_client().get("/api/packages", query_string={
        "variant_id": str(variant.id), "include_source_files": "true",
    }).get_json()


def _assert_not_compiled(scan):
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from sbom_cve_check.analysis.computed_vuln import vex_assessment_from_compiled_sources
    from src.controllers.scc_adapter import build_comp_build

    for package in package_snapshots_for_sbom_scans([scan.id]):
        assert not package.compiled_sources
        build = build_comp_build(package)
        if build is None:  # The upstream application's version is unknown.
            continue
        assert vex_assessment_from_compiled_sources(
            build, (SimpleNamespace(affected_sources={"vulnerable.c"}),),
            datetime.now(timezone.utc),
        ) is None


def test_official_helloworld_mbom_import_and_reimport(app, tmp_path):
    # Unmodified upstream CycloneDX 1.6 MBOM, pinned source documented in the user guide.
    data = json.loads(FIXTURE.read_text())
    _validate(data)
    variant, scan = _import(tmp_path, {"mbom.json": data})
    assert db.session.query(Package).count() == 1
    assert db.session.query(SBOMFile).count() == 2
    assert db.session.query(PackageSourceFile).count() == 2
    assert db.session.query(SBOMBuild).count() == 1
    assert db.session.query(SBOMFileBuild).count() == 2
    package, = _packages(app, variant)
    assert package["name"] == "Hello World"
    assert package["source_file_count"] == 2
    assert package["compiled_source_file_count"] == 0
    assert package["compiled_sources_complete"] is False
    files = package["source_files"]
    assert {file["path"] for file in files} == {"helloworld.c", "Makefile"}
    source = next(file for file in files if file["path"] == "helloworld.c")
    assert source["properties"]["type"] == "file"
    assert source["properties"]["mime-type"] == "text/x-csrc"
    assert source["properties"]["bom-ref"] == data["formulation"][0]["components"][0]["bom-ref"]
    assert source["builds"][0]["compiled"] is False
    assert source["builds"][0]["parameters"][0]["value"] == data["formulation"][0]
    _assert_not_compiled(scan)
    read_inputs(ControllersCache(), scan.id)
    assert _packages(app, variant)[0]["source_files"] == files
    assert db.session.query(SBOMFile).count() == 2
    assert db.session.query(PackageSourceFile).count() == 2
    assert db.session.query(SBOMBuild).count() == 1
    assert db.session.query(SBOMFileBuild).count() == 2
    for document in SBOMDocument.get_by_scan(scan.id):
        Path(document.path).unlink()
    assert _packages(app, variant)[0]["source_files"] == files


def _synthetic(version="1.6", path="src/observed.c", root=False):
    occurrence = {"location": path}
    if version == "1.6":
        occurrence.update(line=12, offset=4, symbol="observed", additionalContext="source match")
    component = {
        "type": "library", "name": "observed", "version": "1.0", "bom-ref": "observed",
        "evidence": {"occurrences": [occurrence, {"bom-ref": "occurrence", "location": "lib/libobserved.so"}]},
        "components": [
            {"type": "file", "name": "src/listed.c", "bom-ref": "listed",
             "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
             "properties": [{"name": "file:custom", "value": "kept"}]},
            {"type": "library", "name": "nested", "version": "2.0", "bom-ref": "nested", "components": [
                {"type": "file", "name": "nested/only.c"},
            ]},
        ],
    }
    return {
        "bomFormat": "CycloneDX", "specVersion": version, "version": 1,
        **({"metadata": {"component": component}} if root else {"components": [component]}),
    }


@pytest.mark.parametrize("version", ["1.5", "1.6"])
@pytest.mark.parametrize("root", [False, True])
def test_synthetic_occurrences_and_nested_files(app, tmp_path, version, root):
    data = _synthetic(version, root=root)
    _validate(data)
    variant, scan = _import(tmp_path, {"occurrences.json": data})
    packages = {package["name"]: package for package in _packages(app, variant)}
    assert set(packages) == {"observed", "nested"}
    observed = packages["observed"]
    assert observed["source_file_count"] == 3
    assert observed["compiled_source_file_count"] == 0
    assert observed["compiled_sources_complete"] is False
    files = observed["source_files"]
    assert {file["path"] for file in files} == {"src/observed.c", "lib/libobserved.so", "src/listed.c"}
    occurrence = next(file for file in files if file["path"] == "src/observed.c")
    assert occurrence["properties"]["occurrence"] == {"location": "src/observed.c", **(
        {"line": 12, "offset": 4, "symbol": "observed", "additionalContext": "source match"}
        if version == "1.6" else {}
    )}
    listed = next(file for file in files if file["path"] == "src/listed.c")
    assert listed["properties"]["type"] == "file"
    assert listed["properties"]["hashes"] == [{"alg": "SHA-256", "content": "a" * 64}]
    assert listed["properties"]["properties"] == [{"name": "file:custom", "value": "kept"}]
    assert all(file["builds"] == [] for file in files)
    assert [file["path"] for file in packages["nested"]["source_files"]] == ["nested/only.c"]
    _assert_not_compiled(scan)
    read_inputs(ControllersCache(), scan.id)
    assert _packages(app, variant) == list(packages.values())
    assert db.session.query(SBOMFile).count() == 4
    assert db.session.query(SBOMBuild).count() == 0


def test_unowned_files_dependencies_and_foreign_formulas_do_not_assign_ownership(app, tmp_path):
    data = json.loads(FIXTURE.read_text())
    data["components"][0]["externalReferences"][0]["url"] = (
        "urn:cdx:00000000-0000-0000-0000-000000000001/1#formula-1"
    )
    data["components"].extend([
        {"type": "file", "name": "unowned.c", "bom-ref": "unowned"},
        {"type": "library", "name": "unrelated", "bom-ref": "unrelated"},
    ])
    data["dependencies"] = [
        {"ref": "helloworld", "dependsOn": ["unowned", "unrelated"]},
    ]
    _validate(data)
    variant, scan = _import(tmp_path, {"mbom.json": data})
    assert db.session.query(Package).count() == 2
    assert db.session.query(SBOMFile).count() == 3
    assert db.session.query(PackageSourceFile).count() == 0
    assert all(not package["source_files"] for package in _packages(app, variant))
    _assert_not_compiled(scan)


def test_documents_scans_and_variants_are_scoped(app, tmp_path):
    first = _synthetic(path="first.c")
    second = _synthetic(path="second.c")
    # Identical local refs and absolute file refs must never join documents.
    first["components"][0]["components"][0]["bom-ref"] = "file:///shared.c"
    second["components"][0]["components"][0]["bom-ref"] = "file:///shared.c"
    variant, scan = _import(tmp_path, {"first.json": first, "second.json": second})
    files = next(row for row in _packages(app, variant) if row["name"] == "observed")["source_files"]
    assert len(files) == 6
    assert len({file["spdx_id"] for file in files}) == 6
    assert {file["document_name"] for file in files} == {"first.json", "second.json"}
    foreign = json.loads(FIXTURE.read_text())
    foreign["components"] = [{"type": "library", "name": "observed", "version": "1.0", "bom-ref": "observed"}]
    _, same_variant_scan = _import(tmp_path, {"unowned-formula.json": foreign}, variant)
    project = Project.create("other-cyclonedx-files")
    other = Variant.create("other", project.id)
    _import(tmp_path, {"other.json": _synthetic(path="other.c")}, other)
    assert db.session.query(PackageSourceFile).filter_by(
        sbom_document_id=SBOMDocument.get_by_scan(same_variant_scan.id)[0].id,
    ).count() == 0
    read_inputs(ControllersCache(), scan.id)
    assert PackageSourceFile.evidence_for_documents(
        {document.id for document in SBOMDocument.get_by_scan(scan.id)},
    )
    other_files = next(row for row in _packages(app, other) if row["name"] == "observed")["source_files"]
    assert len(other_files) == 3
    assert all(file["variant_id"] == str(other.id) for file in other_files)
    assert "other.c" in {file["path"] for file in other_files}
    assert not {file["spdx_id"] for file in files} & {file["spdx_id"] for file in other_files}


def test_file_evidence_without_bom_refs_and_mcp(app, tmp_path, monkeypatch):
    import httpx
    from vulnscout_mcp.client import VulnScoutClient
    from vulnscout_mcp.tools.dependencies import _source_files_impl

    data = _synthetic(root=True)
    del data["metadata"]["component"]["bom-ref"]
    _validate(data)
    variant, scan = _import(tmp_path, {"anonymous.json": data})
    package = next(row for row in _packages(app, variant) if row["name"] == "observed")
    assert package["source_file_count"] == 3
    http = app.test_client()

    def get(client, url, *, params):
        response = http.get(url.removeprefix("http://vulnscout.test"), query_string=params)
        return httpx.Response(response.status_code, json=response.json)

    monkeypatch.setattr(httpx.Client, "get", get)
    result = json.loads(_source_files_impl(
        VulnScoutClient("http://vulnscout.test"), str(variant.id), "observed@1.0", 0, 100,
    ))
    assert result["items"] == package["source_files"]
    assert result["compiled_source_file_count"] == 0
    assert result["compiled_sources_complete"] is False
    read_inputs(ControllersCache(), scan.id)
    assert next(row for row in _packages(app, variant) if row["name"] == "observed") == package


def test_original_yocto_14_inventory_is_unchanged(app, tmp_path):
    path = Path(__file__).parents[2] / "example/yocto-scarthgap-cdx/bom.json"
    data = json.loads(path.read_text())
    assert data["specVersion"] == "1.4"
    variant, _ = _import(tmp_path, {"bom.json": data})
    assert len(data["components"]) == 97
    assert len(_packages(app, variant)) == 93  # Existing name/version duplicate consolidation.
    assert db.session.query(SBOMFile).count() == 0
    assert db.session.query(PackageSourceFile).count() == 0
    assert db.session.query(SBOMBuild).count() == 0
    assert all(not row["source_files"] for row in _packages(app, variant))


def test_synthetic_15_formulation_replacement(app, tmp_path):
    data = json.loads(FIXTURE.read_text())
    data["specVersion"] = "1.5"  # Separate synthetic 1.5 case; do not modify the upstream fixture.
    data["$schema"] = "http://cyclonedx.org/schema/bom-1.5.schema.json"
    _validate(data)
    variant, scan = _import(tmp_path, {"mbom.json": data})
    assert _packages(app, variant)[0]["source_file_count"] == 2
    data["formulation"][0]["components"] = [{
        "type": "file", "name": "replacement.o", "mime-type": "application/x-object",
        "hashes": [{"alg": "SHA-256", "content": "b" * 64}],
        "properties": [{"name": "file:role", "value": "object"}],
    }]
    data["formulation"][0].pop("workflows")
    _validate(data)
    document, = SBOMDocument.get_by_scan(scan.id)
    Path(document.path).write_text(json.dumps(data))
    read_inputs(ControllersCache(), scan.id)
    package, = _packages(app, variant)
    assert [file["path"] for file in package["source_files"]] == ["replacement.o"]
    assert package["source_files"][0]["properties"] == data["formulation"][0]["components"][0]
    assert package["compiled_source_file_count"] == 0
    assert db.session.query(SBOMFile).count() == 1
    assert db.session.query(PackageSourceFile).count() == 1
    assert db.session.query(SBOMBuild).count() == 1
    assert db.session.query(SBOMFileBuild).count() == 1
    data.pop("formulation")
    data["components"][0].pop("externalReferences")
    Path(document.path).write_text(json.dumps(data))
    read_inputs(ControllersCache(), scan.id)
    assert db.session.query(SBOMFile).count() == 0
    assert db.session.query(PackageSourceFile).count() == 0
    assert db.session.query(SBOMBuild).count() == 0
    assert db.session.query(SBOMFileBuild).count() == 0
    assert not _packages(app, variant)[0]["source_files"]


def test_formulation_bom_links_cannot_resolve_in_companion_documents(app, tmp_path):
    data = json.loads(FIXTURE.read_text())
    linked = json.loads(FIXTURE.read_text())
    linked["components"][0]["name"] = "Other application"
    linked["serialNumber"] = "urn:uuid:00000000-0000-0000-0000-000000000001"
    linked.pop("formulation")
    _validate(linked)
    variant, _ = _import(tmp_path, {"owner.json": data, "foreign-link.json": linked})
    packages = {package["name"]: package for package in _packages(app, variant)}
    assert packages["Hello World"]["source_file_count"] == 2
    assert not packages["Other application"]["source_files"]


def test_explicit_file_nesting_preserves_owner_through_non_package_containers(app, tmp_path):
    data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [
        {"type": "application", "name": "owner", "version": "1.0", "components": [
            {"type": "container", "name": "container", "components": [
                {"type": "file", "name": "outer.tar", "components": [
                    {"type": "file", "name": "nested.c"},
                ]},
            ]},
        ]},
    ]}
    _validate(data)
    variant, _ = _import(tmp_path, {"nested.json": data})
    package, = _packages(app, variant)
    assert package["name"] == "owner"
    assert {file["path"] for file in package["source_files"]} == {"outer.tar", "nested.c"}

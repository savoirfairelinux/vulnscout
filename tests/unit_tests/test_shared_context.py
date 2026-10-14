# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Shared entries retain identity, variant scopes and compatibility projections."""

from copy import deepcopy
import uuid
import pytest
from sqlalchemy import text

from src.bin.webapp import create_app
from src.extensions import db
from src.helpers.shared_context import empty_document, project_variant, validate_document
from src.helpers.stride_context import parse_model
from src.models.project import Project
from src.models.project_context import ProjectContext
from src.models.variant import Variant
from src.models.variant_context import VariantContext


@pytest.fixture()
def setup(monkeypatch):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("SCAN_FILE", "/dev/null")
    app = create_app()
    app.config["TESTING"] = True
    app._INT_SCAN_FINISHED = True
    with app.app_context():
        db.create_all()
        project = Project.create("Shared")
        variants = [Variant.create(name, project.id) for name in ("alpha", "beta", "gamma")]
        yield app.test_client(), project, variants
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


def read(client, project):
    response = client.get(f"/api/projects/{project.id}/context/shared")
    assert response.status_code == 200, response.json
    return response.json


def save(client, project, document, section="context", **extra):
    body = {"context": document, "section": section, "expected_revision": read(client, project)["revision"], **extra}
    return client.patch(f"/api/projects/{project.id}/context/shared", json=body)


def component(identifier, targets, name="Device"):
    return {"id": identifier, "variant_ids": targets, "name": name, "description": "", "trustZone": ""}


def threat(identifier, targets, target_ids=None, description="Unauthenticated update"):
    return {"id": identifier, "variant_ids": targets, "category": "Tampering",
            "description": description, "targetIds": target_ids or []}


def risk(identifier, targets, threat_id="T1"):
    return {"id": identifier, "variant_ids": targets, "threatId": threat_id,
            "likelihood": "High", "impact": "", "mitigation": "", "decision": ""}


def scoped_text(identifier, targets, value):
    return {"id": identifier, "variant_ids": targets, "value": value}


def graph(targets):
    document = empty_document()
    document["components"] = [component("C1", targets), component("C2", targets, "Service")]
    document["interactions"] = [{
        "id": "I1", "variant_ids": targets, "name": "Updates", "sourceId": "C2", "destinationId": "C1",
        "protocol": "HTTPS", "description": "Firmware", "trustBoundary": "Public network",
    }]
    document["threats"] = [threat("T1", targets, ["I1"])]
    document["risks"] = [risk("R1", targets)]
    return document


def initialize(client, project, document):
    for section in ("context", "system", "threat_model", "risks"):
        result = save(client, project, document, section)
        assert result.status_code == 200, result.json
    return read(client, project)


def test_read_is_lazy_and_initializes_identical_entries_as_shared(setup):
    client, project, variants = setup
    for variant in variants[:2]:
        VariantContext.upsert(variant.id, environment="Embedded Linux", threat_model="  Original text  ")
    document = read(client, project)["context"]
    assert document["editor_mode"] == "free"
    assert document["fields"]["environment"][0]["variant_ids"] == [str(v.id) for v in variants[:2]]
    assert len(document["free_threat_model"]) == 1
    assert project_variant(document, str(variants[0].id))["threat_model"] == "  Original text  "
    assert ProjectContext.get_by_project(project.id).shared_context is None
    assert VariantContext.get_by_variant(variants[2].id) is None


def test_identical_paths_with_different_orders_and_repetition_are_lossless(setup):
    client, project, variants = setup
    paths = ["/a;/b;/a", "/b;/a", "/a;/b"]
    for variant, value in zip(variants, paths):
        VariantContext.upsert(variant.id, codebase_path=value)
    document = read(client, project)["context"]
    assert [project_variant(document, str(v.id))["codebase_path"] for v in variants] == paths
    assert save(client, project, document).status_code == 200
    assert [VariantContext.get_by_variant(v.id).codebase_path for v in variants] == paths


def test_saves_share_text_and_outdate_only_affected_recipients(setup):
    client, project, variants = setup
    document = read(client, project)["context"]
    targets = [str(v.id) for v in variants[:2]]
    document["fields"]["environment"] = [scoped_text("X1", targets, "RTOS")]
    result = save(client, project, document)
    assert result.status_code == 200
    assert result.json["changed_variant_ids"] == targets
    assert not result.json["description_changed"]
    timestamps = [VariantContext.get_by_variant(v.id).updated_at for v in variants]
    assert timestamps[0] and timestamps[1] and timestamps[2] is None
    document["fields"]["environment"][0]["value"] = "New RTOS"
    assert save(client, project, document).status_code == 200
    assert [VariantContext.get_by_variant(v.id).environment for v in variants] == ["New RTOS", "New RTOS", None]
    future = Variant.create("future", project.id)
    assert str(future.id) not in read(client, project)["context"]["fields"]["environment"][0]["variant_ids"]
    assert VariantContext.get_by_variant(future.id) is None


def test_preview_does_not_write_and_description_change_covers_project(setup):
    client, project, variants = setup
    document = empty_document()
    document["fields"]["environment"] = [scoped_text("X1", [str(variants[0].id)], "Zephyr")]
    preview = save(client, project, document, description="New project", dry_run=True)
    assert preview.json == {"changed_variant_ids": [str(variants[0].id)], "description_changed": True}
    assert ProjectContext.get_by_project(project.id) is None
    assert save(client, project, document, description="New project").json["description_changed"]


def test_section_saves_ignore_other_sections_drafts_and_require_saved_dependencies(setup):
    client, project, variants = setup
    document = graph([str(v.id) for v in variants])
    document["fields"]["environment"] = [scoped_text("X1", [str(variants[0].id)], "Linux")]
    assert save(client, project, document).status_code == 200
    assert read(client, project)["context"]["components"] == []
    assert save(client, project, document, "threat_model").status_code == 400
    assert save(client, project, document, "risks").status_code == 400
    assert save(client, project, document, "system").status_code == 200
    assert read(client, project)["context"]["threats"] == []
    assert save(client, project, document, "threat_model").status_code == 200
    assert save(client, project, document, "risks").status_code == 200
    saved = read(client, project)["context"]
    assert parse_model(VariantContext.get_by_variant(variants[0].id).threat_model)[1]["threats"][0]["targetIds"] == ["I1"]
    changed = deepcopy(saved)
    changed["components"][0]["variant_ids"] = [str(variants[0].id)]
    assert save(client, project, changed, "system").status_code == 400
    changed = deepcopy(saved)
    changed["threats"] = []
    assert "before removing" in save(client, project, changed, "threat_model").json["error"]
    saved["risks"] = []
    assert save(client, project, saved, "risks").status_code == 200
    assert save(client, project, changed, "threat_model").status_code == 200


def test_project_revision_conflicts_and_legacy_description_writes(setup):
    client, project, _ = setup
    document = empty_document()
    first = save(client, project, document)
    assert first.status_code == 200
    stale = first.json["revision"]
    ProjectContext.upsert(project.id, "Agent description")
    result = save(client, project, document, expected_revision=stale, description="Stale overwrite")
    assert result.status_code == 409
    assert ProjectContext.get_by_project(project.id).description == "Agent description"


@pytest.mark.parametrize("method", ["PUT", "PATCH", "model", "description"])
def test_legacy_writes_invalidate_snapshot_before_first_shared_save(setup, method):
    client, project, variants = setup
    baseline = read(client, project)
    if method == "model":
        VariantContext.upsert(variants[0].id, environment="Agent edit")
    elif method == "description":
        ProjectContext.upsert(project.id, "Agent description")
    else:
        result = client.open(f"/api/variants/{variants[0].id}/context", method=method, json={"environment": "Agent edit"})
        assert result.status_code == 200
    result = save(client, project, baseline["context"], expected_revision=baseline["revision"], description=None)
    assert result.status_code == 409
    if method == "description":
        assert ProjectContext.get_by_project(project.id).description == "Agent description"
    else:
        assert VariantContext.get_by_variant(variants[0].id).environment == "Agent edit"
    assert ProjectContext.get_by_project(project.id).shared_context is None


def test_atomic_revision_guard_rejects_writer_after_prepare(setup, monkeypatch):
    client, project, _ = setup
    document = empty_document()
    save(client, project, document)
    from src.helpers import shared_context
    original = shared_context.prepare_section

    def raced(*args):
        prepared = original(*args)
        db.session.execute(db.update(ProjectContext).where(ProjectContext.project_id == project.id).values(
            context_revision=ProjectContext.context_revision + 1,
        ))
        db.session.commit()
        return prepared

    monkeypatch.setattr(shared_context, "prepare_section", raced)
    assert save(client, project, document).status_code == 409


def test_single_variant_patch_detaches_only_changed_information_and_preserves_fields(setup):
    client, project, variants = setup
    targets = [str(v.id) for v in variants]
    document = empty_document("free")
    document["fields"]["environment"] = [scoped_text("X1", targets, "RTOS")]
    document["fields"]["variant_description"] = [scoped_text("X2", targets, "Device")]
    assert save(client, project, document).status_code == 200
    result = client.patch(f"/api/variants/{variants[0].id}/context", json={
        "environment": "Linux", "expected": {"environment": "RTOS"},
    })
    assert result.status_code == 200, result.json
    assert result.json["variant_description"] == "Device"
    assert [VariantContext.get_by_variant(v.id).environment for v in variants] == ["Linux", "RTOS", "RTOS"]
    assert len(read(client, project)["context"]["fields"]["variant_description"]) == 1
    assert client.patch(f"/api/variants/{variants[0].id}/context", json={
        "environment": "Stale", "expected": {"environment": "RTOS"},
    }).status_code == 409
    assert VariantContext.get_by_variant(variants[0].id).environment == "Linux"


def test_legacy_put_and_model_writes_sync_shared_text_without_editing_other_recipients(setup):
    client, project, variants = setup
    targets = [str(v.id) for v in variants]
    document = empty_document("free")
    document["free_threat_model"] = [scoped_text("X1", targets, "Shared model")]
    assert save(client, project, document).status_code == 200
    assert save(client, project, document, "threat_model").status_code == 200
    result = client.put(f"/api/variants/{variants[0].id}/context", json={"threat_model": "Only alpha"})
    assert result.status_code == 200
    VariantContext.upsert(variants[1].id, threat_model="Only beta", commit=False)
    db.session.commit()
    assert [VariantContext.get_by_variant(v.id).threat_model for v in variants] == [
        "Only alpha", "Only beta", "Shared model",
    ]


def test_compatible_patch_new_variant_has_no_implicit_shared_scope(setup):
    client, project, _ = setup
    save(client, project, empty_document())
    new = Variant.create("new", project.id)
    assert client.patch(f"/api/variants/{new.id}/context", json={
        "environment": "Zephyr", "expected": {"environment": None},
    }).status_code == 200
    assert read(client, project)["context"]["fields"]["environment"][0]["variant_ids"] == [str(new.id)]


@pytest.mark.parametrize("reverse", [False, True])
def test_local_id_collisions_never_resolve_another_variants_missing_reference(setup, reverse):
    client, project, variants = setup
    missing, actual = (variants[1], variants[0]) if reverse else variants[:2]
    document = graph([str(actual.id)])
    projected = project_variant(document, str(actual.id))
    VariantContext.upsert(actual.id, threat_model=projected["threat_model"], risks=projected["risks"], editor_mode="stride")
    legacy = graph([str(missing.id)])
    legacy["components"] = []; legacy["interactions"] = []; legacy["risks"] = []
    legacy["threats"] = [threat("T1", [str(missing.id)], ["C1"])]
    VariantContext.upsert(missing.id, **project_variant(legacy, str(missing.id)))
    loaded = read(client, project)["context"]
    validate_document(loaded, {str(v.id) for v in variants})
    unavailable = next(row for row in loaded["threats"] if str(missing.id) in row["variant_ids"])["targetIds"][0]
    assert unavailable not in {row["id"] for row in loaded["components"]}
    actual_fields = project_variant(loaded, str(actual.id))
    _, model = parse_model(actual_fields["threat_model"])
    assert model["threats"][0]["targetIds"][0] in {row["id"] for row in loaded["interactions"]}


def test_mode_conversion_preserves_scoped_context_and_only_presentation_does_not_outdate(setup):
    client, project, variants = setup
    targets = [str(v.id) for v in variants]
    document = graph(targets)
    document["fields"]["environment"] = [
        scoped_text("X1", targets, "Common"), scoped_text("X2", targets[:1], "Alpha details"),
    ]
    initialize(client, project, document)
    timestamps = [VariantContext.get_by_variant(v.id).updated_at for v in variants]
    converted = client.post(f"/api/projects/{project.id}/context/shared", json={
        "context": read(client, project)["context"], "editor_mode": "free",
    })
    assert converted.status_code == 200
    assert converted.json["context"]["fields"]["environment"] == document["fields"]["environment"]
    assert save(client, project, converted.json["context"], "risks").status_code == 400
    result = save(client, project, converted.json["context"])
    assert result.status_code == 200, result.json
    assert result.json["changed_variant_ids"] == []
    assert [VariantContext.get_by_variant(v.id).updated_at for v in variants] == timestamps
    converted_back = client.post(f"/api/projects/{project.id}/context/shared", json={
        "context": result.json["context"], "editor_mode": "stride",
    }).json["context"]
    assert len(converted_back["components"]) == 2
    assert save(client, project, converted_back).json["changed_variant_ids"] == []


def test_scoped_export_import_is_portable_and_partial_import_retains_other_recipients(setup):
    client, project, variants = setup
    targets = [str(v.id) for v in variants]
    document = graph(targets)
    document["fields"]["environment"] = [scoped_text("X1", targets, "Common")]
    initialize(client, project, document)
    exported = client.get(f"/api/context/export?variant_ids={variants[0].id}").json
    assert exported["version"] == "3.0"
    entry = exported["projects"][0]
    assert entry["variants"] == [{"variant_name": "alpha"}]
    assert entry["context"]["components"][0]["variant_names"] == ["alpha"]
    assert "variant_ids" not in str(exported)
    assert client.post("/api/context/import", json=exported).json["failed"] == []
    restored = read(client, project)["context"]
    assert len(restored["components"]) == 2
    assert len(restored["fields"]["environment"]) == 1
    entry["context"]["fields"]["environment"][0]["value"] = "Alpha only"
    assert client.post("/api/context/import", json=exported).json["failed"] == []
    assert [VariantContext.get_by_variant(v.id).environment for v in variants] == ["Alpha only", "Common", "Common"]
    assert len(read(client, project)["context"]["components"]) == 2


def test_export_mixed_shared_and_legacy_projects_uses_one_v3_canonical_schema(setup):
    client, project, _ = setup
    save(client, project, empty_document())
    other = Project.create("Legacy")
    variant = Variant.create("default", other.id)
    VariantContext.upsert(variant.id, threat_model="  Legacy text  ")
    exported = client.get("/api/context/export").json
    assert exported["version"] == "3.0"
    legacy = next(entry for entry in exported["projects"] if entry["project_name"] == "Legacy")
    assert legacy["context"]["free_threat_model"][0]["value"] == "  Legacy text  "
    assert client.post("/api/context/import", json=exported).json["failed"] == []


def test_partial_import_remaps_changed_graph_without_leaking_into_other_variants(setup):
    client, project, variants = setup
    initialize(client, project, graph([str(v.id) for v in variants]))
    original = VariantContext.get_by_variant(variants[1].id).to_dict()
    exported = client.get(f"/api/context/export?variant_ids={variants[0].id}").json
    exported["projects"][0]["context"]["components"][0]["name"] = "Alpha device"
    assert client.post("/api/context/import", json=exported).json["failed"] == []
    alpha = VariantContext.get_by_variant(variants[0].id)
    system, model = parse_model(alpha.threat_model)
    assert system["components"][0]["name"] == "Alpha device"
    identifiers = {row["id"] for row in system["components"]}
    assert system["interactions"][0]["sourceId"] in identifiers
    assert system["interactions"][0]["destinationId"] in identifiers
    assert model["threats"][0]["targetIds"] == [system["interactions"][0]["id"]]
    assert VariantContext.get_by_variant(variants[1].id).to_dict() == original


@pytest.mark.parametrize("missing_project", [False, True])
def test_v3_unknown_recipients_have_explicit_ignored_reporting(setup, missing_project):
    client, project, _ = setup
    payload = {"version": "3.0", "projects": [{
        "project_name": "Unknown" if missing_project else project.name,
        "project_description": None, "variants": [{"variant_name": "unknown"}], "context": empty_document(),
    }]}
    response = client.post("/api/context/import", json=payload)
    assert response.status_code == 200
    assert response.json["ignored"][0]["reason"] == ("Project not found" if missing_project else "Variant not found")
    assert response.json["imported"] == []
    assert ProjectContext.get_by_project(project.id) is None


@pytest.mark.parametrize("change", [
    lambda body: body.update(unknown="Must not be discarded"),
    lambda body: body["projects"][0].update(unknown="Must not be discarded"),
    lambda body: body["projects"][0].update(context=None),
    lambda body: body["projects"][0].update(variants=[{"variant_name": "alpha", "environment": "Extra"}]),
    lambda body: body["projects"][0].update(variants=[{"variant_name": 5}]),
    lambda body: body["projects"][0].update(variants=[{"variant_name": "alpha"}, {"variant_name": "alpha"}]),
    lambda body: body["projects"][0]["context"].update(components={}),
    lambda body: body["projects"][0]["context"]["fields"]["environment"].append(
        {"id": "X1", "value": "Data", "variant_names": ["alpha"], "variant_ids": ["Unexpected UUID"]}),
    lambda body: body["projects"][0]["context"]["fields"]["environment"].append(
        {"id": "X1", "value": "Data", "variant_names": ["undeclared"]}),
    lambda body: body["projects"][0]["context"]["fields"]["environment"].append({"id": "X1", "value": "Data"}),
])
def test_v3_invalid_schema_is_rejected_before_any_project_is_written(setup, change):
    client, project, _ = setup
    body = {"version": "3.0", "projects": [{
        "project_name": project.name, "project_description": None,
        "variants": [{"variant_name": "alpha"}], "context": empty_document(),
    }]}
    change(body)
    response = client.post("/api/context/import", json=body)
    assert response.status_code == 400, response.json
    assert ProjectContext.get_by_project(project.id) is None


def test_shared_patch_absent_variant_rejects_nonnull_expectations(setup):
    client, project, _ = setup
    save(client, project, empty_document())
    future = Variant.create("future", project.id)
    response = client.patch(f"/api/variants/{future.id}/context", json={
        "environment": "New", "expected": {"environment": "Previously saved"},
    })
    assert response.status_code == 409
    assert VariantContext.get_by_variant(future.id) is None


@pytest.mark.parametrize("shared", [False, True])
def test_concurrent_creation_is_a_conflict_not_an_unhandled_integrity_error(setup, monkeypatch, shared):
    client, project, variants = setup
    ProjectContext.upsert(project.id, "Existing description")
    original = ProjectContext.get_by_project
    monkeypatch.setattr(ProjectContext, "get_by_project", staticmethod(lambda _: None))
    if shared:
        response = save(client, project, empty_document())
    else:
        response = client.put(f"/api/variants/{variants[0].id}/context", json={"environment": "New"})
    assert response.status_code == 409
    monkeypatch.setattr(ProjectContext, "get_by_project", staticmethod(original))
    assert ProjectContext.get_by_project(project.id).description == "Existing description"


def test_legacy_revision_guard_rejects_stale_model_write_without_mutating_variant(setup, monkeypatch):
    client, project, variants = setup
    VariantContext.upsert(variants[0].id, environment="Original")
    original = ProjectContext.advance_revision

    def raced(identifier, expected_revision):
        db.session.execute(db.update(ProjectContext).where(ProjectContext.project_id == identifier).values(
            context_revision=ProjectContext.context_revision + 1,
        ))
        db.session.commit()
        original(identifier, expected_revision)

    monkeypatch.setattr(ProjectContext, "advance_revision", staticmethod(raced))
    response = client.put(f"/api/variants/{variants[0].id}/context", json={"environment": "Stale"})
    assert response.status_code == 409
    assert VariantContext.get_by_variant(variants[0].id).environment == "Original"


def test_legacy_import_into_shared_project_keeps_other_recipients_and_advanced_mode(setup):
    client, project, variants = setup
    initialize(client, project, graph([str(v.id) for v in variants]))
    original = VariantContext.get_by_variant(variants[1].id).threat_model
    result = client.post("/api/context/import", json=[{
        "project_name": project.name, "project_description": "Legacy",
        "variants": [{"variant_name": "alpha", "threat_model": "  Opaque model  ", "risks": "Original risks"}],
    }])
    assert result.status_code == 200
    assert result.json["failed"] == []
    assert VariantContext.get_by_variant(variants[0].id).threat_model == "  Opaque model  "
    assert VariantContext.get_by_variant(variants[1].id).threat_model == original
    assert read(client, project)["context"]["editor_mode"] == "free"


def test_deleted_recipients_are_pruned_and_new_missing_references_are_rejected(setup):
    client, project, variants = setup
    document = empty_document()
    targets = [str(v.id) for v in variants[:2]]
    document["threats"] = [threat("T1", targets[:1], ["C99"])]
    # Legacy missing references are legitimate imports, not newly invented links.
    fields = project_variant(document, targets[0])
    VariantContext.upsert(variants[0].id, **fields)
    document = read(client, project)["context"]
    assert save(client, project, document, "threat_model").status_code == 200
    document["threats"][0]["description"] = "Edited"
    assert save(client, project, document, "threat_model").status_code == 200
    document["threats"][0]["variant_ids"] = targets
    assert save(client, project, document, "threat_model").status_code == 400
    document = read(client, project)["context"]
    document["components"] = [component("C99", targets)]
    assert save(client, project, document, "system").status_code == 400
    variants[0].delete()
    assert read(client, project)["context"]["threats"] == []


@pytest.mark.parametrize("change", [
    lambda doc, ids: doc.update(editor_mode="invalid"),
    lambda doc, ids: doc.update(fields=[]),
    lambda doc, ids: doc.update(components={}),
    lambda doc, ids: doc["components"].append({"id": "C1", "variant_ids": ids}),
    lambda doc, ids: doc["components"].append(component("invalid", ids)),
    lambda doc, ids: doc["components"].append(component("C1", [])),
    lambda doc, ids: doc["components"].append(component("C1", [str(uuid.uuid4())])),
    lambda doc, ids: doc["components"].extend([component("C1", ids), component("C1", ids)]),
    lambda doc, ids: doc["fields"]["environment"].append(scoped_text("X1", ids, 123)),
    lambda doc, ids: doc["fields"]["codebase_path"].append(scoped_text("X1", ids, "/a;/b")),
    lambda doc, ids: doc.update(editor_mode="free", components=[component("C1", ids)]),
    lambda doc, ids: doc.update(editor_mode="free", fields={**doc["fields"], "scope": [scoped_text("X1", ids, "Scope")]}),
    lambda doc, ids: doc["free_risks"].append(scoped_text("X1", ids, "Free text")),
])
def test_malformed_documents_return_validation_errors_without_writes(setup, change):
    client, project, variants = setup
    document = empty_document()
    identifiers = [str(variants[0].id)]
    change(document, identifiers)
    result = client.post(f"/api/projects/{project.id}/context/shared", json={"context": document, "editor_mode": "free"})
    assert result.status_code == 400, result.json
    assert ProjectContext.get_by_project(project.id) is None


@pytest.mark.parametrize("extra", [
    {"expected_revision": True}, {"expected_revision": -1}, {"dry_run": "true"}, {"unknown": True},
    {"section": "unknown"}, {"context": None}, {"description": 42},
])
def test_invalid_save_bodies_are_rejected(setup, extra):
    client, project, _ = setup
    assert save(client, project, empty_document(), **extra).status_code == 400


def test_shared_api_invalid_ids_and_nonobjects(setup):
    client, project, _ = setup
    assert client.get("/api/projects/invalid/context/shared").status_code == 400
    assert client.get(f"/api/projects/{uuid.uuid4()}/context/shared").status_code == 404
    assert client.patch(f"/api/projects/{project.id}/context/shared", json=[]).status_code == 400
    assert client.post(f"/api/projects/{project.id}/context/shared", json={"context": empty_document(),
                       "editor_mode": "stride", "ignored": "No"}).status_code == 400


def test_shared_migration_upgrade_downgrade_preserves_legacy_context(monkeypatch):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("SCAN_FILE", "/dev/null")
    monkeypatch.setattr("logging.config.fileConfig", lambda _: None)
    app = create_app()
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["db", "upgrade", "ed91a8f6c302"])
        assert result.exit_code == 0, result.output
        db.session.execute(text("INSERT INTO projects (id, name) VALUES "
                                "('11111111111111111111111111111111', 'Legacy')"))
        db.session.execute(text("INSERT INTO project_context (id, project_id, description, updated_at) VALUES "
                                "('22222222222222222222222222222222', '11111111111111111111111111111111', "
                                "'  Original description  ', '2026-01-01 00:00:00')"))
        db.session.commit()
        original = db.session.execute(text("SELECT description, updated_at FROM project_context")).one()
        result = runner.invoke(args=["db", "upgrade"])
        assert result.exit_code == 0, result.output
        assert db.session.execute(text("SELECT shared_context, context_revision FROM project_context")).one() == (None, 0)
        result = runner.invoke(args=["db", "downgrade", "ed91a8f6c302"])
        assert result.exit_code == 0, result.output
        assert db.session.execute(text("SELECT description, updated_at FROM project_context")).one() == original
        db.session.remove()
        db.drop_all()
        db.engine.dispose()

# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the bulk context export/import endpoints."""

import os
import json
import pytest

from src.bin.webapp import create_app


def _tm(notes):
    """Entry fields whose STRIDE threat model holds only *notes*."""
    return {"codebase_source": "paths", "stride_model": {"notes": notes}}


def _setup_db(app):
    """Create two projects, each with variants and some context."""
    from src.extensions import db
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.project_context import ProjectContext
    from src.models.variant_context import VariantContext

    with app.app_context():
        db.drop_all()
        db.create_all()

        project_a = Project.create("ProjectA")
        variant_a1 = Variant.create("VariantA1", project_a.id)
        variant_a2 = Variant.create("VariantA2", project_a.id)

        project_b = Project.create("ProjectB")
        variant_b1 = Variant.create("VariantB1", project_b.id)

        # Project without variants — should not appear in the export.
        Project.create("EmptyProject")

        ProjectContext.upsert(project_a.id, description="ProjectA description")
        ProjectContext.upsert(project_b.id, description="ProjectB description")

        VariantContext.save_editor(variant_a1.id, {
            "variant_description": "A1 variant desc",
            "codebase_source": "paths",
            "codebase_path": "/src/a1",
            "environment": "prod",
            "other_info": "A1 other",
            "stride": {"notes": "A1 threat model", "risk_notes": "A1 risks"},
        })
        VariantContext.save_editor(variant_a2.id, {"codebase_source": "paths", "stride": {"notes": "A2 threat model"}})
        VariantContext.save_editor(variant_b1.id, {"codebase_source": "paths", "stride": {"notes": "B1 threat model"}})

        return {
            "project_a_id": str(project_a.id),
            "project_b_id": str(project_b.id),
            "variant_a1_id": str(variant_a1.id),
            "variant_a2_id": str(variant_a2.id),
            "variant_b1_id": str(variant_b1.id),
        }


@pytest.fixture()
def app_with_data():
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        application._INT_SCAN_FINISHED = True
        data = _setup_db(application)
        yield application, data
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client_and_data(app_with_data):
    application, data = app_with_data
    return application.test_client(), data


def _export_variants(client, url="/api/context/export"):
    """GET the export endpoint and return a flat list of variant records.

    Each record merges the project's ``project_name`` / ``project_description``
    (exposed as ``description``) with the variant fields, so tests can assert
    on a single variant regardless of the nested envelope shape.
    """
    response = client.get(url)
    assert response.status_code == 200
    body = json.loads(response.data)
    assert isinstance(body, dict)
    assert body["version"]
    assert body["exported_at"]
    assert isinstance(body["projects"], list)
    flat = []
    for project in body["projects"]:
        for variant in project["variants"]:
            flat.append({
                "project_name": project["project_name"],
                "description": project["project_description"],
                **variant,
            })
    return flat


def _nest(flat_entries):
    """Group flat ``{project_name, description, variant...}`` dicts into the
    nested ``projects``/``variants`` import payload."""
    by_project: dict = {}
    order: list = []
    for entry in flat_entries:
        pname = entry.get("project_name")
        if pname not in by_project:
            by_project[pname] = {
                "project_name": pname,
                "project_description": entry.get("description"),
                "variants": [],
            }
            order.append(pname)
        variant = {k: v for k, v in entry.items()
                   if k not in ("project_name", "description")}
        by_project[pname]["variants"].append(variant)
    return [by_project[p] for p in order]


# ===========================================================================
# Export
# ===========================================================================

class TestExportContext:

    def test_export_returns_versioned_envelope(self, client_and_data):
        client, _ = client_and_data
        body = json.loads(client.get("/api/context/export").data)
        assert isinstance(body, dict)
        assert body["version"] == "2.0"
        assert isinstance(body["exported_at"], str) and body["exported_at"]
        assert isinstance(body["projects"], list)

    def test_export_groups_variants_under_projects(self, client_and_data):
        client, _ = client_and_data
        body = json.loads(client.get("/api/context/export").data)
        projects = body["projects"]
        # EmptyProject contributes nothing.
        by_name = {p["project_name"]: p for p in projects}
        assert set(by_name) == {"ProjectA", "ProjectB"}
        assert by_name["ProjectA"]["project_description"] == "ProjectA description"
        a_variants = {v["variant_name"] for v in by_name["ProjectA"]["variants"]}
        assert a_variants == {"VariantA1", "VariantA2"}
        # Project fields are not repeated on the variant objects.
        sample = by_name["ProjectA"]["variants"][0]
        assert "project_name" not in sample
        assert "description" not in sample

    def test_export_all_returns_one_entry_per_variant(self, client_and_data):
        client, _ = client_and_data
        entries = _export_variants(client)
        # 3 variants total; EmptyProject contributes nothing.
        assert len(entries) == 3
        keys = {(e["project_name"], e["variant_name"]) for e in entries}
        assert keys == {
            ("ProjectA", "VariantA1"),
            ("ProjectA", "VariantA2"),
            ("ProjectB", "VariantB1"),
        }

    def test_export_entry_shape_and_values(self, client_and_data):
        client, _ = client_and_data
        entries = _export_variants(client)
        entry = next(e for e in entries if e["variant_name"] == "VariantA1")
        assert entry["description"] == "ProjectA description"
        assert entry["variant_description"] == "A1 variant desc"
        assert entry["codebase_path"] == "/src/a1"
        assert entry["environment"] == "prod"
        assert entry["stride_model"]["notes"] == "A1 threat model"
        assert entry["stride_model"]["risk_notes"] == "A1 risks"
        assert entry["other_info"] == "A1 other"
        assert not {"editor_mode", "threat_model", "risks"} & set(entry)

    def test_export_single_variant(self, client_and_data):
        client, data = client_and_data
        entries = _export_variants(
            client,
            f"/api/context/export?project_id={data['project_a_id']}"
            f"&variant_id={data['variant_a1_id']}",
        )
        assert len(entries) == 1
        assert entries[0]["variant_name"] == "VariantA1"

    def test_export_single_variant_mismatched_project(self, client_and_data):
        client, data = client_and_data
        response = client.get(
            f"/api/context/export?project_id={data['project_b_id']}"
            f"&variant_id={data['variant_a1_id']}"
        )
        assert response.status_code == 400

    def test_export_single_variant_unknown(self, client_and_data):
        client, data = client_and_data
        response = client.get(
            f"/api/context/export?project_id={data['project_a_id']}"
            "&variant_id=00000000-0000-0000-0000-000000000000"
        )
        assert response.status_code == 404

    def test_export_selected_variant_ids_filters_server_side(self, client_and_data):
        client, data = client_and_data
        entries = _export_variants(
            client,
            f"/api/context/export?variant_ids={data['variant_a1_id']},{data['variant_b1_id']}",
        )
        keys = {(e["project_name"], e["variant_name"]) for e in entries}
        assert keys == {("ProjectA", "VariantA1"), ("ProjectB", "VariantB1")}

    def test_export_selected_single_project_only(self, client_and_data):
        client, data = client_and_data
        body = json.loads(client.get(
            f"/api/context/export?variant_ids={data['variant_a1_id']}"
        ).data)
        # Only ProjectA appears; ProjectB (and EmptyProject) are dropped.
        by_name = {p["project_name"]: p for p in body["projects"]}
        assert set(by_name) == {"ProjectA"}
        assert {v["variant_name"] for v in by_name["ProjectA"]["variants"]} == {"VariantA1"}

    def test_export_selected_unknown_id_yields_empty(self, client_and_data):
        client, _ = client_and_data
        body = json.loads(client.get(
            "/api/context/export?variant_ids=00000000-0000-0000-0000-000000000000"
        ).data)
        assert body["projects"] == []

    def test_export_selected_invalid_id_rejected(self, client_and_data):
        client, _ = client_and_data
        response = client.get("/api/context/export?variant_ids=not-a-uuid")
        assert response.status_code == 400


# ===========================================================================
# Import
# ===========================================================================

class TestImportContext:

    def _post(self, client, payload):
        return client.post(
            "/api/context/import",
            data=json.dumps(payload),
            content_type="application/json",
        )

    def _post_entries(self, client, flat_entries):
        """Nest flat variant dicts into the projects payload before posting."""
        return self._post(client, _nest(flat_entries))

    def test_import_non_array_rejected(self, client_and_data):
        client, _ = client_and_data
        response = self._post(client, {"project_name": "ProjectA"})
        assert response.status_code == 400

    def test_import_envelope_accepted(self, client_and_data):
        client, _ = client_and_data
        payload = {
            "version": "1.0",
            "exported_at": "2026-07-22T00:00:00+00:00",
            "projects": [{
                "project_name": "ProjectA",
                "project_description": "From envelope",
                "variants": [{"variant_name": "VariantA1", **_tm("t")}],
            }],
        }
        response = self._post(client, payload)
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["imported"] == [
            {"project_name": "ProjectA", "variant_name": "VariantA1"}
        ]
        entries = _export_variants(client)
        entry = next(e for e in entries if e["variant_name"] == "VariantA1")
        assert entry["description"] == "From envelope"

    def test_import_envelope_missing_projects_rejected(self, client_and_data):
        client, _ = client_and_data
        response = self._post(client, {"version": "1.0", "exported_at": "x"})
        assert response.status_code == 400

    def test_import_valid_overwrites(self, client_and_data):
        client, _ = client_and_data
        response = self._post_entries(client, [{
            "project_name": "ProjectA",
            "variant_name": "VariantA1",
            "description": "New ProjectA description",
            "variant_description": "new variant desc",
            "codebase_source": "paths",
            "stride_model": {"notes": "new threat model", "risk_notes": "new risks"},
        }])
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["imported"] == [
            {"project_name": "ProjectA", "variant_name": "VariantA1"}
        ]
        assert body["ignored"] == []
        assert body["failed"] == []

        # Verify overwrite via export.
        exported = _export_variants(client)
        entry = next(e for e in exported if e["variant_name"] == "VariantA1")
        assert entry["description"] == "New ProjectA description"
        assert entry["variant_description"] == "new variant desc"
        assert entry["stride_model"]["notes"] == "new threat model"
        assert entry["stride_model"]["risk_notes"] == "new risks"
        # Field omitted from the import is cleared (full overwrite).
        assert entry["codebase_path"] is None

    def test_import_unknown_project_ignored(self, client_and_data):
        client, _ = client_and_data
        body = json.loads(self._post_entries(client, [{
            "project_name": "NoSuchProject",
            "variant_name": "VariantA1",
            "description": "d",
            **_tm("t"),
        }]).data)
        assert body["imported"] == []
        assert len(body["ignored"]) == 1
        assert body["ignored"][0]["reason"] == "Project not found"

    def test_import_unknown_variant_ignored(self, client_and_data):
        client, _ = client_and_data
        body = json.loads(self._post_entries(client, [{
            "project_name": "ProjectA",
            "variant_name": "NoSuchVariant",
            "description": "d",
            **_tm("t"),
        }]).data)
        assert body["imported"] == []
        assert body["ignored"][0]["reason"] == "Variant not found"

    def test_import_missing_mandatory_fails(self, client_and_data):
        client, _ = client_and_data
        body = json.loads(self._post_entries(client, [{
            "project_name": "ProjectA",
            "variant_name": "VariantA1",
            "description": "  ",  # blank
            **_tm("t"),
        }]).data)
        assert body["imported"] == []
        assert body["failed"][0]["reason"] == "Missing mandatory field(s): description"

    def test_import_missing_identity_ignored(self, client_and_data):
        client, _ = client_and_data
        body = json.loads(self._post_entries(client, [
            {"description": "d", **_tm("t")}
        ]).data)
        assert body["ignored"][0]["reason"] == "Missing project_name or variant_name"

    def test_import_ignores_unknown_fields(self, client_and_data):
        client, _ = client_and_data
        body = json.loads(self._post_entries(client, [{
            "project_name": "ProjectB",
            "variant_name": "VariantB1",
            "description": "d",
            **_tm("t"),
            "bogus_field": "hello",
        }]).data)
        assert body["imported"] == [
            {"project_name": "ProjectB", "variant_name": "VariantB1"}
        ]
        exported = _export_variants(client)
        entry = next(e for e in exported if e["variant_name"] == "VariantB1")
        assert "bogus_field" not in entry

    def test_import_mixed_batch(self, client_and_data):
        client, _ = client_and_data
        body = json.loads(self._post_entries(client, [
            {"project_name": "ProjectA", "variant_name": "VariantA1",
             "description": "d", **_tm("t")},
            {"project_name": "ProjectA", "variant_name": "NoSuchVariant",
             "description": "d", **_tm("t")},
            {"project_name": "ProjectB", "variant_name": "VariantB1",
             "description": "d", **_tm("")},  # empty threat model
        ]).data)
        assert len(body["imported"]) == 1
        assert len(body["ignored"]) == 1
        assert len(body["failed"]) == 1


# ===========================================================================
# Format 2.0 (editor data)
# ===========================================================================

_STRIDE_MODEL = {
    "components": [
        {"id": "C1", "name": "Updater", "description": "", "trust_zone": "device"},
        {"id": "C2", "name": "Server", "description": "", "trust_zone": "internet"},
    ],
    "interactions": [
        {"id": "I1", "name": "Download", "source_id": "C1", "destination_id": "C2",
         "interface": "HTTPS", "data": "fw", "trust_boundary": "device/internet"},
    ],
    "threats": [
        {"id": "T1", "category": "tampering", "description": "Swapped", "target_ids": ["C1", "I1"]},
    ],
    "notes": "",
    "risks": [
        {"threat_id": "T1", "likelihood": "high", "impact": "medium", "mitigation": "", "residual": ""},
    ],
    "risk_notes": "",
}


def _make_stride(app, variant_id, **overrides):
    import uuid
    from src.models.variant_context import VariantContext
    payload = {
        "variant_description": "stride desc",
        "codebase_source": "paths",
        "codebase_path": "/src/s",
        "system": {"scope": "Firmware", "actors": None, "entry_points": None, "trust_boundaries": None},
        "stride": _STRIDE_MODEL,
    }
    payload.update(overrides)
    with app.app_context():
        VariantContext.save_editor(uuid.UUID(variant_id), payload)


def _post_json(client, payload):
    return client.post("/api/context/import", data=json.dumps(payload), content_type="application/json")


class TestExportImportV2:

    def test_export_v2_contains_editor_fields(self, app_with_data):
        app, data = app_with_data
        _make_stride(app, data["variant_a2_id"])
        client = app.test_client()
        body = json.loads(client.get("/api/context/export").data)
        assert body["version"] == "2.0"
        entries = _export_variants(client)
        stride = next(e for e in entries if e["variant_name"] == "VariantA2")
        assert stride["codebase_source"] == "paths"
        assert stride["system"]["scope"] == "Firmware"
        assert stride["stride_model"] == _STRIDE_MODEL
        # Stored data only, not the agent rendering.
        assert not {"editor_mode", "threat_model", "risks"} & set(stride)
        other = next(e for e in entries if e["variant_name"] == "VariantA1")
        assert set(other["system"]) == {"scope", "actors", "entry_points", "trust_boundaries"}
        assert other["stride_model"]["components"] == []

    def test_export_import_round_trip_stride(self, app_with_data):
        from src.extensions import db
        from src.models.variant_context import VariantContext
        app, data = app_with_data
        _make_stride(app, data["variant_a2_id"], codebase_source="references", codebase_path="/p;/q")
        client = app.test_client()
        before = json.loads(client.get(
            f"/api/context?project_id={data['project_a_id']}&variant_id={data['variant_a2_id']}").data)["editor"]
        exported = json.loads(client.get("/api/context/export").data)
        with app.app_context():
            for vc in db.session.execute(db.select(VariantContext)).scalars().all():
                db.session.delete(vc)
            db.session.commit()
        result = json.loads(_post_json(client, exported["projects"]).data)
        assert result["failed"] == []
        after = json.loads(client.get(
            f"/api/context?project_id={data['project_a_id']}&variant_id={data['variant_a2_id']}").data)["editor"]
        before.pop("updated_at"), after.pop("updated_at")
        assert after == before

    def test_import_v1_text_entry_fails(self, client_and_data):
        client, _ = client_and_data
        result = json.loads(_post_json(client, {"version": "1.0", "projects": [{
            "project_name": "ProjectA", "project_description": "should not apply",
            "variants": [{"variant_name": "VariantA1", "codebase_source": "paths",
                          "threat_model": "legacy tm", "risks": "r"}],
        }]}).data)
        assert result["imported"] == []
        assert result["failed"][0]["reason"].endswith("A threat model is required.")
        entry = next(e for e in _export_variants(client) if e["variant_name"] == "VariantA1")
        assert entry["stride_model"]["notes"] == "A1 threat model"
        assert entry["description"] == "ProjectA description"

    def test_import_v2_invalid_model_fails_entry(self, client_and_data):
        client, _ = client_and_data
        result = json.loads(_post_json(client, [{
            "project_name": "ProjectA", "project_description": "d",
            "variants": [
                {"variant_name": "VariantA1", "codebase_source": "paths",
                 "stride_model": {"components": "nope"}},
                {"variant_name": "VariantA2", **_tm("ok")},
            ],
        }]).data)
        failed = {f["variant_name"]: f["reason"] for f in result["failed"]}
        assert "VariantA1" in failed and failed["VariantA1"]
        assert "VariantA2" not in failed
        assert result["imported"] == [{"project_name": "ProjectA", "variant_name": "VariantA2"}]
        # The session stays usable: the follow-up export still works.
        assert client.get("/api/context/export").status_code == 200

    def test_import_v2_empty_threat_model_fails_entry(self, client_and_data):
        client, _ = client_and_data
        result = json.loads(_post_json(client, [{
            "project_name": "ProjectA", "project_description": "d",
            "variants": [{"variant_name": "VariantA1", **_tm("")}],
        }]).data)
        assert result["failed"][0]["reason"] .endswith("A threat model is required.")
        assert result["imported"] == []


# ===========================================================================
# End-to-end STRIDE flow
# ===========================================================================

def _stride_editor_payload():
    return {
        "variant_description": "Flow gateway",
        "environment": "Linux",
        "other_info": None,
        "codebase_source": "references",
        "codebase_path": "/src/kept",
        "system": {"scope": "Firmware", "actors": None, "entry_points": None, "trust_boundaries": None},
        "stride": _STRIDE_MODEL,
    }


def _flow_editor(client, project_id, variant_id):
    response = client.get(f"/api/context?project_id={project_id}&variant_id={variant_id}")
    assert response.status_code == 200
    return json.loads(response.data)


def test_stride_flow_end_to_end(app_with_data, tmp_path, monkeypatch):
    from io import BytesIO
    from src.extensions import db
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.variant_context import VariantContext

    monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
    app, _ = app_with_data
    client = app.test_client()
    with app.app_context():
        project = Project.create("FlowProject")
        variant = Variant.create("FlowVariant", project.id)
        project_id, variant_id = str(project.id), str(variant.id)

    assert client.put(f"/api/projects/{project_id}/context",
                      json={"description": "Flow project"}).status_code == 200
    assert client.put(f"/api/variants/{variant_id}/context", json=_stride_editor_payload()).status_code == 200
    upload = client.post(f"/api/variants/{variant_id}/context/files",
                         data={"file": (BytesIO(b"int main(void) { return 0; }"), "main.c")})
    assert upload.status_code == 201

    merged = _flow_editor(client, project_id, variant_id)
    assert "Threats:\nTampering\n- T1" in merged["threat_model"]
    assert "Likelihood: High" in merged["risks"]
    assert merged["codebase_path"] is None
    assert [f["id"] for f in merged["files"]] == [json.loads(upload.data)["id"]]

    legacy = client.put(f"/api/variants/{variant_id}/context", json={"threat_model": "legacy"})
    assert legacy.status_code == 400
    assert set(json.loads(legacy.data)["fields"]) == {"threat_model"}

    exported = json.loads(client.get("/api/context/export").data)
    with app.app_context():
        for vc in db.session.execute(db.select(VariantContext)).scalars().all():
            db.session.delete(vc)
        db.session.commit()
    result = json.loads(_post_json(client, exported).data)
    assert result["failed"] == []
    assert {"project_name": "FlowProject", "variant_name": "FlowVariant"} in result["imported"]

    def without_files(editor):
        return {k: v for k, v in editor.items() if k not in ("files", "updated_at")}

    after = _flow_editor(client, project_id, variant_id)
    assert after["files"] == []
    assert without_files(after["editor"]) == without_files(merged["editor"])
    assert after["editor"]["stride"] == _STRIDE_MODEL

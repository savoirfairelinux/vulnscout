# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the bulk context export/import endpoints."""

import os
import json
import pytest

from src.bin.webapp import create_app


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

        VariantContext.upsert(
            variant_a1.id,
            variant_description="A1 variant desc",
            codebase_path="/src/a1",
            environment="prod",
            threat_model="A1 threat model",
            risks="A1 risks",
            other_info="A1 other",
        )
        VariantContext.upsert(
            variant_a2.id,
            threat_model="A2 threat model",
        )
        VariantContext.upsert(
            variant_b1.id,
            threat_model="B1 threat model",
        )

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


def _export_entries(client, url="/api/context/export"):
    """GET the export endpoint and return the entries list from the envelope."""
    response = client.get(url)
    assert response.status_code == 200
    body = json.loads(response.data)
    assert isinstance(body, dict)
    assert body["version"]
    assert body["exported_at"]
    assert isinstance(body["entries"], list)
    return body["entries"]


# ===========================================================================
# Export
# ===========================================================================

class TestExportContext:

    def test_export_returns_versioned_envelope(self, client_and_data):
        client, _ = client_and_data
        body = json.loads(client.get("/api/context/export").data)
        assert isinstance(body, dict)
        assert body["version"] == "1.0"
        assert isinstance(body["exported_at"], str) and body["exported_at"]
        assert isinstance(body["entries"], list)

    def test_export_all_returns_one_entry_per_variant(self, client_and_data):
        client, _ = client_and_data
        entries = _export_entries(client)
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
        entries = _export_entries(client)
        entry = next(e for e in entries if e["variant_name"] == "VariantA1")
        assert entry["description"] == "ProjectA description"
        assert entry["variant_description"] == "A1 variant desc"
        assert entry["codebase_path"] == "/src/a1"
        assert entry["environment"] == "prod"
        assert entry["threat_model"] == "A1 threat model"
        assert entry["risks"] == "A1 risks"
        assert entry["other_info"] == "A1 other"

    def test_export_single_variant(self, client_and_data):
        client, data = client_and_data
        entries = _export_entries(
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

    def test_import_non_array_rejected(self, client_and_data):
        client, _ = client_and_data
        response = self._post(client, {"project_name": "ProjectA"})
        assert response.status_code == 400

    def test_import_envelope_accepted(self, client_and_data):
        client, _ = client_and_data
        payload = {
            "version": "1.0",
            "exported_at": "2026-07-22T00:00:00+00:00",
            "entries": [{
                "project_name": "ProjectA",
                "variant_name": "VariantA1",
                "description": "From envelope",
                "threat_model": "t",
            }],
        }
        response = self._post(client, payload)
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["imported"] == [
            {"project_name": "ProjectA", "variant_name": "VariantA1"}
        ]
        entries = _export_entries(client)
        entry = next(e for e in entries if e["variant_name"] == "VariantA1")
        assert entry["description"] == "From envelope"

    def test_import_envelope_missing_entries_rejected(self, client_and_data):
        client, _ = client_and_data
        response = self._post(client, {"version": "1.0", "exported_at": "x"})
        assert response.status_code == 400

    def test_import_valid_overwrites(self, client_and_data):
        client, _ = client_and_data
        payload = [{
            "project_name": "ProjectA",
            "variant_name": "VariantA1",
            "description": "New ProjectA description",
            "variant_description": "new variant desc",
            "threat_model": "new threat model",
            "risks": "new risks",
        }]
        response = self._post(client, payload)
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["imported"] == [
            {"project_name": "ProjectA", "variant_name": "VariantA1"}
        ]
        assert body["ignored"] == []
        assert body["failed"] == []

        # Verify overwrite via export.
        exported = _export_entries(client)
        entry = next(e for e in exported if e["variant_name"] == "VariantA1")
        assert entry["description"] == "New ProjectA description"
        assert entry["variant_description"] == "new variant desc"
        assert entry["threat_model"] == "new threat model"
        assert entry["risks"] == "new risks"
        # Field omitted from the import is cleared (full overwrite).
        assert entry["codebase_path"] is None

    def test_import_unknown_project_ignored(self, client_and_data):
        client, _ = client_and_data
        payload = [{
            "project_name": "NoSuchProject",
            "variant_name": "VariantA1",
            "description": "d",
            "threat_model": "t",
        }]
        body = json.loads(self._post(client, payload).data)
        assert body["imported"] == []
        assert len(body["ignored"]) == 1
        assert body["ignored"][0]["reason"] == "Project not found"

    def test_import_unknown_variant_ignored(self, client_and_data):
        client, _ = client_and_data
        payload = [{
            "project_name": "ProjectA",
            "variant_name": "NoSuchVariant",
            "description": "d",
            "threat_model": "t",
        }]
        body = json.loads(self._post(client, payload).data)
        assert body["imported"] == []
        assert body["ignored"][0]["reason"] == "Variant not found"

    def test_import_missing_mandatory_fails(self, client_and_data):
        client, _ = client_and_data
        payload = [{
            "project_name": "ProjectA",
            "variant_name": "VariantA1",
            "description": "  ",  # blank
            # threat_model missing
        }]
        body = json.loads(self._post(client, payload).data)
        assert body["imported"] == []
        assert len(body["failed"]) == 1
        reason = body["failed"][0]["reason"]
        assert "description" in reason
        assert "threat_model" in reason

    def test_import_missing_identity_ignored(self, client_and_data):
        client, _ = client_and_data
        payload = [{"description": "d", "threat_model": "t"}]
        body = json.loads(self._post(client, payload).data)
        assert body["ignored"][0]["reason"] == "Missing project_name or variant_name"

    def test_import_ignores_unknown_and_nontext_fields(self, client_and_data):
        client, _ = client_and_data
        payload = [{
            "project_name": "ProjectB",
            "variant_name": "VariantB1",
            "description": "d",
            "threat_model": "t",
            "risks": 12345,          # non-text -> ignored (cleared)
            "bogus_field": "hello",  # unknown -> ignored
        }]
        body = json.loads(self._post(client, payload).data)
        assert body["imported"] == [
            {"project_name": "ProjectB", "variant_name": "VariantB1"}
        ]
        exported = _export_entries(client)
        entry = next(e for e in exported if e["variant_name"] == "VariantB1")
        assert entry["risks"] is None

    def test_import_mixed_batch(self, client_and_data):
        client, _ = client_and_data
        payload = [
            {"project_name": "ProjectA", "variant_name": "VariantA1",
             "description": "d", "threat_model": "t"},
            {"project_name": "ProjectA", "variant_name": "NoSuchVariant",
             "description": "d", "threat_model": "t"},
            {"project_name": "ProjectB", "variant_name": "VariantB1",
             "description": "d"},  # missing threat_model
        ]
        body = json.loads(self._post(client, payload).data)
        assert len(body["imported"]) == 1
        assert len(body["ignored"]) == 1
        assert len(body["failed"]) == 1

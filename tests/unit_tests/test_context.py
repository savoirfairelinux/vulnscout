# -*- coding: utf-8 -*-
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import uuid
import pytest
from unittest.mock import patch
from src.bin.webapp import create_app
from src.extensions import db as _db
from src.models.project import Project
from src.models.variant import Variant


@pytest.fixture()
def app():
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        # Mark scan as finished so the /api middleware allows all requests.
        application._INT_SCAN_FINISHED = True
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def project(app):
    return Project.create("TestProject")


@pytest.fixture()
def variant(app, project):
    return Variant.create("TestVariant", project.id)


# ---------------------------------------------------------------------------
# ProjectContext model
# ---------------------------------------------------------------------------

class TestProjectContextModel:

    def test_create_project_context(self, app, project):
        from src.models.project_context import ProjectContext
        pc = ProjectContext.upsert(project.id, description="A test project.")
        assert pc.project_id == project.id
        assert pc.description == "A test project."

    def test_upsert_updates_existing(self, app, project):
        from src.models.project_context import ProjectContext
        ProjectContext.upsert(project.id, description="First")
        pc = ProjectContext.upsert(project.id, description="Second")
        assert pc.description == "Second"
        assert _db.session.execute(_db.select(ProjectContext)).scalars().all().__len__() == 1

    def test_upsert_none_clears_description(self, app, project):
        from src.models.project_context import ProjectContext
        ProjectContext.upsert(project.id, description="Something")
        pc = ProjectContext.upsert(project.id, description=None)
        assert pc.description is None

    def test_get_by_project_returns_none_when_missing(self, app, project):
        from src.models.project_context import ProjectContext
        assert ProjectContext.get_by_project(project.id) is None

    def test_cascade_delete_with_project(self, app, project):
        from src.models.project_context import ProjectContext
        ProjectContext.upsert(project.id, description="will be deleted")
        project.delete()
        assert _db.session.execute(_db.select(ProjectContext)).scalars().all() == []

    def test_to_dict(self, app, project):
        from src.models.project_context import ProjectContext
        pc = ProjectContext.upsert(project.id, description="desc")
        d = pc.to_dict()
        assert d["project_id"] == str(project.id)
        assert d["description"] == "desc"


# ---------------------------------------------------------------------------
# VariantContext model
# ---------------------------------------------------------------------------

class TestVariantContextModel:

    def test_create_variant_context(self, app, variant):
        from src.models.variant_context import VariantContext
        vc = VariantContext.upsert(variant.id, threat_model="High CVE severity")
        assert vc.variant_id == variant.id
        assert vc.threat_model == "High CVE severity"
        assert vc.environment is None

    def test_upsert_replaces_all_fields(self, app, variant):
        from src.models.variant_context import VariantContext
        VariantContext.upsert(variant.id, threat_model="Old", environment="Linux")
        vc = VariantContext.upsert(variant.id, threat_model="New", environment=None)
        assert vc.threat_model == "New"
        assert vc.environment is None

    def test_get_by_variant(self, app, variant):
        from src.models.variant_context import VariantContext
        assert VariantContext.get_by_variant(variant.id) is None
        VariantContext.upsert(variant.id)
        assert VariantContext.get_by_variant(variant.id) is not None

    def test_cascade_delete_with_variant(self, app, variant, project):
        from src.models.variant_context import VariantContext
        with patch("src.models.variant_context._delete_context_dir"):
            VariantContext.upsert(variant.id)
            variant.delete()
            assert _db.session.execute(_db.select(VariantContext)).scalars().all() == []

    def test_to_dict(self, app, variant):
        from src.models.variant_context import VariantContext
        vc = VariantContext.upsert(variant.id, threat_model="T", risks="R")
        d = vc.to_dict()
        assert d["variant_id"] == str(variant.id)
        assert d["threat_model"] == "T"
        assert d["risks"] == "R"
        assert d["files"] == []


# ---------------------------------------------------------------------------
# ContextFile model
# ---------------------------------------------------------------------------

class TestContextFileModel:

    def test_create_context_file(self, app, variant, tmp_path):
        from src.models.variant_context import VariantContext, ContextFile
        vc = VariantContext.upsert(variant.id)
        fake_path = str(tmp_path / "somefile")
        cf = ContextFile.create(vc.id, original_name="report.pdf", file_path=fake_path)
        assert cf.variant_context_id == vc.id
        assert cf.original_name == "report.pdf"
        assert cf.file_path == fake_path
        assert cf.description is None

    def test_create_context_file_with_description(self, app, variant, tmp_path):
        from src.models.variant_context import VariantContext, ContextFile
        vc = VariantContext.upsert(variant.id)
        cf = ContextFile.create(
            vc.id, original_name="report.pdf", file_path=str(tmp_path / "f"),
            description="a spec"
        )
        assert cf.description == "a spec"
        assert cf.to_dict()["description"] == "a spec"

    def test_count_for_variant_context(self, app, variant, tmp_path):
        from src.models.variant_context import VariantContext, ContextFile
        vc = VariantContext.upsert(variant.id)
        assert ContextFile.count_for_variant_context(vc.id) == 0
        ContextFile.create(vc.id, "a.txt", str(tmp_path / "a"))
        assert ContextFile.count_for_variant_context(vc.id) == 1

    def test_get_by_id_and_variant_context(self, app, variant, tmp_path):
        from src.models.variant_context import VariantContext, ContextFile
        vc = VariantContext.upsert(variant.id)
        cf = ContextFile.create(vc.id, "b.txt", str(tmp_path / "b"))
        assert ContextFile.get_by_id_and_variant_context(cf.id, vc.id) is not None
        assert ContextFile.get_by_id_and_variant_context(uuid.uuid4(), vc.id) is None

    def test_cascade_delete_with_variant_context(self, app, variant, tmp_path):
        from src.models.variant_context import VariantContext, ContextFile
        with patch("src.models.variant_context._delete_context_dir"):
            vc = VariantContext.upsert(variant.id)
            ContextFile.create(vc.id, "c.txt", str(tmp_path / "c"))
            variant.delete()
            assert _db.session.execute(_db.select(ContextFile)).scalars().all() == []


# ---------------------------------------------------------------------------
# Controllers
# ---------------------------------------------------------------------------

class TestProjectContextController:

    def test_get_or_create_project_context(self, app, project):
        from src.controllers.context import ProjectContextController
        result = ProjectContextController.get_or_create(str(project.id))
        assert result.project_id == project.id

    def test_upsert_saves_description(self, app, project):
        from src.controllers.context import ProjectContextController
        result = ProjectContextController.upsert(str(project.id), description="My project")
        assert result.description == "My project"

    def test_upsert_invalid_uuid_raises(self, app):
        from src.controllers.context import ProjectContextController
        with pytest.raises(ValueError):
            ProjectContextController.upsert("not-a-uuid", description="x")

    def test_get_raises_on_missing_project(self, app):
        from src.controllers.context import ProjectContextController
        with pytest.raises(ValueError):
            ProjectContextController.upsert(str(uuid.uuid4()), description="x")

    def test_serialize(self, app, project):
        from src.controllers.context import ProjectContextController
        pc = ProjectContextController.upsert(str(project.id), description="desc")
        d = ProjectContextController.serialize(pc)
        assert d["description"] == "desc"
        assert "project_id" in d


class TestVariantContextController:

    def test_upsert_creates_variant_context(self, app, variant):
        from src.controllers.context import VariantContextController
        vc = VariantContextController.upsert(
            str(variant.id),
            threat_model="Any CVSS >= 7.0",
        )
        assert vc.threat_model == "Any CVSS >= 7.0"

    def test_upsert_full_replacement(self, app, variant):
        from src.controllers.context import VariantContextController
        VariantContextController.upsert(str(variant.id), environment="Linux 6.1")
        vc = VariantContextController.upsert(str(variant.id), environment=None)
        assert vc.environment is None

    def test_get_or_create_creates_row(self, app, variant):
        from src.controllers.context import VariantContextController
        vc = VariantContextController.get_or_create(str(variant.id))
        assert vc.variant_id == variant.id

    def test_serialize(self, app, variant):
        from src.controllers.context import VariantContextController
        vc = VariantContextController.upsert(str(variant.id), risks="Risk A")
        d = VariantContextController.serialize(vc)
        assert d["risks"] == "Risk A"
        assert d["files"] == []


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(app):
    return app.test_client()


class TestGetMergedContext:

    def test_returns_nulls_when_no_context_rows(self, client, project, variant):
        resp = client.get(
            f"/api/context?project_id={project.id}&variant_id={variant.id}"
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["project_id"] == str(project.id)
        assert data["description"] is None
        assert data["variant_id"] == str(variant.id)
        assert data["threat_model"] is None
        assert data["files"] == []

    def test_returns_saved_values(self, client, project, variant):
        from src.models.project_context import ProjectContext
        from src.models.variant_context import VariantContext
        ProjectContext.upsert(project.id, description="proj desc")
        VariantContext.upsert(variant.id, threat_model="CVSS >= 7")
        resp = client.get(
            f"/api/context?project_id={project.id}&variant_id={variant.id}"
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["description"] == "proj desc"
        assert data["threat_model"] == "CVSS >= 7"

    def test_400_when_project_id_missing(self, client, variant):
        resp = client.get(f"/api/context?variant_id={variant.id}")
        assert resp.status_code == 400

    def test_400_when_variant_id_missing(self, client, project):
        resp = client.get(f"/api/context?project_id={project.id}")
        assert resp.status_code == 400

    def test_400_when_invalid_uuid(self, client):
        resp = client.get("/api/context?project_id=bad&variant_id=alsobad")
        assert resp.status_code == 400

    def test_404_when_project_not_found(self, client, variant):
        resp = client.get(
            f"/api/context?project_id={uuid.uuid4()}&variant_id={variant.id}"
        )
        assert resp.status_code == 404

    def test_404_when_variant_not_found(self, client, project):
        resp = client.get(
            f"/api/context?project_id={project.id}&variant_id={uuid.uuid4()}"
        )
        assert resp.status_code == 404

    def test_400_when_variant_not_in_project(self, client, project):
        other_project = Project.create("OtherProject")
        other_variant = Variant.create("OtherVariant", other_project.id)
        resp = client.get(
            f"/api/context?project_id={project.id}&variant_id={other_variant.id}"
        )
        assert resp.status_code == 400


class TestGetProjectContext:

    def test_returns_null_description_when_no_row(self, client, project):
        resp = client.get(f"/api/projects/{project.id}/context")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["project_id"] == str(project.id)
        assert data["description"] is None

    def test_returns_saved_description(self, client, project):
        from src.models.project_context import ProjectContext
        ProjectContext.upsert(project.id, description="hello")
        resp = client.get(f"/api/projects/{project.id}/context")
        assert resp.status_code == 200
        assert resp.get_json()["description"] == "hello"

    def test_404_when_project_not_found(self, client):
        resp = client.get(f"/api/projects/{uuid.uuid4()}/context")
        assert resp.status_code == 404


class TestPutProjectContext:

    def test_upsert_creates_row(self, client, project):
        resp = client.put(
            f"/api/projects/{project.id}/context",
            json={"description": "My project"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["description"] == "My project"

    def test_upsert_updates_existing(self, client, project):
        client.put(f"/api/projects/{project.id}/context", json={"description": "Old"})
        resp = client.put(
            f"/api/projects/{project.id}/context", json={"description": "New"}
        )
        assert resp.get_json()["description"] == "New"

    def test_null_description_clears_field(self, client, project):
        client.put(f"/api/projects/{project.id}/context", json={"description": "X"})
        resp = client.put(
            f"/api/projects/{project.id}/context", json={"description": None}
        )
        assert resp.get_json()["description"] is None

    def test_404_when_project_not_found(self, client):
        resp = client.put(
            f"/api/projects/{uuid.uuid4()}/context", json={"description": "x"}
        )
        assert resp.status_code == 404


class TestPutVariantContext:

    def test_upsert_creates_row(self, client, variant):
        resp = client.put(
            f"/api/variants/{variant.id}/context",
            json={"threat_model": "CVSS >= 7"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["threat_model"] == "CVSS >= 7"

    def test_full_replacement_nulls_omitted_fields(self, client, variant):
        client.put(
            f"/api/variants/{variant.id}/context",
            json={"threat_model": "T", "environment": "Linux"},
        )
        resp = client.put(
            f"/api/variants/{variant.id}/context",
            json={"threat_model": "T2"},
        )
        assert resp.get_json()["environment"] is None

    def test_404_when_variant_not_found(self, client):
        resp = client.put(
            f"/api/variants/{uuid.uuid4()}/context",
            json={"threat_model": "x"},
        )
        assert resp.status_code == 404


class TestPostContextFile:

    def test_upload_file(self, client, variant, tmp_path):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            from io import BytesIO
            data = {"file": (BytesIO(b"content"), "report.pdf")}
            resp = client.post(
                f"/api/variants/{variant.id}/context/files",
                data=data,
                content_type="multipart/form-data",
            )
        assert resp.status_code == 201
        body = resp.get_json()
        assert body["original_name"] == "report.pdf"
        assert "id" in body
        assert body["description"] is None

    def test_upload_file_with_description(self, client, variant, tmp_path):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            from io import BytesIO
            data = {"file": (BytesIO(b"content"), "report.pdf"), "description": "spec sheet"}
            resp = client.post(
                f"/api/variants/{variant.id}/context/files",
                data=data,
                content_type="multipart/form-data",
            )
        assert resp.status_code == 201
        assert resp.get_json()["description"] == "spec sheet"

    def test_blank_description_stored_as_null(self, client, variant, tmp_path):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            from io import BytesIO
            data = {"file": (BytesIO(b"content"), "report.pdf"), "description": "   "}
            resp = client.post(
                f"/api/variants/{variant.id}/context/files",
                data=data,
                content_type="multipart/form-data",
            )
        assert resp.status_code == 201
        assert resp.get_json()["description"] is None

    def test_400_when_no_file(self, client, variant):
        resp = client.post(
            f"/api/variants/{variant.id}/context/files",
            data={},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400

    def test_no_file_count_limit(self, client, variant, tmp_path):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            from io import BytesIO
            for i in range(5):
                resp = client.post(
                    f"/api/variants/{variant.id}/context/files",
                    data={"file": (BytesIO(b"x"), f"file{i}.txt")},
                    content_type="multipart/form-data",
                )
                assert resp.status_code == 201

    def test_404_when_variant_not_found(self, client):
        from io import BytesIO
        resp = client.post(
            f"/api/variants/{uuid.uuid4()}/context/files",
            data={"file": (BytesIO(b"x"), "f.txt")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 404


class TestDeleteContextFile:

    def _upload(self, client, variant, tmp_path):
        from io import BytesIO
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            resp = client.post(
                f"/api/variants/{variant.id}/context/files",
                data={"file": (BytesIO(b"data"), "doc.txt")},
                content_type="multipart/form-data",
            )
        return resp.get_json()["id"]

    def test_delete_removes_file_and_db_row(self, client, variant, tmp_path):
        file_id = self._upload(client, variant, tmp_path)
        resp = client.delete(f"/api/variants/{variant.id}/context/files/{file_id}")
        assert resp.status_code == 204

    def test_404_when_file_not_found(self, client, variant):
        resp = client.delete(
            f"/api/variants/{variant.id}/context/files/{uuid.uuid4()}"
        )
        assert resp.status_code == 404

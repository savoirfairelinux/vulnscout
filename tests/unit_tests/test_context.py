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
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path / "cache"))
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

    def test_updated_at_none_for_empty_context(self, app, project):
        """A bare read creates the row; that must not count as an edit."""
        from src.models.project_context import ProjectContext
        pc = ProjectContext.upsert(project.id, description=None)
        assert pc.updated_at is None

    def test_updated_at_set_on_creation_with_content(self, app, project):
        from src.models.project_context import ProjectContext
        pc = ProjectContext.upsert(project.id, description="A description")
        assert pc.updated_at is not None

    def test_updated_at_bumped_only_on_real_change(self, app, project):
        from src.models.project_context import ProjectContext
        pc = ProjectContext.upsert(project.id, description="First")
        first = pc.updated_at
        pc = ProjectContext.upsert(project.id, description="First")
        assert pc.updated_at == first
        pc = ProjectContext.upsert(project.id, description="Second")
        assert pc.updated_at > first

    def test_updated_at_set_when_first_filled(self, app, project):
        from src.models.project_context import ProjectContext
        ProjectContext.upsert(project.id, description=None)
        pc = ProjectContext.upsert(project.id, description="Now described")
        assert pc.updated_at is not None

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
        vc = VariantContext.upsert(variant.id, environment="Linux")
        assert vc.variant_id == variant.id
        assert vc.environment == "Linux"
        assert vc.other_info is None

    def test_upsert_replaces_all_fields(self, app, variant):
        from src.models.variant_context import VariantContext
        VariantContext.upsert(variant.id, other_info="Old", environment="Linux")
        vc = VariantContext.upsert(variant.id, other_info="New", environment=None)
        assert vc.other_info == "New"
        assert vc.environment is None

    def test_updated_at_none_for_empty_context(self, app, variant):
        from src.models.variant_context import VariantContext
        vc = VariantContext.upsert(variant.id)
        assert vc.updated_at is None
        assert vc.to_dict()["updated_at"] is None

    def test_updated_at_set_on_creation_with_content(self, app, variant):
        from src.models.variant_context import VariantContext
        vc = VariantContext.upsert(variant.id, environment="x")
        assert vc.updated_at is not None
        assert vc.to_dict()["updated_at"] is not None

    def test_updated_at_bumped_only_on_real_change(self, app, variant):
        from src.models.variant_context import VariantContext
        vc = VariantContext.upsert(variant.id, environment="x")
        first = vc.updated_at
        vc = VariantContext.upsert(variant.id, environment="x")
        assert vc.updated_at == first
        vc = VariantContext.upsert(variant.id, environment="y")
        assert vc.updated_at > first

    def test_updated_at_set_when_first_filled(self, app, variant):
        from src.models.variant_context import VariantContext
        VariantContext.upsert(variant.id)
        vc = VariantContext.upsert(variant.id, other_info="o")
        assert vc.updated_at is not None

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
        vc = VariantContext.upsert(variant.id, environment="E")
        d = vc.to_dict()
        assert d["variant_id"] == str(variant.id)
        assert d["environment"] == "E"
        assert d["threat_model"] is None
        assert d["risks"] is None
        assert not {"codebase_source", "codebase_path"} & d.keys()
        assert not {"codebase_source", "codebase_path"} & d["editor"].keys()
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
            environment="Linux 6.1",
        )
        assert vc.environment == "Linux 6.1"

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
        vc = VariantContextController.upsert(str(variant.id), other_info="Info A")
        d = VariantContextController.serialize(vc)
        assert d["other_info"] == "Info A"
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
        VariantContext.upsert(variant.id, environment="Linux")
        resp = client.get(
            f"/api/context?project_id={project.id}&variant_id={variant.id}"
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["description"] == "proj desc"
        assert data["environment"] == "Linux"
        assert "codebase_path" not in data

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
            json={"environment": "Linux"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["environment"] == "Linux"

    def test_full_replacement_nulls_omitted_fields(self, client, variant):
        client.put(
            f"/api/variants/{variant.id}/context",
            json={"other_info": "O", "environment": "Linux"},
        )
        resp = client.put(
            f"/api/variants/{variant.id}/context",
            json={"other_info": "O2"},
        )
        assert resp.get_json()["environment"] is None

    @pytest.mark.parametrize("editor", [False, True])
    def test_removed_codebase_fields_are_not_persisted_or_returned(self, client, variant, editor):
        from src.models.variant_context import VariantContext
        resp = client.put(
            f"/api/variants/{variant.id}/context",
            json={**(_editor_payload() if editor else {"environment": "Linux"}),
                  "codebase_source": "paths", "codebase_path": "/home/user/src/proj"},
        )
        assert resp.status_code == 200
        assert not {"codebase_source", "codebase_path"} & resp.get_json().keys()
        assert not {"codebase_source", "codebase_path"} & resp.get_json()["editor"].keys()
        assert not {"codebase_source", "codebase_path"} & set(VariantContext.__table__.columns.keys())

    def test_404_when_variant_not_found(self, client):
        resp = client.put(
            f"/api/variants/{uuid.uuid4()}/context",
            json={"environment": "x"},
        )
        assert resp.status_code == 404


class TestPostContextFile:

    @pytest.mark.parametrize("size", [5 * 1024 * 1024 + 64 * 1024 + 1, 10 * 1024 * 1024])
    def test_upload_accepts_large_files(self, client, variant, tmp_path, size):
        from io import BytesIO
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            response = client.post(
                f"/api/variants/{variant.id}/context/files",
                data={"file": (BytesIO(b"x" * size), "main.c")},
            )
        assert response.status_code == 201
        assert next(tmp_path.rglob(response.get_json()["id"])).stat().st_size == size

    def test_upload_accepts_files_above_previous_10mb_limit(self, client, variant, tmp_path):
        from io import BytesIO
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            response = client.post(
                f"/api/variants/{variant.id}/context/files",
                data={"file": (BytesIO(b"x" * (10 * 1024 * 1024 + 1)), "main.c")},
            )
        assert response.status_code == 201
        assert next(tmp_path.rglob(response.get_json()["id"])).stat().st_size == 10 * 1024 * 1024 + 1

    @pytest.mark.parametrize("archive_type", ["zip", "tar"])
    def test_malformed_archive_names_return_400(self, client, variant, tmp_path, archive_type):
        from .test_codebase_reference import malformed_name_source
        from src.models.variant_context import VariantContext
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            response = client.post(
                f"/api/variants/{variant.id}/context/files",
                data={"file": (malformed_name_source(archive_type), f"source.{archive_type}")},
            )
        assert response.status_code == 400
        assert response.get_json()["error"]
        assert VariantContext.get_by_variant(variant.id) is None
        assert not list(tmp_path.iterdir())

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

    def test_upload_file_bumps_variant_context_updated_at(self, client, variant, tmp_path):
        from src.models.variant_context import VariantContext
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            from io import BytesIO
            resp = client.post(
                f"/api/variants/{variant.id}/context/files",
                data={"file": (BytesIO(b"content"), "report.pdf")},
                content_type="multipart/form-data",
            )
        assert resp.status_code == 201
        vc = VariantContext.get_by_variant(variant.id)
        assert vc is not None
        assert vc.updated_at is not None

    def test_upload_file_to_existing_variant_context_bumps_updated_at(self, client, variant, tmp_path):
        from src.models.variant_context import VariantContext
        VariantContext.upsert(variant.id, environment="Linux")
        old_updated_at = VariantContext.get_by_variant(variant.id).updated_at
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            from io import BytesIO
            resp = client.post(
                f"/api/variants/{variant.id}/context/files",
                data={"file": (BytesIO(b"content"), "report.pdf")},
                content_type="multipart/form-data",
            )
        assert resp.status_code == 201
        new_updated_at = VariantContext.get_by_variant(variant.id).updated_at
        assert new_updated_at > old_updated_at


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

    def test_delete_bumps_variant_context_updated_at(self, client, variant, tmp_path):
        from src.models.variant_context import VariantContext
        file_id = self._upload(client, variant, tmp_path)
        post_upload_updated_at = VariantContext.get_by_variant(variant.id).updated_at
        resp = client.delete(f"/api/variants/{variant.id}/context/files/{file_id}")
        assert resp.status_code == 204
        post_delete_updated_at = VariantContext.get_by_variant(variant.id).updated_at
        assert post_delete_updated_at > post_upload_updated_at


class TestCodebaseSource:
    def _upload(self, client, variant, tmp_path):
        from io import BytesIO
        import zipfile
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("repo/main.c", "first\nunsafe_call();\nlast\n")
            archive.writestr("repo/data.bin", b"\x00data")
        stream.seek(0)
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            response = client.post(
                f"/api/variants/{variant.id}/context/files", data={"file": (stream, "source.zip")},
            )
        assert response.status_code == 201
        return response.get_json()["id"]

    def test_upload_list_search_read_delete(self, client, variant, project, tmp_path):
        file_id = self._upload(client, variant, tmp_path)
        context = client.get(f"/api/context?project_id={project.id}&variant_id={variant.id}").get_json()
        assert context["files"] == [{"id": file_id, "original_name": "source.zip", "description": None}]
        base = f"/api/variants/{variant.id}/context/files/{file_id}/source"
        listing = client.get(base, query_string={"limit": 1}).get_json()
        assert listing["total"] == 2
        assert listing["next_offset"] == 1
        assert "file_path" not in str(listing)
        result = client.get(base, query_string={"operation": "search", "query": "unsafe_call"}).get_json()
        assert result["matches"] == [{"path": "repo/main.c", "line": 2, "text": "unsafe_call();"}]
        assert result["skipped_binary_files"] == 1
        read = client.get(base, query_string={
            "operation": "read", "path": "repo/main.c", "start_line": 2, "max_lines": 1,
        }).get_json()
        assert read["content"] == "unsafe_call();\n"
        assert read["next_line"] == 3
        assert client.delete(base.removesuffix("/source")).status_code == 204
        assert client.get(base).status_code == 404
        assert not list(tmp_path.rglob(file_id))

    @pytest.mark.parametrize("parameters", [
        {"limit": 201}, {"limit": "oops"}, {"offset": -1}, {"offset": 500_001}, {"operation": "execute"},
        {"operation": "read", "path": "repo/main.c", "start_line": 0},
        {"operation": "search"}, {"operation": "search", "query": "x" * 201},
        {"operation": "read", "path": "repo/data.bin"}, {"pattern": "x" * 513},
    ])
    def test_invalid_parameters(self, client, variant, tmp_path, parameters):
        file_id = self._upload(client, variant, tmp_path)
        response = client.get(
            f"/api/variants/{variant.id}/context/files/{file_id}/source", query_string=parameters,
        )
        assert response.status_code == 400
        assert response.get_json()["error"]

    @pytest.mark.parametrize("offset", [5001, 499_999, 500_000])
    def test_listing_accepts_offsets_up_to_entry_limit(self, client, variant, tmp_path, offset):
        file_id = self._upload(client, variant, tmp_path)
        response = client.get(
            f"/api/variants/{variant.id}/context/files/{file_id}/source", query_string={"offset": offset},
        )
        assert response.status_code == 200
        assert response.get_json()["files"] == []
        assert response.get_json()["next_offset"] is None

    def test_listing_reaches_last_file_at_entry_limit(self, client, variant, tmp_path):
        file_id = self._upload(client, variant, tmp_path)
        entries = {f"source-{index:06d}.c": (0, None) for index in range(500_000)}

        def index(reference):
            reference.entries = entries

        base = f"/api/variants/{variant.id}/context/files/{file_id}/source"
        with patch("src.helpers.codebase_reference.CodebaseReference._index", index):
            response = client.get(base, query_string={"offset": 499_799})
            assert response.status_code == 200
            page = response.get_json()
            assert len(page["files"]) == 200
            assert page["total"] == 500_000
            assert page["next_offset"] == 499_999
            response = client.get(base, query_string={"offset": page["next_offset"]})
            assert response.status_code == 200
            assert response.get_json()["files"] == [{"path": "source-499999.c", "size": 0}]
            assert response.get_json()["next_offset"] is None

    def test_reference_is_variant_scoped(self, client, variant, project, tmp_path):
        file_id = self._upload(client, variant, tmp_path)
        other = Variant.create("other", project.id)
        assert client.get(f"/api/variants/{other.id}/context/files/{file_id}/source").status_code == 404
        assert client.get(
            f"/api/variants/{variant.id}/context/files/{file_id}/source",
            query_string={"operation": "read", "path": "../../etc/passwd"},
        ).status_code == 404
        assert client.get(f"/api/variants/invalid/context/files/{file_id}/source").status_code == 400
        assert client.get(f"/api/variants/{variant.id}/context/files/invalid/source").status_code == 400
        assert client.get(f"/api/variants/{uuid.uuid4()}/context/files/{file_id}/source").status_code == 404

    def test_invalid_upload_leaves_no_reference(self, client, variant, tmp_path):
        from io import BytesIO
        from src.models.variant_context import VariantContext
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            response = client.post(
                f"/api/variants/{variant.id}/context/files", data={"file": (BytesIO(b"bad"), "bad.zip")},
            )
        assert response.status_code == 400
        assert VariantContext.get_by_variant(variant.id) is None
        assert not list(tmp_path.iterdir())

    def test_missing_storage_is_explicit(self, client, variant, tmp_path):
        file_id = self._upload(client, variant, tmp_path)
        next(tmp_path.rglob(file_id)).unlink()
        response = client.get(f"/api/variants/{variant.id}/context/files/{file_id}/source")
        assert response.status_code == 500
        assert "unavailable" in response.get_json()["error"]

    def test_failed_commit_removes_upload_and_preserves_context(self, client, variant, tmp_path):
        from io import BytesIO
        from sqlalchemy.exc import SQLAlchemyError
        from src.models.variant_context import VariantContext
        context = VariantContext.upsert(variant.id, environment="existing")
        updated_at = context.updated_at
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)), \
                patch.object(_db.session, "commit", side_effect=SQLAlchemyError("failed")):
            response = client.post(
                f"/api/variants/{variant.id}/context/files", data={"file": (BytesIO(b"source"), "main.c")},
            )
        assert response.status_code == 500
        assert context.environment == "existing"
        assert context.updated_at == updated_at
        assert context.files == []
        assert not [path for path in tmp_path.rglob("*") if path.is_file()]


# ---------------------------------------------------------------------------
# Editor-shape saves, legacy writes on STRIDE variants, agent view
# ---------------------------------------------------------------------------

def _risk(mitigation):
    return [{"id": "R1", "description": "", "threat_ids": ["T1"], "likelihood": "high", "impact": "medium", "mitigation": mitigation, "residual": ""}]


def _stride_model(**overrides):
    model = {
        "components": [
            {"id": "C1", "name": "OTA updater", "description": "fetches images", "trust_zone": "device"},
            {"id": "C2", "name": "Update server", "description": "", "trust_zone": "internet"},
        ],
        "interactions": [
            {"id": "I1", "name": "Download", "source_id": "C1", "destination_id": "C2",
             "interface": "HTTPS", "data": "firmware", "trust_boundary": "device/internet"},
        ],
        "threats": [
            {"id": "T1", "category": "tampering", "description": "Image swapped", "target_ids": ["C1", "I1"]},
        ],
        "risks": [
            {"id": "R1", "description": "", "threat_ids": ["T1"], "likelihood": "high", "impact": "medium", "mitigation": "", "residual": ""},
        ],
    }
    model.update(overrides)
    return model


def _editor_payload(**overrides):
    payload = {
        "variant_description": "Gateway",
        "environment": "Linux",
        "other_info": None,
        "system": {"scope": "Firmware", "actors": None, "entry_points": None, "trust_boundaries": None},
        "stride": _stride_model(),
    }
    payload.update(overrides)
    return payload


class TestCodebaseDirectory:

    @pytest.fixture
    def directory(self, client, variant, tmp_path, monkeypatch):
        from pathlib import Path
        monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
        response = client.post(f"/api/variants/{variant.id}/context/directory")
        assert response.status_code == 200
        return Path(response.get_json()["path"])

    def _source(self, client, variant, **params):
        return client.get(f"/api/variants/{variant.id}/context/files/directory/source", query_string=params)

    def _select(self, client, variant):
        response = client.put(f"/api/variants/{variant.id}/context", json=_editor_payload())
        assert response.status_code == 200
        return response.get_json()

    @pytest.mark.parametrize("first_read", ["merged", "status", "source"])
    @pytest.mark.parametrize("saved_context", [False, True])
    def test_ci_directory_is_discovered_without_provisioning(
        self, client, project, variant, tmp_path, monkeypatch, first_read, saved_context,
    ):
        from src.models.variant_context import VariantContext

        monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
        before = VariantContext.save_editor(variant.id, _editor_payload()).to_dict() if saved_context else None
        directory = tmp_path / "context-TestProject-TestVariant"
        directory.mkdir()
        (directory / "main.c").write_text("first\nneedle\n")
        metadata = {"file_id": "directory", "path": str(directory)}
        merged_url = f"/api/context?project_id={project.id}&variant_id={variant.id}"
        status_url = f"/api/variants/{variant.id}/context/directory"
        urls = {"merged": merged_url, "status": status_url,
                "source": f"/api/variants/{variant.id}/context/files/directory/source"}

        with patch("src.routes.context.provision_directory", side_effect=AssertionError("Must not create paths")):
            response = client.get(urls[first_read])
            assert response.status_code == 200
            vc = VariantContext.get_by_variant(variant.id)
            assert vc.codebase_directory == directory.name and vc.updated_at is not None
            after = vc.to_dict()
            if before is not None:
                assert after == {
                    **before, "codebase_directory": metadata, "updated_at": after["updated_at"],
                    "editor": {**before["editor"], "updated_at": after["updated_at"]},
                }
            assert client.get(merged_url).get_json()["codebase_directory"] == metadata
            status = client.get(status_url).get_json()
            assert status["status"] == "ready" and status["file_count"] == 1
            assert self._source(client, variant).get_json()["files"] == [{"path": "main.c", "size": 13}]
            assert self._source(client, variant, operation="read", path="main.c").get_json()["content"] == "first\nneedle\n"
            assert self._source(client, variant, operation="search", query="needle").get_json()["matches"] == [
                {"path": "main.c", "line": 2, "text": "needle"},
            ]
            assert vc.to_dict()["updated_at"] == after["updated_at"]

    def test_discovery_does_not_create_cache_or_context_when_directory_is_absent(
        self, client, project, variant, tmp_path, monkeypatch,
    ):
        from src.models.variant_context import VariantContext

        cache = tmp_path / "absent"
        monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(cache))
        merged = client.get("/api/context", query_string={"project_id": project.id, "variant_id": variant.id})
        assert merged.status_code == 200 and merged.get_json()["codebase_directory"] is None
        assert client.get(f"/api/variants/{variant.id}/context/directory").get_json()["status"] == "not_created"
        assert self._source(client, variant).status_code == 404
        assert not cache.exists()
        assert VariantContext.get_by_variant(variant.id) is None

    @pytest.mark.parametrize("kind", ["symlink", "file"])
    def test_discovery_rejects_unsafe_directory_roots(self, client, project, variant, tmp_path, monkeypatch, kind):
        from src.models.variant_context import VariantContext

        monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
        root = tmp_path / "context-TestProject-TestVariant"
        if kind == "symlink":
            outside = tmp_path / "outside"
            outside.mkdir()
            (outside / "main.c").write_text("private")
            root.symlink_to(outside, target_is_directory=True)
        else:
            root.write_text("not a directory")
        response = client.get("/api/context", query_string={"project_id": project.id, "variant_id": variant.id})
        assert response.status_code == 500
        assert "error" in response.get_json()
        assert self._source(client, variant).status_code == 500
        assert VariantContext.get_by_variant(variant.id) is None

    def test_discovery_rejects_ambiguous_names_until_explicitly_claimed(
        self, client, project, variant, tmp_path, monkeypatch,
    ):
        from src.models.variant_context import VariantContext

        monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
        other = Variant.create(variant.name + "@", project.id)
        root = tmp_path / "context-TestProject-TestVariant"
        root.mkdir()
        (root / "main.c").write_text("ambiguous")
        for candidate in (variant, other):
            response = client.get("/api/context", query_string={"project_id": project.id, "variant_id": candidate.id})
            assert response.status_code == 409
            assert self._source(client, candidate).status_code == 409
            assert VariantContext.get_by_variant(candidate.id) is None
        assert client.post(f"/api/variants/{variant.id}/context/directory").status_code == 200
        assert self._source(client, variant).status_code == 200
        assert self._source(client, other).status_code == 409

    def test_on_demand_provisioning_preserves_draft_fields_and_exposes_directory(
        self, client, project, variant, tmp_path, monkeypatch,
    ):
        from pathlib import Path
        from src.models.variant_context import VariantContext
        monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
        url = f"/api/variants/{variant.id}/context/directory"
        assert client.get(url).get_json()["status"] == "not_created"
        assert list(tmp_path.iterdir()) == []
        assert VariantContext.get_by_variant(variant.id) is None
        vc = VariantContext.save_editor(variant.id, _editor_payload())
        before = vc.to_dict()
        created = client.post(url)
        path = Path(created.get_json()["path"])
        assert path.is_dir() and path.parent == tmp_path
        assert path.name == "context-TestProject-TestVariant"
        assert created.get_json()["status"] == "unavailable"
        assert created.get_json()["file_count"] == 0
        assert created.get_json()["directory_count"] == 0
        assert "empty" in created.get_json()["message"]
        after = vc.to_dict()
        assert after["updated_at"] != before["updated_at"]
        assert after["editor"] == {
            **before["editor"], "updated_at": after["updated_at"],
        }
        for field in ("variant_description", "environment", "other_info", "threat_model", "risks"):
            assert after[field] == before[field]
        assert after["codebase_directory"] == {"file_id": "directory", "path": str(path)}
        assert client.post(url).get_json()["path"] == str(path)
        assert vc.to_dict()["updated_at"] == after["updated_at"]
        (path / "main.c").write_text("source")
        assert client.get(url).get_json()["status"] == "ready"

    def test_refreshed_counts_exclude_sensitive_files_and_links(self, client, variant, directory):
        url = f"/api/variants/{variant.id}/context/directory"
        (directory / "src").mkdir()
        (directory / "src" / "empty").mkdir()
        empty = client.get(url).get_json()
        assert empty["file_count"] == 0 and empty["directory_count"] == 2
        (directory / "src" / "main.c").write_text("source")
        (directory / ".git").mkdir()
        (directory / ".git" / "config").write_text("excluded")
        (directory / "secret.txt").write_text("excluded")
        (directory / "linked-src").symlink_to(directory / "src", target_is_directory=True)
        (directory / "link.c").symlink_to(directory / "src" / "main.c")
        first = client.get(url).get_json()
        assert first["file_count"] == 1 and first["directory_count"] == 2
        (directory / "README.md").write_text("readme")
        (directory / "docs").mkdir()
        refreshed = client.get(url).get_json()
        assert refreshed["file_count"] == 2 and refreshed["directory_count"] == 3

    def test_directory_is_discovered_from_mcp_without_source_selection(
        self, client, project, variant, directory,
    ):
        from src.models.variant_context import VariantContext
        from vulnscout_mcp.tools.context import _fmt_merged_context
        VariantContext.save_editor(variant.id, _editor_payload())
        (directory / "main.c").write_text("needle\n")
        status = client.get(f"/api/variants/{variant.id}/context/directory").get_json()
        assert status["status"] == "ready" and status["file_count"] == 1
        merged = client.get("/api/context", query_string={"project_id": project.id, "variant_id": variant.id}).get_json()
        text = _fmt_merged_context(merged)
        assert "codebase_directory=" in text
        assert "codebase_source=" not in text and "codebase_path=" not in text
        assert merged["codebase_directory"] == {"file_id": "directory", "path": str(directory)}
        assert self._source(client, variant).get_json()["files"] == [{"path": "main.c", "size": 7}]
        assert self._source(client, variant, operation="read", path="main.c").get_json()["content"] == "needle\n"
        assert self._source(client, variant, operation="search", query="needle").get_json()["matches"] == [
            {"path": "main.c", "line": 1, "text": "needle"},
        ]

    def test_directory_uses_existing_tools_and_preserves_attachments(self, client, project, variant, directory):
        from io import BytesIO
        (directory / "main.c").write_text("first\nneedle\nlast\n")
        uploaded = client.post(f"/api/variants/{variant.id}/context/files",
                               data={"file": (BytesIO(b"upload"), "upload.c")}).get_json()
        assert self._source(client, variant).status_code == 200
        unsaved = client.get("/api/context", query_string={"project_id": project.id, "variant_id": variant.id}).get_json()
        assert unsaved["threat_model"] is None
        assert unsaved["codebase_directory"] == {"file_id": "directory", "path": str(directory)}
        selected = self._select(client, variant)
        assert selected["files"] == [uploaded]
        assert selected["codebase_directory"] == {"file_id": "directory", "path": str(directory)}
        assert selected["editor"]["files"] == [uploaded]
        merged = client.get("/api/context", query_string={"project_id": project.id, "variant_id": variant.id}).get_json()
        assert merged["codebase_directory"] == selected["codebase_directory"]
        assert self._source(client, variant).get_json()["files"] == [{"path": "main.c", "size": 18}]
        assert self._source(client, variant, operation="read", path="main.c", start_line=2,
                            max_lines=1).get_json()["content"] == "needle\n"
        assert self._source(client, variant, operation="search", query="needle").get_json()["matches"] == [
            {"path": "main.c", "line": 2, "text": "needle"},
        ]
        assert self._source(client, variant, operation="read", path="../outside").status_code == 404
        other = Variant.create("Other", variant.project_id)
        assert self._source(client, other).status_code == 404
        updated = client.put(f"/api/variants/{variant.id}/context", json={"environment": "New environment"})
        assert updated.get_json()["codebase_directory"] == selected["codebase_directory"]
        assert self._source(client, variant).status_code == 200

    def test_missing_and_unreadable_directory_are_explicit(self, client, variant, directory):
        self._select(client, variant)
        assert "empty" in self._source(client, variant).get_json()["error"]
        directory.rmdir()
        url = f"/api/variants/{variant.id}/context/directory"
        assert client.get(url).get_json()["status"] == "missing"
        assert client.get(url).get_json()["file_count"] is None
        assert client.get(url).get_json()["directory_count"] is None
        response = self._source(client, variant)
        assert response.status_code == 400 and "missing or unreadable" in response.get_json()["error"]
        assert client.post(url).status_code == 200
        with patch("src.helpers.codebase_directory.os.scandir", side_effect=PermissionError("denied")):
            body = client.get(url).get_json()
            assert body["status"] == "unreadable"
            assert body["file_count"] is None and body["directory_count"] is None
            assert self._source(client, variant).status_code == 400

    def test_renames_keep_existing_path(self, client, project, variant, directory):
        url = f"/api/variants/{variant.id}/context/directory"
        project.update("Renamed")
        variant.update("Renamed")
        assert client.post(url).get_json()["path"] == str(directory)

    @pytest.mark.parametrize("first,second", [
        (("demo", "board@dev"), ("demo", "board-dev")),
        (("demo", "x" * 48 + "a"), ("demo", "x" * 48 + "b")),
        (("a-b", "c"), ("a", "b-c")),
    ])
    def test_colliding_directory_names_cannot_share_source(self, client, tmp_path, monkeypatch, first, second):
        from pathlib import Path
        from src.models.variant_context import VariantContext

        monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
        project = Project.create(first[0])
        first_variant = Variant.create(first[1], project.id)
        other_project = project if second[0] == first[0] else Project.create(second[0])
        other_variant = Variant.create(second[1], other_project.id)
        created = client.post(f"/api/variants/{first_variant.id}/context/directory")
        assert created.status_code == 200
        root = Path(created.get_json()["path"])
        (root / "main.c").write_text("first variant only")
        response = client.post(f"/api/variants/{other_variant.id}/context/directory")
        assert response.status_code == 409
        assert "already assigned" in response.get_json()["error"]
        other_context = VariantContext.get_by_variant(other_variant.id)
        assert other_context.codebase_directory is None and other_context.updated_at is None
        assert self._source(client, other_variant).status_code == 409
        assert self._source(client, first_variant, operation="read", path="main.c").get_json()["content"] == (
            "first variant only"
        )

    def test_concurrent_directory_claim_preserves_losing_context(self, client, project, variant, tmp_path, monkeypatch):
        from src.helpers.codebase_directory import provision_directory
        from src.models.variant_context import VariantContext

        monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
        vc = VariantContext.save_editor(variant.id, _editor_payload())
        before = vc.to_dict()
        other = Variant.create(f"{variant.name}@", project.id)

        def claim_directory(cache_dir, name):
            provision_directory(cache_dir, name)
            winner = VariantContext.get_or_create(other.id)
            winner.codebase_directory = name
            _db.session.commit()

        with patch("src.routes.context.provision_directory", side_effect=claim_directory):
            response = client.post(f"/api/variants/{variant.id}/context/directory")
        assert response.status_code == 409
        assert "already assigned" in response.get_json()["error"]
        assert VariantContext.get_by_variant(variant.id).to_dict() == before
        assert VariantContext.get_by_variant(other.id).codebase_directory == "context-TestProject-TestVariant"
        assert self._source(client, variant).status_code == 409

    def test_existing_uuid_directory_is_not_moved_or_renamed(self, client, variant, tmp_path, monkeypatch):
        from src.helpers.codebase_directory import provision_directory
        from src.models.variant_context import VariantContext

        monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
        name = f"context-TestProject-TestVariant-{variant.id}"
        provision_directory(str(tmp_path), name)
        root = tmp_path / name
        (root / "main.c").write_text("existing mount")
        vc = VariantContext.get_or_create(variant.id)
        vc.codebase_directory = name
        _db.session.commit()
        response = client.post(f"/api/variants/{variant.id}/context/directory")
        assert response.status_code == 200 and response.get_json()["path"] == str(root)
        assert not (tmp_path / "context-TestProject-TestVariant").exists()
        assert self._source(client, variant, operation="read", path="main.c").get_json()["content"] == "existing mount"

    @pytest.mark.parametrize("delete_project", [False, True])
    def test_deletion_retains_admin_source_and_recreation_reuses_portable_name(
        self, client, project, variant, directory, delete_project,
    ):
        (directory / "main.c").write_text("keep")
        original_id = variant.id
        project_name, variant_name = project.name, variant.name
        if delete_project:
            project.delete()
            project = Project.create(project_name)
        else:
            variant.delete()
        assert client.get(f"/api/variants/{original_id}/context/directory").status_code == 404
        other = Variant.create(variant_name, project.id)
        created = client.post(f"/api/variants/{other.id}/context/directory")
        assert created.status_code == 200 and created.get_json()["path"] == str(directory)
        assert other.id != original_id
        assert (directory / "main.c").read_text() == "keep"
        assert self._source(client, other, operation="read", path="main.c").get_json()["content"] == "keep"

    def test_incomplete_scan_does_not_report_partial_counts(self, client, variant, directory, monkeypatch):
        from src.helpers import codebase_directory
        (directory / "src").mkdir()
        (directory / "src" / "main.c").write_text("source")
        monkeypatch.setattr(codebase_directory, "MAX_ENTRIES", 1)
        body = client.get(f"/api/variants/{variant.id}/context/directory").get_json()
        assert body["status"] == "unavailable"
        assert "limit" in body["message"]
        assert body["file_count"] is None and body["directory_count"] is None

    def test_source_response_and_parameter_limits(self, client, variant, directory, monkeypatch):
        from src.helpers import codebase_reference
        self._select(client, variant)
        (directory / "main.c").write_text("needle " + "x" * 1000)
        monkeypatch.setattr(codebase_reference, "MAX_RESPONSE_BYTES", 400)
        response = self._source(client, variant, operation="search", query="needle")
        assert response.status_code == 400 and "64 KB" in response.get_json()["error"]
        for params in ({"limit": 201}, {"offset": -1}, {"operation": "search", "query": ""},
                       {"operation": "read", "path": "main.c", "max_lines": 201}, {"operation": "bad"}):
            assert self._source(client, variant, **params).status_code == 400

    def test_unprovisioned_directory_and_unknown_variants(self, client, variant):
        body = client.get(f"/api/variants/{variant.id}/context/directory").get_json()
        assert body["file_count"] is None and body["directory_count"] is None
        self._select(client, variant)
        assert self._source(client, variant).status_code == 404
        assert client.post("/api/variants/bad/context/directory").status_code == 400
        assert client.post(f"/api/variants/{uuid.uuid4()}/context/directory").status_code == 404
        assert self._source(client, Variant(id=uuid.uuid4(), name="Missing", project_id=variant.project_id)
                            ).status_code == 404

    @pytest.mark.parametrize("concurrent_edit", [False, True])
    def test_failed_provision_preserves_source_and_context_changes(
        self, client, project, variant, tmp_path, monkeypatch, concurrent_edit,
    ):
        from io import BytesIO
        from src.models.variant_context import VariantContext

        monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
        VariantContext.save_editor(variant.id, _editor_payload())
        uploaded = client.post(f"/api/variants/{variant.id}/context/files", data={
            "file": (BytesIO(b"working source"), "main.c"),
        }).get_json()
        context_url = "/api/context"
        scope = {"project_id": project.id, "variant_id": variant.id}
        expected = client.get(context_url, query_string=scope).get_json()

        def fail_provision(cache_dir, name):
            if concurrent_edit:
                updated = VariantContext.save_editor(
                    variant.id, _editor_payload(environment="Concurrent edit"),
                )
                expected["environment"] = "Concurrent edit"
                expected["editor"] = {**expected["editor"], "updated_at": updated.to_dict()["updated_at"]}
            raise PermissionError("denied")

        url = f"/api/variants/{variant.id}/context/directory"
        with patch("src.routes.context.provision_directory", side_effect=fail_provision):
            response = client.post(url)
        assert response.status_code == 500
        assert client.get(context_url, query_string=scope).get_json() == expected
        assert VariantContext.get_by_variant(variant.id).codebase_directory is None
        assert client.get(url).get_json()["status"] == "not_created"
        read = client.get(f"/api/variants/{variant.id}/context/files/{uploaded['id']}/source",
                          query_string={"operation": "read", "path": "main.c"})
        assert read.status_code == 200 and read.get_json()["content"] == "working source"

    def test_provisioning_errors_are_reported(self, client, variant, tmp_path, monkeypatch):
        monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
        with patch("src.routes.context.provision_directory", side_effect=PermissionError("denied")):
            response = client.post(f"/api/variants/{variant.id}/context/directory")
        assert response.status_code == 500
        assert "ownership and permissions" in response.get_json()["error"]

    def test_context_transfer_does_not_transfer_directory_storage(self, client, project, variant, directory):
        from src.models.variant_context import VariantContext
        self._select(client, variant)
        client.put(f"/api/projects/{project.id}/context", json={"description": "Project"})
        exported = client.get("/api/context/export", query_string={"variant_ids": str(variant.id)}).get_json()
        entry = exported["projects"][0]["variants"][0]
        assert not {"codebase_source", "codebase_path", "codebase_directory"} & entry.keys()
        other = Variant.create("Other", project.id)
        entry["variant_name"] = other.name
        response = client.post("/api/context/import", json=exported)
        assert response.status_code == 200 and len(response.get_json()["imported"]) == 1
        vc = VariantContext.get_by_variant(other.id)
        assert vc.codebase_directory is None
        assert self._source(client, other).status_code == 404
        assert directory.is_dir()

    @pytest.mark.parametrize("with_directory", [False, True])
    def test_directory_migration_preserves_evidence_and_enforces_unique_names(self, with_directory):
        import importlib
        import sqlalchemy as sa
        from alembic.migration import MigrationContext
        from alembic.operations import Operations

        migration = importlib.import_module("src.migrations.versions.df135a79b246_directory_codebase_context")
        engine = sa.create_engine("sqlite://")
        with engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            connection.exec_driver_sql(
                "CREATE TABLE variant_context (id INTEGER PRIMARY KEY, codebase_source TEXT NOT NULL, "
                "codebase_path TEXT, environment TEXT, updated_at DATETIME)"
            )
            if with_directory:
                connection.exec_driver_sql("ALTER TABLE variant_context ADD COLUMN codebase_directory TEXT")
            for row in (
                (1, "paths", "/old"),
                (2, "paths", "/old"),
                (3, "references", "/hidden"),
                (4, "paths", None),
                (5, "paths", "   "),
                (6, "paths", ""),
                (7, "paths", None),
                (8, "paths", "   "),
                (9, "paths", ""),
            ):
                connection.exec_driver_sql(
                    "INSERT INTO variant_context (id, codebase_source, codebase_path, environment, updated_at) "
                    "VALUES (?, ?, ?, 'Linux', '2026-01-01T00:00:00Z')", row,
                )
            if with_directory:
                connection.exec_driver_sql(
                    "UPDATE variant_context SET codebase_directory = 'context-p-v-uuid' WHERE id = 1"
                )
            connection.exec_driver_sql(
                "CREATE TABLE context_files (id INTEGER PRIMARY KEY, variant_context_id INTEGER "
                "REFERENCES variant_context(id) ON DELETE CASCADE)"
            )
            files = [(ctx_id, ctx_id) for ctx_id in (1, 3, 4, 5, 6)]
            connection.exec_driver_sql("INSERT INTO context_files VALUES (?, ?)", files)
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
                connection.exec_driver_sql(
                    "UPDATE variant_context SET codebase_directory = 'context-p-v' WHERE id = 2"
                )
                before_retry = connection.exec_driver_sql("SELECT * FROM variant_context ORDER BY id").all()
                migration.upgrade()
                assert connection.exec_driver_sql("SELECT * FROM variant_context ORDER BY id").all() == before_retry
                assert not {"codebase_source", "codebase_path"} & {
                    column["name"] for column in sa.inspect(connection).get_columns("variant_context")
                }
                rows = connection.exec_driver_sql("SELECT * FROM variant_context ORDER BY id").mappings().all()
                assert rows[0]["codebase_directory"] == ("context-p-v-uuid" if with_directory else None)
                assert {row["environment"] for row in rows} == {"Linux"}
                assert (rows[0]["updated_at"] == "2026-01-01T00:00:00Z") is with_directory
                assert all(row["updated_at"] != "2026-01-01T00:00:00Z"
                           for row in rows if row["id"] in (2, 4, 5, 6))
                assert all(row["updated_at"] == "2026-01-01T00:00:00Z"
                           for row in rows if row["id"] in (3, 7, 8, 9))
                assert connection.exec_driver_sql("SELECT * FROM context_files ORDER BY id").all() == files
                with pytest.raises(sa.exc.IntegrityError), connection.begin_nested():
                    connection.exec_driver_sql(
                        "INSERT INTO variant_context (id, codebase_directory) VALUES (10, 'context-p-v')"
                    )
                migration.downgrade()
                restored = connection.exec_driver_sql("SELECT * FROM variant_context ORDER BY id").mappings().all()
                assert all(row["codebase_path"] is None and row["codebase_source"] == "paths" for row in restored)
                assert "codebase_directory" not in {
                    column["name"] for column in sa.inspect(connection).get_columns("variant_context")
                }
                assert connection.exec_driver_sql("SELECT * FROM context_files ORDER BY id").all() == files
        engine.dispose()


class TestVariantEditorSave:

    def test_editor_save_round_trip(self, app, variant):
        from src.models.variant_context import VariantContext
        payload = _editor_payload()
        vc = VariantContext.save_editor(variant.id, payload)
        editor = VariantContext.get_by_variant(variant.id).to_dict()["editor"]
        assert vc.updated_at is not None
        assert not {"editor_mode", "free"} & set(editor)
        assert not {"codebase_source", "codebase_path"} & editor.keys()
        assert editor["system"] == payload["system"]
        assert editor["stride"] == payload["stride"]
        assert editor["files"] == []
        assert editor["updated_at"] == vc.to_dict()["updated_at"]

    def test_editor_save_blank_text_stored_as_none(self, app, variant):
        from src.models.variant_context import VariantContext
        vc = VariantContext.save_editor(variant.id, _editor_payload(
            variant_description="", environment="  ",
            system={"scope": "Firmware", "actors": "", "entry_points": None, "trust_boundaries": None},
        ))
        assert vc.variant_description is None
        assert vc.environment is None
        assert vc.system_actors is None

    @pytest.mark.parametrize("description,scope", [("Gateway", None), (None, "Firmware")])
    def test_add_model_after_basic_editor_save(self, client, project, variant, description, scope):
        from src.helpers.stride_model import empty_stride_model
        save_url = f"/api/variants/{variant.id}/context"
        load_url = f"/api/context?project_id={project.id}&variant_id={variant.id}"
        payload = _editor_payload(variant_description=description, environment=None,
                                  system={"scope": scope}, stride=empty_stride_model())
        assert client.put(save_url, json=payload).status_code == 200
        saved = client.get(load_url).get_json()
        assert saved["variant_description"] == description
        assert saved["editor"]["system"]["scope"] == scope
        assert saved["editor"]["stride"] == empty_stride_model()
        if scope:
            assert scope in saved["threat_model"]
        else:
            assert saved["threat_model"] is None
        assert saved["risks"] is None

        payload["stride"] = _stride_model()
        assert client.put(save_url, json=payload).status_code == 200
        saved = client.get(load_url).get_json()
        assert saved["variant_description"] == description
        assert saved["editor"]["system"]["scope"] == scope
        assert saved["editor"]["stride"] == payload["stride"]
        assert "Tampering" in saved["threat_model"]
        assert "Likelihood: High" in saved["risks"]

    def test_editor_save_rejects_bad_model(self, app, variant):
        from src.helpers.stride_model import StrideValidationError
        from src.models.variant_context import VariantContext
        bad = _stride_model(threats=[{"id": "T1", "category": "tampering", "target_ids": ["C9"]}], risks=[])
        with pytest.raises(StrideValidationError) as exc:
            VariantContext.save_editor(variant.id, _editor_payload(stride=bad))
        assert "threats[0].target_ids" in exc.value.fields

    @pytest.mark.parametrize("stride,system,errors", [
        ({}, {"trust_boundary": "Between services"}, {"system.trust_boundary": "unknown field in empty replacement"}),
        (None, {"scope": "Gateway"}, {"model": "must be an object"}),
        ({"threat": [{"id": "T1"}]}, {},
         {"model": "expected at least one of: components, interactions, threats, risks"}),
        ({"components": [], "threat": [{"id": "T1"}]}, {},
         {"model": "cannot clear tables with unknown table names"}),
        *[({table: None}, {}, {table: "must be a list"})
          for table in ("components", "interactions", "threats", "risks")],
    ])
    def test_invalid_stride_preserves_saved_context(self, client, project, variant, stride, system, errors):
        save_url = f"/api/variants/{variant.id}/context"
        load_url = f"/api/context?project_id={project.id}&variant_id={variant.id}"
        assert client.put(save_url, json=_editor_payload()).status_code == 200
        before = client.get(load_url).get_json()
        resp = client.put(save_url, json=_editor_payload(environment="Lab", stride=stride, system=system))
        assert resp.status_code == 400
        assert resp.get_json()["fields"] == errors
        assert client.get(load_url).get_json() == before

    def test_unknown_root_field_cannot_turn_editor_save_into_a_clear(self, client, project, variant):
        from src.helpers.stride_model import empty_stride_model
        url = f"/api/variants/{variant.id}/context"
        load_url = f"/api/context?project_id={project.id}&variant_id={variant.id}"
        assert client.put(url, json=_editor_payload()).status_code == 200
        before = client.get(load_url).get_json()

        rejected = client.put(url, json={"scope": "Gateway", "stride": {}})
        assert rejected.status_code == 400
        assert rejected.get_json()["fields"] == {"scope": "unknown field in empty replacement"}
        assert client.get(load_url).get_json() == before

        assert client.put(url, json={"stride": {}}).status_code == 200
        cleared = client.get(load_url).get_json()
        assert all(cleared[key] is None for key in ("variant_description", "environment", "other_info"))
        assert not any(cleared["editor"]["system"].values())
        assert cleared["editor"]["stride"] == empty_stride_model()

    def test_system_only_save_must_explicitly_replace_model(self, client, variant):
        from src.helpers.stride_model import empty_stride_model
        url = f"/api/variants/{variant.id}/context"
        payload = _editor_payload()
        assert client.put(url, json=payload).status_code == 200
        system = {"scope": "Gateway"}
        resp = client.put(url, json={"system": system})
        assert resp.status_code == 200
        assert resp.get_json()["editor"]["system"]["scope"] == payload["system"]["scope"]
        assert resp.get_json()["editor"]["stride"] == payload["stride"]

        resp = client.put(url, json={"system": system, "stride": {}})
        assert resp.status_code == 200
        assert resp.get_json()["editor"]["system"]["scope"] == "Gateway"
        assert resp.get_json()["editor"]["stride"] == empty_stride_model()

    def test_identical_editor_save_keeps_updated_at(self, app, variant):
        from src.models.variant_context import VariantContext
        first = VariantContext.save_editor(variant.id, _editor_payload()).updated_at
        vc = VariantContext.save_editor(variant.id, _editor_payload())
        assert vc.updated_at == first

    def test_editor_save_bumps_on_model_change(self, app, variant):
        from src.models.variant_context import VariantContext
        vc = VariantContext.save_editor(variant.id, _editor_payload(stride=_stride_model(risks=_risk("a"))))
        first = vc.updated_at
        vc = VariantContext.save_editor(variant.id, _editor_payload(stride=_stride_model(risks=_risk("b"))))
        assert vc.updated_at > first
        assert vc.stride_model["risks"][0]["mitigation"] == "b"

    def test_controller_save_editor_missing_variant(self, app):
        from src.controllers.context import VariantContextController
        with pytest.raises(ValueError):
            VariantContextController.save_editor(uuid.uuid4(), _editor_payload())


class TestLegacyWrite:

    def test_legacy_write_with_threat_model_text_is_rejected(self, client, variant):
        from src.models.variant_context import VariantContext
        client.put(f"/api/variants/{variant.id}/context", json=_editor_payload())
        before = VariantContext.get_by_variant(variant.id).to_dict()
        resp = client.put(f"/api/variants/{variant.id}/context",
                          json={"environment": "changed", "threat_model": "text", "risks": "r"})
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["fields"] == {
            "threat_model": "is generated from the STRIDE model; edit it in the AI Context page",
            "risks": "is generated from the STRIDE model; edit it in the AI Context page",
        }
        assert VariantContext.get_by_variant(variant.id).to_dict() == before

    def test_legacy_write_with_null_text_applies_other_fields(self, client, variant):
        from src.models.variant_context import VariantContext
        client.put(f"/api/variants/{variant.id}/context", json=_editor_payload())
        resp = client.put(f"/api/variants/{variant.id}/context",
                          json={"environment": "Yocto", "threat_model": None, "risks": None})
        assert resp.status_code == 200
        vc = VariantContext.get_by_variant(variant.id)
        assert vc.environment == "Yocto"
        assert vc.variant_description is None
        assert vc.stride_model == _stride_model()
        assert "Tampering" in resp.get_json()["threat_model"]

    def test_legacy_create_has_no_stride_model(self, app, variant):
        from src.models.variant_context import VariantContext
        vc = VariantContext.upsert(variant.id, environment="x")
        assert vc.stride_model is None
        assert vc.agent_threat_model() is None


class TestAgentView:

    def _with_file(self, variant):
        from src.models.variant_context import ContextFile, VariantContext
        vc = VariantContext.get_by_variant(variant.id)
        ContextFile.create(vc.id, "src.zip", "/tmp/none/src.zip")
        _db.session.refresh(vc)
        return vc

    def test_agent_view_includes_attachments_without_source_selection(self, app, variant):
        from src.models.variant_context import VariantContext
        VariantContext.save_editor(variant.id, _editor_payload())
        vc = self._with_file(variant)
        d = vc.to_dict()
        assert [f["original_name"] for f in d["files"]] == ["src.zip"]
        assert [f["original_name"] for f in d["editor"]["files"]] == ["src.zip"]

    def test_agent_view_stride_renders(self, app, variant):
        from src.helpers.stride_model import render_risks, render_threat_model
        from src.models.variant_context import VariantContext
        payload = _editor_payload()
        vc = VariantContext.save_editor(variant.id, payload)
        d = vc.to_dict()
        assert d["threat_model"] == render_threat_model(payload["system"], payload["stride"])
        assert "Threats:\nTampering\n- T1" in d["threat_model"]
        assert d["risks"] == render_risks(payload["stride"])

    def test_put_route_400_carries_fields(self, client, variant):
        bad = _stride_model(threats=[{"id": "T1", "category": "tampering", "target_ids": ["C9"]}], risks=[])
        resp = client.put(f"/api/variants/{variant.id}/context", json=_editor_payload(stride=bad))
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["error"]
        assert "threats[0].target_ids" in body["fields"]

    def test_put_route_editor_save(self, client, variant):
        resp = client.put(f"/api/variants/{variant.id}/context", json=_editor_payload())
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["editor"]["stride"] == _stride_model()
        assert "Tampering" in body["threat_model"]

    def test_put_route_editor_save_404(self, client):
        resp = client.put(f"/api/variants/{uuid.uuid4()}/context", json=_editor_payload())
        assert resp.status_code == 404

    def test_first_upload_creates_context_row(self, client, project, variant, tmp_path):
        from io import BytesIO
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            resp = client.post(
                f"/api/variants/{variant.id}/context/files", data={"file": (BytesIO(b"code"), "main.c")},
            )
        assert resp.status_code == 201
        data = client.get(f"/api/context?project_id={project.id}&variant_id={variant.id}").get_json()
        assert [f["id"] for f in data["files"]] == [resp.get_json()["id"]]

    def test_upload_after_text_only_create_is_visible_to_agents(self, client, project, variant, tmp_path):
        from io import BytesIO
        client.put(f"/api/variants/{variant.id}/context", json={"environment": "Yocto"})
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            resp = client.post(
                f"/api/variants/{variant.id}/context/files", data={"file": (BytesIO(b"code"), "main.c")},
            )
        assert resp.status_code == 201
        data = client.get(f"/api/context?project_id={project.id}&variant_id={variant.id}").get_json()
        assert [f["id"] for f in data["files"]] == [resp.get_json()["id"]]

    def test_get_context_default_editor_block(self, client, project, variant):
        from src.models.variant_context import default_editor_block
        resp = client.get(f"/api/context?project_id={project.id}&variant_id={variant.id}")
        data = resp.get_json()
        assert data["editor"] == default_editor_block()
        assert data["threat_model"] is None
        assert not {"codebase_source", "codebase_path"} & data.keys()
        assert not {"codebase_source", "codebase_path"} & data["editor"].keys()

    def test_get_context_returns_agent_view_and_editor(self, client, project, variant):
        client.put(f"/api/variants/{variant.id}/context", json=_editor_payload(variant_description="Desc"))
        data = client.get(f"/api/context?project_id={project.id}&variant_id={variant.id}").get_json()
        assert data["variant_description"] == "Desc"
        assert "Tampering" in data["threat_model"]
        assert "Likelihood: High" in data["risks"]
        assert data["editor"]["stride"] == _stride_model()
        assert {"project_id", "description", "variant_id", "variant_description", "codebase_directory",
                "environment", "threat_model", "risks", "other_info", "files"} <= set(data)
# ---------------------------------------------------------------------------
# AI threat-model drafts
# ---------------------------------------------------------------------------


def _draft_values(**overrides):
    values = {
        "variant_description": None, "environment": None, "other_info": None,
        "system": {"scope": "Gateway", "actors": None, "entry_points": None, "trust_boundaries": None},
        "stride": {"components": [{"id": "C1", "name": "Web UI", "description": "", "trust_zone": ""}],
                   "interactions": [], "threats": [], "risks": []},
    }
    values.update(overrides)
    return values


class TestContextDraftRoutes:

    def _url(self, variant):
        return f"/api/variants/{variant.id}/context/draft"

    def _put(self, client, variant, base=None, **body):
        return client.put(self._url(variant), json={
            "source": "report.pdf", "base_updated_at": base, "values": _draft_values(), **body,
        })

    @pytest.mark.parametrize("with_context", [False, True])
    def test_absent_draft_is_no_content_without_creating_or_modifying_context(
        self, client, variant, tmp_path, with_context,
    ):
        from src.models.variant_context import VariantContext

        if with_context:
            VariantContext.get_or_create(variant.id)
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            for _ in range(2):
                response = client.get(self._url(variant))
                assert response.status_code == 204 and response.data == b""
        context = VariantContext.get_by_variant(variant.id)
        if with_context:
            assert context is not None and context.updated_at is None
        else:
            assert context is None
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.parametrize("upload", [False, True])
    @pytest.mark.parametrize("missing_lookup", [1, 2])
    def test_creation_never_replaces_a_concurrently_saved_context(
            self, client, variant, tmp_path, upload, missing_lookup):
        from io import BytesIO
        from src.models.variant_context import VariantContext

        get_by_variant = VariantContext.get_by_variant
        saved = {}
        lookups = 0

        def save_after_missing_lookup(variant_id):
            nonlocal lookups
            lookups += 1
            if lookups != missing_lookup:
                return get_by_variant(variant_id)
            assert get_by_variant(variant_id) is None
            vc = VariantContext.save_editor(variant_id, {
                **_draft_values(variant_description="Saved", environment="Production", other_info="Keep"),
            })
            saved.update(vc.to_dict())
            return None

        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)), \
                patch.object(VariantContext, "get_by_variant", side_effect=save_after_missing_lookup):
            if upload:
                response = client.post(f"/api/variants/{variant.id}/context/import-source",
                                       data={"file": (BytesIO(b"document"), "model.md")})
            else:
                response = self._put(client, variant)
            assert response.status_code == (201 if upload else 409)
            assert get_by_variant(variant.id).to_dict() == saved
            assert client.get(self._url(variant)).status_code == 204

    def test_put_creates_the_context_and_get_returns_a_current_draft(self, client, variant, tmp_path):
        from src.models.variant_context import VariantContext

        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            assert client.get(self._url(variant)).status_code == 204
            put = self._put(client, variant)
            got = client.get(self._url(variant))
        assert put.status_code == 200 and put.get_json()["status"] == "current"
        body = got.get_json()
        assert got.status_code == 200
        assert body["status"] == "current" and body["source"] == "report.pdf"
        assert body["values"]["stride"]["components"][0]["name"] == "Web UI"
        assert body["conflicts"] == [] and body["renumbered"] == {}
        vc = VariantContext.get_by_variant(variant.id)
        assert vc is not None and vc.updated_at is None  # drafting never outdates assessments

    def test_put_rejects_invalid_values_with_fields(self, client, variant, tmp_path):
        bad = _draft_values(stride={"components": [{"id": "X1", "name": ""}]})
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            resp = self._put(client, variant, values=bad)
            missing_source = self._put(client, variant, source=" ")
        assert resp.status_code == 400 and "components[0].id" in resp.get_json()["fields"]
        assert missing_source.status_code == 400 and "source" in missing_source.get_json()["fields"]

    def test_put_rejects_a_stale_base(self, client, variant, tmp_path):
        from src.models.variant_context import VariantContext

        VariantContext.save_editor(variant.id, _draft_values())
        saved_at = VariantContext.get_by_variant(variant.id).to_dict()["updated_at"]
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            stale = self._put(client, variant, base=None)
            ok = self._put(client, variant, base=saved_at)
        assert stale.status_code == 409 and stale.get_json()["updated_at"] == saved_at
        assert ok.status_code == 200
        assert VariantContext.get_by_variant(variant.id).to_dict()["updated_at"] == saved_at

    def test_get_rebases_or_reports_conflicts_after_a_save(self, client, variant, tmp_path):
        from src.models.variant_context import VariantContext

        VariantContext.save_editor(variant.id, _draft_values())
        base = VariantContext.get_by_variant(variant.id).to_dict()["updated_at"]
        proposal = _draft_values(stride={**_draft_values()["stride"], "components": [
            {"id": "C1", "name": "Web UI", "description": "", "trust_zone": ""},
            {"id": "C2", "name": "Updater", "description": "", "trust_zone": ""}]})
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            self._put(client, variant, base=base, values=proposal)
            VariantContext.save_editor(variant.id, _draft_values(
                system={"scope": "Gateway", "actors": "Admins", "entry_points": None, "trust_boundaries": None}))
            rebased = client.get(self._url(variant)).get_json()
            VariantContext.save_editor(variant.id, _draft_values(
                stride={**_draft_values()["stride"], "components": [
                    {"id": "C1", "name": "Renamed", "description": "", "trust_zone": ""}]}))
            self._put(client, variant, base=VariantContext.get_by_variant(variant.id).to_dict()["updated_at"],
                      values=_draft_values(stride={**_draft_values()["stride"], "components": [
                          {"id": "C1", "name": "AI name", "description": "", "trust_zone": ""}]}))
            VariantContext.save_editor(variant.id, _draft_values(
                stride={**_draft_values()["stride"], "components": [
                    {"id": "C1", "name": "Mine", "description": "", "trust_zone": ""}]}))
            conflict = client.get(self._url(variant)).get_json()
        assert rebased["status"] == "rebased"
        assert rebased["values"]["system"]["actors"] == "Admins"
        assert [c["id"] for c in rebased["values"]["stride"]["components"]] == ["C1", "C2"]
        assert conflict["status"] == "conflict" and conflict["values"] is None
        assert conflict["conflicts"] == [{"path": "components[C1]", "reason": "changed in both"}]

    def test_corrupt_draft_is_removed_and_returns_no_content(self, client, variant, tmp_path):
        from src.helpers import context_draft
        from src.models.variant_context import VariantContext

        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            self._put(client, variant)
            directory = context_draft.context_dir(str(tmp_path), VariantContext.get_by_variant(variant.id).id)
            with open(os.path.join(directory, context_draft.DRAFT_NAME), "w") as handle:
                handle.write("{broken")
            resp = client.get(self._url(variant))
        assert resp.status_code == 204
        assert not os.path.exists(os.path.join(directory, context_draft.DRAFT_NAME))

    @pytest.mark.parametrize("second_collision", [False, True])
    def test_accepted_renumbering_survives_failed_cleanup(self, client, variant, tmp_path, second_collision):
        from src.models.variant_context import VariantContext

        base = _draft_values()
        common = base["stride"]["components"]
        proposal = _draft_values(stride=_stride_model(components=[
            *common, {"id": "C2", "name": "Updater", "description": "", "trust_zone": ""},
        ]))
        concurrent = _draft_values(stride=_stride_model(components=[
            *common, {"id": "C2", "name": "Cloud", "description": "", "trust_zone": ""},
        ]))
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            vc = VariantContext.save_editor(variant.id, base)
            original = self._put(client, variant, base=vc.to_dict()["updated_at"], values=proposal).get_json()
            VariantContext.save_editor(variant.id, concurrent)
            with patch("src.helpers.context_draft.write_draft", side_effect=OSError("disk full")):
                assert client.get(self._url(variant)).status_code == 500
            first = client.get(self._url(variant)).get_json()
            mapping = {"C2": "C3", "I1": "I2", "T1": "T2", "R1": "R2"}
            assert first["renumbered"] == mapping
            assert first["revision"] == original["revision"]
            assert client.get(self._url(variant)).get_json()["renumbered"] == mapping
            if second_collision:
                concurrent["stride"]["components"].append(
                    {"id": "C3", "name": "Another saved component", "description": "", "trust_zone": ""})
                VariantContext.save_editor(variant.id, concurrent)
                first = client.get(self._url(variant)).get_json()
                mapping["C2"] = "C4"
                assert first["renumbered"] == mapping
            accepted = VariantContext.save_editor(
                variant.id, first["values"]).to_dict()
            with patch("src.helpers.context_draft.delete_draft", side_effect=OSError("cleanup failed")):
                assert client.delete(self._url(variant), json={"revision": first["revision"]}).status_code == 500
            again = client.get(self._url(variant)).get_json()
            assert again["values"]["stride"] == accepted["editor"]["stride"]
            assert again["renumbered"] == mapping and again["revision"] == first["revision"]
            restarted = self._put(client, variant, base=accepted["updated_at"], values=again["values"]).get_json()
            assert restarted["revision"] != first["revision"]
            assert client.get(self._url(variant)).get_json()["renumbered"] == {}

    def test_delete_is_idempotent(self, client, variant, tmp_path):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            assert client.delete(self._url(variant), json={"revision": None}).status_code == 204
            draft = self._put(client, variant).get_json()
            assert client.delete(self._url(variant), json={"revision": draft["revision"]}).status_code == 204
            assert client.delete(self._url(variant), json={"revision": draft["revision"]}).status_code == 204
            assert client.get(self._url(variant)).status_code == 204

    def test_stale_cleanup_keeps_a_new_draft_and_its_source(self, client, variant, tmp_path):
        from io import BytesIO

        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            client.post(f"/api/variants/{variant.id}/context/import-source",
                        data={"file": (BytesIO(b"document"), "report.md")})
            first = self._put(client, variant).get_json()
            second = self._put(client, variant).get_json()
            assert second["revision"] != first["revision"]
            for body in ({}, {"revision": None}, {"revision": first["revision"]}):
                result = client.delete(self._url(variant), json=body)
                assert result.status_code == (400 if not body else 409)
            assert client.get(self._url(variant)).get_json()["revision"] == second["revision"]
            assert client.get(f"/api/variants/{variant.id}/context/import-source/source").status_code == 200
            assert client.delete(self._url(variant), json={"revision": second["revision"]}).status_code == 204
            assert client.get(f"/api/variants/{variant.id}/context/import-source/source").status_code == 404

    def test_stale_cleanup_keeps_an_identical_reuploaded_source(self, client, variant, tmp_path):
        from io import BytesIO

        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            revisions = []
            for _ in range(2):
                upload = client.post(f"/api/variants/{variant.id}/context/import-source",
                                     data={"file": (BytesIO(b"document"), "report.md")})
                revisions.append(upload.get_json()["revision"])
            assert revisions[0] != revisions[1]
            assert client.delete(self._url(variant), json={"revision": revisions[0]}).status_code == 409
            assert client.get(f"/api/variants/{variant.id}/context/import-source/source").status_code == 200
            assert client.delete(self._url(variant), json={"revision": revisions[1]}).status_code == 204

    def test_delete_failure_is_reported(self, client, variant, tmp_path):
        from io import BytesIO

        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            client.post(f"/api/variants/{variant.id}/context/import-source",
                        data={"file": (BytesIO(b"document"), "report.md")})
            revision = self._put(client, variant).get_json()["revision"]
            with patch("src.helpers.context_draft.shutil.rmtree", side_effect=OSError("permission denied")):
                assert client.delete(self._url(variant), json={"revision": revision}).status_code == 500
            assert client.get(self._url(variant)).get_json()["revision"] == revision
            assert client.delete(self._url(variant), json={"revision": revision}).status_code == 204

    def test_unknown_variant_and_bad_id(self, client, tmp_path):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            assert client.get(f"/api/variants/{uuid.uuid4()}/context/draft").status_code == 404
            assert client.put("/api/variants/nope/context/draft", json={}).status_code == 400
            assert client.delete(f"/api/variants/{uuid.uuid4()}/context/draft").status_code == 404

    def test_storage_failure_is_a_500(self, client, variant, tmp_path):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)), \
                patch("src.helpers.context_draft.write_draft", side_effect=OSError("disk full")):
            assert self._put(client, variant).status_code == 500


class TestImportSourceRoutes:

    def _post(self, client, variant, content, name):
        from io import BytesIO
        return client.post(f"/api/variants/{variant.id}/context/import-source",
                           data={"file": (BytesIO(content), name)}, content_type="multipart/form-data")

    def _source(self, client, variant, **params):
        return client.get(f"/api/variants/{variant.id}/context/import-source/source", query_string=params)

    def test_upload_then_list_read_search(self, client, variant, tmp_path):
        from src.models.variant_context import ContextFile, VariantContext

        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            assert self._source(client, variant).status_code == 404
            resp = self._post(client, variant, b"line one\nneedle two\n", "model.yaml")
            listed = self._source(client, variant).get_json()
            read = self._source(client, variant, operation="read", path="model.yaml", max_lines=1).get_json()
            found = self._source(client, variant, operation="search", query="needle").get_json()
            bad = self._source(client, variant, operation="nope")
        assert resp.status_code == 201
        assert resp.get_json() == {"name": "model.yaml", "size": 20, "revision": resp.get_json()["revision"]}
        assert resp.get_json()["revision"]
        assert listed["name"] == "model.yaml" and listed["files"] == [{"path": "model.yaml", "size": 20}]
        assert read["content"] == "line one\n" and read["next_line"] == 2
        assert found["matches"] == [{"path": "model.yaml", "line": 2, "text": "needle two"}]
        assert bad.status_code == 400
        vc = VariantContext.get_by_variant(variant.id)
        assert vc.updated_at is None and ContextFile.count_for_variant_context(vc.id) == 0

    def test_new_upload_replaces_the_source_and_clears_the_draft(self, client, variant, tmp_path):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            self._post(client, variant, b"first", "a.md")
            client.put(f"/api/variants/{variant.id}/context/draft",
                       json={"source": "a.md", "base_updated_at": None, "values": _draft_values()})
            self._post(client, variant, b"second", "b.md")
            listed = self._source(client, variant).get_json()
            draft = client.get(f"/api/variants/{variant.id}/context/draft")
        assert [f["path"] for f in listed["files"]] == ["b.md"]
        assert draft.status_code == 204

    def test_import_reads_and_proposals_reject_replacement_sources(self, client, variant, tmp_path):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            first = self._post(client, variant, b"first page\nsecond page\n", "model.md").get_json()["revision"]
            read = self._source(client, variant, operation="read", path="model.md", max_lines=1,
                                revision=first)
            assert read.status_code == 200 and read.get_json()["content"] == "first page\n"
            draft_url = f"/api/variants/{variant.id}/context/draft"
            body = {"source": "model.md", "base_updated_at": None, "values": _draft_values(),
                    "import_revision": first}
            for _ in range(2):
                assert client.put(draft_url, json=body).status_code == 200
                assert self._source(client, variant, revision=first).get_json()["revision"] == first
            second = self._post(client, variant, b"replacement\n", "model.md").get_json()["revision"]
            assert second != first
            read = self._source(client, variant, operation="read", path="model.md", start_line=2,
                                revision=first)
            assert read.status_code == 409 and "source changed" in read.get_json()["error"]
            assert client.put(draft_url, json=body).status_code == 409
            assert client.get(draft_url).status_code == 204
            assert self._source(client, variant, revision=second).get_json()["revision"] == second
            assert client.put(draft_url, json={**body, "import_revision": second}).status_code == 200
            draft = client.get(draft_url).get_json()
            assert client.delete(draft_url, json={"revision": draft["revision"]}).status_code == 204
            assert client.put(draft_url, json={**body, "import_revision": second}).status_code == 409
            assert self._source(client, variant, revision=second).status_code == 409

    @pytest.mark.parametrize("content,name,error", [
        (b"\x00\x01binary", "blob.bin", "binary"),
        (b"\xff\xfe\xfa", "latin.txt", "UTF-8"),
        (b"not a zip", "bundle.zip", "Invalid or unsupported source archive"),
    ])
    def test_unreadable_content_is_rejected(self, client, variant, tmp_path, content, name, error):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            resp = self._post(client, variant, content, name)
        assert resp.status_code == 400 and error in resp.get_json()["error"]

    def test_unsafe_names_never_clobber_the_draft(self, client, variant, tmp_path):
        from src.helpers import context_draft
        from src.models.variant_context import VariantContext

        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            for name in ("..", ".", "a\x01b.md", "x" * 256 + ".md"):
                assert self._post(client, variant, b"text", name).status_code == 400, name
            assert self._post(client, variant, b"text", "draft.json").status_code == 201
            assert self._post(client, variant, b"text", "../../evil.md").get_json()["name"] == "evil.md"
            directory = context_draft.context_dir(str(tmp_path), VariantContext.get_by_variant(variant.id).id)
        assert sorted(os.listdir(directory)) == ["import", "import-revision"]
        assert os.listdir(os.path.join(directory, "import")) == ["evil.md"]

    def test_windows_paths_keep_only_the_base_name(self):
        # Werkzeug 3.1.9+ unescapes backslashes in multipart filenames, so this is tested off the route.
        from src.routes.context import _import_name

        assert _import_name("..\\..\\evil.md") == "evil.md"
        assert _import_name("C:\\Users\\me\\model.pdf") == "model.pdf"

    def test_missing_file_and_unknown_variant(self, client, variant, tmp_path):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)):
            assert client.post(f"/api/variants/{variant.id}/context/import-source").status_code == 400
            assert client.post(f"/api/variants/{uuid.uuid4()}/context/import-source").status_code == 404

    def test_storage_failure_is_a_500(self, client, variant, tmp_path):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)), \
                patch("werkzeug.datastructures.FileStorage.save", side_effect=OSError("disk full")):
            assert self._post(client, variant, b"text", "a.md").status_code == 500

    def test_pdf_without_text_is_rejected_on_upload(self, client, variant, tmp_path):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)), \
                patch("src.helpers.codebase_reference._pdf_text", side_effect=ValueError("PDF has no extractable text")):
            resp = self._post(client, variant, b"%PDF-1.4", "scan.pdf")
        assert resp.status_code == 400 and "no extractable text" in resp.get_json()["error"]

    @pytest.mark.parametrize("archive", [False, True])
    def test_source_byte_limit_preserves_the_existing_source_and_draft(self, client, variant, tmp_path, archive):
        from io import BytesIO
        from zipfile import ZipFile

        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)), \
                patch("src.routes.context.MAX_FILE_BYTES", 256):
            assert self._post(client, variant, b"saved", "saved.md").status_code == 201
            assert client.put(f"/api/variants/{variant.id}/context/draft",
                              json={"source": "saved.md", "base_updated_at": None,
                                    "values": _draft_values()}).status_code == 200
            if archive:
                stream = BytesIO()
                with ZipFile(stream, "w") as bundle:
                    bundle.writestr("tiny.md", "text")
                content, name = b"x" * 257 + stream.getvalue(), "bundle.zip"
            else:
                content, name = b"x" * 257, "large.md"
            response = self._post(client, variant, content, name)
            assert response.status_code == 413
            assert "size limit" in response.get_json()["error"]
            assert self._source(client, variant).get_json()["name"] == "saved.md"
            assert client.get(f"/api/variants/{variant.id}/context/draft").status_code == 200

    def test_source_at_the_byte_limit_is_accepted(self, client, variant, tmp_path):
        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)), \
                patch("src.routes.context.MAX_FILE_BYTES", 256):
            response = self._post(client, variant, b"x" * 256, "model.md")
        assert response.status_code == 201 and response.get_json()["size"] == 256

    def test_import_preserves_a_stricter_server_request_limit(self, client, variant):
        with patch.dict(client.application.config, {"MAX_CONTENT_LENGTH": 128}):
            response = self._post(client, variant, b"text", "model.md")
        assert response.status_code == 413 and "size limit" in response.get_json()["error"]

    @pytest.mark.parametrize("content_length", [True, False])
    def test_request_limit_applies_before_unbounded_multipart_parsing(self, client, variant, tmp_path, content_length):
        from io import BytesIO
        from werkzeug.test import EnvironBuilder

        with patch("src.routes.context._get_cache_dir", return_value=str(tmp_path)), \
                patch("src.routes.context.MAX_FILE_BYTES", 256):
            builder = EnvironBuilder(path=f"/api/variants/{variant.id}/context/import-source", method="POST",
                                     data={"file": (BytesIO(b"x" * (64 * 1024 + 257)), "large.md")})
            try:
                environ = builder.get_environ()
                if not content_length:
                    environ.pop("CONTENT_LENGTH", None)
                    environ["wsgi.input_terminated"] = True
                response = client.open(environ)
            finally:
                builder.close()
        assert response.status_code == 413
        assert "size limit" in response.get_json()["error"]

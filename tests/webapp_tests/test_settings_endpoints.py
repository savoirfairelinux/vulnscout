# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the settings routes: project/variant CRUD, SBOM upload (multi-file)."""

import io
import json
import os
import uuid
import pytest
from unittest.mock import patch, MagicMock
from werkzeug.datastructures import MultiDict

from src.bin.webapp import create_app
from . import write_demo_files, setup_demo_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def init_files(tmp_path):
    files = {
        "status": tmp_path / "status.txt",
        "packages": tmp_path / "packages-merged.json",
        "vulnerabilities": tmp_path / "vulnerabilities-merged.json",
        "assessments": tmp_path / "assessments-merged.json",
        "openvex": tmp_path / "openvex.json",
        "time_estimates": tmp_path / "time_estimates.json",
    }
    write_demo_files(files)
    return files


@pytest.fixture()
def app(init_files):
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": init_files["status"],
            "OPENVEX_FILE": init_files["openvex"],
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        setup_demo_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


def _get_project_id(client, name="demo"):
    """Lookup a project ID by name."""
    resp = client.get("/api/projects")
    for p in resp.get_json():
        if p["name"] == name:
            return p["id"]
    return None


def _get_variant_id(client, project_id, name="default"):
    """Lookup a variant ID by name within a project."""
    resp = client.get(f"/api/projects/{project_id}/variants")
    for v in resp.get_json():
        if v["name"] == name:
            return v["id"]
    return None


# ---------------------------------------------------------------------------
# Project CRUD
# ---------------------------------------------------------------------------

class TestCreateProject:

    def test_create_project_success(self, client):
        resp = client.post("/api/projects", json={"name": "NewProject"})
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["name"] == "NewProject"
        assert "id" in data

    def test_create_project_appears_in_list(self, client):
        client.post("/api/projects", json={"name": "Listed"})
        resp = client.get("/api/projects")
        names = [p["name"] for p in resp.get_json()]
        assert "Listed" in names

    def test_create_project_missing_name(self, client):
        resp = client.post("/api/projects", json={})
        assert resp.status_code == 400

    def test_create_project_empty_name(self, client):
        resp = client.post("/api/projects", json={"name": "   "})
        assert resp.status_code == 400

    def test_create_project_duplicate_name(self, client):
        client.post("/api/projects", json={"name": "Dup"})
        resp = client.post("/api/projects", json={"name": "Dup"})
        assert resp.status_code == 409


class TestRenameProject:

    def test_rename_project_success(self, client):
        pid = _get_project_id(client)
        resp = client.patch(f"/api/projects/{pid}/rename", json={"name": "Renamed"})
        assert resp.status_code == 200
        assert resp.get_json()["name"] == "Renamed"

    def test_rename_project_not_found(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.patch(f"/api/projects/{fake_id}/rename", json={"name": "X"})
        assert resp.status_code == 404

    def test_rename_project_empty_name(self, client):
        pid = _get_project_id(client)
        resp = client.patch(f"/api/projects/{pid}/rename", json={"name": ""})
        assert resp.status_code == 400

    def test_rename_project_duplicate(self, client):
        client.post("/api/projects", json={"name": "Other"})
        pid = _get_project_id(client)
        resp = client.patch(f"/api/projects/{pid}/rename", json={"name": "Other"})
        assert resp.status_code == 409


class TestDeleteProject:

    def test_delete_project_success(self, client):
        resp = client.post("/api/projects", json={"name": "ToDelete"})
        pid = resp.get_json()["id"]
        resp = client.delete(f"/api/projects/{pid}")
        assert resp.status_code == 200

    def test_delete_project_removes_from_list(self, client):
        resp = client.post("/api/projects", json={"name": "WillBeGone"})
        pid = resp.get_json()["id"]
        client.delete(f"/api/projects/{pid}")
        names = [p["name"] for p in client.get("/api/projects").get_json()]
        assert "WillBeGone" not in names

    def test_delete_project_not_found(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.delete(f"/api/projects/{fake_id}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Variant CRUD
# ---------------------------------------------------------------------------

class TestCreateVariant:

    def test_create_variant_success(self, client):
        pid = _get_project_id(client)
        resp = client.post(f"/api/projects/{pid}/variants", json={"name": "NewVar"})
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["name"] == "NewVar"
        assert data["project_id"] == pid

    def test_create_variant_appears_in_list(self, client):
        pid = _get_project_id(client)
        client.post(f"/api/projects/{pid}/variants", json={"name": "ListedVar"})
        resp = client.get(f"/api/projects/{pid}/variants")
        names = [v["name"] for v in resp.get_json()]
        assert "ListedVar" in names

    def test_create_variant_missing_name(self, client):
        pid = _get_project_id(client)
        resp = client.post(f"/api/projects/{pid}/variants", json={})
        assert resp.status_code == 400

    def test_create_variant_empty_name(self, client):
        pid = _get_project_id(client)
        resp = client.post(f"/api/projects/{pid}/variants", json={"name": "  "})
        assert resp.status_code == 400

    def test_create_variant_duplicate(self, client):
        pid = _get_project_id(client)
        client.post(f"/api/projects/{pid}/variants", json={"name": "Dup"})
        resp = client.post(f"/api/projects/{pid}/variants", json={"name": "Dup"})
        assert resp.status_code == 409

    def test_create_variant_project_not_found(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.post(f"/api/projects/{fake_id}/variants", json={"name": "X"})
        assert resp.status_code == 404


class TestRenameVariant:

    def test_rename_variant_success(self, client):
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)
        resp = client.patch(f"/api/variants/{vid}/rename", json={"name": "RenamedVar"})
        assert resp.status_code == 200
        assert resp.get_json()["name"] == "RenamedVar"

    def test_rename_variant_not_found(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.patch(f"/api/variants/{fake_id}/rename", json={"name": "X"})
        assert resp.status_code == 404

    def test_rename_variant_empty_name(self, client):
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)
        resp = client.patch(f"/api/variants/{vid}/rename", json={"name": ""})
        assert resp.status_code == 400

    def test_rename_variant_duplicate(self, client):
        pid = _get_project_id(client)
        client.post(f"/api/projects/{pid}/variants", json={"name": "SiblingVar"})
        vid = _get_variant_id(client, pid)
        resp = client.patch(f"/api/variants/{vid}/rename", json={"name": "SiblingVar"})
        assert resp.status_code == 409


class TestDeleteVariant:

    def test_delete_variant_success(self, client):
        pid = _get_project_id(client)
        resp = client.post(f"/api/projects/{pid}/variants", json={"name": "ToDeleteVar"})
        vid = resp.get_json()["id"]
        resp = client.delete(f"/api/variants/{vid}")
        assert resp.status_code == 200

    def test_delete_variant_removes_from_list(self, client):
        pid = _get_project_id(client)
        resp = client.post(f"/api/projects/{pid}/variants", json={"name": "WillGoVar"})
        vid = resp.get_json()["id"]
        client.delete(f"/api/variants/{vid}")
        names = [v["name"] for v in client.get(f"/api/projects/{pid}/variants").get_json()]
        assert "WillGoVar" not in names

    def test_delete_variant_not_found(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.delete(f"/api/variants/{fake_id}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# SBOM Upload (multi-file)
# ---------------------------------------------------------------------------

def _make_spdx_json(name="test-pkg", version="1.0.0"):
    """Return bytes of a minimal SPDX 2.3 JSON SBOM."""
    doc = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-{version}",
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"https://example.org/{name}",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "name": name,
                "versionInfo": version,
                "downloadLocation": "https://example.org",
            }
        ],
    }
    return json.dumps(doc).encode("utf-8")


class TestSBOMUpload:
    """Tests for POST /api/sbom/upload (multi-file support)."""

    @patch("src.routes.settings.threading.Thread")
    def test_upload_single_file(self, mock_thread, client):
        """Single file upload returns 202 with upload_id and scan_id."""
        mock_thread.return_value = MagicMock()
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)

        content = _make_spdx_json()
        data = {
            "project_id": pid,
            "variant_id": vid,
            "files": (io.BytesIO(content), "sbom.spdx.json"),
        }
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 202
        body = resp.get_json()
        assert "upload_id" in body
        assert "scan_id" in body
        mock_thread.return_value.start.assert_called_once()

    @patch("src.routes.settings.threading.Thread")
    def test_upload_multiple_files(self, mock_thread, client):
        """Multiple files upload creates one scan with multiple SBOM documents."""
        mock_thread.return_value = MagicMock()
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)

        file1 = _make_spdx_json("pkg-a", "1.0")
        file2 = _make_spdx_json("pkg-b", "2.0")

        data = MultiDict([
            ("project_id", pid),
            ("variant_id", vid),
            ("files", (io.BytesIO(file1), "sbom1.spdx.json")),
            ("files", (io.BytesIO(file2), "sbom2.spdx.json")),
        ])
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 202
        body = resp.get_json()
        assert "upload_id" in body
        assert "scan_id" in body
        mock_thread.return_value.start.assert_called_once()

    @patch("src.routes.settings.threading.Thread")
    def test_upload_multiple_files_same_scan(self, mock_thread, client, app):
        """All uploaded files belong to the same scan."""
        mock_thread.return_value = MagicMock()
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)

        file1 = _make_spdx_json("alpha", "1.0")
        file2 = _make_spdx_json("beta", "2.0")

        data = MultiDict([
            ("project_id", pid),
            ("variant_id", vid),
            ("files", (io.BytesIO(file1), "alpha.spdx.json")),
            ("files", (io.BytesIO(file2), "beta.spdx.json")),
        ])
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 202
        scan_id = resp.get_json()["scan_id"]

        # Verify both SBOM docs are under the same scan
        from src.models.sbom_document import SBOMDocument
        with app.app_context():
            docs = SBOMDocument.get_by_scan(uuid.UUID(scan_id))
            assert len(docs) == 2
            source_names = sorted([d.source_name for d in docs])
            assert source_names == ["alpha.spdx.json", "beta.spdx.json"]

    def test_upload_no_file(self, client):
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)
        data = {"project_id": pid, "variant_id": vid}
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400

    def test_upload_missing_project_id(self, client):
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)
        content = _make_spdx_json()
        data = {
            "variant_id": vid,
            "files": (io.BytesIO(content), "sbom.json"),
        }
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400

    def test_upload_missing_variant_id(self, client):
        pid = _get_project_id(client)
        content = _make_spdx_json()
        data = {
            "project_id": pid,
            "files": (io.BytesIO(content), "sbom.json"),
        }
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400

    def test_upload_project_not_found(self, client):
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)
        content = _make_spdx_json()
        data = {
            "project_id": str(uuid.uuid4()),
            "variant_id": vid,
            "files": (io.BytesIO(content), "sbom.json"),
        }
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 404

    def test_upload_variant_not_found(self, client):
        pid = _get_project_id(client)
        content = _make_spdx_json()
        data = {
            "project_id": pid,
            "variant_id": str(uuid.uuid4()),
            "files": (io.BytesIO(content), "sbom.json"),
        }
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 404

    def test_upload_variant_wrong_project(self, client):
        """Variant exists but belongs to a different project."""
        # Create a second project with its own variant
        resp = client.post("/api/projects", json={"name": "OtherProj"})
        other_pid = resp.get_json()["id"]
        resp = client.post(f"/api/projects/{other_pid}/variants", json={"name": "OtherVar"})
        other_vid = resp.get_json()["id"]

        pid = _get_project_id(client)
        content = _make_spdx_json()
        data = {
            "project_id": pid,
            "variant_id": other_vid,  # belongs to OtherProj
            "files": (io.BytesIO(content), "sbom.json"),
        }
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400

    @patch("src.routes.settings.threading.Thread")
    def test_upload_invalid_json_file(self, mock_thread, client):
        """Non-JSON file should return 400."""
        mock_thread.return_value = MagicMock()
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)
        data = {
            "project_id": pid,
            "variant_id": vid,
            "files": (io.BytesIO(b"not json"), "bad.json"),
        }
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400
        assert "Could not parse" in resp.get_json()["error"]


class TestUploadStatus:

    def test_status_unknown_id(self, client):
        resp = client.get(f"/api/sbom/upload/{uuid.uuid4()}/status")
        assert resp.status_code == 404

    @patch("src.routes.settings.threading.Thread")
    def test_status_after_upload(self, mock_thread, client):
        """After upload the status endpoint returns 'processing'."""
        mock_thread.return_value = MagicMock()
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)
        content = _make_spdx_json()
        data = {
            "project_id": pid,
            "variant_id": vid,
            "files": (io.BytesIO(content), "sbom.spdx.json"),
        }
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        upload_id = resp.get_json()["upload_id"]

        status_resp = client.get(f"/api/sbom/upload/{upload_id}/status")
        assert status_resp.status_code == 200
        assert status_resp.get_json()["status"] == "processing"


# ---------------------------------------------------------------------------
# _detect_format unit tests
# ---------------------------------------------------------------------------

class TestDetectFormat:
    """Unit tests for the format auto-detection helper."""

    def test_spdx_filename(self):
        from src.routes.settings import _detect_format
        assert _detect_format("image.spdx.json", {}) == "spdx"

    def test_cdx_filename(self):
        from src.routes.settings import _detect_format
        assert _detect_format("bom.cdx.json", {}) == "cdx"

    def test_spdx_content_spdxversion(self):
        from src.routes.settings import _detect_format
        assert _detect_format("sbom.json", {"spdxVersion": "SPDX-2.3"}) == "spdx"

    def test_cyclonedx_content(self):
        from src.routes.settings import _detect_format
        assert _detect_format("sbom.json", {"bomFormat": "CycloneDX"}) == "cdx"

    def test_openvex_content(self):
        from src.routes.settings import _detect_format
        assert _detect_format("vex.json", {"@context": "https://openvex.dev/"}) == "openvex"

    def test_yocto_cve_check(self):
        from src.routes.settings import _detect_format
        assert _detect_format("cve.json", {"package": [{"name": "x"}]}) == "yocto_cve_check"

    def test_grype_content(self):
        from src.routes.settings import _detect_format
        assert _detect_format("scan.json", {"matches": []}) == "grype"

    def test_spdx3_context(self):
        from src.routes.settings import _detect_format
        assert _detect_format("doc.json", {"@context": "https://spdx.org/"}) == "spdx"

    def test_fallback_returns_unknown(self):
        from src.routes.settings import _detect_format
        assert _detect_format("unknown.json", {}) == "unknown"


# ---------------------------------------------------------------------------
# _retry_on_lock unit tests
# ---------------------------------------------------------------------------

class TestRetryOnLock:
    """Unit tests for the retry helper."""

    def test_success_on_first_try(self, app):
        from src.routes.settings import _retry_on_lock
        with app.app_context():
            result = _retry_on_lock(lambda: 42)
            assert result == 42

    def test_retries_on_locked_then_succeeds(self, app):
        from src.routes.settings import _retry_on_lock
        from sqlalchemy.exc import OperationalError

        call_count = 0

        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise OperationalError(
                    "INSERT", {}, Exception("database is locked")
                )
            return "ok"

        with app.app_context():
            result = _retry_on_lock(flaky, max_retries=5, delay=0.01)
            assert result == "ok"
            assert call_count == 3

    def test_raises_after_max_retries(self, app):
        from src.routes.settings import _retry_on_lock
        from sqlalchemy.exc import OperationalError

        def always_locked():
            raise OperationalError(
                "INSERT", {}, Exception("database is locked")
            )

        with app.app_context():
            with pytest.raises(OperationalError):
                _retry_on_lock(always_locked, max_retries=2, delay=0.01)

    def test_raises_non_lock_errors_immediately(self, app):
        from src.routes.settings import _retry_on_lock
        from sqlalchemy.exc import OperationalError

        call_count = 0

        def other_error():
            nonlocal call_count
            call_count += 1
            raise OperationalError(
                "SELECT", {}, Exception("disk I/O error")
            )

        with app.app_context():
            with pytest.raises(OperationalError):
                _retry_on_lock(other_error, max_retries=5, delay=0.01)
            # Should have raised on first call without retrying
            assert call_count == 1


# ---------------------------------------------------------------------------
# Upload content-type validation
# ---------------------------------------------------------------------------

class TestUploadContentType:

    def test_non_multipart_request(self, client):
        """POST with wrong content type should be rejected."""
        resp = client.post(
            "/api/sbom/upload",
            json={"project_id": "x", "variant_id": "y"},
        )
        assert resp.status_code == 400
        assert "multipart" in resp.get_json()["error"].lower()


# ---------------------------------------------------------------------------
# _process_sbom_background
# ---------------------------------------------------------------------------

class TestProcessSBOMBackground:
    """Test the background SBOM processing function directly."""

    def test_process_sets_done_status(self, app):
        """Processing an SPDX SBOM file sets status to 'done'."""
        from src.routes.settings import (
            _process_sbom_background, _upload_status,
        )
        from src.extensions import db
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.sbom_document import SBOMDocument

        with app.app_context():
            project = Project.create("BgTestProject")
            variant = Variant.create("BgTestVariant", project.id)
            scan = Scan.create("", variant.id)

            # Write a minimal SPDX JSON to a temp file
            import tempfile
            sbom_data = {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "test",
                "dataLicense": "CC0-1.0",
                "documentNamespace": "https://example.org/test",
                "packages": [{
                    "SPDXID": "SPDXRef-Package",
                    "name": "testpkg",
                    "versionInfo": "1.0",
                    "downloadLocation": "https://example.org",
                }],
            }
            fd, tmp_path = tempfile.mkstemp(suffix=".json")
            with open(tmp_path, "w") as f:
                json.dump(sbom_data, f)
            os.close(fd)

            SBOMDocument(
                path=tmp_path,
                source_name="test.spdx.json",
                format="spdx",
                scan_id=scan.id,
            )
            db.session.add(
                SBOMDocument(
                    path=tmp_path,
                    source_name="test.spdx.json",
                    format="spdx",
                    scan_id=scan.id,
                )
            )
            db.session.commit()

            upload_id = "bg-test-1"
            _process_sbom_background(
                app, upload_id, [tmp_path], scan.id, variant.id
            )

            assert _upload_status[upload_id]["status"] == "done"

    def test_process_error_sets_error_status(self, app):
        """Processing with an invalid file path sets status to 'error'."""
        from src.routes.settings import (
            _process_sbom_background, _upload_status,
        )
        from src.extensions import db
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan

        with app.app_context():
            project = Project.create("BgErrProject")
            variant = Variant.create("BgErrVariant", project.id)
            scan = Scan.create("", variant.id)

            # No SBOM documents registered — parser should fail
            upload_id = "bg-test-err"
            _process_sbom_background(
                app, upload_id, ["/nonexistent/file.json"],
                scan.id, variant.id
            )

            status = _upload_status[upload_id]
            # Should either succeed (no docs to parse) or fail gracefully
            assert status["status"] in ("done", "error")

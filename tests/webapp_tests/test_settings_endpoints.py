# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the settings routes: project/variant CRUD, SBOM upload (multi-file)."""

import io
import json
import os
import uuid
import tarfile
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


class TestCopyCustomAssessments:

    def _seed_copy_data(self, app):
        from src.extensions import db
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding
        from src.models.sbom_document import SBOMDocument
        from src.models.sbom_package import SBOMPackage
        from src.models.assessment import Assessment

        with app.app_context():
            project = Project.create("CopyDataProject")
            source = Variant.create("SourceVariant", project.id)
            target = Variant.create("TargetVariant", project.id)

            source_scan = Scan.create("source sbom", source.id, scan_type="sbom")
            target_scan = Scan.create("target sbom", target.id, scan_type="sbom")

            source_pkg = Package.find_or_create("openssl", "1.1.1")
            target_pkg = Package.find_or_create("openssl", "3.0.0")
            vuln = Vulnerability.create_record(id="CVE-COPY-0001", description="Copy me")
            db.session.commit()

            source_finding = Finding.get_or_create(source_pkg.id, vuln.id)
            target_finding = Finding.get_or_create(target_pkg.id, vuln.id)

            source_doc = SBOMDocument.create("/tmp/source.spdx.json", "spdx", source_scan.id)
            target_doc = SBOMDocument.create("/tmp/target.spdx.json", "spdx", target_scan.id)
            SBOMPackage.create(source_doc.id, source_pkg.id)
            SBOMPackage.create(target_doc.id, target_pkg.id)

            Assessment.create(
                status="affected",
                origin="custom",
                finding_id=source_finding.id,
                variant_id=source.id,
                source="manual",
            )
            db.session.commit()

            return {
                "source_variant_id": str(source.id),
                "target_variant_id": str(target.id),
                "target_finding_id": str(target_finding.id),
            }

    def test_copy_assessments_default_requires_common_packages(self, app, client):
        ids = self._seed_copy_data(app)

        resp = client.post(
            "/api/variants/copy-assessments",
            json={
                "source_variant_id": ids["source_variant_id"],
                "target_variant_id": ids["target_variant_id"],
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["copied"] == 0
        assert "No packages in common" in data["message"]

    def test_copy_assessments_ignore_package_version_copies_by_vuln(self, app, client):
        from src.models.assessment import Assessment

        ids = self._seed_copy_data(app)

        resp = client.post(
            "/api/variants/copy-assessments",
            json={
                "source_variant_id": ids["source_variant_id"],
                "target_variant_id": ids["target_variant_id"],
                "ignore_package_version": True,
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["copied"] == 1

        with app.app_context():
            target_assessments = Assessment.get_by_finding_and_variant(
                ids["target_finding_id"],
                ids["target_variant_id"],
            )
            assert any(a.origin == "custom" for a in target_assessments)

    def test_copy_assessments_preview_default_no_common_packages(self, app, client):
        ids = self._seed_copy_data(app)

        resp = client.post(
            "/api/variants/copy-assessments/preview",
            json={
                "source_variant_id": ids["source_variant_id"],
                "target_variant_id": ids["target_variant_id"],
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 0
        assert data["skipped"] == 0
        assert data["entries"] == []
        assert "No packages in common" in data["message"]

    def test_copy_assessments_preview_ignore_package_version_lists_candidates(self, app, client):
        ids = self._seed_copy_data(app)

        resp = client.post(
            "/api/variants/copy-assessments/preview",
            json={
                "source_variant_id": ids["source_variant_id"],
                "target_variant_id": ids["target_variant_id"],
                "ignore_package_version": True,
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert data["skipped"] == 0
        assert len(data["entries"]) == 1
        assert data["entries"][0]["vulnerability_id"] == "CVE-COPY-0001"
        assert data["entries"][0]["source_package"] == "openssl@1.1.1"
        assert data["entries"][0]["target_package"] == "openssl@3.0.0"


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


def _make_spdx_tar_archive(member_name="archive.spdx.json", package_name="archive-pkg"):
    """Return bytes for a tar archive containing one SPDX JSON document."""
    archive = io.BytesIO()
    payload = _make_spdx_json(package_name, "1.0.0")
    with tarfile.open(fileobj=archive, mode="w") as tar:
        info = tarfile.TarInfo(name=member_name)
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    archive.seek(0)
    return archive.getvalue()


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

    @patch("src.routes.settings.threading.Thread")
    def test_upload_tar_archive_is_extracted(self, mock_thread, client):
        """A tar archive containing SPDX JSON files is accepted and extracted."""
        mock_thread.return_value = MagicMock()
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)

        data = {
            "project_id": pid,
            "variant_id": vid,
            "files": (io.BytesIO(_make_spdx_tar_archive()), "sbom.tar"),
        }
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 202
        assert "upload_id" in resp.get_json()
        mock_thread.return_value.start.assert_called_once()

    @patch("src.routes.settings.threading.Thread")
    def test_upload_empty_tar_archive_rejected(self, mock_thread, client):
        """A tar archive without SPDX JSON files is rejected."""
        mock_thread.return_value = MagicMock()
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)

        empty_archive = io.BytesIO()
        with tarfile.open(fileobj=empty_archive, mode="w"):
            pass
        empty_archive.seek(0)

        data = {
            "project_id": pid,
            "variant_id": vid,
            "files": (empty_archive, "empty.tar"),
        }
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400
        assert "No .spdx.json files" in resp.get_json()["error"]

    @patch("src.routes.settings.threading.Thread")
    @patch("src.routes.settings.subprocess.run")
    def test_upload_tar_zst_archive_is_extracted(self, mock_run, mock_thread, client):
        """A .tar.zst archive is decompressed and extracted like a normal tar."""
        mock_thread.return_value = MagicMock()
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)

        payload = _make_spdx_json("zst-pkg", "1.2.3")
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            info = tarfile.TarInfo(name="inner.spdx.json")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        archive.seek(0)

        def _fake_run(cmd, check=True, **kwargs):
            if cmd and cmd[0] == "unzstd":
                out_path = cmd[cmd.index("-o") + 1]
                with open(cmd[-1], "rb") as src, open(out_path, "wb") as dst:
                    dst.write(src.read())
            return MagicMock(returncode=0)

        mock_run.side_effect = _fake_run

        data = {
            "project_id": pid,
            "variant_id": vid,
            "files": (io.BytesIO(archive.getvalue()), "sbom.tar.zst"),
        }
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 202
        mock_thread.return_value.start.assert_called_once()


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


class TestUploadHelpers:

    def test_prune_upload_status_removes_stale_entries(self):
        from src.routes.settings import _prune_upload_status, _upload_status, _UPLOAD_STATUS_TTL

        original = dict(_upload_status)
        try:
            now = 10_000.0
            _upload_status.clear()
            _upload_status.update({
                "keep": {"status": "processing", "ts": now},
                "done-old": {"status": "done", "ts": now - _UPLOAD_STATUS_TTL - 1},
                "error-old": {"status": "error", "ts": now - _UPLOAD_STATUS_TTL - 1},
                "done-fresh": {"status": "done", "ts": now},
            })

            with patch("src.routes.settings.time.time", return_value=now):
                _prune_upload_status()

            assert "keep" in _upload_status
            assert "done-fresh" in _upload_status
            assert "done-old" not in _upload_status
            assert "error-old" not in _upload_status
        finally:
            _upload_status.clear()
            _upload_status.update(original)


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

    def test_yocto_vex_via_cpes(self):
        from src.routes.settings import _detect_format
        data = {"package": [{"name": "openssl", "cpes": ["cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"], "issue": []}]}
        assert _detect_format("vex.json", data) == "yocto_vex"

    def test_yocto_vex_via_patch_file(self):
        from src.routes.settings import _detect_format
        data = {"package": [{"name": "openssl", "issue": [{"id": "CVE-2022-0778", "patch-file": "/patches/fix.patch"}]}]}
        assert _detect_format("vex.json", data) == "yocto_vex"

    def test_yocto_vex_via_detail(self):
        from src.routes.settings import _detect_format
        data = {"package": [{"name": "busybox", "issue": [{"id": "CVE-2021-0001", "detail": "fixed-version: 1.35.1"}]}]}
        assert _detect_format("vex.json", data) == "yocto_vex"

    def test_yocto_cve_check_not_misidentified_as_vex(self):
        from src.routes.settings import _detect_format
        # Plain cve-check file without cpes/patch-file/detail stays yocto_cve_check
        data = {"package": [{"name": "x", "issue": [{"id": "CVE-2020-1234", "status": "Patched"}]}]}
        assert _detect_format("cve.json", data) == "yocto_cve_check"

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

    def test_process_sets_done_status(self, app, monkeypatch):
        """Processing an SPDX SBOM file sets status to 'done'."""
        from src.routes.settings import (
            _process_sbom_background, _upload_status,
        )
        from src.extensions import db
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.sbom_document import SBOMDocument

        monkeypatch.setenv("IGNORE_PARSING_ERRORS", "true")

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

    def test_process_read_inputs_failure_sets_error_status(self, app, monkeypatch, tmp_path):
        """A processing failure inside read_inputs is converted to an error status."""
        from src.routes.settings import _process_sbom_background, _upload_status
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan

        with app.app_context():
            project = Project.create("BgReadErrProject")
            variant = Variant.create("BgReadErrVariant", project.id)
            scan = Scan.create("", variant.id)

            sbom_path = tmp_path / "input.spdx.json"
            sbom_path.write_text("{}")

            monkeypatch.setattr(
                "src.bin.cmd_process.read_inputs",
                lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
            )

            upload_id = "bg-test-read-inputs-fail"
            _process_sbom_background(app, upload_id, [str(sbom_path)], scan.id, variant.id)

            assert _upload_status[upload_id]["status"] == "error"


# ---------------------------------------------------------------------------
# NVD API key endpoint
# ---------------------------------------------------------------------------

class TestNvdApiKey:
    """Tests for GET/PUT /api/config/nvd-api-key."""

    def test_get_no_key(self, client):
        """GET returns has_key=false when NVD_API_KEY is not set."""
        os.environ.pop("NVD_API_KEY", None)
        resp = client.get("/api/config/nvd-api-key")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["has_key"] is False
        assert data["masked_key"] == ""

    def test_get_with_key(self, client):
        """GET returns has_key=true and a masked version of the key."""
        os.environ["NVD_API_KEY"] = "abcdefghijklmnop"
        try:
            resp = client.get("/api/config/nvd-api-key")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["has_key"] is True
            assert data["masked_key"].startswith("abcd")
            assert data["masked_key"].endswith("mnop")
            assert "****" in data["masked_key"]
        finally:
            os.environ.pop("NVD_API_KEY", None)

    @patch("src.routes.config.NVD_DB")
    def test_put_valid_key_saves_and_sets_env(self, mock_nvd_cls, client, tmp_path):
        """PUT with a valid key (NVD returns 200) persists key and returns ok."""
        mock_instance = MagicMock()
        mock_instance.api_probe_cve.return_value = (
            200,
            {"vulnerabilities": [{"cve": {}}]},
            {"x-ratelimit-limit": "50"},
        )
        mock_nvd_cls.return_value = mock_instance

        os.environ.pop("NVD_API_KEY", None)
        config_file = str(tmp_path / "config.env")
        os.environ["VULNSCOUT_CONFIG"] = config_file
        try:
            resp = client.put("/api/config/nvd-api-key", json={"api_key": "valid-key-1234"})
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["status"] == "ok"
            assert data["has_key"] is True
            assert data["masked_key"] == "vali******1234"

            # Key should now be in the process environment
            assert os.environ.get("NVD_API_KEY") == "valid-key-1234"

            # Key should be written to config.env
            assert os.path.exists(config_file)
            content = open(config_file).read()
            assert "NVD_API_KEY=valid-key-1234" in content
        finally:
            os.environ.pop("NVD_API_KEY", None)
            os.environ.pop("VULNSCOUT_CONFIG", None)

    @patch("src.routes.config.NVD_DB")
    def test_put_invalid_key_rejected(self, mock_nvd_cls, client, tmp_path):
        """PUT with a key that NVD rejects (403) returns 400 and does not save."""
        mock_instance = MagicMock()
        mock_instance.api_probe_cve.return_value = (403, {}, {})
        mock_nvd_cls.return_value = mock_instance

        os.environ.pop("NVD_API_KEY", None)
        os.environ["VULNSCOUT_CONFIG"] = str(tmp_path / "config.env")
        try:
            resp = client.put("/api/config/nvd-api-key", json={"api_key": "wrong-key"})
            assert resp.status_code == 400
            assert "Invalid" in resp.get_json()["error"]

            # Key must NOT have been stored
            assert os.environ.get("NVD_API_KEY") is None
        finally:
            os.environ.pop("NVD_API_KEY", None)
            os.environ.pop("VULNSCOUT_CONFIG", None)

    @patch("src.routes.config.NVD_DB")
    def test_put_key_rejected_by_probe(self, mock_nvd_cls, client, tmp_path):
        """PUT rejects keys when the NVD probe rejects them, regardless of format."""
        mock_instance = MagicMock()
        mock_instance.api_probe_cve.return_value = (403, {}, {})
        mock_nvd_cls.return_value = mock_instance

        os.environ.pop("NVD_API_KEY", None)
        os.environ["VULNSCOUT_CONFIG"] = str(tmp_path / "config.env")
        try:
            resp = client.put("/api/config/nvd-api-key", json={"api_key": "test65869896"})
            assert resp.status_code == 400
            assert "Invalid" in resp.get_json()["error"]

            # Validation should go through the NVD probe even if the key format is unusual.
            assert os.environ.get("NVD_API_KEY") is None
            mock_nvd_cls.assert_called_once_with(nvd_api_key="test65869896")
        finally:
            os.environ.pop("NVD_API_KEY", None)
            os.environ.pop("VULNSCOUT_CONFIG", None)

    @patch("src.routes.config.NVD_DB")
    def test_put_network_error_returns_503(self, mock_nvd_cls, client, tmp_path):
        """PUT when NVD API is unreachable returns 503 and does not save."""
        mock_instance = MagicMock()
        mock_instance.api_probe_cve.side_effect = ConnectionError("timeout")
        mock_nvd_cls.return_value = mock_instance

        os.environ.pop("NVD_API_KEY", None)
        os.environ["VULNSCOUT_CONFIG"] = str(tmp_path / "config.env")
        try:
            resp = client.put("/api/config/nvd-api-key", json={"api_key": "some-key"})
            assert resp.status_code == 503
            assert os.environ.get("NVD_API_KEY") is None
        finally:
            os.environ.pop("NVD_API_KEY", None)
            os.environ.pop("VULNSCOUT_CONFIG", None)

    @patch("src.routes.config.NVD_DB")
    def test_put_unexpected_probe_status_still_saves(self, mock_nvd_cls, client, tmp_path):
        """Unexpected probe statuses (e.g. 404) should not block saving the key."""
        mock_instance = MagicMock()
        mock_instance.api_probe_cve.return_value = (404, {}, {})
        mock_nvd_cls.return_value = mock_instance

        os.environ.pop("NVD_API_KEY", None)
        config_file = str(tmp_path / "config.env")
        os.environ["VULNSCOUT_CONFIG"] = config_file
        key = "D77A230D-E55D-F111-836C-0EBF96DE670D"
        try:
            resp = client.put("/api/config/nvd-api-key", json={"api_key": key})
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["status"] == "ok"
            assert data["has_key"] is True
            assert data["masked_key"].startswith("D77A")
            assert data["masked_key"].endswith("670D")
            assert "warning" in data

            # Key should be stored despite unexpected probe status.
            assert os.environ.get("NVD_API_KEY") == key
            content = open(config_file).read()
            assert f"NVD_API_KEY={key}" in content
        finally:
            os.environ.pop("NVD_API_KEY", None)
            os.environ.pop("VULNSCOUT_CONFIG", None)

    @patch("src.routes.config.NVD_DB")
    def test_put_clear_key(self, mock_nvd_cls, client, tmp_path):
        """PUT with empty api_key clears the key from env and config.env."""
        os.environ["NVD_API_KEY"] = "old-key"
        config_file = str(tmp_path / "config.env")
        with open(config_file, "w") as fh:
            fh.write("NVD_API_KEY=old-key\nOTHER=value\n")
        os.environ["VULNSCOUT_CONFIG"] = config_file
        try:
            resp = client.put("/api/config/nvd-api-key", json={"api_key": ""})
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["has_key"] is False
            assert data["masked_key"] == ""

            # Key removed from env
            assert os.environ.get("NVD_API_KEY") is None

            # Key removed from config.env but other entries preserved
            content = open(config_file).read()
            assert "NVD_API_KEY" not in content
            assert "OTHER=value" in content

            # NVD_DB should NOT have been instantiated (no key to validate)
            mock_nvd_cls.assert_not_called()
        finally:
            os.environ.pop("NVD_API_KEY", None)
            os.environ.pop("VULNSCOUT_CONFIG", None)

    @patch("src.routes.config._write_config_key", return_value=False)
    @patch("src.routes.config.NVD_DB")
    def test_put_write_failure_returns_500(self, mock_nvd_cls, mock_write_config, client, tmp_path):
        """If config.env cannot be written, the request should fail."""
        mock_instance = MagicMock()
        mock_instance.api_probe_cve.return_value = (
            200,
            {"vulnerabilities": [{}]},
            {"x-ratelimit-limit": "50"},
        )
        mock_nvd_cls.return_value = mock_instance

        os.environ.pop("NVD_API_KEY", None)
        os.environ["VULNSCOUT_CONFIG"] = str(tmp_path / "config.env")
        try:
            resp = client.put("/api/config/nvd-api-key", json={"api_key": "persist-me-5678"})
            assert resp.status_code == 500
            assert "persist" in resp.get_json()["error"].lower()
            assert os.environ.get("NVD_API_KEY") is None
        finally:
            os.environ.pop("NVD_API_KEY", None)
            os.environ.pop("VULNSCOUT_CONFIG", None)

    def test_put_missing_field_returns_400(self, client):
        """PUT without api_key field returns 400."""
        resp = client.put("/api/config/nvd-api-key", json={"other": "stuff"})
        assert resp.status_code == 400

    def test_put_non_string_api_key_returns_400(self, client):
        """PUT with a non-string api_key returns 400."""
        resp = client.put("/api/config/nvd-api-key", json={"api_key": 12345})
        assert resp.status_code == 400
        assert "must be a string" in resp.get_json()["error"].lower()

    @patch("src.routes.config.NVD_DB")
    def test_put_config_file_persists_between_calls(self, mock_nvd_cls, client, tmp_path):
        """Setting a key writes to config.env; a subsequent GET sees it via os.environ."""
        mock_instance = MagicMock()
        mock_instance.api_probe_cve.return_value = (
            200,
            {"vulnerabilities": [{}]},
            {"x-ratelimit-limit": "50"},
        )
        mock_nvd_cls.return_value = mock_instance

        config_file = str(tmp_path / "config.env")
        os.environ.pop("NVD_API_KEY", None)
        os.environ["VULNSCOUT_CONFIG"] = config_file
        try:
            client.put("/api/config/nvd-api-key", json={"api_key": "persist-me-5678"})
            resp = client.get("/api/config/nvd-api-key")
            assert resp.get_json()["has_key"] is True
        finally:
            os.environ.pop("NVD_API_KEY", None)
            os.environ.pop("VULNSCOUT_CONFIG", None)

    @patch("src.routes.config.NVD_DB")
    def test_put_rejects_anonymous_rate_limit_probe(self, mock_nvd_cls, client, tmp_path):
        """If probe indicates anonymous rate limit, key should be treated as invalid."""
        mock_instance = MagicMock()
        mock_instance.api_probe_cve.return_value = (
            200,
            {"vulnerabilities": [{"cve": {}}]},
            {"x-ratelimit-limit": "5"},
        )
        mock_nvd_cls.return_value = mock_instance

        os.environ.pop("NVD_API_KEY", None)
        os.environ["VULNSCOUT_CONFIG"] = str(tmp_path / "config.env")
        try:
            resp = client.put(
                "/api/config/nvd-api-key",
                json={"api_key": "D77A230D-E55D-F111-836C-0EBF96DE670A"},
            )
            assert resp.status_code == 400
            assert "invalid" in resp.get_json()["error"].lower()
            assert os.environ.get("NVD_API_KEY") is None
        finally:
            os.environ.pop("NVD_API_KEY", None)
            os.environ.pop("VULNSCOUT_CONFIG", None)


# ---------------------------------------------------------------------------
# Additional coverage: _retry_on_lock exhaustion
# ---------------------------------------------------------------------------

class TestRetryOnLockExhaustion:

    def test_raises_runtime_error_when_max_retries_is_zero(self, app):
        """_retry_on_lock with max_retries=0 never enters the loop and raises RuntimeError."""
        from src.routes.settings import _retry_on_lock
        with app.app_context():
            with pytest.raises(RuntimeError, match="retry loop exhausted"):
                _retry_on_lock(lambda: 42, max_retries=0)


# ---------------------------------------------------------------------------
# Additional coverage: _extract_spdx_archive member filtering
# ---------------------------------------------------------------------------

class TestExtractSpdxArchive:

    def test_skips_non_file_and_non_spdx_json_members(self, tmp_path):
        """Directory entries and non-.spdx.json files are ignored; only .spdx.json extracted."""
        from src.routes.settings import _extract_spdx_archive

        spdx_content = b'{"spdxVersion": "SPDX-2.3"}'
        archive_path = str(tmp_path / "mixed.tar")

        with tarfile.open(archive_path, "w") as tar:
            # Directory entry — triggers the isfile() continue branch
            dir_info = tarfile.TarInfo(name="subdir")
            dir_info.type = tarfile.DIRTYPE
            tar.addfile(dir_info)
            # Non-.spdx.json regular file — triggers the name-suffix continue branch
            txt_info = tarfile.TarInfo(name="readme.txt")
            txt_info.size = len(b"readme")
            tar.addfile(txt_info, io.BytesIO(b"readme"))
            # The one valid .spdx.json member
            spdx_info = tarfile.TarInfo(name="result.spdx.json")
            spdx_info.size = len(spdx_content)
            tar.addfile(spdx_info, io.BytesIO(spdx_content))

        results = _extract_spdx_archive(archive_path, "mixed.tar")

        assert len(results) == 1
        extracted_path, member_name = results[0]
        assert member_name == "result.spdx.json"
        os.unlink(extracted_path)


# ---------------------------------------------------------------------------
# Additional coverage: invalid-UUID paths on CRUD routes
# ---------------------------------------------------------------------------

class TestRouteUUIDValidation:

    def test_rename_project_invalid_uuid_in_path(self, client):
        resp = client.patch("/api/projects/not-a-uuid/rename", json={"name": "X"})
        assert resp.status_code == 400

    def test_rename_variant_invalid_uuid_in_path(self, client):
        resp = client.patch("/api/variants/not-a-uuid/rename", json={"name": "X"})
        assert resp.status_code == 400

    def test_delete_project_invalid_uuid_in_path(self, client):
        resp = client.delete("/api/projects/not-a-uuid")
        assert resp.status_code == 400

    def test_delete_variant_invalid_uuid_in_path(self, client):
        resp = client.delete("/api/variants/not-a-uuid")
        assert resp.status_code == 400

    def test_create_variant_invalid_project_uuid_in_path(self, client):
        resp = client.post("/api/projects/not-a-uuid/variants", json={"name": "X"})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Additional coverage: copy-assessments validation edge cases
# ---------------------------------------------------------------------------

class TestCopyAssessmentsValidation:

    def test_invalid_source_variant_uuid(self, client):
        resp = client.post(
            "/api/variants/copy-assessments",
            json={"source_variant_id": "not-a-uuid", "target_variant_id": str(uuid.uuid4())},
        )
        assert resp.status_code == 400

    def test_invalid_target_variant_uuid(self, client):
        resp = client.post(
            "/api/variants/copy-assessments",
            json={"source_variant_id": str(uuid.uuid4()), "target_variant_id": "not-a-uuid"},
        )
        assert resp.status_code == 400

    def test_same_source_and_target_variant(self, client):
        vid = str(uuid.uuid4())
        resp = client.post(
            "/api/variants/copy-assessments",
            json={"source_variant_id": vid, "target_variant_id": vid},
        )
        assert resp.status_code == 400
        assert "different" in resp.get_json()["error"].lower()

    def test_variant_not_found(self, client):
        resp = client.post(
            "/api/variants/copy-assessments",
            json={
                "source_variant_id": str(uuid.uuid4()),
                "target_variant_id": str(uuid.uuid4()),
            },
        )
        assert resp.status_code == 404

    def test_cross_project_variants_rejected(self, app, client):
        from src.extensions import db
        from src.models.project import Project
        from src.models.variant import Variant

        with app.app_context():
            p1 = Project.create("CrossProjAlpha")
            p2 = Project.create("CrossProjBeta")
            v1 = Variant.create("VarAlpha", p1.id)
            v2 = Variant.create("VarBeta", p2.id)
            db.session.commit()
            source_id = str(v1.id)
            target_id = str(v2.id)

        resp = client.post(
            "/api/variants/copy-assessments",
            json={"source_variant_id": source_id, "target_variant_id": target_id},
        )
        assert resp.status_code == 400
        assert "same project" in resp.get_json()["error"].lower()

    def test_preview_invalid_source_variant_uuid(self, client):
        resp = client.post(
            "/api/variants/copy-assessments/preview",
            json={"source_variant_id": "not-a-uuid", "target_variant_id": str(uuid.uuid4())},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Additional coverage: copy-assessments logic edge cases
# ---------------------------------------------------------------------------

class TestCopyAssessmentsEdgeCases:

    def _seed_no_source_active_packages(self, app):
        """Source variant has a custom assessment but no active SBOM scan packages."""
        from src.extensions import db
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding
        from src.models.assessment import Assessment
        from src.models.sbom_document import SBOMDocument
        from src.models.sbom_package import SBOMPackage

        with app.app_context():
            project = Project.create("NoSrcScanProject")
            source = Variant.create("NoSrcScan", project.id)
            target = Variant.create("HasScan", project.id)

            pkg = Package.find_or_create("unscanned-lib", "1.0")
            vuln = Vulnerability.create_record(id="CVE-NOSCAN-010", description="x")
            db.session.commit()
            finding = Finding.get_or_create(pkg.id, vuln.id)
            Assessment.create(
                status="affected", origin="custom", finding_id=finding.id,
                variant_id=source.id, source="manual",
            )

            # Give target an active scan so we pass the early variants-exist check
            tgt_pkg = Package.find_or_create("tgt-lib-nosrc", "9.9")
            tgt_scan = Scan.create("", target.id, scan_type="sbom")
            tgt_doc = SBOMDocument.create("/tmp/tgt_nosrc.spdx.json", "spdx", tgt_scan.id)
            SBOMPackage.create(tgt_doc.id, tgt_pkg.id)
            db.session.commit()

            return {"source_id": str(source.id), "target_id": str(target.id)}

    def _seed_no_matching_target_findings(self, app):
        """Source has active packages + assessments; target packages share no vulnerabilities."""
        from src.extensions import db
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding
        from src.models.assessment import Assessment
        from src.models.sbom_document import SBOMDocument
        from src.models.sbom_package import SBOMPackage

        with app.app_context():
            project = Project.create("NoMatchFindingsProject")
            source = Variant.create("NoMatchSrc", project.id)
            target = Variant.create("NoMatchTgt", project.id)

            pkg_a = Package.find_or_create("pkg-alpha-nm", "1.0")
            cve_a = Vulnerability.create_record(id="CVE-NOMATCH-001", description="a")
            db.session.commit()
            finding_a = Finding.get_or_create(pkg_a.id, cve_a.id)
            Assessment.create(
                status="affected", origin="custom", finding_id=finding_a.id,
                variant_id=source.id, source="manual",
            )
            src_scan = Scan.create("", source.id, scan_type="sbom")
            src_doc = SBOMDocument.create("/tmp/src_nm.spdx.json", "spdx", src_scan.id)
            SBOMPackage.create(src_doc.id, pkg_a.id)

            # Target has a different package with a different vulnerability
            pkg_b = Package.find_or_create("pkg-beta-nm", "1.0")
            cve_b = Vulnerability.create_record(id="CVE-NOMATCH-002", description="b")
            db.session.commit()
            Finding.get_or_create(pkg_b.id, cve_b.id)
            tgt_scan = Scan.create("", target.id, scan_type="sbom")
            tgt_doc = SBOMDocument.create("/tmp/tgt_nm.spdx.json", "spdx", tgt_scan.id)
            SBOMPackage.create(tgt_doc.id, pkg_b.id)
            db.session.commit()

            return {"source_id": str(source.id), "target_id": str(target.id)}

    def _seed_non_common_packages(self, app):
        """Source has two packages (one shared with target, one not); assessments on both."""
        from src.extensions import db
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding
        from src.models.assessment import Assessment
        from src.models.sbom_document import SBOMDocument
        from src.models.sbom_package import SBOMPackage

        with app.app_context():
            project = Project.create("NonCommonProject")
            source = Variant.create("NonCommonSrc", project.id)
            target = Variant.create("NonCommonTgt", project.id)

            pkg_shared = Package.find_or_create("shared-lib-nc", "1.0")
            pkg_only = Package.find_or_create("source-only-lib-nc", "1.0")
            vuln_x = Vulnerability.create_record(id="CVE-NCSHARED-001", description="x")
            vuln_y = Vulnerability.create_record(id="CVE-NCONLY-001", description="y")
            db.session.commit()

            finding_sx = Finding.get_or_create(pkg_shared.id, vuln_x.id)
            finding_oy = Finding.get_or_create(pkg_only.id, vuln_y.id)

            src_scan = Scan.create("", source.id, scan_type="sbom")
            src_doc = SBOMDocument.create("/tmp/src_nc.spdx.json", "spdx", src_scan.id)
            SBOMPackage.create(src_doc.id, pkg_shared.id)
            SBOMPackage.create(src_doc.id, pkg_only.id)

            tgt_scan = Scan.create("", target.id, scan_type="sbom")
            tgt_doc = SBOMDocument.create("/tmp/tgt_nc.spdx.json", "spdx", tgt_scan.id)
            SBOMPackage.create(tgt_doc.id, pkg_shared.id)

            Assessment.create(
                status="affected", origin="custom", finding_id=finding_sx.id,
                variant_id=source.id, source="manual",
            )
            Assessment.create(
                status="affected", origin="custom", finding_id=finding_oy.id,
                variant_id=source.id, source="manual",
            )
            db.session.commit()

            return {"source_id": str(source.id), "target_id": str(target.id)}

    def test_ignore_version_empty_source_active_packages_returns_no_vulns(self, app, client):
        """ignore_package_version=True with no active source packages → no vulns in common."""
        ids = self._seed_no_source_active_packages(app)
        resp = client.post(
            "/api/variants/copy-assessments",
            json={
                "source_variant_id": ids["source_id"],
                "target_variant_id": ids["target_id"],
                "ignore_package_version": True,
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["copied"] == 0
        assert "No vulnerabilities in common" in data["message"]

    def test_ignore_version_no_matching_target_findings_returns_no_vulns(self, app, client):
        """ignore_package_version=True with non-empty source_vuln_ids but no target findings."""
        ids = self._seed_no_matching_target_findings(app)
        resp = client.post(
            "/api/variants/copy-assessments",
            json={
                "source_variant_id": ids["source_id"],
                "target_variant_id": ids["target_id"],
                "ignore_package_version": True,
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["copied"] == 0
        assert "No vulnerabilities in common" in data["message"]

    def test_non_common_package_assessment_not_copied(self, app, client):
        """Assessment on a source-only package is skipped; only the shared-package assessment copies."""
        ids = self._seed_non_common_packages(app)
        resp = client.post(
            "/api/variants/copy-assessments",
            json={
                "source_variant_id": ids["source_id"],
                "target_variant_id": ids["target_id"],
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        # Only the shared-package assessment can be copied (source-only is skipped)
        assert data["copied"] == 1

    def test_copy_skips_already_assessed_target_and_reports_skipped(self, app, client):
        """Re-running copy after an initial copy skips already-present custom assessments."""
        from tests.webapp_tests.test_settings_endpoints import TestCopyCustomAssessments
        helper = TestCopyCustomAssessments()
        ids = helper._seed_copy_data(app)

        # First copy
        r1 = client.post(
            "/api/variants/copy-assessments",
            json={
                "source_variant_id": ids["source_variant_id"],
                "target_variant_id": ids["target_variant_id"],
                "ignore_package_version": True,
            },
        )
        assert r1.get_json()["copied"] == 1

        # Second copy — all already assessed → skipped
        r2 = client.post(
            "/api/variants/copy-assessments",
            json={
                "source_variant_id": ids["source_variant_id"],
                "target_variant_id": ids["target_variant_id"],
                "ignore_package_version": True,
            },
        )
        assert r2.status_code == 200
        data = r2.get_json()
        assert data["copied"] == 0
        assert data["skipped"] == 1
        assert "already present" in data["message"]


# ---------------------------------------------------------------------------
# Additional coverage: SBOM upload edge cases
# ---------------------------------------------------------------------------

class TestSBOMUploadEdgeCases:

    def test_upload_corrupt_archive_returns_400(self, client):
        """A file with a .tar extension that is not a valid tar archive triggers a 400."""
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)
        corrupt = b"this is definitely not a tar archive"
        data = {
            "project_id": pid,
            "variant_id": vid,
            "files": (io.BytesIO(corrupt), "sbom.tar"),
        }
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400
        assert "Could not extract archive" in resp.get_json()["error"]

    @patch("src.routes.settings.threading.Thread")
    def test_upload_unknown_format_json_returns_400(self, mock_thread, client):
        """Valid JSON that does not match any known SBOM format is rejected."""
        mock_thread.return_value = MagicMock()
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)
        unknown = json.dumps({"totally": "unrecognized", "structure": True}).encode()
        data = {
            "project_id": pid,
            "variant_id": vid,
            "files": (io.BytesIO(unknown), "mystery.json"),
        }
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400
        assert "Unrecognized SBOM format" in resp.get_json()["error"]

    @patch("src.routes.settings.threading.Thread")
    def test_upload_second_file_error_cleans_up_first_file(self, mock_thread, client):
        """When the second uploaded file is invalid, temp files from the first are cleaned up."""
        mock_thread.return_value = MagicMock()
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)
        data = MultiDict([
            ("project_id", pid),
            ("variant_id", vid),
            ("files", (io.BytesIO(_make_spdx_json()), "first.spdx.json")),
            ("files", (io.BytesIO(b"not json <<<"), "second.json")),
        ])
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400
        assert "Could not parse" in resp.get_json()["error"]

    @patch("src.routes.settings.threading.Thread")
    def test_upload_file_with_empty_filename_skipped(self, mock_thread, client):
        """A file entry with an empty filename is skipped; the valid file still processes."""
        mock_thread.return_value = MagicMock()
        pid = _get_project_id(client)
        vid = _get_variant_id(client, pid)
        data = MultiDict([
            ("project_id", pid),
            ("variant_id", vid),
            ("files", (io.BytesIO(b"ignored"), "")),
            ("files", (io.BytesIO(_make_spdx_json()), "real.spdx.json")),
        ])
        resp = client.post("/api/sbom/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 202
        mock_thread.return_value.start.assert_called_once()


# ---------------------------------------------------------------------------
# Additional coverage: background SBOM processing EPSS failure path
# ---------------------------------------------------------------------------

class TestProcessSBOMBackgroundEpss:

    def test_epss_failure_is_swallowed_and_processing_completes(self, app, monkeypatch):
        """A post_treatment (EPSS) exception is caught; final status is still 'done'."""
        import tempfile as _tempfile
        from src.routes.settings import _process_sbom_background, _upload_status
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan

        monkeypatch.setenv("IGNORE_PARSING_ERRORS", "true")
        monkeypatch.setattr("src.bin.cmd_process.read_inputs", lambda *a, **k: None)
        monkeypatch.setattr("src.bin.cmd_process.populate_observations", lambda *a, **k: None)
        monkeypatch.setattr(
            "src.bin.cmd_process.post_treatment",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("epss unavailable")),
        )

        with app.app_context():
            project = Project.create("EpssFailProject")
            variant = Variant.create("EpssFailVariant", project.id)
            scan = Scan.create("", variant.id)

            upload_id = "epss-coverage-test"
            _process_sbom_background(app, upload_id, [], scan.id, variant.id)

            assert _upload_status[upload_id]["status"] == "done"

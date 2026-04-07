# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the review-specific assessment endpoints:
- GET  /api/assessments/review
- GET  /api/assessments/review/export
- POST /api/assessments/review/import
"""

import io
import json
import tarfile
import uuid

import pytest

from src.bin.webapp import create_app
from . import write_demo_files, setup_demo_db

VARIANT_UUID = "22222222-2222-2222-2222-222222222222"
PROJECT_UUID = "11111111-1111-1111-1111-111111111111"


# ── fixtures ──────────────────────────────────────────────────────────────

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
    import os
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": init_files["status"],
            "OPENVEX_FILE": str(init_files["openvex"]),
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        setup_demo_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


def _create_handmade_assessment(client, vuln_id="CVE-2020-35492",
                                packages=None, status="affected",
                                variant_id=VARIANT_UUID, **extra):
    """Helper – create a custom assessment via POST."""
    payload = {
        "packages": packages or ["cairo@1.16.0"],
        "status": status,
        "variant_id": variant_id,
    }
    payload.update(extra)
    resp = client.post(
        f"/api/vulnerabilities/{vuln_id}/assessments",
        json=payload,
    )
    return resp


# ── GET /api/assessments/review ──────────────────────────────────────────

def test_review_list_empty(client):
    """No handmade assessments yet → empty list."""
    resp = client.get("/api/assessments/review")
    assert resp.status_code == 200
    assert json.loads(resp.data) == []


def test_review_list_after_create(client):
    """After creating a custom assessment it appears in the review list."""
    _create_handmade_assessment(client)
    resp = client.get("/api/assessments/review")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1


def test_review_list_by_variant(client):
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review?variant_id={VARIANT_UUID}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1


def test_review_list_by_variant_invalid(client):
    resp = client.get("/api/assessments/review?variant_id=not-a-uuid")
    assert resp.status_code == 400


def test_review_list_by_project(client):
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review?project_id={PROJECT_UUID}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1


def test_review_list_by_project_invalid(client):
    resp = client.get("/api/assessments/review?project_id=bad")
    assert resp.status_code == 400


def test_review_list_by_project_no_variants(client):
    """Project with no variants → empty list."""
    fake_project = str(uuid.uuid4())
    resp = client.get(f"/api/assessments/review?project_id={fake_project}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data == []


# ── GET /api/assessments (project_id path) ───────────────────────────────

def test_assessments_list_by_project(client):
    resp = client.get(f"/api/assessments?project_id={PROJECT_UUID}")
    assert resp.status_code == 200


def test_assessments_list_by_project_invalid(client):
    resp = client.get("/api/assessments?project_id=xxx")
    assert resp.status_code == 400


# ── GET /api/assessments/review/export ───────────────────────────────────

def test_export_empty(client):
    """No handmade assessments → 404."""
    resp = client.get("/api/assessments/review/export")
    assert resp.status_code == 404


def test_export_tar_gz(client):
    _create_handmade_assessment(client)
    resp = client.get("/api/assessments/review/export")
    assert resp.status_code == 200
    assert resp.content_type == "application/gzip"
    buf = io.BytesIO(resp.data)
    with tarfile.open(fileobj=buf, mode="r:gz") as tar:
        members = tar.getmembers()
        assert len(members) >= 1
        # Each member should be a valid OpenVEX JSON
        for m in members:
            assert m.name.endswith(".json")
            f = tar.extractfile(m)
            doc = json.load(f)
            assert "openvex" in doc.get("@context", "")
            assert isinstance(doc.get("statements"), list)
            for stmt in doc["statements"]:
                assert "vulnerability" in stmt
                assert "products" in stmt
                assert "status" in stmt


def test_export_contains_variant_name(client):
    _create_handmade_assessment(client)
    resp = client.get("/api/assessments/review/export")
    buf = io.BytesIO(resp.data)
    with tarfile.open(fileobj=buf, mode="r:gz") as tar:
        names = [m.name for m in tar.getmembers()]
        # The demo variant is named "default"
        assert "default.json" in names


def test_export_enriched_fields(client):
    """Exported statements should have enriched vulnerability and product fields."""
    _create_handmade_assessment(client)
    resp = client.get("/api/assessments/review/export")
    buf = io.BytesIO(resp.data)
    with tarfile.open(fileobj=buf, mode="r:gz") as tar:
        for m in tar.getmembers():
            doc = json.load(tar.extractfile(m))
            for stmt in doc["statements"]:
                vuln = stmt["vulnerability"]
                assert "name" in vuln
                assert "description" in vuln
                assert "aliases" in vuln
                for prod in stmt["products"]:
                    assert "identifiers" in prod
                assert "scanners" in stmt


# ── POST /api/assessments/review/import ──────────────────────────────────

def _make_openvex_json(variant_name, statements):
    """Build a minimal OpenVEX JSON document."""
    return json.dumps({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.com/test",
        "author": "test",
        "timestamp": "2025-01-01T00:00:00Z",
        "version": 1,
        "statements": statements,
    }).encode("utf-8")


def _make_tar_gz(files_dict):
    """Build a tar.gz archive from {filename: bytes} dict."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files_dict.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf


def test_import_no_file(client):
    resp = client.post("/api/assessments/review/import",
                       content_type="multipart/form-data")
    assert resp.status_code == 400


def test_import_json_valid(client):
    """Import a single .json named after the demo variant."""
    statements = [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "products": [{"@id": "cairo@1.16.0"}],
        "status": "affected",
        "status_notes": "test import",
        "justification": "",
        "impact_statement": "",
        "action_statement": "",
    }]
    data = _make_openvex_json("default", statements)
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["status"] == "success"
    assert result["imported"] >= 1


def test_import_json_unknown_variant(client):
    data = _make_openvex_json("unknown_variant", [])
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "unknown_variant.json")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert "variant" in json.loads(resp.data)["error"].lower()


def test_import_json_invalid_json(client):
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(b"not json"), "default.json")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_import_json_not_openvex(client):
    data = json.dumps({"foo": "bar"}).encode()
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert "openvex" in json.loads(resp.data)["error"].lower()


def test_import_tar_gz_valid(client):
    """Import a tar.gz with one file named after the demo variant."""
    statements = [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "products": [{"@id": "cairo@1.16.0"}],
        "status": "not_affected",
        "justification": "component_not_present",
        "impact_statement": "not present",
        "status_notes": "",
        "action_statement": "",
    }]
    content = _make_openvex_json("default", statements)
    tar_buf = _make_tar_gz({"default.json": content})
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (tar_buf, "review.tar.gz")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["status"] == "success"
    assert result["imported"] >= 1


def test_import_tar_gz_unknown_variant(client):
    """Archive with a .json not matching any variant → error."""
    content = _make_openvex_json("nonexistent", [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "products": [{"@id": "cairo@1.16.0"}],
        "status": "affected",
    }])
    tar_buf = _make_tar_gz({"nonexistent.json": content})
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (tar_buf, "review.tar.gz")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_import_tar_gz_invalid_archive(client):
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(b"notatar"), "bad.tar.gz")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_import_tar_gz_invalid_json_inside(client):
    tar_buf = _make_tar_gz({"default.json": b"not json"})
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (tar_buf, "review.tar.gz")},
        content_type="multipart/form-data",
    )
    # The bad JSON is reported as error but request succeeds if no valid files
    assert resp.status_code in (200, 400)


def test_import_tar_gz_not_openvex_inside(client):
    content = json.dumps({"not": "openvex"}).encode()
    tar_buf = _make_tar_gz({"default.json": content})
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (tar_buf, "review.tar.gz")},
        content_type="multipart/form-data",
    )
    assert resp.status_code in (200, 400)


def test_import_unsupported_file_type(client):
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(b"data"), "review.xml")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert "unsupported" in json.loads(resp.data)["error"].lower()


def test_import_not_multipart(client):
    resp = client.post(
        "/api/assessments/review/import",
        json={"statements": []},
    )
    assert resp.status_code == 400


def test_import_duplicate_skipped(client):
    """Importing the same data twice should skip duplicates."""
    statements = [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "products": [{"@id": "cairo@1.16.0"}],
        "status": "affected",
        "status_notes": "",
        "justification": "",
        "impact_statement": "",
        "action_statement": "",
    }]
    data = _make_openvex_json("default", statements)
    # First import
    resp1 = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json")},
        content_type="multipart/form-data",
    )
    assert resp1.status_code == 200
    r1 = json.loads(resp1.data)
    assert r1["imported"] >= 1

    # Second import — same data
    resp2 = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json")},
        content_type="multipart/form-data",
    )
    assert resp2.status_code == 200
    r2 = json.loads(resp2.data)
    assert r2["skipped"] >= 1
    assert r2["imported"] == 0


def test_import_statement_missing_vuln(client):
    """Statement without vulnerability name → error."""
    statements = [{
        "vulnerability": {},
        "products": [{"@id": "cairo@1.16.0"}],
        "status": "affected",
    }]
    data = _make_openvex_json("default", statements)
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["imported"] == 0


def test_import_statement_missing_status(client):
    statements = [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "products": [{"@id": "cairo@1.16.0"}],
    }]
    data = _make_openvex_json("default", statements)
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["imported"] == 0


def test_import_statement_missing_products(client):
    statements = [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "status": "affected",
    }]
    data = _make_openvex_json("default", statements)
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["imported"] == 0


def test_import_product_string_format(client):
    """Products can also be plain strings instead of dicts."""
    statements = [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "products": ["cairo@1.16.0"],
        "status": "affected",
        "status_notes": "",
        "justification": "",
        "impact_statement": "",
        "action_statement": "",
    }]
    data = _make_openvex_json("default", statements)
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["imported"] >= 1


def test_import_product_without_version(client):
    """Package without @ separator should still work."""
    statements = [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "products": [{"@id": "somepkg"}],
        "status": "affected",
        "status_notes": "",
        "justification": "",
        "impact_statement": "",
        "action_statement": "",
    }]
    data = _make_openvex_json("default", statements)
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["imported"] >= 1


# ── round-trip: export then import ───────────────────────────────────────

def test_export_import_round_trip(client):
    """Export Review → Import Review should be a valid round-trip."""
    _create_handmade_assessment(client, status="affected")
    # Export
    export_resp = client.get("/api/assessments/review/export")
    assert export_resp.status_code == 200
    # Import the exported file back
    import_resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(export_resp.data), "review.tar.gz")},
        content_type="multipart/form-data",
    )
    assert import_resp.status_code == 200
    result = json.loads(import_resp.data)
    assert result["status"] == "success"

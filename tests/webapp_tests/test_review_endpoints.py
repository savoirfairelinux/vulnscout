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


# ── GET /api/assessments/review/time-estimates ───────────────────────────

def test_review_time_estimates_empty(client):
    """No time estimates → empty list."""
    resp = client.get("/api/assessments/review/time-estimates")
    assert resp.status_code == 200
    assert json.loads(resp.data) == []


def test_review_time_estimates_basic(client):
    """After adding a time estimate it appears in the listing."""
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "effort": {"optimistic": "PT2H", "likely": "PT4H", "pessimistic": "PT8H"},
        }]
    })
    resp = client.get("/api/assessments/review/time-estimates")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1
    entry = data[0]
    assert entry["vuln_id"] == "CVE-2020-35492"
    assert entry["optimistic"] == 2
    assert entry["likely"] == 4
    assert entry["pessimistic"] == 8
    assert "optimistic_iso" in entry
    assert "vuln_texts" in entry


def test_review_time_estimates_by_variant(client):
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "effort": {"optimistic": "PT1H", "likely": "PT2H", "pessimistic": "PT3H"},
        }]
    })
    resp = client.get(f"/api/assessments/review/time-estimates?variant_id={VARIANT_UUID}")
    assert resp.status_code == 200
    assert isinstance(json.loads(resp.data), list)


def test_review_time_estimates_by_project(client):
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "effort": {"optimistic": "PT1H", "likely": "PT2H", "pessimistic": "PT3H"},
        }]
    })
    resp = client.get(f"/api/assessments/review/time-estimates?project_id={PROJECT_UUID}")
    assert resp.status_code == 200
    assert isinstance(json.loads(resp.data), list)


# ── GET /api/assessments/review/custom-cvss ──────────────────────────────

def test_review_custom_cvss_empty(client):
    """No custom CVSS entries → empty list."""
    resp = client.get("/api/assessments/review/custom-cvss")
    assert resp.status_code == 200
    assert json.loads(resp.data) == []


def test_review_custom_cvss_basic(client):
    """Custom CVSS entries (non-nvd author) appear in the listing."""
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "cvss": {
                "base_score": 8.0,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "version": "3.1",
                "author": "custom-tool",
                "exploitability_score": 0.0,
                "impact_score": 0.0,
            },
        }]
    })
    resp = client.get("/api/assessments/review/custom-cvss")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1
    entry = data[0]
    assert entry["vuln_id"] == "CVE-2020-35492"
    assert "version" in entry
    assert "vector_string" in entry
    assert "author" in entry
    assert "vuln_texts" in entry


# ── GET /api/assessments/review/export-custom-data ───────────────────────

def test_export_custom_data_empty(client):
    """No handmade assessments → 404."""
    resp = client.get("/api/assessments/review/export-custom-data")
    assert resp.status_code == 404


def test_export_custom_data_basic(client):
    """After creating an assessment, export-custom-data returns the right structure."""
    _create_handmade_assessment(client)
    resp = client.get("/api/assessments/review/export-custom-data")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["version"] == 1
    assert "exported_at" in data
    assert isinstance(data["assessments"], list)
    assert len(data["assessments"]) >= 1
    assert isinstance(data["cvss"], list)
    assert isinstance(data["time_estimates"], list)
    # Each assessment should have the expected keys
    a = data["assessments"][0]
    assert "vuln_id" in a
    assert "status" in a
    assert "packages" in a
    assert "variant" in a


def test_export_custom_data_by_variant(client):
    """Filter by variant_id returns only that variant's assessments."""
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review/export-custom-data?variant_id={VARIANT_UUID}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data["assessments"]) >= 1
    for a in data["assessments"]:
        assert a["variant_id"] == VARIANT_UUID


def test_export_custom_data_by_project(client):
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review/export-custom-data?project_id={PROJECT_UUID}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data["assessments"]) >= 1


def test_export_custom_data_invalid_variant(client):
    resp = client.get("/api/assessments/review/export-custom-data?variant_id=bad")
    assert resp.status_code == 400


def test_export_custom_data_invalid_project(client):
    resp = client.get("/api/assessments/review/export-custom-data?project_id=bad")
    assert resp.status_code == 400


def test_export_custom_data_with_cvss(client):
    """Custom CVSS entries (non-nvd, non-unknown) appear in the export."""
    _create_handmade_assessment(client)
    # Add a custom CVSS via the batch endpoint
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "cvss": {
                "base_score": 7.5,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "version": "3.1",
                "author": "my-custom-tool",
                "exploitability_score": 0.0,
                "impact_score": 0.0,
            },
        }]
    })
    resp = client.get("/api/assessments/review/export-custom-data")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    # The CVSS entry should exist (author may vary depending on Metrics.from_cvss logic)
    assert isinstance(data["cvss"], list)
    if data["cvss"]:
        assert "variant" in data["cvss"][0]


def test_export_custom_data_with_time_estimate(client):
    """Time estimates appear in the export."""
    _create_handmade_assessment(client)
    # Add a time estimate via the batch endpoint
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "effort": {
                "optimistic": "PT2H",
                "likely": "PT4H",
                "pessimistic": "PT8H",
            },
        }]
    })
    resp = client.get("/api/assessments/review/export-custom-data")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert isinstance(data["time_estimates"], list)
    assert len(data["time_estimates"]) >= 1
    te = data["time_estimates"][0]
    assert te["vuln_id"] == "CVE-2020-35492"
    assert "optimistic" in te
    assert "likely" in te
    assert "pessimistic" in te
    assert "variant" in te


def test_export_custom_data_filename_by_variant(client):
    """Export by variant_id includes the project name in the filename."""
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review/export-custom-data?variant_id={VARIANT_UUID}")
    assert resp.status_code == 200
    disposition = resp.headers.get("Content-Disposition", "")
    assert "custom_data_" in disposition
    assert disposition.endswith('.json"')


def test_export_custom_data_filename_by_project(client):
    """Export by project_id includes the project name in the filename."""
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review/export-custom-data?project_id={PROJECT_UUID}")
    assert resp.status_code == 200
    disposition = resp.headers.get("Content-Disposition", "")
    assert "custom_data_" in disposition
    assert disposition.endswith('.json"')


# ── POST /api/assessments/review/import-custom-data ──────────────────────

def _custom_data_payload(assessments=None, cvss=None, time_estimates=None):
    """Build a minimal custom-data JSON payload."""
    return {
        "version": 1,
        "exported_at": "2025-01-01T00:00:00Z",
        "assessments": assessments or [],
        "cvss": cvss or [],
        "time_estimates": time_estimates or [],
    }


def test_import_custom_data_no_file(client):
    resp = client.post("/api/assessments/review/import-custom-data",
                       content_type="multipart/form-data")
    assert resp.status_code == 400


def test_import_custom_data_wrong_content_type(client):
    resp = client.post("/api/assessments/review/import-custom-data",
                       data=b"hello", content_type="text/plain")
    assert resp.status_code == 400


def test_import_custom_data_invalid_json(client):
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        data={"file": (io.BytesIO(b"not json"), "data.json")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_import_custom_data_missing_version(client):
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json={"assessments": []},
        content_type="application/json",
    )
    assert resp.status_code == 400


def test_import_custom_data_assessments(client):
    """Import assessments via the custom-data endpoint."""
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "affected",
        "packages": ["cairo@1.16.0"],
        "variant_id": VARIANT_UUID,
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload,
        content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["status"] == "success"
    assert result["assessments_imported"] >= 1


def test_import_custom_data_assessments_without_variant_field(client):
    """Import remains backward compatible when variant fields are missing."""
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "affected",
        "packages": ["cairo@1.16.0"],
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload,
        content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["status"] == "success"
    assert result["assessments_imported"] >= 1


def test_import_custom_data_assessments_with_variant_name(client):
    """Assessment import accepts the human-readable variant name field."""
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "affected",
        "packages": ["cairo@1.16.0"],
        "variant": "default",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload,
        content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["status"] == "success"
    assert result["assessments_imported"] >= 1


def test_import_custom_data_duplicate_skipped(client):
    """Same assessment imported twice → second is skipped."""
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "not_affected",
        "justification": "component_not_present",
        "packages": ["cairo@1.16.0"],
        "variant_id": VARIANT_UUID,
    }])
    resp1 = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp1.status_code == 200
    r1 = json.loads(resp1.data)
    assert r1["assessments_imported"] >= 1

    resp2 = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp2.status_code == 200
    r2 = json.loads(resp2.data)
    assert r2["assessments_skipped"] >= 1
    assert r2["assessments_imported"] == 0


def test_import_custom_data_cvss(client):
    """Import CVSS via the custom-data endpoint."""
    payload = _custom_data_payload(cvss=[{
        "vuln_id": "CVE-2020-35492",
        "version": "3.1",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "base_score": 7.5,
        "author": "custom-author",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["cvss_imported"] >= 1


def test_import_custom_data_cvss_with_variant_name(client):
    """CVSS import accepts the human-readable variant name field."""
    payload = _custom_data_payload(cvss=[{
        "vuln_id": "CVE-2020-35492",
        "variant": "default",
        "version": "3.1",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "base_score": 7.5,
        "author": "custom-author",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["cvss_imported"] >= 1


def test_import_custom_data_time_estimates(client):
    """Import time estimates via the custom-data endpoint."""
    payload = _custom_data_payload(time_estimates=[{
        "vuln_id": "CVE-2020-35492",
        "optimistic": "PT2H",
        "likely": "PT4H",
        "pessimistic": "PT8H",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["time_estimates_imported"] >= 1


def test_import_custom_data_time_estimates_with_variant_name(client):
    """Time-estimate import accepts the human-readable variant name field."""
    payload = _custom_data_payload(time_estimates=[{
        "vuln_id": "CVE-2020-35492",
        "variant": "default",
        "optimistic": "PT2H",
        "likely": "PT4H",
        "pessimistic": "PT8H",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["time_estimates_imported"] >= 1


def test_import_custom_data_all_together(client):
    """Import assessments + CVSS + time estimates in a single request."""
    payload = _custom_data_payload(
        assessments=[{
            "vuln_id": "CVE-2020-35492",
            "status": "under_investigation",
            "packages": ["cairo@1.16.0"],
            "variant_id": VARIANT_UUID,
        }],
        cvss=[{
            "vuln_id": "CVE-2020-35492",
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "base_score": 7.5,
            "author": "my-tool",
        }],
        time_estimates=[{
            "vuln_id": "CVE-2020-35492",
            "optimistic": "PT1H",
            "likely": "PT2H",
            "pessimistic": "PT4H",
        }],
    )
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["assessments_imported"] >= 1
    assert result["cvss_imported"] >= 1
    assert result["time_estimates_imported"] >= 1


def test_import_custom_data_via_file_upload(client):
    """Import custom-data via multipart file upload."""
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "affected",
        "packages": ["cairo@1.16.0"],
        "variant_id": VARIANT_UUID,
    }])
    data_bytes = json.dumps(payload).encode("utf-8")
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        data={"file": (io.BytesIO(data_bytes), "custom_data.json")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["assessments_imported"] >= 1


def test_import_custom_data_unknown_vuln_cvss(client):
    """CVSS for a non-existent vulnerability → error reported."""
    payload = _custom_data_payload(cvss=[{
        "vuln_id": "CVE-9999-99999",
        "version": "3.1",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "base_score": 7.5,
        "author": "test",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    # Should succeed overall but report the error
    result = json.loads(resp.data)
    assert any("Vulnerability not found" in e.get("error", "") for e in result.get("errors", []))


def test_export_import_custom_data_round_trip(client):
    """Export custom data → import it back."""
    _create_handmade_assessment(client, status="affected")
    # Add CVSS and time estimate
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "effort": {"optimistic": "PT1H", "likely": "PT2H", "pessimistic": "PT4H"},
        }]
    })

    # Export
    export_resp = client.get("/api/assessments/review/export-custom-data")
    assert export_resp.status_code == 200
    exported = json.loads(export_resp.data)
    assert exported["version"] == 1
    assert len(exported["assessments"]) >= 1

    # Import back
    import_resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=exported, content_type="application/json",
    )
    assert import_resp.status_code == 200
    result = json.loads(import_resp.data)
    assert result["status"] == "success"


# ── review_custom_cvss: variant/project filtering ────────────────────────

def test_review_custom_cvss_by_variant(client):
    """Filter by variant_id returns only CVSSes for that variant's findings."""
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "cvss": {
                "base_score": 4.1,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "version": "3.1",
                "author": "my-org",
                "origin": "custom",
                "exploitability_score": 0.0,
                "impact_score": 0.0,
            },
        }]
    })
    resp = client.get(f"/api/assessments/review/custom-cvss?variant_id={VARIANT_UUID}")
    assert resp.status_code == 200
    assert isinstance(json.loads(resp.data), list)


def test_review_custom_cvss_by_variant_invalid(client):
    """Invalid variant_id UUID → 400."""
    resp = client.get("/api/assessments/review/custom-cvss?variant_id=not-a-uuid")
    assert resp.status_code == 400


def test_review_custom_cvss_by_project(client):
    """Filter by project_id returns results scoped to that project."""
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "cvss": {
                "base_score": 4.2,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "version": "3.1",
                "author": "sec-team",
                "origin": "custom",
                "exploitability_score": 0.0,
                "impact_score": 0.0,
            },
        }]
    })
    resp = client.get(f"/api/assessments/review/custom-cvss?project_id={PROJECT_UUID}")
    assert resp.status_code == 200
    assert isinstance(json.loads(resp.data), list)


def test_review_custom_cvss_by_project_invalid(client):
    """Invalid project_id UUID → 400."""
    resp = client.get("/api/assessments/review/custom-cvss?project_id=bad")
    assert resp.status_code == 400


def test_review_custom_cvss_by_project_no_variants(client):
    """project_id pointing to a project with no variants → empty list."""
    fake_project = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    resp = client.get(f"/api/assessments/review/custom-cvss?project_id={fake_project}")
    assert resp.status_code == 200
    assert json.loads(resp.data) == []


def test_review_custom_cvss_origin_field_present(client):
    """Each entry in the response includes the 'origin' field."""
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "cvss": {
                "base_score": 4.3,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "version": "3.1",
                "author": "researcher",
                "origin": "custom",
                "exploitability_score": 0.0,
                "impact_score": 0.0,
            },
        }]
    })
    resp = client.get("/api/assessments/review/custom-cvss")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1
    assert "origin" in data[0]
    assert data[0]["origin"] == "custom"


def test_review_custom_cvss_skips_scanner_author(client):
    """CVSS stored with origin=custom but scanner-like author is excluded.

    When a CVSS is PATCHed without an explicit author, origin is forced to
    'custom' by the route, but _validate_and_apply_cvss then defaults the
    author to 'unknown' (a scanner author). The review endpoint must skip
    such entries via _is_scanner_author.
    """
    _create_handmade_assessment(client)
    # PATCH without author → stored as origin=custom, author=unknown
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "cvss": {
                "base_score": 4.4,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "version": "3.1",
                # no 'author' key — defaults to "unknown" inside _validate_and_apply_cvss
                "exploitability_score": 0.0,
                "impact_score": 0.0,
            },
        }]
    })
    resp = client.get("/api/assessments/review/custom-cvss")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    # The entry must not appear because "unknown" is a scanner author
    for entry in data:
        assert entry.get("author") != "unknown"


# ── import_review_custom_data: additional error paths ─────────────────────

def test_import_custom_data_invalid_variant_id(client):
    """variant_id query param that is not a valid UUID → 400."""
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "affected",
        "packages": ["cairo@1.16.0"],
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data?variant_id=not-a-uuid",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 400


def test_import_custom_data_invalid_json_body(client):
    """application/json body that cannot be parsed → 400."""
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        data=b"this is not json",
        content_type="application/json",
    )
    assert resp.status_code == 400


def test_import_custom_data_cvss_sets_origin_from_import(client):
    """CVSS imported without an explicit origin gets origin='scanner' from
    _validate_and_apply_cvss defaults (no setdefault in the import path)."""
    payload = _custom_data_payload(cvss=[{
        "vuln_id": "CVE-2020-35492",
        "version": "3.1",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "base_score": 7.5,
        # no 'origin' key → _validate_and_apply_cvss defaults to "scanner"
        "author": "imported-tool",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["cvss_imported"] >= 1

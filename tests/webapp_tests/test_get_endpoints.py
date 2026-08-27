# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import io
import json
import os
import time
import zipfile
from src.bin.webapp import create_app
from . import write_demo_files, setup_demo_db


def _make_png_bytes() -> bytes:
    """Return the raw bytes of a genuine, tiny, valid 1x1 PNG image."""
    from io import BytesIO
    from PIL import Image
    buf = BytesIO()
    Image.new("RGB", (1, 1), color=(255, 0, 0)).save(buf, format="PNG")
    return buf.getvalue()


def _make_jpeg_bytes() -> bytes:
    """Return the raw bytes of a genuine, tiny, valid 1x1 JPEG image."""
    from io import BytesIO
    from PIL import Image
    buf = BytesIO()
    Image.new("RGB", (1, 1), color=(0, 255, 0)).save(buf, format="JPEG")
    return buf.getvalue()


@pytest.fixture()
def init_files(tmp_path):
    files = {
        "status": tmp_path / "status.txt",
        "packages": tmp_path / "packages-merged.json",
        "vulnerabilities": tmp_path / "vulnerabilities-merged.json",
        "assessments": tmp_path / "assessments-merged.json",
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
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db"
        })
        setup_demo_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)

    # clean up / reset resources here
    # tmp_file are automatically deleted by pytest


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()


@pytest.fixture()
def demo_ids(app):
    from src.extensions import db
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.scan import Scan
    from src.models.variant import Variant
    import uuid as uuid_module

    with app.app_context():
        vuln_id = "CVE-1999-12345"
        other_vuln_id = "CVE-1999-99999"
        for vid in (vuln_id, other_vuln_id):
            if Vulnerability.get_by_id(vid) is None:
                Vulnerability.create_record(id=vid)

        pkg_a = Package.find_or_create("cairo", "1.16.0")
        pkg_b = Package.find_or_create("libpng", "1.6.37")
        db.session.commit()

        variant_id = uuid_module.UUID("22222222-2222-2222-2222-222222222222")
        other_variant = Variant(
            id=uuid_module.uuid4(), name="other",
            project_id=uuid_module.UUID("11111111-1111-1111-1111-111111111111"))
        db.session.add(other_variant)
        db.session.commit()

        existing_scan_id = uuid_module.UUID("33333333-3333-3333-3333-333333333333")
        other_scan = Scan(id=uuid_module.uuid4(), variant_id=other_variant.id)
        db.session.add(other_scan)
        db.session.commit()

        for vid in (vuln_id, other_vuln_id):
            for pkg in (pkg_a, pkg_b):
                finding = Finding.get_or_create(pkg.id, vid)
                db.session.add(Observation(finding_id=finding.id, scan_id=existing_scan_id))
                db.session.add(Observation(finding_id=finding.id, scan_id=other_scan.id))
        db.session.commit()

        return {
            "vuln_id": vuln_id,
            "other_vuln_id": other_vuln_id,
            "variant_id": str(variant_id),
            "other_variant_id": str(other_variant.id),
            "two_packages": [pkg_a.string_id, pkg_b.string_id],
        }


def test_get_status(client):
    response = client.get("/api/scan/status")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "done"
    assert isinstance(data["maxsteps"], int)
    assert data["step"] == data["maxsteps"]
    assert "complete" in data["message"]


def test_get_packages_list(client):
    response = client.get("/api/packages?format=list")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert data[0]["name"] == "cairo"
    assert data[0]["version"] == "1.16.0"
    assert len(data[0]["cpe"]) == 4
    assert "sbom_documents" in data[0]
    assert "grype.json" in data[0]["sbom_documents"]


def test_get_packages_dict(client):
    response = client.get("/api/packages?format=dict")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert "cairo@1.16.0" in data
    assert data["cairo@1.16.0"]["name"] == "cairo"
    assert data["cairo@1.16.0"]["version"] == "1.16.0"
    assert len(data["cairo@1.16.0"]["cpe"]) == 4
    assert "sbom_documents" in data["cairo@1.16.0"]
    assert "grype.json" in data["cairo@1.16.0"]["sbom_documents"]


def test_get_vulnerabilities_list(client):
    response = client.get("/api/vulnerabilities?format=list")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert data[0]["id"] == "CVE-2020-35492"
    assert data[0]["severity"]["severity"] == "high"
    assert "cairo@1.16.0" in data[0]["packages"]
    # found_by must be populated from the SBOM chain (grype doc in setup_demo_db)
    assert "grype" in data[0]["found_by"]
    assert data[0]["texts"] == [
        {
            "title": "description",
            "content": "A flaw was found in cairo's image-compositor.c in all versions prior to 1.17.4 [...]"
        },
        {
            "title": "yocto",
            "content": "Some Yocto description",
            "packages": ["cairo"]
        }
    ]


def test_get_vulnerabilities_compact_defers_modal_details(client):
    response = client.get("/api/vulnerabilities?format=compact")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1

    vuln = data[0]
    assert vuln["id"] == "CVE-2020-35492"
    assert vuln["details_loaded"] is False
    assert "texts" not in vuln
    assert "urls" not in vuln
    assert vuln["severity"]["severity"] == "high"
    for cvss in vuln["severity"]["cvss"]:
        assert set(cvss) == {"version", "base_score", "attack_vector"}


def test_search_vulnerability_descriptions(client):
    response = client.post(
        "/api/vulnerabilities/search-descriptions",
        json={
            "vulnerability_ids": ["CVE-2020-35492"],
            "terms": ["IMAGE-COMPOSITOR", "yocto", "missing"],
        },
    )
    assert response.status_code == 200
    assert response.get_json() == {
        "matches": {
            "image-compositor": ["CVE-2020-35492"],
            "yocto": ["CVE-2020-35492"],
            "missing": [],
        }
    }


def test_search_vulnerability_descriptions_validates_payload(client):
    response = client.post(
        "/api/vulnerabilities/search-descriptions",
        json={"vulnerability_ids": "CVE-2020-35492", "terms": ["cairo"]},
    )
    assert response.status_code == 400


def test_get_vulnerabilities_dict(client):
    response = client.get("/api/vulnerabilities?format=dict")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert "CVE-2020-35492" in data
    assert data["CVE-2020-35492"]["severity"]["severity"] == "high"
    assert "cairo@1.16.0" in data["CVE-2020-35492"]["packages"]


def test_get_vulnerability_by_id(client):
    response = client.get("/api/vulnerabilities/CVE-2020-35492")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == "CVE-2020-35492"
    assert data["severity"]["severity"] == "high"
    assert "cairo@1.16.0" in data["packages"]
    assert "urls" in data
    for cvss in data["severity"]["cvss"]:
        assert "vector_string" in cvss
        assert "author" in cvss
    assert data["texts"] == [
        {
            "title": "description",
            "content": "A flaw was found in cairo's image-compositor.c in all versions prior to 1.17.4 [...]"
        },
        {
            "title": "yocto",
            "content": "Some Yocto description",
            "packages": ["cairo"]
        }
    ]

    response = client.get("/api/vulnerabilities/CVE-0000-00000")
    assert response.status_code == 404


def test_get_assessments_dict(app, client):
    import uuid
    from src.extensions import db
    from src.models.assessment_target import AssessmentTarget

    seed_id = "da4d18f0-d89e-4d54-819d-86fc884cc737"
    demo_variant_id = "22222222-2222-2222-2222-222222222222"
    with app.app_context():
        # The seed assessment has no scalar variant_id (it predates variant
        # tracking); attach it to the demo variant here so it has a target
        # row and is reachable through the listing routes, which now read
        # targets exclusively from assessment_targets.
        from src.models.assessment import Assessment
        seed = Assessment.get_by_id(seed_id)
        db.session.add(AssessmentTarget(
            assessment_id=seed.id, variant_id=uuid.UUID(demo_variant_id), finding_id=seed.finding_id))
        db.session.commit()

    response = client.get("/api/assessments?format=dict")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert "da4d18f0-d89e-4d54-819d-86fc884cc737" in data
    assert data["da4d18f0-d89e-4d54-819d-86fc884cc737"]["vuln_id"] == "CVE-2020-35492"
    assert data["da4d18f0-d89e-4d54-819d-86fc884cc737"]["status"] == "fixed"
    assert "cairo@1.16.0" in data["da4d18f0-d89e-4d54-819d-86fc884cc737"]["packages"]
    assert data["da4d18f0-d89e-4d54-819d-86fc884cc737"]["impact_statement"] == "Yocto reported vulnerability as Patched"


def test_get_assessments_compact(app, client):
    import uuid
    from src.extensions import db
    from src.models.assessment_target import AssessmentTarget

    demo_variant_id = "22222222-2222-2222-2222-222222222222"
    with app.app_context():
        # See test_get_assessments_dict: the seed assessment needs a target
        # row to be reachable through the listing routes.
        from src.models.assessment import Assessment
        seed = Assessment.get_by_id("da4d18f0-d89e-4d54-819d-86fc884cc737")
        db.session.add(AssessmentTarget(
            assessment_id=seed.id, variant_id=uuid.UUID(demo_variant_id), finding_id=seed.finding_id))
        db.session.commit()

    response = client.get("/api/assessments?format=compact")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assessment = data[0]
    assert assessment[0] == "da4d18f0-d89e-4d54-819d-86fc884cc737"
    assert assessment[1] == "CVE-2020-35492"
    assert assessment[2] == "cairo@1.16.0"
    assert assessment[3] == demo_variant_id
    assert isinstance(assessment[4], str)
    assert assessment[5] == "fixed"
    assert len(assessment) == 6


def test_compact_listing_returns_every_custom_assessment(app, client):
    """Three custom assessments on distinct packages must all appear.

    Regression test for impact finding 1.1: with NULL scalar
    ``variant_id``/``finding_id`` columns, SQLite's ``PARTITION BY`` treats
    NULLs as equal, collapsing every custom assessment into one partition so
    only the top-ranked row survived. This passes today (the scalar columns
    are still dual-written) and must keep passing once Task 11 drops them,
    since the ranking now partitions on the joined ``assessment_targets``
    columns, which are never NULL.
    """
    import uuid
    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability

    vuln_id = "CVE-2026-3000"
    with app.app_context():
        project = Project.create(f"CompactListingProj-{uuid.uuid4()}")
        variant = Variant.create("default", project.id)
        Vulnerability.create_record(id=vuln_id)
        for name in ("openssl", "zlib", "curl"):
            pkg = Package.create(name=name, version="1.0.0")
            finding = Finding.create(package_id=pkg.id, vulnerability_id=vuln_id)
            Assessment.create(
                status="not_affected", origin="custom",
                finding_id=finding.id, variant_id=variant.id,
                commit=True,
            )

    response = client.get("/api/assessments?format=compact")
    assert response.status_code == 200
    data = json.loads(response.data)
    packages = {row[2] for row in data if row[1] == vuln_id}
    assert packages == {"openssl@1.0.0", "zlib@1.0.0", "curl@1.0.0"}


def test_full_and_list_formats_show_one_row_per_multi_target_assessment(app, client):
    """A multi-target (reconciled) assessment must appear exactly once in
    both ``format=list`` and ``format=dict`` — never once per target and
    never dropped from the ``dict`` keyed-by-id view.

    Regression test for impact finding 2: the full/list branch joins
    ``assessment_targets`` the same way the compact branch does, but its
    consumers (``format=dict`` keys by assessment id, ``format=list`` is
    consumed positionally) expect one row per assessment, unlike compact
    which is intentionally one row per target.
    """
    import uuid
    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability

    vuln_id = "CVE-2026-4000"
    with app.app_context():
        project = Project.create(f"MultiTargetProj-{uuid.uuid4()}")
        variant_a = Variant.create("a", project.id)
        variant_b = Variant.create("b", project.id)
        Vulnerability.create_record(id=vuln_id)
        pkg = Package.create(name="openssl", version="1.0.0")
        finding = Finding.create(package_id=pkg.id, vulnerability_id=vuln_id)
        assessment = Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant_a.id, finding.id), (variant_b.id, finding.id)],
            commit=True,
        )
        assessment_id = str(assessment.id)
        variant_a_id, variant_b_id = str(variant_a.id), str(variant_b.id)

    list_response = client.get("/api/assessments?format=list")
    assert list_response.status_code == 200
    list_data = json.loads(list_response.data)
    matching = [a for a in list_data if a["id"] == assessment_id]
    assert len(matching) == 1, "the assessment must not appear once per target"

    dict_response = client.get("/api/assessments?format=dict")
    assert dict_response.status_code == 200
    dict_data = json.loads(dict_response.data)
    assert assessment_id in dict_data, "the assessment must not be dropped from the dict view"
    assert len([k for k in dict_data if k == assessment_id]) == 1

    # The variant filter must still find the assessment through either target.
    for vid in (variant_a_id, variant_b_id):
        filtered = client.get(f"/api/assessments?format=list&variant_id={vid}")
        assert filtered.status_code == 200
        filtered_data = json.loads(filtered.data)
        matches = [a for a in filtered_data if a["id"] == assessment_id]
        assert len(matches) == 1, f"variant {vid} must select the assessment exactly once"


def test_get_assessment_by_id(client):
    response = client.get("/api/assessments/da4d18f0-d89e-4d54-819d-86fc884cc737")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == "da4d18f0-d89e-4d54-819d-86fc884cc737"
    assert data["vuln_id"] == "CVE-2020-35492"
    assert data["status"] == "fixed"

    response = client.get("/api/assessments/00-0-0-0-000")
    assert response.status_code == 404


def test_get_assessments_by_vuln(client):
    response = client.get("/api/vulnerabilities/CVE-2020-35492/assessments")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert data[0]["id"] == "da4d18f0-d89e-4d54-819d-86fc884cc737"
    assert data[0]["vuln_id"] == "CVE-2020-35492"
    assert data[0]["status"] == "fixed"

    response = client.get("/api/vulnerabilities/CVE-2020-35492/assessments?format=dict")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["da4d18f0-d89e-4d54-819d-86fc884cc737"]["vuln_id"] == "CVE-2020-35492"

    response = client.get("/api/vulnerabilities/CVE-0000-00000/assessments")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 0


def test_get_documents_list(client):
    response = client.get("/api/documents")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) >= 1
    summary_item = filter(lambda x: x["id"] == "summary.adoc", data).__next__() or None
    assert summary_item
    assert summary_item["is_template"] is True
    assert "built-in" in summary_item["category"]


def test_render_document_adoc(client):
    response = client.get("/api/documents/summary.adoc")
    assert response.status_code == 200
    content = response.data.decode("utf-8")
    assert "Vulnerabilities Report" in content
    assert "| Fixed\n^.^| 0\n^.^| 1\n" in content


@pytest.mark.parametrize(
    ("mode", "expected_name"),
    [
        ("consolidated", "summary.adoc"),
        ("per_variant", "default/summary.adoc"),
    ],
)
def test_export_documents_archive(client, mode, expected_name):
    response = client.post("/api/documents/export", json={
        "project_id": "11111111-1111-1111-1111-111111111111",
        "mode": mode,
        "documents": [{"name": "summary.adoc", "extension": "adoc"}],
    })

    assert response.status_code == 200
    assert response.mimetype == "application/zip"
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.namelist() == [expected_name]
        assert b"Vulnerabilities Report" in archive.read(expected_name)


def test_export_documents_archive_selected_variants(app, client):
    import uuid
    from src.models.variant import Variant

    with app.app_context():
        Variant.create("secondary", uuid.UUID("11111111-1111-1111-1111-111111111111"))

    response = client.post("/api/documents/export", json={
        "project_id": "11111111-1111-1111-1111-111111111111",
        "variant_ids": ["22222222-2222-2222-2222-222222222222"],
        "mode": "per_variant",
        "documents": [{"name": "summary.adoc", "extension": "adoc"}],
    })

    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.namelist() == ["default/summary.adoc"]


def test_export_documents_disambiguates_colliding_archive_paths(app, client):
    import uuid
    from src.models.variant import Variant

    with app.app_context():
        Variant.create("default!", uuid.UUID("11111111-1111-1111-1111-111111111111"))

    response = client.post("/api/documents/export", json={
        "project_id": "11111111-1111-1111-1111-111111111111",
        "mode": "per_variant",
        "documents": [{"name": "summary.adoc", "extension": "adoc"}],
    })

    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.namelist() == ["default/summary.adoc", "default/summary_2.adoc"]


def test_export_documents_async_progress_and_download(client):
    response = client.post("/api/documents/export", json={
        "project_id": "11111111-1111-1111-1111-111111111111",
        "mode": "consolidated",
        "async": True,
        "documents": [{"name": "summary.adoc", "extension": "adoc"}],
    })

    assert response.status_code == 202
    job_id = response.get_json()["job_id"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status = client.get(f"/api/documents/export/{job_id}").get_json()
        if status["status"] != "running":
            break
        time.sleep(0.01)

    assert status["status"] == "done"
    assert status["current"] == status["total"] == 1
    assert status["logs"] == ["Generating 1 of 1 element: summary.adoc (adoc)"]

    from src.routes.documents import _export_jobs, _export_jobs_lock
    with _export_jobs_lock:
        archive_path = str(_export_jobs[job_id]["archive_path"])
    assert os.path.isfile(archive_path)

    download = client.get(f"/api/documents/export/{job_id}/download")
    assert download.status_code == 200
    assert download.mimetype == "application/zip"
    with zipfile.ZipFile(io.BytesIO(download.data)) as archive:
        assert archive.namelist() == ["summary.adoc"]
    assert not os.path.exists(archive_path)
    assert client.get(f"/api/documents/export/{job_id}").status_code == 404


def test_export_documents_rejects_when_async_queue_is_full(client):
    from src.routes.documents import EXPORT_MAX_QUEUED_JOBS, EXPORT_MAX_WORKERS, _export_capacity

    capacity = EXPORT_MAX_WORKERS + EXPORT_MAX_QUEUED_JOBS
    for _ in range(capacity):
        assert _export_capacity.acquire(blocking=False)
    try:
        response = client.post("/api/documents/export", json={
            "project_id": "11111111-1111-1111-1111-111111111111",
            "mode": "consolidated",
            "async": True,
            "documents": [{"name": "summary.adoc", "extension": "adoc"}],
        })
    finally:
        for _ in range(capacity):
            _export_capacity.release()

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"
    assert response.get_json() == {"error": "Export queue is full; retry later"}


def test_export_documents_rejects_when_sync_capacity_is_full(client):
    from src.routes.documents import EXPORT_MAX_WORKERS, _sync_export_capacity

    for _ in range(EXPORT_MAX_WORKERS):
        assert _sync_export_capacity.acquire(blocking=False)
    try:
        response = client.post("/api/documents/export", json={
            "project_id": "11111111-1111-1111-1111-111111111111",
            "mode": "consolidated",
            "documents": [{"name": "summary.adoc", "extension": "adoc"}],
        })
    finally:
        for _ in range(EXPORT_MAX_WORKERS):
            _sync_export_capacity.release()

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"


def test_export_retention_evicts_oldest_archive(monkeypatch, tmp_path):
    from src.routes import documents

    old_archive = tmp_path / "old.zip"
    old_archive.write_bytes(b"1234")
    job_id = "retention-test-job"
    with documents._export_jobs_lock:
        documents._export_jobs[job_id] = {
            "archive_path": str(old_archive),
            "finished_at": 1.0,
        }
        monkeypatch.setattr(documents, "EXPORT_MAX_RETAINED_ARCHIVE_BYTES", 5)
        documents._reserve_retained_archive(3)

    assert job_id not in documents._export_jobs
    assert not old_archive.exists()


def test_export_missing_tool_does_not_disclose_server_path(monkeypatch, client):
    def missing_tool(*_args, **_kwargs):
        raise FileNotFoundError(2, "missing", "/private/server/bin/converter")

    monkeypatch.setattr("src.routes.documents._build_export_archive", missing_tool)
    response = client.post("/api/documents/export", json={
        "project_id": "11111111-1111-1111-1111-111111111111",
        "mode": "consolidated",
        "documents": [{"name": "summary.adoc", "extension": "pdf"}],
    })

    assert response.status_code == 503
    assert response.get_json() == {"error": "Required conversion tool was not found"}
    assert "/private/server" not in response.get_data(as_text=True)


def test_export_documents_rejects_assets(monkeypatch, client):
    monkeypatch.setattr("src.routes.documents.list_assets", lambda: [
        {"id": "logo.png", "extension": "png", "is_template": False, "category": ["assets"]},
    ])

    response = client.post("/api/documents/export", json={
        "project_id": "11111111-1111-1111-1111-111111111111",
        "mode": "consolidated",
        "documents": [{"name": "logo.png", "extension": "png"}],
    })

    assert response.status_code == 400
    assert response.get_json()["error"] == "Unsupported document selection: logo.png (png)"


def test_export_documents_rejects_consolidated_sbom(client):
    response = client.post("/api/documents/export", json={
        "project_id": "11111111-1111-1111-1111-111111111111",
        "variant_ids": ["22222222-2222-2222-2222-222222222222"],
        "mode": "consolidated",
        "documents": [{"name": "CycloneDX 1.6", "extension": "json"}],
    })

    assert response.status_code == 400
    assert response.get_json()["error"] == "SBOM files must be exported per variant as a ZIP archive"


def test_export_documents_archive_multiple_sboms(client):
    response = client.post("/api/documents/export", json={
        "project_id": "11111111-1111-1111-1111-111111111111",
        "variant_ids": ["22222222-2222-2222-2222-222222222222"],
        "mode": "per_variant",
        "documents": [
            {"name": "SPDX 2.3", "extension": "json"},
            {"name": "SPDX 2.3", "extension": "xml"},
            {"name": "SPDX 3.0", "extension": "json"},
            {"name": "CycloneDX 1.4", "extension": "json"},
            {"name": "CycloneDX 1.5", "extension": "json"},
            {"name": "CycloneDX 1.6", "extension": "json"},
            {"name": "OpenVex", "extension": "json"},
        ],
    })

    assert response.status_code == 200
    assert response.mimetype == "application/zip"
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.namelist() == [
            "default/spdx_v2_3.json",
            "default/spdx_v2_3.xml",
            "default/spdx_v3_0.json",
            "default/cyclonedx_v1_4.json",
            "default/cyclonedx_v1_5.json",
            "default/cyclonedx_v1_6.json",
            "default/openvex.json",
        ]


def test_render_document_with_options(client):
    response = client.get("/api/documents/all_assessments.adoc?" + '&'.join([
        "author=AUTHOR_NAME",
        "client_name=CLIENT_NAME",
        "export_date=2002-02-02"
    ]))
    assert response.status_code == 200
    content = response.data.decode("utf-8")
    assert "AUTHOR_NAME" in content
    assert "CLIENT_NAME" in content
    assert "2002-02-02" in content
    assert "CVE-2020-35492" in content


def test_render_document_with_filter(client):
    response = client.get("/api/documents/all_assessments.adoc?" + '&'.join([
        "ignore_before=2000-01-01T00:00",
        "only_epss_greater=45.67"
    ]))
    assert response.status_code == 200
    content = response.data.decode("utf-8")
    assert "CVE-2020-35492" not in content

    response = client.get("/api/documents/all_assessments.adoc?" + '&'.join([
        "ignore_before=2024-09-01T00:00",
        "only_epss_greater=05.00"
    ]))
    assert response.status_code == 200
    content = response.data.decode("utf-8")
    assert "CVE-2020-35492" not in content

    response = client.get("/api/documents/all_assessments.adoc?" + '&'.join([
        "ignore_before=2000-01-01T00:00",
        "only_epss_greater=05.00"
    ]))
    assert response.status_code == 200
    content = response.data.decode("utf-8")
    assert "CVE-2020-35492" in content


def test_render_document_pdf(client):
    import shutil
    response = client.get("/api/documents/summary.adoc?ext=pdf")
    if shutil.which("asciidoctor-pdf") is None:
        assert response.status_code == 503
    else:
        assert response.status_code == 200


def test_render_document_html(client):
    import shutil
    response = client.get("/api/documents/summary.adoc?ext=html")
    if shutil.which("asciidoctor") is None:
        assert response.status_code == 503
    else:
        assert response.status_code == 200


def test_render_cdx_v1_6(client):
    response = client.get("/api/documents/CycloneDX 1.6?ext=json")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.6"
    assert len(data["vulnerabilities"]) == 1


def test_render_document_not_found(client):
    response = client.get("/api/documents/doesnt_exist.adoc")
    assert response.status_code >= 400
    data = json.loads(response.data)
    assert data["error"] is not None


def test_render_document_invalid_ext(client):
    response = client.get("/api/documents/CycloneDX 1.4?ext=pdf")
    assert response.status_code >= 400
    data = json.loads(response.data)
    assert data["error"] is not None


def test_render_spdx_json(client):
    response = client.get("/api/documents/SPDX 2.3?ext=json")
    assert response.status_code == 200
    assert response.headers.get("Content-Type") == "application/json"
    cd = response.headers.get("Content-Disposition", "")
    assert "attachment" in cd
    assert "filename=spdx_v2_3.json" in cd

    data = json.loads(response.data)
    assert data["SPDXID"] == "SPDXRef-DOCUMENT"
    assert data["spdxVersion"] == "SPDX-2.3"
    assert data["dataLicense"] == "CC0-1.0"
    assert "packages" in data


def test_render_spdx_xml(monkeypatch, client):
    # Ensure expected_mime is 'text/xml' for '?ext=xml'
    def fake_guess(name):
        if isinstance(name, str) and ("xml" in name or name.endswith(".xml")):
            return "text/xml"
        if isinstance(name, str) and ("json" in name or name.endswith(".json")):
            return "application/json"
        if isinstance(name, str) and ("adoc" in name or name.endswith(".adoc") or name.endswith(".asciidoc")):
            return "text/asciidoc"
        return "application/octet-stream"
    monkeypatch.setattr("src.routes.documents.guess_mime_type", fake_guess)

    response = client.get("/api/documents/SPDX 2.3?ext=xml")
    assert response.status_code == 200
    assert response.headers.get("Content-Type") == "text/xml"
    cd = response.headers.get("Content-Disposition", "")
    assert "attachment" in cd and "filename=spdx_v2_3.xml" in cd
    assert response.data.decode("utf-8").lstrip().startswith("<")


def test_render_openvex_json(client):
    response = client.get("/api/documents/OpenVex?ext=json")
    assert response.status_code == 200
    assert response.headers.get("Content-Type") == "application/json"
    cd = response.headers.get("Content-Disposition", "")
    assert "attachment" in cd and "openvex.json" in cd
    json.loads(response.data)


def test_render_cdx_v1_4(client):
    response = client.get("/api/documents/CycloneDX 1.4?ext=json")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.4"


def test_render_cdx_v1_5(client):
    response = client.get("/api/documents/CycloneDX 1.5?ext=json")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.5"


def test_documents_list_extension_bin(monkeypatch, client):
    def fake_list_documents(self):
        return [{"id": "MYDOC", "is_template": True, "category": []}]
    monkeypatch.setattr("src.routes.documents.Templates.list_documents", fake_list_documents)
    response = client.get("/api/documents")
    assert response.status_code == 200
    docs = json.loads(response.data)
    item = next(d for d in docs if d["id"] == "MYDOC")
    assert item["extension"] == "bin"


def test_documents_list_error(monkeypatch, client):
    def boom(self):
        raise Exception("boom")
    monkeypatch.setattr("src.routes.documents.Templates.list_documents", boom)
    response = client.get("/api/documents")
    assert response.status_code == 500
    data = json.loads(response.data)
    assert "error" in data


def test_only_epss_greater_invalid(client):
    response = client.get("/api/documents/all_assessments.adoc?only_epss_greater=oops")
    assert response.status_code == 200
    assert len(response.data) > 0


def test_render_document_invalid_conversion(client):
    response = client.get("/api/documents/summary.adoc?ext=xml")
    assert response.status_code >= 400
    data = json.loads(response.data)
    assert data["error"]


def test_render_spdx3_json(client):
    """GET /api/documents/SPDX 3.0?ext=json returns a valid SPDX 3.0 JSON document (lines 180-186)."""
    response = client.get("/api/documents/SPDX 3.0?ext=json")
    assert response.status_code == 200
    assert response.headers.get("Content-Type") == "application/json"
    cd = response.headers.get("Content-Disposition", "")
    assert "attachment" in cd
    assert "spdx_v3_0.json" in cd
    data = json.loads(response.data)
    assert "@context" in data or "@graph" in data


def test_documents_list_categories_enrichment(monkeypatch, client):
    """Documents list applies CategoriesDictionary categories to template docs (lines 77-79)."""
    def fake_list_documents(self):
        # Return a template doc with no 'extension' key and an id that maps to CategoriesDictionary
        return [{"id": "my_report.adoc", "is_template": True, "category": ["misc"]}]

    monkeypatch.setattr("src.routes.documents.Templates.list_documents", fake_list_documents)
    monkeypatch.setattr("src.routes.documents.CategoriesDictionary", {"my_report.adoc": ["vex", "misc"]})

    response = client.get("/api/documents")
    assert response.status_code == 200
    docs = json.loads(response.data)
    item = next((d for d in docs if d["id"] == "my_report.adoc"), None)
    assert item is not None
    # "vex" should have been appended, "misc" was already present (not duplicated)
    assert "vex" in item["category"]
    assert item["category"].count("misc") == 1


def test_packages_variant_no_active_scans(app, client):
    """packages.py line 80: variant with no active sbom scans returns empty list."""
    from src.models.project import Project
    from src.models.variant import Variant
    with app.app_context():
        project = Project.create("PkgEmptyProj1")
        variant = Variant.create("PkgEmptyVar1", project.id)
        variant_id = str(variant.id)
    response = client.get(f"/api/packages?variant_id={variant_id}&format=list")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)


def test_packages_project_no_active_scans(app, client):
    """packages.py line 93: project with no active sbom scans returns empty list."""
    from src.models.project import Project
    with app.app_context():
        project = Project.create("PkgEmptyProj2")
        project_id = str(project.id)
    response = client.get(f"/api/packages?project_id={project_id}&format=list")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)


def test_upload_template_success(tmp_path, monkeypatch, client):
    """POST /api/documents/templates saves a valid template and returns 201."""
    from io import BytesIO
    monkeypatch.setattr("src.routes.documents.TEMPLATE_UPLOAD_DIRS", [str(tmp_path)])

    response = client.post(
        "/api/documents/templates",
        data={"file": (BytesIO(b"= My custom report\n"), "my_report.adoc")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["id"] == "my_report.adoc"
    assert "custom" in data["category"]
    saved = tmp_path / "my_report.adoc"
    assert saved.exists()
    assert saved.read_bytes() == b"= My custom report\n"


def test_upload_template_rejects_bad_extension(tmp_path, monkeypatch, client):
    """POST /api/documents/templates rejects unsupported extensions with 400."""
    from io import BytesIO
    monkeypatch.setattr("src.routes.documents.TEMPLATE_UPLOAD_DIRS", [str(tmp_path)])

    response = client.post(
        "/api/documents/templates",
        data={"file": (BytesIO(b"MZ..."), "evil.exe")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert json.loads(response.data)["error"]
    assert not (tmp_path / "evil.exe").exists()


def test_upload_template_rejects_path_traversal(tmp_path, monkeypatch, client):
    """POST /api/documents/templates strips directory components from the name."""
    from io import BytesIO
    monkeypatch.setattr("src.routes.documents.TEMPLATE_UPLOAD_DIRS", [str(tmp_path)])

    response = client.post(
        "/api/documents/templates",
        data={"file": (BytesIO(b"data"), "../../escape.adoc")},
        content_type="multipart/form-data",
    )
    # basename keeps "escape.adoc"; it must not escape the target directory.
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["id"] == "escape.adoc"
    assert (tmp_path / "escape.adoc").exists()
    assert not (tmp_path.parent.parent / "escape.adoc").exists()


def test_upload_template_missing_file(client):
    """POST /api/documents/templates without a file returns 400."""
    response = client.post(
        "/api/documents/templates",
        data={},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert json.loads(response.data)["error"]


# ---------------------------------------------------------------------------
# POST /api/documents/assets
# ---------------------------------------------------------------------------

def test_upload_asset_success(tmp_path, monkeypatch, client):
    """POST /api/documents/assets saves a valid image and returns 201."""
    from io import BytesIO
    monkeypatch.setattr("src.routes.documents.TEMPLATE_UPLOAD_DIRS", [str(tmp_path)])
    monkeypatch.setattr("src.views.templates._ASSET_SEARCH_DIRS", [str(tmp_path / "assets")])

    png_bytes = _make_png_bytes()
    response = client.post(
        "/api/documents/assets",
        data={"file": (BytesIO(png_bytes), "logo.png")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["name"] == "logo.png"
    saved = tmp_path / "assets" / "logo.png"
    assert saved.exists()
    assert saved.read_bytes() == png_bytes

    documents = client.get("/api/documents")
    assert documents.status_code == 200
    assets = [item for item in json.loads(documents.data) if item["id"] == "logo.png"]
    assert assets == [{"id": "logo.png", "extension": "png", "is_template": False, "category": ["assets"]}]

    download = client.get("/api/documents/logo.png?ext=png")
    assert download.status_code == 200
    assert download.data == png_bytes
    assert download.headers["Content-Type"] == "image/png"
    assert "attachment; filename=logo.png" in download.headers["Content-Disposition"]


def test_upload_asset_rejects_bad_extension(tmp_path, monkeypatch, client):
    """POST /api/documents/assets rejects non-image extensions with 400."""
    from io import BytesIO
    monkeypatch.setattr("src.routes.documents.TEMPLATE_UPLOAD_DIRS", [str(tmp_path)])

    response = client.post(
        "/api/documents/assets",
        data={"file": (BytesIO(b"script"), "evil.js")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    error = json.loads(response.data)["error"]
    assert error
    assert not (tmp_path / "assets" / "evil.js").exists()


def test_upload_asset_rejects_svg(tmp_path, monkeypatch, client):
    """POST /api/documents/assets rejects SVG uploads (excluded to avoid active content)."""
    from io import BytesIO
    monkeypatch.setattr("src.routes.documents.TEMPLATE_UPLOAD_DIRS", [str(tmp_path)])

    svg_bytes = b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"
    response = client.post(
        "/api/documents/assets",
        data={"file": (BytesIO(svg_bytes), "logo.svg")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert json.loads(response.data)["error"]
    assert not (tmp_path / "assets" / "logo.svg").exists()


def test_upload_asset_rejects_content_extension_mismatch(tmp_path, monkeypatch, client):
    """POST /api/documents/assets rejects a file whose decoded format doesn't match its extension."""
    from io import BytesIO
    monkeypatch.setattr("src.routes.documents.TEMPLATE_UPLOAD_DIRS", [str(tmp_path)])

    # A genuine JPEG renamed with a .png extension must be rejected: the
    # declared extension is trusted only after the decoded content confirms it.
    jpeg_bytes = _make_jpeg_bytes()
    response = client.post(
        "/api/documents/assets",
        data={"file": (BytesIO(jpeg_bytes), "logo.png")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert json.loads(response.data)["error"]
    assert not (tmp_path / "assets" / "logo.png").exists()


def test_upload_asset_rejects_non_image_content(tmp_path, monkeypatch, client):
    """POST /api/documents/assets rejects a file with an image extension but non-image bytes."""
    from io import BytesIO
    monkeypatch.setattr("src.routes.documents.TEMPLATE_UPLOAD_DIRS", [str(tmp_path)])

    response = client.post(
        "/api/documents/assets",
        data={"file": (BytesIO(b"not actually an image"), "fake.png")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert json.loads(response.data)["error"]
    assert not (tmp_path / "assets" / "fake.png").exists()


def test_upload_asset_rejects_oversized_upload(tmp_path, monkeypatch, client):
    """POST /api/documents/assets rejects a file bigger than the configured size cap."""
    from io import BytesIO
    import src.routes.documents as documents_module
    monkeypatch.setattr("src.routes.documents.TEMPLATE_UPLOAD_DIRS", [str(tmp_path)])
    monkeypatch.setattr(documents_module, "MAX_ASSET_UPLOAD_BYTES", 16)

    response = client.post(
        "/api/documents/assets",
        data={"file": (BytesIO(_make_png_bytes()), "logo.png")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 413
    assert json.loads(response.data)["error"]
    assert not (tmp_path / "assets" / "logo.png").exists()


def test_upload_asset_rejects_request_larger_than_content_limit(app, client):
    """Werkzeug rejects oversized multipart bodies before the route parses files."""
    request_limit = app.config["MAX_CONTENT_LENGTH"]
    response = client.post(
        "/api/documents/assets",
        data=b"x" * (request_limit + 1),
        content_type="multipart/form-data",
    )
    assert response.status_code == 413


def test_upload_asset_rejects_path_traversal(tmp_path, monkeypatch, client):
    """POST /api/documents/assets strips directory components from the filename."""
    from io import BytesIO
    monkeypatch.setattr("src.routes.documents.TEMPLATE_UPLOAD_DIRS", [str(tmp_path)])

    png_bytes = _make_png_bytes()
    response = client.post(
        "/api/documents/assets",
        data={"file": (BytesIO(png_bytes), "../../escape.png")},
        content_type="multipart/form-data",
    )
    # basename keeps "escape.png" and it must not leave the assets directory.
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["name"] == "escape.png"
    assert (tmp_path / "assets" / "escape.png").exists()
    assert not (tmp_path.parent.parent / "escape.png").exists()


def test_upload_asset_missing_file(client):
    """POST /api/documents/assets without a file returns 400."""
    response = client.post(
        "/api/documents/assets",
        data={},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert json.loads(response.data)["error"]


def test_upload_asset_no_multipart(client):
    """POST /api/documents/assets without multipart content type returns 400."""
    response = client.post(
        "/api/documents/assets",
        data=b"\x89PNG",
        content_type="application/octet-stream",
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# GET assessment-groups endpoints
# ---------------------------------------------------------------------------

def test_assessment_groups_by_vuln_returns_one_entry_per_group(client, demo_ids):
    """A multi-package write still creates one row per package (unmigrated in
    this phase); each row is now its own group with exactly its own target."""
    created = client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "not_affected",
            "justification": "component_not_present",
            "packages": demo_ids["two_packages"],
            "variant_id": demo_ids["variant_id"],
        },
    ).get_json()
    created_group_ids = {a["group_id"] for a in created["assessments"]}

    response = client.get(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessment-groups")

    assert response.status_code == 200
    match = [g for g in response.get_json() if g["group_id"] in created_group_ids]
    assert len(match) == 2
    assert all(len(g["targets"]) == 1 for g in match)
    assert all(g["status"] == "not_affected" for g in match)


def test_assessment_group_by_id_returns_the_group(client, demo_ids):
    created = client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "not_affected",
            "justification": "component_not_present",
            "packages": demo_ids["two_packages"],
            "variant_id": demo_ids["variant_id"],
        },
    ).get_json()
    group_id = created["assessments"][0]["group_id"]

    response = client.get(f"/api/assessment-groups/{group_id}")

    assert response.status_code == 200
    assert response.get_json()["group_id"] == group_id


def test_unknown_assessment_group_is_404(client):
    import uuid

    assert client.get(f"/api/assessment-groups/{uuid.uuid4()}").status_code == 404


def test_ungrouped_assessment_appears_with_its_own_group_id(client, demo_ids):
    """group_id is never None now: a single-target assessment is its own,
    single-member group."""
    created = client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "affected",
            "packages": [demo_ids["two_packages"][0]],
            "variant_id": demo_ids["variant_id"],
        },
    ).get_json()
    assessment_id = created["assessments"][0]["id"]

    groups = client.get(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessment-groups").get_json()

    match = [g for g in groups if g["group_id"] == assessment_id]
    assert len(match) == 1
    assert len(match[0]["targets"]) == 1


def test_review_assessment_groups_filters(client, demo_ids):
    created = client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "not_affected",
            "justification": "component_not_present",
            "packages": demo_ids["two_packages"],
            "variant_id": demo_ids["variant_id"],
        },
    ).get_json()
    group_id = created["assessments"][0]["group_id"]

    response = client.get(
        f"/api/reviews/assessment-groups?variant_id={demo_ids['variant_id']}&origin=custom")
    assert response.status_code == 200
    match = [g for g in response.get_json() if g["group_id"] == group_id]
    assert len(match) == 1

    other_variant_response = client.get(
        f"/api/reviews/assessment-groups?variant_id={demo_ids['other_variant_id']}")
    assert other_variant_response.status_code == 200
    assert all(
        g["group_id"] != group_id for g in other_variant_response.get_json())


def test_assessment_groups_targets_carry_their_owning_assessment_id(client, demo_ids):
    """Each target dict must carry the id of the assessment record it came
    from, so the frontend can PUT/DELETE that exact row for legacy per-row
    edits (Task 13). A multi-package write still creates one row per package
    (unmigrated in this phase); each row is its own group with one target
    that points back at itself."""
    created = client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "not_affected",
            "justification": "component_not_present",
            "packages": demo_ids["two_packages"],
            "variant_id": demo_ids["variant_id"],
        },
    ).get_json()
    created_ids = {a["id"] for a in created["assessments"]}

    response = client.get(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessment-groups")
    assert response.status_code == 200
    matches = [g for g in response.get_json() if g["group_id"] in created_ids]
    assert len(matches) == 2
    for group in matches:
        assert len(group["targets"]) == 1
        assert group["targets"][0]["assessment_id"] == group["group_id"]
    assert {g["group_id"] for g in matches} == created_ids


def test_review_assessment_groups_include_vuln_id_and_texts(client, demo_ids, app):
    """The cross-vuln review endpoint must tag each group with its
    vulnerability id and enrich it with that vulnerability's texts, since the
    review table spans several CVEs and the frontend needs both for its
    columns and hover tooltips (Task 13)."""
    from src.extensions import db
    from src.models.vulnerability import Vulnerability

    with app.app_context():
        vuln = Vulnerability.get_by_id(demo_ids["vuln_id"])
        vuln.description = "a description used for the review tooltip"
        db.session.commit()

    client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "affected",
            "packages": [demo_ids["two_packages"][0]],
            "variant_id": demo_ids["variant_id"],
        },
    )

    response = client.get(
        f"/api/reviews/assessment-groups?variant_id={demo_ids['variant_id']}&origin=custom")
    assert response.status_code == 200
    groups = [g for g in response.get_json() if g["vuln_id"] == demo_ids["vuln_id"]]
    assert len(groups) == 1
    assert groups[0]["vuln_texts"]
    assert any(
        t["content"] == "a description used for the review tooltip"
        for t in groups[0]["vuln_texts"]
    )

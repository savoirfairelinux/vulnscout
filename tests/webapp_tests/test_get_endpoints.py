# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import json
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


def test_get_assessments_dict(client):
    response = client.get("/api/assessments?format=dict")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert "da4d18f0-d89e-4d54-819d-86fc884cc737" in data
    assert data["da4d18f0-d89e-4d54-819d-86fc884cc737"]["vuln_id"] == "CVE-2020-35492"
    assert data["da4d18f0-d89e-4d54-819d-86fc884cc737"]["status"] == "fixed"
    assert "cairo@1.16.0" in data["da4d18f0-d89e-4d54-819d-86fc884cc737"]["packages"]
    assert data["da4d18f0-d89e-4d54-819d-86fc884cc737"]["impact_statement"] == "Yocto reported vulnerability as Patched"


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

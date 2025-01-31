# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import json
from src.bin.webapp import create_app
from . import write_demo_files


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
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SCAN_FILE": init_files["status"],
        "PKG_FILE": init_files["packages"],
        "VULNS_FILE": init_files["vulnerabilities"],
        "ASSESSMENTS_FILE": init_files["assessments"],
        "NVD_DB_PATH": "tests/webapp_tests/mini_nvd.db"
    })

    yield app

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


def test_get_packages_dict(client):
    response = client.get("/api/packages?format=dict")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert "cairo@1.16.0" in data
    assert data["cairo@1.16.0"]["name"] == "cairo"
    assert data["cairo@1.16.0"]["version"] == "1.16.0"
    assert len(data["cairo@1.16.0"]["cpe"]) == 4


def test_get_vulnerabilities_list(client):
    response = client.get("/api/vulnerabilities?format=list")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert data[0]["id"] == "CVE-2020-35492"
    assert "grype" in data[0]["found_by"]
    assert data[0]["severity"]["severity"] == "high"
    assert "cairo@1.16.0" in data[0]["packages"]


def test_get_vulnerabilities_dict(client):
    response = client.get("/api/vulnerabilities?format=dict")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert "CVE-2020-35492" in data
    assert "grype" in data["CVE-2020-35492"]["found_by"]
    assert data["CVE-2020-35492"]["severity"]["severity"] == "high"
    assert "cairo@1.16.0" in data["CVE-2020-35492"]["packages"]


def test_get_vulnerability_by_id(client):
    response = client.get("/api/vulnerabilities/CVE-2020-35492")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == "CVE-2020-35492"
    assert "grype" in data["found_by"]
    assert data["severity"]["severity"] == "high"
    assert "cairo@1.16.0" in data["packages"]

    response = client.get("/api/vulnerabilities/CVE-0000-00000")
    assert response.status_code == 404


def test_get_assessments_list(client):
    response = client.get("/api/assessments?format=list")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert data[0]["id"] == "da4d18f0-d89e-4d54-819d-86fc884cc737"
    assert data[0]["vuln_id"] == "CVE-2020-35492"
    assert data[0]["status"] == "fixed"
    assert "cairo@1.16.0" in data[0]["packages"]
    assert data[0]["impact_statement"] == "Yocto reported vulnerability as Patched"


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
    response = client.get("/api/documents/summary.adoc?ext=pdf")
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


def test_get_patch_finder_status(client):
    response = client.get("/api/patch-finder/status")
    assert response.status_code == 200
    data = json.loads(response.data)
    # values allowed to be changed on future updates
    assert data["api_version"] == "nvd2.0-vulnscout1.1"
    assert data["db_version"] == "nvd2.0-vulnscout1.1"

    # following should be true whichever version is used
    assert data["api_version"] == data["db_version"]
    assert data["db_ready"] is True
    assert data["vulns_count"] == 264387
    assert data["last_modified"] == "2024-10-03T13:35:12.847678+00:00"

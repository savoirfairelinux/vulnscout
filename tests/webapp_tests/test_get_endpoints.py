# -*- coding: utf-8 -*-
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
    assert data[0]["found_by"] == "grype"
    assert data[0]["severity"]["severity"] == "high"
    assert "cairo@1.16.0" in data[0]["packages"]


def test_get_vulnerabilities_dict(client):
    response = client.get("/api/vulnerabilities?format=dict")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert "CVE-2020-35492" in data
    assert data["CVE-2020-35492"]["found_by"] == "grype"
    assert data["CVE-2020-35492"]["severity"]["severity"] == "high"
    assert "cairo@1.16.0" in data["CVE-2020-35492"]["packages"]


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

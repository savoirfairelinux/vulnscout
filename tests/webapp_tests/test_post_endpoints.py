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
        "openvex": tmp_path / "openvex.json",
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
        "OPENVEX_FILE": init_files["openvex"],
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


def test_post_minimal_assessment(client):
    response = client.post("/api/vulnerabilities/CVE-1999-12345/assessments", json={
        'packages': ['abc@1.2.3', 'cairo@1.16.0'],
        'status': 'exploitable',
        'workaround': 'Disable option X in configuration'
    })
    assert response.status_code == 200

    response = client.get("/api/assessments?format=list")
    assert response.status_code == 200
    data = json.loads(response.data)
    data_str = response.get_data(as_text=True)
    assert len(data) == 2
    assert "CVE-1999-12345" in data_str
    assert "Disable option X in configuration" in data_str


def test_post_detailled_assessment(client):
    response = client.post("/api/vulnerabilities/CVE-1999-12345/assessments", json={
        'vuln_id': 'CVE-1999-12345',
        'packages': ['abc@1.2.3', 'cairo@1.16.0'],
        'status': 'exploitable',
        'status_notes': 'Demonstration assessment',
        'responses': ['can_not_fix'],
        'impact_statement': 'This doesn\'t matter',
        'workaround': 'Disable option X in configuration',
        'workaround_timestamp': '2021-01-01T00:00:00Z',
        'timestamp': '2021-01-01T00:00:00Z',
        'last_updated': '2021-01-01T00:00:00Z'
    })
    assert response.status_code == 200

    response = client.get("/api/assessments?format=list")
    assert response.status_code == 200
    data = json.loads(response.data)
    data_str = response.get_data(as_text=True)
    assert len(data) == 2
    assert "CVE-1999-12345" in data_str
    assert "Demonstration assessment" in data_str


def test_post_assessment_missing_data(client):
    # no payload
    response = client.post("/api/vulnerabilities/CVE-1999-6789/assessments", json={})
    assert response.status_code == 400

    # missing status
    response = client.post("/api/vulnerabilities/CVE-1999-6789/assessments", json={
        'packages': ['abc@1.2.3']
    })
    assert response.status_code == 400

    # missing packages
    response = client.post("/api/vulnerabilities/CVE-1999-6789/assessments", json={
        'status': 'exploitable'
    })
    assert response.status_code == 400

    # missing justification
    response = client.post("/api/vulnerabilities/CVE-1999-6789/assessments", json={
        'vuln_id': 'CVE-1999-6789',
        'packages': ['abc@1.2.3'],
        'status': 'not_affected'
    })
    assert response.status_code == 400


def test_post_assessment_invalid_payloads(client):
    # different vulnerability ID
    response = client.post("/api/vulnerabilities/CVE-1999-6789/assessments", json={
        'vuln_id': 'CVE-1999-12345',
        'packages': ['abc@1.2.3'],
        'status': 'exploitable'
    }, )
    assert response.status_code == 400

    # invalid status
    response = client.post("/api/vulnerabilities/CVE-1999-6789/assessments", json={
        'packages': ['abc@1.2.3'],
        'status': 'random_text'
    }, )
    assert response.status_code == 400

    # invalid justification
    response = client.post("/api/vulnerabilities/CVE-1999-6789/assessments", json={
        'packages': ['abc@1.2.3'],
        'status': 'not_affected',
        'justification': 'random_text'
    }, )
    assert response.status_code == 400

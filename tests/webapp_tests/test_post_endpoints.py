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
        "openvex": tmp_path / "openvex.json",
        "time_estimates": tmp_path / "time_estimates.json",
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
        "TIME_ESTIMATES_PATH": init_files["time_estimates"],
        "NVD_DB_PATH": "webapp_tests/mini_nvd.db"
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


def test_patch_vulnerability_empty(client):
    response = client.patch("/api/vulnerabilities/CVE-2020-35492", json={})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == "CVE-2020-35492"


def test_patch_vulnerability_efforts(init_files, client):
    response = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        'effort': {
            'optimistic': 'PT2H',
            'likely': 'P1D',
            'pessimistic': 'P2.5D'
        }
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["effort"]["optimistic"] == "PT2H"
    assert data["effort"]["likely"] == "P1D"
    assert data["effort"]["pessimistic"] == "P2DT4H"

    estimates_content = json.loads(init_files["time_estimates"].read_text())
    assert "CVE-2020-35492" in estimates_content["tasks"]
    assert estimates_content["tasks"]["CVE-2020-35492"]["pessimistic"] == "P2DT4H"


def test_patch_vulnerability_invalids(client):
    response = client.patch("/api/vulnerabilities/CVE-0000-00000", json={
        'effort': {
            'optimistic': 'PT2H',
            'likely': 'P1D',
            'pessimistic': 'P2.5D'
        }
    })
    assert response.status_code == 404

    response = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        'effort': {
            'optimistic': 'PT2H',
            'likely': 'P1D',
        }
    })
    assert response.status_code == 400

    response = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        'effort': {
            'optimistic': 'P2H',
            'likely': 'PT1D',
            'pessimistic': 'P'
        }
    })
    assert response.status_code == 400


def test_post_scan_patch_finder(client):
    response = client.post("/api/patch-finder/scan", json=[
        "CVE-2021-37322",
        "CVE-0000-00000"
    ])
    assert response.status_code == 200

    data = json.loads(response.data)
    assert "binutils" in data
    assert "CVE-2021-37322 (nvd-cpe-match)" in data["binutils"]
    assert "gcc" in data
    assert "CVE-2021-37322 (nvd-cpe-match)" in data["gcc"]
    fixs_binutils = data["binutils"]["CVE-2021-37322 (nvd-cpe-match)"]["fix"]
    affected_gcc = data["gcc"]["CVE-2021-37322 (nvd-cpe-match)"]["affected"]
    assert fixs_binutils == [">=? 2.32"]
    assert affected_gcc == ["< 10.1"]


def test_update_assessment(client):
    # First create an assessment
    response = client.post("/api/vulnerabilities/CVE-1999-12345/assessments", json={
        'packages': ['abc@1.2.3'],
        'status': 'exploitable',
        'status_notes': 'Initial assessment',
        'workaround': 'No workaround available'
    })
    assert response.status_code == 200
    
    created_data = json.loads(response.data)
    assert created_data["status"] == "success"
    assessment_id = created_data["assessment"]["id"]
    
    # Now update the assessment
    response = client.put(f"/api/assessments/{assessment_id}", json={
        'status': 'fixed',
        'status_notes': 'Updated assessment - vulnerability has been fixed',
        'workaround': 'Update to latest version'
    })
    assert response.status_code == 200
    
    updated_data = json.loads(response.data)
    assert updated_data["status"] == "success"
    assert updated_data["assessment"]["status"] == "fixed"
    assert updated_data["assessment"]["status_notes"] == "Updated assessment - vulnerability has been fixed"
    assert updated_data["assessment"]["workaround"] == "Update to latest version"
    assert updated_data["assessment"]["id"] == assessment_id


def test_update_assessment_not_found(client):
    response = client.put("/api/assessments/non-existent-id", json={
        'status': 'fixed',
        'status_notes': 'This should fail'
    })
    assert response.status_code == 404
    
    data = json.loads(response.data)
    assert data["error"] == "Assessment not found"


def test_update_assessment_invalid_status(client):
    # First create an assessment
    response = client.post("/api/vulnerabilities/CVE-1999-12345/assessments", json={
        'packages': ['abc@1.2.3'],
        'status': 'exploitable'
    })
    assert response.status_code == 200
    
    created_data = json.loads(response.data)
    assessment_id = created_data["assessment"]["id"]
    
    # Try to update with invalid status
    response = client.put(f"/api/assessments/{assessment_id}", json={
        'status': 'invalid_status'
    })
    assert response.status_code == 400
    
    data = json.loads(response.data)
    assert data["error"] == "Invalid status"


def test_delete_assessment(client):
    # First create an assessment
    response = client.post("/api/vulnerabilities/CVE-1999-12345/assessments", json={
        'packages': ['abc@1.2.3'],
        'status': 'exploitable',
        'status_notes': 'Assessment to be deleted'
    })
    assert response.status_code == 200
    
    created_data = json.loads(response.data)
    assessment_id = created_data["assessment"]["id"]
    
    # Verify the assessment exists
    response = client.get(f"/api/assessments/{assessment_id}")
    assert response.status_code == 200
    
    # Delete the assessment
    response = client.delete(f"/api/assessments/{assessment_id}")
    assert response.status_code == 200
    
    deleted_data = json.loads(response.data)
    assert deleted_data["status"] == "success"
    assert deleted_data["message"] == "Assessment deleted successfully"
    
    # Verify the assessment no longer exists
    response = client.get(f"/api/assessments/{assessment_id}")
    assert response.status_code == 404


def test_delete_assessment_not_found(client):
    response = client.delete("/api/assessments/non-existent-id")
    assert response.status_code == 404
    
    data = json.loads(response.data)
    assert data["error"] == "Assessment not found"

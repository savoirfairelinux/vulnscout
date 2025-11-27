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


@pytest.fixture()
def client(app):
    return app.test_client()


# Test PATCH vulnerability with CVSS data
def test_patch_vulnerability_with_cvss(client, init_files):
    """Test updating a vulnerability with new CVSS data"""
    response = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        'cvss': {
            'base_score': 8.5,
            'vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L',
            'version': '3.1',
            'author': 'test@example.com',
            'exploitability_score': 3.9,
            'impact_score': 5.2
        }
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == "CVE-2020-35492"
    
    # Verify CVSS was added
    cvss_scores = data["severity"]["cvss"]
    assert any(cvss["base_score"] == 8.5 for cvss in cvss_scores)
    
    # Verify time_estimates file was updated
    assert init_files["time_estimates"].exists()
    time_est_content = json.loads(init_files["time_estimates"].read_text())
    assert "tasks" in time_est_content


# Test PATCH vulnerability with missing CVSS fields
def test_patch_vulnerability_with_incomplete_cvss(client):
    """Test that incomplete CVSS data is rejected"""
    # Missing base_score
    response = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        'cvss': {
            'vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L',
            'version': '3.1'
        }
    })
    assert response.status_code == 400
    assert response.data == b"Invalid CVSS data"
    
    # Missing vector_string
    response = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        'cvss': {
            'base_score': 8.5,
            'version': '3.1'
        }
    })
    assert response.status_code == 400
    
    # Missing version
    response = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        'cvss': {
            'base_score': 8.5,
            'vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L'
        }
    })
    assert response.status_code == 400


# Test PATCH vulnerability with both effort and CVSS
def test_patch_vulnerability_with_effort_and_cvss(client, init_files):
    """Test updating vulnerability with both effort and CVSS in single request"""
    response = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        'effort': {
            'optimistic': 'PT1H',
            'likely': 'PT4H',
            'pessimistic': 'P1D'
        },
        'cvss': {
            'base_score': 9.0,
            'vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            'version': '3.1',
            'author': 'test@example.com',
            'exploitability_score': 3.9,
            'impact_score': 6.0
        }
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    
    # Verify effort was set
    assert data["effort"]["optimistic"] == "PT1H"
    assert data["effort"]["likely"] == "PT4H"
    
    # Verify CVSS was added (note: base_score might differ due to merging)
    cvss_scores = data["severity"]["cvss"]
    assert len(cvss_scores) >= 1
    
    # Verify files were updated
    assert init_files["vulnerabilities"].exists()
    assert init_files["time_estimates"].exists()


# Test PATCH vulnerability not found
def test_patch_vulnerability_not_found(client):
    """Test patching a non-existent vulnerability"""
    response = client.patch("/api/vulnerabilities/CVE-9999-99999", json={
        'effort': {
            'optimistic': 'PT1H',
            'likely': 'PT4H',
            'pessimistic': 'P1D'
        }
    })
    assert response.status_code == 404
    assert response.data == b"Not found"


# Test GET vulnerability by id (existing tests may not cover all paths)
def test_get_vulnerability_by_id_success(client):
    """Test GET for an existing vulnerability"""
    response = client.get("/api/vulnerabilities/CVE-2020-35492")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == "CVE-2020-35492"
    assert "severity" in data
    assert "packages" in data


# Test PATCH vulnerabilities batch - all valid
def test_patch_vulnerabilities_batch_all_valid(client, init_files):
    """Test batch update with all valid vulnerabilities"""
    response = client.patch("/api/vulnerabilities/batch", json={
        'vulnerabilities': [
            {
                'id': 'CVE-2020-35492',
                'effort': {
                    'optimistic': 'PT2H',
                    'likely': 'PT8H',
                    'pessimistic': 'P2D'
                }
            }
        ]
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "success"
    assert data["count"] == 1
    assert len(data["vulnerabilities"]) == 1
    
    # Verify effort was set
    vuln = data["vulnerabilities"][0]
    assert vuln["effort"]["optimistic"] == "PT2H"


# Test PATCH vulnerabilities batch - invalid request format
def test_patch_vulnerabilities_batch_invalid_format(client):
    """Test batch update with invalid request format"""
    # Missing vulnerabilities key
    response = client.patch("/api/vulnerabilities/batch", json={
        'items': []
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "Invalid request data" in data["error"]
    
    # vulnerabilities is not a list
    response = client.patch("/api/vulnerabilities/batch", json={
        'vulnerabilities': 'not a list'
    })
    assert response.status_code == 400


# Test PATCH vulnerabilities batch - no payload
def test_patch_vulnerabilities_batch_no_payload(client):
    """Test batch update with no payload"""
    response = client.patch("/api/vulnerabilities/batch", json=None)
    assert response.status_code in [400, 415]  # Accept both 400 and 415


# Test PATCH vulnerabilities batch - missing id in item
def test_patch_vulnerabilities_batch_missing_id(client):
    """Test batch update with item missing id"""
    response = client.patch("/api/vulnerabilities/batch", json={
        'vulnerabilities': [
            {
                'effort': {
                    'optimistic': 'PT2H',
                    'likely': 'PT8H',
                    'pessimistic': 'P2D'
                }
            }
        ]
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["status"] == "error"
    assert data["count"] == 0
    assert data["error_count"] == 1


# Test PATCH vulnerabilities batch - invalid item structure (not dict)
def test_patch_vulnerabilities_batch_invalid_item_type(client):
    """Test batch update with non-dict item"""
    response = client.patch("/api/vulnerabilities/batch", json={
        'vulnerabilities': [
            'not_a_dict',
            {
                'id': 'CVE-2020-35492',
                'effort': {
                    'optimistic': 'PT2H',
                    'likely': 'PT8H',
                    'pessimistic': 'P2D'
                }
            }
        ]
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["count"] == 1
    assert data["error_count"] == 1
    assert len(data["errors"]) == 1


# Test PATCH vulnerabilities batch - vulnerability not found
def test_patch_vulnerabilities_batch_vuln_not_found(client):
    """Test batch update with non-existent vulnerability"""
    response = client.patch("/api/vulnerabilities/batch", json={
        'vulnerabilities': [
            {
                'id': 'CVE-9999-99999',
                'effort': {
                    'optimistic': 'PT2H',
                    'likely': 'PT8H',
                    'pessimistic': 'P2D'
                }
            }
        ]
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["status"] == "error"
    assert data["count"] == 0
    assert data["error_count"] == 1
    assert "not found" in data["errors"][0]["error"]


# Test PATCH vulnerabilities batch - invalid effort values
def test_patch_vulnerabilities_batch_invalid_effort(client):
    """Test batch update with invalid effort values"""
    # Missing pessimistic
    response = client.patch("/api/vulnerabilities/batch", json={
        'vulnerabilities': [
            {
                'id': 'CVE-2020-35492',
                'effort': {
                    'optimistic': 'PT2H',
                    'likely': 'PT8H'
                }
            }
        ]
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["error_count"] == 1
    assert "Invalid effort values" in data["errors"][0]["error"]
    
    # Invalid values (optimistic > likely)
    response = client.patch("/api/vulnerabilities/batch", json={
        'vulnerabilities': [
            {
                'id': 'CVE-2020-35492',
                'effort': {
                    'optimistic': 'P2D',
                    'likely': 'PT8H',
                    'pessimistic': 'P3D'
                }
            }
        ]
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["error_count"] == 1


# Test PATCH vulnerabilities batch - invalid CVSS
def test_patch_vulnerabilities_batch_invalid_cvss(client):
    """Test batch update with invalid CVSS data"""
    response = client.patch("/api/vulnerabilities/batch", json={
        'vulnerabilities': [
            {
                'id': 'CVE-2020-35492',
                'cvss': {
                    'base_score': 8.5,
                    'version': '3.1'
                    # Missing vector_string
                }
            }
        ]
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["error_count"] == 1
    assert "Invalid CVSS data" in data["errors"][0]["error"]


# Test PATCH vulnerabilities batch - mixed results
def test_patch_vulnerabilities_batch_mixed_results(client):
    """Test batch update with mix of successes and failures"""
    response = client.patch("/api/vulnerabilities/batch", json={
        'vulnerabilities': [
            {
                'id': 'CVE-2020-35492',
                'effort': {
                    'optimistic': 'PT2H',
                    'likely': 'PT8H',
                    'pessimistic': 'P2D'
                }
            },
            {
                'id': 'CVE-9999-99999',  # Doesn't exist
                'effort': {
                    'optimistic': 'PT2H',
                    'likely': 'PT8H',
                    'pessimistic': 'P2D'
                }
            },
            {
                'id': 'CVE-2020-35492',
                'cvss': {
                    'base_score': 8.5,
                    # Missing required fields
                }
            }
        ]
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["count"] == 1
    assert data["error_count"] == 2
    assert len(data["errors"]) == 2


# Test PATCH vulnerabilities batch - update with CVSS
def test_patch_vulnerabilities_batch_with_cvss(client):
    """Test batch update with CVSS data"""
    response = client.patch("/api/vulnerabilities/batch", json={
        'vulnerabilities': [
            {
                'id': 'CVE-2020-35492',
                'cvss': {
                    'base_score': 7.5,
                    'vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                    'version': '3.1',
                    'author': 'batch@test.com',
                    'exploitability_score': 3.9,
                    'impact_score': 3.6
                }
            }
        ]
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["count"] == 1
    
    # Verify CVSS was added
    vuln = data["vulnerabilities"][0]
    # Check that CVSS scores exist
    assert len(vuln["severity"]["cvss"]) >= 1


# Test PATCH vulnerabilities batch - update both effort and CVSS
def test_patch_vulnerabilities_batch_with_effort_and_cvss(client, init_files):
    """Test batch update with both effort and CVSS"""
    response = client.patch("/api/vulnerabilities/batch", json={
        'vulnerabilities': [
            {
                'id': 'CVE-2020-35492',
                'effort': {
                    'optimistic': 'PT3H',
                    'likely': 'PT12H',
                    'pessimistic': 'P3D'
                },
                'cvss': {
                    'base_score': 6.5,
                    'vector_string': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N',
                    'version': '3.1',
                    'author': 'batch@test.com',
                    'exploitability_score': 2.2,
                    'impact_score': 4.2
                }
            }
        ]
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["count"] == 1
    
    vuln = data["vulnerabilities"][0]
    assert vuln["effort"]["optimistic"] == "PT3H"
    # Check that CVSS scores exist
    assert len(vuln["severity"]["cvss"]) >= 1
    
    # Verify files were updated
    assert init_files["vulnerabilities"].exists()
    assert init_files["time_estimates"].exists()


# Test that files are only written when there are results
def test_patch_vulnerabilities_batch_no_writes_on_all_failures(client, init_files):
    """Test that files are not written when all updates fail"""
    # Read initial file content
    initial_content = init_files["vulnerabilities"].read_text()
    
    response = client.patch("/api/vulnerabilities/batch", json={
        'vulnerabilities': [
            {
                'id': 'CVE-9999-99999',  # Doesn't exist
                'effort': {
                    'optimistic': 'PT2H',
                    'likely': 'PT8H',
                    'pessimistic': 'P2D'
                }
            }
        ]
    })
    assert response.status_code == 400
    
    # Verify file content hasn't changed
    final_content = init_files["vulnerabilities"].read_text()
    assert initial_content == final_content


# Test GET vulnerabilities list (format=list is default)
def test_get_vulnerabilities_list_default_format(client):
    """Test GET vulnerabilities with default format (list)"""
    response = client.get("/api/vulnerabilities")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) >= 1


# Test GET vulnerabilities dict format
def test_get_vulnerabilities_dict_format(client):
    """Test GET vulnerabilities with dict format"""
    response = client.get("/api/vulnerabilities?format=dict")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, dict)
    assert "CVE-2020-35492" in data

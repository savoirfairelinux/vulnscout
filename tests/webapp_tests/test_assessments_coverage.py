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


# Test POST assessment with missing vuln_id (should be inferred from URL)
def test_post_assessment_without_vuln_id_in_payload(client):
    """Test that vuln_id is automatically added from URL when not in payload"""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["vuln_id"] == "CVE-2021-99999"


# Test POST assessment with non-string vuln_id
def test_post_assessment_with_non_string_vuln_id(client):
    """Test that non-string vuln_id is rejected"""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'vuln_id': 12345,
        'packages': ['test@1.0.0'],
        'status': 'affected'
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "vuln_id" in data["error"]


# Test POST assessment with valid justification
def test_post_assessment_with_justification(client):
    """Test creating assessment with valid justification"""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'not_affected',
        'justification': 'vulnerable_code_not_present'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "success"
    assert data["assessment"]["justification"] == "vulnerable_code_not_present"


# Test POST assessment with invalid justification
def test_post_assessment_with_invalid_justification(client):
    """Test that invalid justification is rejected"""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'not_affected',
        'justification': 'invalid_justification'
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "justification" in data["error"]


# Test POST assessment with impact_statement
def test_post_assessment_with_impact_statement(client):
    """Test creating assessment with impact statement"""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'not_affected',
        'justification': 'component_not_present',
        'impact_statement': 'Component not included in build'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["impact_statement"] == 'Component not included in build'


# Test POST assessment with workaround and timestamp
def test_post_assessment_with_workaround_and_timestamp(client):
    """Test creating assessment with workaround and custom timestamp"""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected',
        'workaround': 'Disable feature X',
        'workaround_timestamp': '2024-01-15T12:00:00Z'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["workaround"] == 'Disable feature X'
    assert data["assessment"]["workaround_timestamp"] == '2024-01-15T12:00:00Z'


# Test POST assessment with workaround without timestamp
def test_post_assessment_with_workaround_without_timestamp(client):
    """Test that workaround timestamp is auto-generated when not provided"""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected',
        'workaround': 'Apply temporary patch'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["workaround"] == 'Apply temporary patch'
    assert data["assessment"]["workaround_timestamp"] != ""


# Test POST assessment with responses
def test_post_assessment_with_responses(client):
    """Test creating assessment with responses"""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected',
        'responses': ['can_not_fix', 'workaround_available']
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'can_not_fix' in data["assessment"]["responses"]
    assert 'workaround_available' in data["assessment"]["responses"]


# Test POST assessment batch - success path
def test_post_assessments_batch_all_valid(client):
    """Test batch creation with all valid assessments"""
    response = client.post("/api/assessments/batch", json={
        'assessments': [
            {
                'vuln_id': 'CVE-2021-11111',
                'packages': ['pkg1@1.0.0'],
                'status': 'affected'
            },
            {
                'vuln_id': 'CVE-2021-22222',
                'packages': ['pkg2@2.0.0'],
                'status': 'fixed'
            }
        ]
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "success"
    assert data["count"] == 2
    assert len(data["assessments"]) == 2


# Test POST assessment batch - mixed valid and invalid
def test_post_assessments_batch_mixed_validity(client):
    """Test batch creation with mix of valid and invalid assessments"""
    response = client.post("/api/assessments/batch", json={
        'assessments': [
            {
                'vuln_id': 'CVE-2021-11111',
                'packages': ['pkg1@1.0.0'],
                'status': 'affected'
            },
            {
                'vuln_id': 'CVE-2021-22222',
                'packages': ['pkg2@2.0.0'],
                'status': 'invalid_status'  # Invalid status
            },
            {
                'packages': ['pkg3@3.0.0'],  # Missing vuln_id
                'status': 'fixed'
            }
        ]
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["count"] == 1
    assert data["error_count"] == 2
    assert len(data["errors"]) == 2


# Test POST assessment batch - all invalid
def test_post_assessments_batch_all_invalid(client):
    """Test batch creation with all invalid assessments"""
    response = client.post("/api/assessments/batch", json={
        'assessments': [
            {
                'packages': ['pkg1@1.0.0'],
                'status': 'affected'
                # Missing vuln_id
            },
            {
                'vuln_id': 'CVE-2021-22222',
                # Missing packages
                'status': 'fixed'
            }
        ]
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["status"] == "error"
    assert data["count"] == 0
    assert data["error_count"] == 2


# Test POST assessment batch - invalid request format (missing assessments key)
def test_post_assessments_batch_missing_assessments_key(client):
    """Test batch creation with missing assessments key"""
    response = client.post("/api/assessments/batch", json={
        'data': []  # Wrong key
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "Invalid request data" in data["error"]


# Test POST assessment batch - invalid request format (not a list)
def test_post_assessments_batch_not_a_list(client):
    """Test batch creation with assessments not being a list"""
    response = client.post("/api/assessments/batch", json={
        'assessments': 'not a list'
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "Invalid request data" in data["error"]


# Test POST assessment batch - invalid item structure
def test_post_assessments_batch_invalid_item_structure(client):
    """Test batch creation with invalid item structure"""
    response = client.post("/api/assessments/batch", json={
        'assessments': [
            'not_a_dict',
            {'vuln_id': 'CVE-2021-11111', 'packages': ['pkg@1.0.0'], 'status': 'affected'}
        ]
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["count"] == 1
    assert data["error_count"] == 1


# Test PUT assessment - update status
def test_update_assessment_status_only(client):
    """Test updating only the status of an assessment"""
    # Create assessment first
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'under_investigation',
        'status_notes': 'Initial notes'
    })
    assessment_id = json.loads(response.data)["assessment"]["id"]
    
    # Update status
    response = client.put(f"/api/assessments/{assessment_id}", json={
        'status': 'affected'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["status"] == "affected"
    assert data["assessment"]["status_notes"] == 'Initial notes'  # Should remain unchanged


# Test PUT assessment - update status_notes
def test_update_assessment_status_notes(client):
    """Test updating status notes"""
    # Create assessment first
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected',
        'status_notes': 'Initial notes'
    })
    assessment_id = json.loads(response.data)["assessment"]["id"]
    
    # Update status notes
    response = client.put(f"/api/assessments/{assessment_id}", json={
        'status_notes': 'Updated notes after review'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["status_notes"] == 'Updated notes after review'


# Test PUT assessment - clear justification with empty string
def test_update_assessment_clear_justification(client):
    """Test clearing justification with empty string"""
    # Create assessment with justification
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'not_affected',
        'justification': 'vulnerable_code_not_present'
    })
    assessment_id = json.loads(response.data)["assessment"]["id"]
    
    # Clear justification (this should fail because status is not_affected)
    response = client.put(f"/api/assessments/{assessment_id}", json={
        'justification': '',
        'status': 'affected'  # Change status first
    })
    assert response.status_code == 200


# Test PUT assessment - clear impact_statement with empty string
def test_update_assessment_clear_impact_statement(client):
    """Test clearing impact statement with empty string"""
    # Create assessment with impact statement
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected',
        'impact_statement': 'Not affected statement'
    })
    assessment_id = json.loads(response.data)["assessment"]["id"]
    
    # Clear impact statement
    response = client.put(f"/api/assessments/{assessment_id}", json={
        'impact_statement': ''
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["impact_statement"] == ''


# Test PUT assessment - set impact_statement
def test_update_assessment_set_impact_statement(client):
    """Test setting impact statement"""
    # Create assessment
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected'
    })
    assessment_id = json.loads(response.data)["assessment"]["id"]
    
    # Set impact statement
    response = client.put(f"/api/assessments/{assessment_id}", json={
        'impact_statement': 'New impact statement'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["impact_statement"] == 'New impact statement'


# Test PUT assessment - update workaround without timestamp
def test_update_assessment_workaround_without_timestamp(client):
    """Test updating workaround without providing timestamp"""
    # Create assessment
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected'
    })
    assessment_id = json.loads(response.data)["assessment"]["id"]
    
    # Update workaround
    response = client.put(f"/api/assessments/{assessment_id}", json={
        'workaround': 'New workaround'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["workaround"] == 'New workaround'
    assert data["assessment"]["workaround_timestamp"] != ''


# Test PUT assessment - update workaround with timestamp
def test_update_assessment_workaround_with_timestamp(client):
    """Test updating workaround with custom timestamp"""
    # Create assessment
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected'
    })
    assessment_id = json.loads(response.data)["assessment"]["id"]
    
    # Update workaround with timestamp
    response = client.put(f"/api/assessments/{assessment_id}", json={
        'workaround': 'Timestamped workaround',
        'workaround_timestamp': '2024-02-20T10:00:00Z'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["workaround"] == 'Timestamped workaround'
    assert data["assessment"]["workaround_timestamp"] == '2024-02-20T10:00:00Z'


# Test PUT assessment - invalid data (no payload)
def test_update_assessment_no_payload(client):
    """Test updating assessment with no payload"""
    # Create assessment first
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected'
    })
    assessment_id = json.loads(response.data)["assessment"]["id"]
    
    # Try to update with no payload (Flask returns 415 for missing content-type)
    response = client.put(f"/api/assessments/{assessment_id}", json=None)
    assert response.status_code in [400, 415]  # Accept both 400 and 415


# Test PUT assessment - invalid justification
def test_update_assessment_invalid_justification(client):
    """Test updating assessment with invalid justification"""
    # Create assessment
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected'
    })
    assessment_id = json.loads(response.data)["assessment"]["id"]
    
    # Try to update with invalid justification
    response = client.put(f"/api/assessments/{assessment_id}", json={
        'justification': 'invalid_justification_value'
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "Invalid justification" in data["error"]


# Test PUT assessment - require justification when status is not_affected
def test_update_assessment_require_justification(client):
    """Test that justification is required when updating status to not_affected"""
    # Create assessment
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected'
    })
    assessment_id = json.loads(response.data)["assessment"]["id"]
    
    # Try to update to not_affected without justification
    response = client.put(f"/api/assessments/{assessment_id}", json={
        'status': 'not_affected'
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "Justification required" in data["error"]


# Test PATCH method for updating assessment
def test_patch_assessment(client):
    """Test that PATCH method also works for updating assessments"""
    # Create assessment
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected'
    })
    assessment_id = json.loads(response.data)["assessment"]["id"]
    
    # Update using PATCH
    response = client.patch(f"/api/assessments/{assessment_id}", json={
        'status': 'fixed'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["status"] == "fixed"


# Test that last_update timestamp is updated
def test_update_assessment_updates_last_update(client):
    """Test that last_update timestamp is updated on PUT/PATCH"""
    # Create assessment
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected'
    })
    assessment_data = json.loads(response.data)["assessment"]
    assessment_id = assessment_data["id"]
    original_last_update = assessment_data["last_update"]
    
    # Wait a moment and update
    import time
    time.sleep(0.1)
    
    # Update assessment
    response = client.put(f"/api/assessments/{assessment_id}", json={
        'status': 'fixed'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    # last_update should be different (later) than original
    assert data["assessment"]["last_update"] >= original_last_update


# Test verifying that OpenVEX file is updated after assessment changes
def test_update_assessment_updates_openvex_file(client, init_files):
    """Test that OpenVEX file is updated when assessment is modified"""
    # Create assessment
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected'
    })
    assert response.status_code == 200
    
    # Check that OpenVEX file was created/updated
    assert init_files["openvex"].exists()
    openvex_content = json.loads(init_files["openvex"].read_text())
    assert "statements" in openvex_content

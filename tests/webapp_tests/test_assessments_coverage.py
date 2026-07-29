# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import json
from src.bin.webapp import create_app
from src.extensions import db
from src.models.finding import Finding
from src.models.metrics import Metrics
from src.models.time_estimate import TimeEstimate
from . import write_demo_files, setup_demo_db


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
            "OPENVEX_FILE": init_files["openvex"],
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db"
        })
        setup_demo_db(application, extra_packages=["test@1.0.0", "pkg@1.0.0", "pkg1@1.0.0", "pkg2@2.0.0", "pkg3@3.0.0"])
        with application.app_context():
            from src.extensions import db
            from src.models.finding import Finding
            from src.models.observation import Observation
            from src.models.package import Package
            from src.models.vulnerability import Vulnerability

            for vuln_id in ("CVE-2021-99999", "CVE-2021-11111", "CVE-2021-22222"):
                Vulnerability.get_or_create(vuln_id)
                for package_id in ("test@1.0.0", "pkg@1.0.0", "pkg1@1.0.0", "pkg2@2.0.0", "pkg3@3.0.0"):
                    package = Package.get_by_string_id(package_id)
                    assert package is not None
                    finding = Finding.get_or_create(package.id, vuln_id)
                    Observation.create(finding.id, "33333333-3333-3333-3333-333333333333", commit=False)
            db.session.commit()
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


# Test POST assessment with missing vuln_id (should be inferred from URL)
DEMO_VARIANT_ID = "22222222-2222-2222-2222-222222222222"


def test_post_assessment_without_vuln_id_in_payload(client):
    """Test that vuln_id is automatically added from URL when not in payload"""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected',
        'variant_id': DEMO_VARIANT_ID,
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["vuln_id"] == "CVE-2021-99999"


def test_bulk_delete_review_time_estimates(client, app):
    with app.app_context():
        finding = Finding.get_by_vulnerability("CVE-2020-35492")[0]
        estimate = TimeEstimate(
            finding_id=finding.id,
            optimistic=1,
            likely=2,
            pessimistic=3,
        )
        db.session.add(estimate)
        db.session.commit()
        estimate_id = str(estimate.id)

    listed = client.get("/api/assessments/review/time-estimates")
    assert listed.status_code == 200
    assert any(item["id"] == estimate_id for item in listed.get_json())

    deleted = client.delete("/api/assessments/review/time-estimates", json={"ids": [estimate_id]})
    assert deleted.status_code == 200
    assert deleted.get_json()["deleted"] == [estimate_id]
    assert all(item["id"] != estimate_id for item in client.get("/api/assessments/review/time-estimates").get_json())


def test_bulk_delete_review_custom_cvss_preserves_scanner_data(client, app):
    with app.app_context():
        custom = Metrics.create(
            vulnerability_id="CVE-2020-35492",
            version="3.1",
            score=7.5,
            vector="CVSS:3.1/AV:N",
            author="reviewer",
            origin="custom",
        )
        scanner = Metrics.create(
            vulnerability_id="CVE-2020-35492",
            version="3.1",
            score=7.5,
            vector="CVSS:3.1/AV:N",
            author="nvd@nist.gov",
            origin="scanner",
        )
        custom_id = str(custom.id)
        scanner_id = str(scanner.id)

    listed = client.get("/api/assessments/review/custom-cvss")
    assert listed.status_code == 200
    assert any(item["id"] == custom_id for item in listed.get_json())

    deleted = client.delete("/api/assessments/review/custom-cvss", json={"ids": [custom_id]})
    assert deleted.status_code == 200
    assert deleted.get_json()["deleted"] == [custom_id]

    scanner_delete = client.delete("/api/assessments/review/custom-cvss", json={"ids": [scanner_id]})
    assert scanner_delete.status_code == 404
    with app.app_context():
        assert Metrics.get_by_id(scanner_id) is not None


# Test POST assessment with non-string vuln_id
def test_post_assessment_with_non_string_vuln_id(client):
    """Test that non-string vuln_id is rejected"""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'vuln_id': 12345,
        'packages': ['test@1.0.0'],
        'status': 'affected',
        'variant_id': DEMO_VARIANT_ID,
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
        'justification': 'vulnerable_code_not_present',
        'variant_id': DEMO_VARIANT_ID,
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
        'justification': 'invalid_justification',
        'variant_id': DEMO_VARIANT_ID,
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
        'impact_statement': 'Component not included in build',
        'variant_id': DEMO_VARIANT_ID,
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
        'workaround_timestamp': '2024-01-15T12:00:00Z',
        'variant_id': DEMO_VARIANT_ID,
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["workaround"] == 'Disable feature X'


# Test POST assessment with workaround without timestamp
def test_post_assessment_with_workaround_without_timestamp(client):
    """Test that workaround timestamp is auto-generated when not provided"""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected',
        'workaround': 'Apply temporary patch',
        'variant_id': DEMO_VARIANT_ID,
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["workaround"] == 'Apply temporary patch'


# Test POST assessment with responses
def test_post_assessment_with_responses(client):
    """Test creating assessment with responses"""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected',
        'responses': ['can_not_fix', 'workaround_available'],
        'variant_id': DEMO_VARIANT_ID,
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
                'status': 'affected',
                'variant_id': DEMO_VARIANT_ID,
            },
            {
                'vuln_id': 'CVE-2021-22222',
                'packages': ['pkg2@2.0.0'],
                'status': 'fixed',
                'variant_id': DEMO_VARIANT_ID,
            }
        ]
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "success"
    assert data["count"] == 2
    assert data["vuln_count"] == 2
    assert len(data["assessments"]) == 2


# Test POST assessment batch - mixed valid and invalid
def test_post_assessments_batch_mixed_validity(client):
    """A mix of valid and invalid assessments cancels the whole batch."""
    response = client.post("/api/assessments/batch", json={
        'assessments': [
            {
                'vuln_id': 'CVE-2021-11111',
                'packages': ['pkg1@1.0.0'],
                'status': 'affected',
                'variant_id': DEMO_VARIANT_ID,
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
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["count"] == 0
    assert data["vuln_count"] == 0
    assert data["assessments"] == []
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
        ],
        'variant_id': DEMO_VARIANT_ID,
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
    """An invalid item structure cancels valid entries in the same batch."""
    response = client.post("/api/assessments/batch", json={
        'assessments': [
            'not_a_dict',
            {'vuln_id': 'CVE-2021-11111', 'packages': ['pkg@1.0.0'], 'status': 'affected',
             'variant_id': DEMO_VARIANT_ID}
        ]
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["count"] == 0
    assert data["assessments"] == []
    assert data["error_count"] == 1


# Test PUT assessment - update status
def test_update_assessment_status_only(client):
    """Test updating only the status of an assessment"""
    # Create assessment first
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'under_investigation',
        'status_notes': 'Initial notes',
        'variant_id': DEMO_VARIANT_ID,
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


def test_update_assessment_can_preserve_timestamp(client):
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'under_investigation',
        'variant_id': DEMO_VARIANT_ID,
        'timestamp': '2024-01-15T12:00:00Z',
    })
    assessment = json.loads(response.data)["assessment"]

    response = client.put(f"/api/assessments/{assessment['id']}", json={
        'status': 'affected',
        'update_timestamp': False,
    })

    assert response.status_code == 200
    updated = json.loads(response.data)["assessment"]
    assert updated["timestamp"] == assessment["timestamp"]


def test_update_assessment_accepts_shared_timestamp(client):
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'under_investigation',
        'variant_id': DEMO_VARIANT_ID,
    })
    assessment_id = json.loads(response.data)["assessment"]["id"]

    response = client.put(f"/api/assessments/{assessment_id}", json={
        'status': 'affected',
        'update_timestamp': True,
        'timestamp': '2026-07-28T12:34:56Z',
    })

    assert response.status_code == 200
    assert json.loads(response.data)["assessment"]["timestamp"] == '2026-07-28T12:34:56+00:00'


# Test PUT assessment - update status_notes
def test_update_assessment_status_notes(client):
    """Test updating status notes"""
    # Create assessment first
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected',
        'status_notes': 'Initial notes',
        'variant_id': DEMO_VARIANT_ID,
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
        'justification': 'vulnerable_code_not_present',
        'variant_id': DEMO_VARIANT_ID,
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
        'impact_statement': 'Not affected statement',
        'variant_id': DEMO_VARIANT_ID,
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
        'status': 'affected',
        'variant_id': DEMO_VARIANT_ID,
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
        'status': 'affected',
        'variant_id': DEMO_VARIANT_ID,
    })
    assessment_id = json.loads(response.data)["assessment"]["id"]
    
    # Update workaround
    response = client.put(f"/api/assessments/{assessment_id}", json={
        'workaround': 'New workaround'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["workaround"] == 'New workaround'


# Test PUT assessment - update workaround with timestamp
def test_update_assessment_workaround_with_timestamp(client):
    """Test updating workaround with custom timestamp"""
    # Create assessment
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected',
        'variant_id': DEMO_VARIANT_ID,
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


# Test PUT assessment - invalid data (no payload)
def test_update_assessment_no_payload(client):
    """Test updating assessment with no payload"""
    # Create assessment first
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        'packages': ['test@1.0.0'],
        'status': 'affected',
        'variant_id': DEMO_VARIANT_ID,
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
        'status': 'affected',
        'variant_id': DEMO_VARIANT_ID,
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
        'status': 'affected',
        'variant_id': DEMO_VARIANT_ID,
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
        'status': 'affected',
        'variant_id': DEMO_VARIANT_ID,
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
        'status': 'affected',
        'variant_id': DEMO_VARIANT_ID,
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


def test_post_assessment_invalid_timestamp(client):
    """POST with an unparseable timestamp string falls back silently (lines 257-258)."""
    response = client.post("/api/vulnerabilities/CVE-2020-35492/assessments", json={
        "packages": ["cairo@1.16.0"],
        "status": "affected",
        "timestamp": "not-a-valid-timestamp",
        'variant_id': DEMO_VARIANT_ID,
    })
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# GET /api/assessments?project_id=... — invalid UUID (line 71)
# ---------------------------------------------------------------------------

def test_get_assessments_invalid_project_id(client):
    """GET /api/assessments with an invalid project_id UUID returns 400 (line 71)."""
    response = client.get("/api/assessments?project_id=not-a-valid-uuid")
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "Invalid project_id" in data["error"]


# ---------------------------------------------------------------------------
# GET /api/vulnerabilities/<vuln_id>/variants — line 111 (return variants_out, 200)
# ---------------------------------------------------------------------------

def test_get_variants_by_vuln(client):
    """GET /api/vulnerabilities/<vuln_id>/variants returns 200 list (line 111)."""
    response = client.get("/api/vulnerabilities/CVE-2020-35492/variants")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)


# ---------------------------------------------------------------------------
# POST /api/vulnerabilities/<vuln_id>/assessments — variant_id / vuln_id errors
# ---------------------------------------------------------------------------

def test_post_assessment_invalid_variant_id(client):
    """POST assessment with non-UUID variant_id returns 400 (lines 175-176)."""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        "packages": ["test@1.0.0"],
        "status": "affected",
        "variant_id": "not-a-valid-uuid",
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "variant_id" in data["error"].lower() or "invalid" in data["error"].lower()


def test_post_assessment_vuln_id_mismatch(client):
    """POST assessment with mismatched vuln_id in payload returns 400 (line 179)."""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        "vuln_id": "CVE-2021-DIFFERENT",
        "packages": ["test@1.0.0"],
        "status": "affected",
        'variant_id': DEMO_VARIANT_ID,
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "vuln_id" in data["error"].lower() or "invalid" in data["error"].lower()


# ---------------------------------------------------------------------------
# POST /api/assessments/batch — invalid variant_id (lines 212-213)
# ---------------------------------------------------------------------------

def test_post_assessments_batch_invalid_variant_id(client):
    """Batch assessment with invalid variant_id appends error and continues (lines 212-213)."""
    response = client.post("/api/assessments/batch", json={
        "assessments": [
            {
                "vuln_id": "CVE-2021-11111",
                "packages": ["pkg1@1.0.0"],
                "status": "affected",
                "variant_id": "not-a-valid-uuid",
            }
        ]
    })
    data = json.loads(response.data)
    assert data["error_count"] >= 1
    assert any("variant_id" in str(e).lower() or "invalid" in str(e).lower()
               for e in data["errors"])


def test_post_assessments_batch_is_atomic_when_one_variant_is_invalid(client, app):
    """One invalid package/variant pair cancels every item in the batch."""
    from src.models.assessment import Assessment

    with app.app_context():
        before = len(Assessment.get_by_vulnerability("CVE-2021-11111"))

    response = client.post("/api/assessments/batch", json={
        "assessments": [
            {
                "vuln_id": "CVE-2021-11111",
                "packages": ["pkg1@1.0.0"],
                "status": "affected",
                "variant_id": DEMO_VARIANT_ID,
            },
            {
                "vuln_id": "CVE-2021-11111",
                "packages": ["pkg1@1.0.0"],
                "status": "affected",
                "variant_id": "22222222-2222-2222-2222-222222222223",
            },
        ]
    })

    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["status"] == "error"
    assert data["count"] == 0
    assert data["assessments"] == []
    assert data["error_count"] == 1
    with app.app_context():
        assert len(Assessment.get_by_vulnerability("CVE-2021-11111")) == before


# ---------------------------------------------------------------------------
# POST /api/assessments/batch — DB error in item (lines 252-253)
# ---------------------------------------------------------------------------

def test_post_assessments_batch_db_error(client, monkeypatch):
    """A DB error during batch item processing appends error entry (lines 252-253)."""
    from src.models.finding import Finding as DBFinding

    def fail_get_or_create(*args, **kwargs):
        raise RuntimeError("simulated DB error")

    monkeypatch.setattr(DBFinding, "get_or_create", fail_get_or_create)

    response = client.post("/api/assessments/batch", json={
        "assessments": [
            {
                "vuln_id": "CVE-2021-11111",
                "packages": ["pkg1@1.0.0"],
                "status": "affected",
            }
        ],
        'variant_id': DEMO_VARIANT_ID,
    })
    data = json.loads(response.data)
    assert data["error_count"] >= 1


# ---------------------------------------------------------------------------
# POST /api/vulnerabilities/<vuln_id>/assessments — missing variant_id rejected
# ---------------------------------------------------------------------------

def test_post_assessment_missing_variant_id_returns_400(client):
    """POST assessment without variant_id must be rejected with 400."""
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        "packages": ["test@1.0.0"],
        "status": "affected",
        # no variant_id
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "variant_id" in data["error"].lower()


# ---------------------------------------------------------------------------
# POST /api/assessments/batch — missing variant_id rejected per item
# ---------------------------------------------------------------------------

def test_post_assessments_batch_missing_variant_id_returns_error(client):
    """Batch assessment item without variant_id must produce an error entry."""
    response = client.post("/api/assessments/batch", json={
        "assessments": [
            {
                "vuln_id": "CVE-2021-11111",
                "packages": ["pkg1@1.0.0"],
                "status": "affected",
                # no variant_id
            }
        ]
    })
    data = json.loads(response.data)
    assert data.get("error_count", 0) >= 1
    assert any("variant_id" in str(e).lower() for e in data.get("errors", []))


# ---------------------------------------------------------------------------
# PATCH /api/assessments/<id> — clearing justification for non-not_affected (line 271)
# ---------------------------------------------------------------------------

def test_patch_assessment_clears_justification_and_impact(client):
    """PATCH to a non-not_affected/false_positive status clears justification (line 271)."""
    # Create an assessment with not_affected + justification
    response = client.post("/api/vulnerabilities/CVE-2021-99999/assessments", json={
        "packages": ["test@1.0.0"],
        "status": "not_affected",
        "justification": "component_not_present",
        "impact_statement": "Not present in this build",
        'variant_id': DEMO_VARIANT_ID,
    })
    assert response.status_code == 200
    assessment_id = json.loads(response.data)["assessment"]["id"]

    # Now PATCH to 'affected' — should clear justification and impact_statement
    response = client.patch(f"/api/assessments/{assessment_id}", json={
        "status": "affected",
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    # justification and impact_statement should be cleared (line 271)
    assert data["assessment"]["justification"] == "" or data["assessment"]["justification"] is None
    assert data["assessment"]["impact_statement"] == "" or data["assessment"]["impact_statement"] is None

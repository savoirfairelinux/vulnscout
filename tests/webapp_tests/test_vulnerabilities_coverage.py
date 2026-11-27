# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import gzip
import json
from uuid import UUID
from flask import Flask
from src.bin.webapp import create_app
from src.routes.vulnerabilities import _compact_json_response
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
        setup_demo_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


def test_match_condition_returns_matching_vulnerability_ids(client):
    response = client.post("/api/vulnerabilities/match-condition", json={
        "condition": "cvss >= 7 and pending",
        "items": [
            {"id": "CVE-HIGH", "data": {"cvss": 8.1, "pending": True}},
            {"id": "CVE-LOW", "data": {"cvss": 4.2, "pending": True}},
            {"id": "CVE-FIXED", "data": {"cvss": 9.0, "pending": False}},
        ],
    })

    assert response.status_code == 200
    assert response.get_json() == {"matching_ids": ["CVE-HIGH"]}


def test_match_condition_rejects_invalid_expression(client):
    response = client.post("/api/vulnerabilities/match-condition", json={
        "condition": "cvss >",
        "items": [{"id": "CVE-1", "data": {"cvss": 8.1}}],
    })

    assert response.status_code == 400
    assert response.get_json()["error"].startswith("Invalid match condition:")


def test_match_condition_rejects_oversized_condition(client):
    response = client.post("/api/vulnerabilities/match-condition", json={
        "condition": "cvss > 7 " + "or cvss > 7 " * 200,
        "items": [{"id": "CVE-1", "data": {"cvss": 8.1}}],
    })

    assert response.status_code == 400
    assert "at most" in response.get_json()["error"]


def test_match_condition_rejects_oversized_items_list(client):
    response = client.post("/api/vulnerabilities/match-condition", json={
        "condition": "cvss > 7",
        "items": [{"id": f"CVE-{i}", "data": {}} for i in range(50_001)],
    })

    assert response.status_code == 400
    assert "at most" in response.get_json()["error"]


@pytest.mark.parametrize("condition", [
    "id == CVE-TEST-0001",
    "cvss > 8",
    "cvss > -1",
    "cvss >= 9.8",
    "cvss_min < 8",
    "cvss_min <= 7.5",
    "epss == 50%",
    "epss > .42",
    "epss != 25%",
    "effort == 3600",
    "effort_min <= 1800",
    "effort_max >= 7200",
    "known_exploitable",
    "fixed",
    "not ignored",
    "affected or pending",
    "fixed AND NOT ignored",
    "not new",
    "(cvss >= 9 or epss >= 50%) and affected",
    "true == true",
    "false == false",
])
def test_match_condition_supports_documented_language(client, condition):
    item = {
        "id": "CVE-TEST-0001",
        "data": {
            "id": "CVE-TEST-0001",
            "cvss": 9.8,
            "cvss_min": 7.5,
            "epss": 0.5,
            "effort": 3600,
            "effort_min": 1800,
            "effort_max": 7200,
            "known_exploitable": True,
            "fixed": True,
            "ignored": False,
            "affected": True,
            "pending": False,
            "new": False,
        },
    }

    response = client.post("/api/vulnerabilities/match-condition", json={
        "condition": condition,
        "items": [item],
    })

    assert response.status_code == 200, response.get_json()
    assert response.get_json() == {"matching_ids": ["CVE-TEST-0001"]}


@pytest.mark.parametrize("condition", [
    "unknown == 2",
    "true == true == true",
    "true == true and",
    "cvss > CVE-TEST-0001",
])
def test_match_condition_rejects_invalid_language(client, condition):
    response = client.post("/api/vulnerabilities/match-condition", json={
        "condition": condition,
        "items": [{"id": "CVE-1", "data": {"cvss": 8.1, "fixed": False}}],
    })

    assert response.status_code == 400
    assert response.get_json()["error"].startswith("Invalid match condition:")


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


def test_patch_vulnerability_no_body(client):
    """PATCH with no JSON body returns 400/415 instead of 500 (None payload guard)."""
    # Wrong content-type → Flask returns 415; empty JSON body → our guard returns 400
    response = client.patch("/api/vulnerabilities/CVE-2020-35492",
                            data=b"", content_type="text/plain")
    assert response.status_code in (400, 415)

    response = client.patch("/api/vulnerabilities/CVE-2020-35492",
                            data=b"null", content_type="application/json")
    assert response.status_code == 400


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
def test_patch_vulnerabilities_batch_with_cvss(client, monkeypatch):
    """Test batch update with CVSS data"""
    from src.models import Metrics
    monkeypatch.setattr(Metrics, "_seen", set())

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


# ---------------------------------------------------------------------------
# PATCH /api/vulnerabilities/<id> — effort missing keys / invalid value / ordering
# ---------------------------------------------------------------------------

def test_patch_vulnerability_effort_missing_key(client):
    """PATCH effort with missing 'pessimistic' key returns 400 (line 63)."""
    response = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        "effort": {
            "optimistic": "PT1H",
            "likely": "PT4H"
            # missing pessimistic
        }
    })
    assert response.status_code == 400
    assert b"Invalid effort" in response.data


def test_patch_vulnerability_effort_invalid_type(client):
    """PATCH effort with non-string/int values raises (ValueError) → 400 (lines 67-68)."""
    response = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        "effort": {
            "optimistic": None,
            "likely": None,
            "pessimistic": None,
        }
    })
    assert response.status_code == 400
    assert b"Invalid effort" in response.data


def test_patch_vulnerability_effort_not_ordered(client):
    """PATCH effort where optimistic > likely returns 400 (lines 78-79)."""
    response = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        "effort": {
            "optimistic": "P2D",   # 2 days
            "likely": "PT1H",      # 1 hour  (optimistic > likely)
            "pessimistic": "P3D",
        }
    })
    assert response.status_code == 400
    assert b"Invalid effort" in response.data


# ---------------------------------------------------------------------------
# PATCH /api/vulnerabilities/batch — effort and CVSS error paths
# ---------------------------------------------------------------------------

def test_patch_batch_effort_invalid_type(client):
    """Batch PATCH: invalid effort type for a valid vulnerability (line 128-129)."""
    response = client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "effort": {
                "optimistic": None,
                "likely": None,
                "pessimistic": None,
            }
        }]
    })
    data = json.loads(response.data)
    assert data["error_count"] == 1
    assert "Invalid effort values" in data["errors"][0]["error"]


def test_patch_batch_effort_ordering_error(client):
    """Batch PATCH: optimistic > likely returns error entry (line 124)."""
    response = client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "effort": {
                "optimistic": "P2D",
                "likely": "PT1H",
                "pessimistic": "P3D",
            }
        }]
    })
    data = json.loads(response.data)
    assert data["error_count"] == 1
    assert "Invalid effort values" in data["errors"][0]["error"]


def test_bulk_effort_rejects_note_only_targets_and_round_trips_historical_zero(app, client, monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError

    from src.extensions import db
    from src.models import (
        Finding, Observation, Package, Project, SBOMDocument, SBOMObservation, SBOMPackage,
        Scan, TimeEstimate, Variant, Vulnerability,
    )

    note_id = "TEST-EFFORT-NOTE"
    historical_id = "TEST-EFFORT-HISTORICAL"
    with app.app_context():
        project = Project.create("Effort project")
        first = Variant.create("first", project.id)
        second = Variant.create("second", project.id)
        first_id, second_id, project_id = map(str, (first.id, second.id, project.id))
        old = Scan.create("old inventory", first.id)
        old_doc = SBOMDocument.create("/old.cdx.json", "old.cdx.json", old.id)
        package = Package.find_or_create("test-effort-package", "1")
        SBOMPackage.create(old_doc.id, package.id)
        Vulnerability.create_record(id=historical_id)
        historical_finding = Finding.get_or_create(package.id, historical_id)
        Observation.create(historical_finding.id, old.id)
        finding_id = historical_finding.id
        Scan.create("current inventory", first.id)
        note_scan = Scan.create("note inventory", second.id)
        note_doc = SBOMDocument.create("/note.cdx.json", "note.cdx.json", note_scan.id)
        Vulnerability.create_record(id=note_id)
        db.session.add_all([
            SBOMObservation(
                vulnerability_id=vuln_id, sbom_document_id=note_doc.id, key="description", description="Note only",
            )
            for vuln_id in (historical_id, note_id)
        ])
        db.session.commit()

    comparison = f"variant_ids={first_id},{second_id}&operation=union"
    historical = {row["id"]: row for row in client.get(
        f"/api/vulnerabilities?{comparison}&include_outdated=true"
    ).get_json()}
    assert historical[historical_id]["effort_variant_ids"] == [first_id]
    assert historical[note_id]["effort_variant_ids"] == []
    current = {row["id"]: row for row in client.get(f"/api/vulnerabilities?{comparison}").get_json()}
    assert current[historical_id]["effort_variant_ids"] == []
    difference = client.get(
        f"/api/vulnerabilities/{historical_id}?variant_ids={first_id},{second_id}"
        "&operation=difference&include_outdated=true"
    ).get_json()
    assert difference["effort_variant_ids"] == []

    effort = {"optimistic": "P0D", "likely": "P0D", "pessimistic": "P0D"}
    updates = [
        {"id": note_id, "variant_id": second_id, "effort": effort},
        {"id": historical_id, "variant_id": second_id, "effort": effort},
        {"id": historical_id, "variant_id": first_id, "effort": effort},
    ]
    rejected = client.patch("/api/vulnerabilities/batch", json={"vulnerabilities": updates[:2]})
    assert rejected.status_code == 400
    assert rejected.get_json()["count"] == 0
    assert rejected.get_json()["error_count"] == 2

    def fail_write(**kwargs):
        raise SQLAlchemyError("Simulated write failure")

    with monkeypatch.context() as patch:
        patch.setattr(TimeEstimate, "create", fail_write)
        failed = client.patch("/api/vulnerabilities/batch", json={"vulnerabilities": updates[2:]})
    assert failed.status_code == 400
    assert failed.get_json()["count"] == 0
    assert failed.get_json()["errors"] == [{"id": historical_id, "error": "Failed to save time estimate"}]

    mixed = client.patch("/api/vulnerabilities/batch", json={"vulnerabilities": updates})
    assert mixed.status_code == 200
    result = mixed.get_json()
    assert result["count"] == 1
    assert result["error_count"] == 2
    assert result["vulnerabilities"][0]["effort"] == effort
    with app.app_context():
        estimates = TimeEstimate.get_by_finding(finding_id)
        assert [(str(row.variant_id), row.optimistic, row.likely, row.pessimistic) for row in estimates] == [
            (first_id, 0, 0, 0),
        ]
    scope = f"project_id={project_id}&include_outdated=true"
    rows = {row["id"]: row for row in client.get(f"/api/vulnerabilities?{scope}").get_json()}
    assert rows[historical_id]["effort"] == effort
    assert client.get(f"/api/vulnerabilities/{historical_id}?{scope}").get_json()["effort"] == effort


@pytest.mark.parametrize(("batch", "existing_in_variant"), [(True, False), (True, True), (False, True)])
def test_effort_prefers_variant_finding_and_survives_scan_cleanup(app, client, batch, existing_in_variant):
    from src.extensions import db
    from src.helpers.assessment_io import build_custom_data_export, build_variant_by_name_map, import_custom_data
    from src.models import Finding, Observation, Package, Project, Scan, TimeEstimate, Variant, Vulnerability

    vuln_id = "TEST-LEGACY-EFFORT"
    with app.app_context():
        project = Project.create("Legacy effort")
        edited = Variant.create("edited", project.id)
        sibling = Variant.create("sibling", project.id)
        edited_scan = Scan.create("edited scan", edited.id)
        sibling_scan = Scan.create("sibling scan", sibling.id)
        Vulnerability.create_record(id=vuln_id)
        expected_finding = Finding.get_or_create(Package.find_or_create("edited-package", "1").id, vuln_id)
        legacy_finding = Finding.get_or_create(Package.find_or_create("sibling-package", "1").id, vuln_id)
        Observation.create(expected_finding.id, edited_scan.id)
        Observation.create(legacy_finding.id, sibling_scan.id)
        edited_id, sibling_scan_id = edited.id, sibling_scan.id
        project_id = project.id
        expected_finding_id, legacy_finding_id = expected_finding.id, legacy_finding.id
        legacy_id = UUID(int=1)
        estimate_id = UUID(int=2) if existing_in_variant else legacy_id
        db.session.add(TimeEstimate(id=legacy_id, finding_id=legacy_finding_id, variant_id=edited_id, likely=1))
        if existing_in_variant:
            db.session.add(TimeEstimate(id=estimate_id, finding_id=expected_finding_id, variant_id=edited_id, likely=2))
        sibling_estimate_id = TimeEstimate.create(legacy_finding_id, sibling.id, 2, 2, 2).id

    effort = {"optimistic": "PT3H", "likely": "PT4H", "pessimistic": "PT5H"}
    update = {"variant_id": str(edited_id), "effort": effort}
    if batch:
        response = client.patch("/api/vulnerabilities/batch", json={"vulnerabilities": [{"id": vuln_id, **update}]})
    else:
        response = client.patch(f"/api/vulnerabilities/{vuln_id}", json=update)
    assert response.status_code == 200
    result = response.get_json()
    assert (result["vulnerabilities"][0] if batch else result)["effort"] == effort
    response = client.get(f"/api/vulnerabilities/{vuln_id}?variant_id={edited_id}")
    assert response.get_json()["effort"] == effort
    with app.app_context():
        estimate = TimeEstimate.get_by_finding_and_variant(expected_finding_id, edited_id)
        assert estimate is not None
        assert (estimate.id, estimate.optimistic, estimate.likely, estimate.pessimistic) == (estimate_id, 3, 4, 5)
        if existing_in_variant:
            legacy = TimeEstimate.get_by_id(legacy_id)
            assert (legacy.finding_id, legacy.likely) == (legacy_finding_id, 1)
            exported = build_custom_data_export([edited_id])
            assert exported["time_estimates"] == [{"vuln_id": vuln_id, "variant": "edited", **effort}]
            estimate.update(0, 0, 0)
            assert build_custom_data_export([edited_id])["time_estimates"] == []
            imported = import_custom_data(
                json.loads(json.dumps(exported)), build_variant_by_name_map(project_id),
                use_original_timestamps=True,
            )
            assert imported["errors"] == []
            assert imported["time_estimates_imported"] == 1
            assert (estimate.optimistic, estimate.likely, estimate.pessimistic) == (3, 4, 5)
            assert legacy.likely == 1
        sibling_estimate = TimeEstimate.get_by_id(sibling_estimate_id)
        assert (sibling_estimate.finding_id, sibling_estimate.likely) == (legacy_finding_id, 2)

    response = client.delete(f"/api/scans/{sibling_scan_id}")
    assert response.status_code == 200
    assert response.get_json()["orphaned_findings_removed"] == 1
    with app.app_context():
        assert db.session.get(Finding, legacy_finding_id) is None
        estimates = TimeEstimate.get_by_variant(edited_id)
        assert [(row.id, row.finding_id, row.optimistic, row.likely, row.pessimistic) for row in estimates] == [
            (estimate_id, expected_finding_id, 3, 4, 5),
        ]


# ---------------------------------------------------------------------------
# GET /api/vulnerabilities — compare_variant_id paths (lines 88, 100, 118)
# ---------------------------------------------------------------------------

@pytest.fixture
def empty_comparison(app):
    from src.models import Project, Variant

    with app.app_context():
        project = Project.create("EmptyComparison")
        base = Variant.create("Base", project.id)
        compare = Variant.create("Compare", project.id)
        return f"variant_id={base.id}&compare_variant_id={compare.id}"


def test_get_vulnerabilities_compare_base_none(client, empty_comparison):
    """GET with variant_id+compare_variant_id where base has no scan → base_ids=set() (line 88)."""
    response = client.get(f"/api/vulnerabilities?{empty_comparison}")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)


def test_get_vulnerabilities_compare_intersection_no_scan(client, empty_comparison):
    """GET with operation=intersection and compare has no scan → records=[] (line 100)."""
    response = client.get(f"/api/vulnerabilities?{empty_comparison}&operation=intersection")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data == []


def test_get_vulnerabilities_compare_difference_no_scan(client, empty_comparison):
    """GET (default difference) compare has no scan → records=[] (line 118)."""
    response = client.get(f"/api/vulnerabilities?{empty_comparison}&operation=difference")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data == []


def test_get_vulnerabilities_compare_with_data(app, client):
    """GET with real compare data exercises the populated compare branch."""
    from src.extensions import db
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.observation import Observation
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from datetime import datetime, timezone
    import uuid as _uuid

    with app.app_context():
        project = Project.create("CompareProject")
        base_variant = Variant.create("BaseVariant", project.id)
        compare_variant = Variant.create("CompareVariant", project.id)
        pkg = Package.find_or_create("compare-pkg", "1.0.0", [], [], "")
        db.session.commit()
        vuln = Vulnerability.create_record(
            id="CVE-COMPARE-0001",
            description="Compare branch vuln",
            status="medium",
        )
        db.session.commit()
        base_finding = Finding.get_or_create(pkg.id, vuln.id)
        compare_finding = Finding.get_or_create(pkg.id, vuln.id)

        base_scan = Scan(
            id=_uuid.uuid4(),
            variant_id=base_variant.id,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        compare_scan = Scan(
            id=_uuid.uuid4(),
            variant_id=compare_variant.id,
            timestamp=datetime(2024, 1, 2, tzinfo=timezone.utc),
        )
        db.session.add(base_scan)
        db.session.add(compare_scan)

        base_doc = SBOMDocument(
            id=_uuid.uuid4(),
            path="/demo/base.spdx.json",
            source_name="base.spdx.json",
            format="spdx",
            scan_id=base_scan.id,
        )
        compare_doc = SBOMDocument(
            id=_uuid.uuid4(),
            path="/demo/compare.spdx.json",
            source_name="compare.spdx.json",
            format="spdx",
            scan_id=compare_scan.id,
        )
        db.session.add(base_doc)
        db.session.add(compare_doc)
        db.session.add(SBOMPackage(sbom_document_id=base_doc.id, package_id=pkg.id))
        db.session.add(SBOMPackage(sbom_document_id=compare_doc.id, package_id=pkg.id))
        db.session.add(Observation(finding_id=base_finding.id, scan_id=base_scan.id))
        db.session.add(Observation(finding_id=compare_finding.id, scan_id=compare_scan.id))
        db.session.commit()

        base_id = str(base_variant.id)
        compare_id = str(compare_variant.id)
        package_id = pkg.string_id

    response = client.get(
        f"/api/vulnerabilities?variant_id={base_id}&compare_variant_id={compare_id}&operation=intersection"
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    vulnerability = next(v for v in data if v["id"] == "CVE-COMPARE-0001")
    assert vulnerability["packages_current_by_variant"] == {
        base_id: [package_id], compare_id: [package_id],
    }


@pytest.mark.parametrize("pair", [False, True])
def test_vulnerability_comparison_validates_project_scope(app, client, pair):
    import uuid
    from src.models import Project, Variant

    with app.app_context():
        project = Project.create("ComparisonScope")
        base = Variant.create("Base", project.id)
        same_project = Variant.create("Selected", project.id)
        other_project = Project.create("OtherComparisonScope")
        other = Variant.create("Other", other_project.id)
        project_id, other_project_id = str(project.id), str(other_project.id)
        base_id, selected_id, other_id = str(base.id), str(same_project.id), str(other.id)

    def comparison_query(second_id):
        if pair:
            return f"variant_id={base_id}&compare_variant_id={second_id}&operation=intersection"
        return f"variant_ids={base_id},{second_id}&operation=union"

    for second_id, project_param, status in [
        (selected_id, project_id, 200),
        (selected_id, other_project_id, 400),
        (other_id, project_id, 400),
        (other_id, None, 400),
        (str(uuid.uuid4()), project_id, 404),
    ]:
        query = f"{comparison_query(second_id)}&include_outdated=true"
        if project_param:
            query += f"&project_id={project_param}"
        assert client.get(f"/api/vulnerabilities?{query}").status_code == status
        response = client.post(
            f"/api/vulnerabilities/search-descriptions?{query}",
            json={"vulnerability_ids": ["CVE-2020-35492"], "terms": ["sample"]},
        )
        assert response.status_code == status
        response = client.get(f"/api/vulnerabilities/CVE-2020-35492?{query}")
        assert response.status_code == status


@pytest.mark.parametrize("include_outdated", ["false", "true"])
def test_single_variant_evidence_scope_validates_project(app, include_outdated):
    import uuid
    from src.models import Project, Variant
    from src.routes._evidence_scope import resolve_evidence_scope

    with app.app_context():
        project = Project.create("Selected project")
        other_project = Project.create("Other project")
        variant = Variant.create("Selected variant", project.id)
        args = {"variant_id": str(variant.id), "include_outdated": include_outdated}

        scope, error = resolve_evidence_scope({**args, "project_id": str(other_project.id)})
        assert scope is None
        assert error == ({"error": "Variant must belong to the selected project"}, 400)

        scope, error = resolve_evidence_scope({**args, "project_id": str(project.id)})
        assert error is None
        assert scope.selected == [variant.id]
        assert scope.historical is (include_outdated == "true")

        scope, error = resolve_evidence_scope({
            **args, "project_id": str(project.id), "variant_id": str(uuid.uuid4()),
        })
        assert error is None
        assert scope.selected == []


@pytest.mark.parametrize("include_outdated", ["false", "true"])
def test_explorer_endpoints_honor_explicit_single_variant_project(app, client, include_outdated):
    from src.models import Project, Variant, Vulnerability

    vuln_id = "CVE-SYNTH-PROJECT-SCOPE"
    with app.app_context():
        project = Project.create("Explorer scope")
        variant = Variant.create("Explorer board", project.id)
        other_project = Project.create("Other scope")
        Vulnerability.create_record(vuln_id)
        query = {"variant_id": str(variant.id), "include_outdated": include_outdated}
        project_id, other_project_id = str(project.id), str(other_project.id)

    for selected_project, status in [(project_id, 200), (other_project_id, 400)]:
        scope = {**query, "project_id": selected_project}
        for path in ("/api/packages", "/api/vulnerabilities", f"/api/vulnerabilities/{vuln_id}"):
            assert client.get(path, query_string=scope).status_code == status
        response = client.post(
            "/api/vulnerabilities/search-descriptions", query_string=scope,
            json={"vulnerability_ids": [vuln_id], "terms": ["synthetic"]},
        )
        assert response.status_code == status


# ---------------------------------------------------------------------------
# GET /api/vulnerabilities — invalid variant_id/project_id (lines 140, 162)
# ---------------------------------------------------------------------------

def test_get_vulnerabilities_invalid_variant_id(client):
    """GET /api/vulnerabilities?variant_id=bad-uuid returns 400 (line 140)."""
    response = client.get("/api/vulnerabilities?variant_id=not-a-valid-uuid")
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "invalid" in data["error"].lower() or "variant" in data["error"].lower()


def test_get_vulnerabilities_invalid_project_id(client):
    """GET /api/vulnerabilities?project_id=bad-uuid returns 400 (line 162)."""
    response = client.get("/api/vulnerabilities?project_id=not-a-valid-uuid")
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "invalid" in data["error"].lower() or "project" in data["error"].lower()


def test_get_vulnerabilities_reports_current_packages_per_variant(client):
    variant_id = "22222222-2222-2222-2222-222222222222"

    response = client.get(f"/api/vulnerabilities?variant_id={variant_id}")

    assert response.status_code == 200
    vulnerability = next(
        item for item in response.get_json()
        if item["id"] == "CVE-2020-35492"
    )
    assert vulnerability["packages_current_by_variant"] == {
        variant_id: ["cairo@1.16.0"],
    }


def test_current_packages_per_variant_keeps_supplier_identity(app, client):
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.package import Package

    variant_id = "22222222-2222-2222-2222-222222222222"
    with app.app_context():
        other_supplier = Package.find_or_create(
            "cairo", "1.16.0", supplier="Other Supplier")
        Finding.get_or_create(other_supplier.id, "CVE-2020-35492")
        db.session.commit()

    response = client.get(f"/api/vulnerabilities?variant_id={variant_id}")

    assert response.status_code == 200
    vulnerability = next(
        item for item in response.get_json()
        if item["id"] == "CVE-2020-35492"
    )
    assert vulnerability["packages_current_by_variant"] == {
        variant_id: ["cairo@1.16.0"],
    }
    assert "cairo@1.16.0::Other Supplier" not in vulnerability["packages_current"]


def test_vulnerabilities_include_outdated_is_opt_in_and_scoped(app, client):
    from datetime import datetime, timezone

    from src.extensions import db
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.project import Project
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_observation import SBOMObservation
    from src.models.sbom_package import SBOMPackage
    from src.models.scan import Scan
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability

    with app.app_context():
        project = Project.create("OutdatedVulnerabilityProject")
        variant = Variant.create("OutdatedVariant", project.id)
        sibling = Variant.create("SiblingVariant", project.id)
        old_package = Package.find_or_create("outdated-lib", "1.0", [], [], "")
        current_package = Package.find_or_create("outdated-lib", "2.0", [], [], "")
        sibling_package = Package.find_or_create("sibling-lib", "1.0", [], [], "")
        original_supplier = Package.find_or_create("supplier-lib", "1.0", supplier="Original")
        later_supplier = Package.find_or_create("supplier-lib", "1.0", supplier="Later")
        supplierless_tool = Package.find_or_create("tool-lib", "1.0")
        documented_tool = Package.find_or_create("tool-lib", "1.0", supplier="Documented")
        later_tool = Package.find_or_create("tool-lib", "1.0", supplier="Later")
        db.session.commit()

        old_only = Vulnerability.create_record(
            id="CVE-OUTDATED-ONLY-0001", description="Old package only", status="high",
        )
        shared = Vulnerability.create_record(
            id="CVE-OUTDATED-SHARED-0001", description="Old and current package", status="high",
        )
        sibling_vulnerability = Vulnerability.create_record(
            id="CVE-OUTDATED-SIBLING-0001", description="Sibling variant", status="high",
        )
        notes_only = Vulnerability.create_record(
            id="CVE-OUTDATED-NOTES", description="Note without a package", status="high",
        )
        tool_only_finding_vuln = Vulnerability.create_record(
            id="CVE-OUTDATED-RETAINED-TOOL", description="Reported by the active tool only", status="high",
        )
        db.session.commit()

        old_only_finding = Finding.get_or_create(old_package.id, old_only.id)
        shared_old_finding = Finding.get_or_create(old_package.id, shared.id)
        shared_current_finding = Finding.get_or_create(current_package.id, shared.id)
        sibling_finding = Finding.get_or_create(sibling_package.id, sibling_vulnerability.id)
        supplier_finding = Finding.get_or_create(original_supplier.id, old_only.id)
        supplierless_finding = Finding.get_or_create(supplierless_tool.id, old_only.id)
        notes_sibling_finding = Finding.get_or_create(sibling_package.id, notes_only.id)
        retained_tool_finding = Finding.get_or_create(current_package.id, tool_only_finding_vuln.id)
        db.session.commit()

        old_scan = Scan(
            variant_id=variant.id, scan_type="sbom",
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        current_scan = Scan(
            variant_id=variant.id, scan_type="sbom",
            timestamp=datetime(2024, 6, 1, tzinfo=timezone.utc),
        )
        sibling_scan = Scan(
            variant_id=sibling.id, scan_type="sbom",
            timestamp=datetime(2024, 6, 1, tzinfo=timezone.utc),
        )
        stale_tool_scan = Scan(
            variant_id=variant.id, scan_type="tool", scan_source="osv",
            timestamp=datetime(2024, 3, 1, tzinfo=timezone.utc),
        )
        db.session.add_all([old_scan, current_scan, sibling_scan, stale_tool_scan])
        db.session.flush()
        old_document = SBOMDocument(
            path="/outdated/old.spdx.json", source_name="old.spdx.json",
            format="spdx", scan_id=old_scan.id,
        )
        current_document = SBOMDocument(
            path="/outdated/current.spdx.json", source_name="current.spdx.json",
            format="spdx", scan_id=current_scan.id,
        )
        sibling_document = SBOMDocument(
            path="/outdated/sibling.spdx.json", source_name="sibling.spdx.json",
            format="spdx", scan_id=sibling_scan.id,
        )
        tool_document = SBOMDocument(
            path="/outdated/tool.grype.json", source_name="tool.grype.json",
            format="grype", scan_id=stale_tool_scan.id,
        )
        db.session.add_all([old_document, current_document, sibling_document, tool_document])
        db.session.flush()
        db.session.add_all([
            SBOMPackage(sbom_document_id=old_document.id, package_id=old_package.id),
            SBOMPackage(sbom_document_id=current_document.id, package_id=current_package.id),
            SBOMPackage(sbom_document_id=old_document.id, package_id=original_supplier.id),
            SBOMPackage(sbom_document_id=current_document.id, package_id=later_supplier.id),
            SBOMPackage(sbom_document_id=tool_document.id, package_id=documented_tool.id),
            SBOMPackage(sbom_document_id=current_document.id, package_id=later_tool.id),
            SBOMPackage(sbom_document_id=sibling_document.id, package_id=sibling_package.id),
            Observation(finding_id=old_only_finding.id, scan_id=old_scan.id),
            Observation(finding_id=supplier_finding.id, scan_id=old_scan.id),
            Observation(finding_id=supplierless_finding.id, scan_id=stale_tool_scan.id),
            Observation(finding_id=shared_old_finding.id, scan_id=old_scan.id),
            Observation(finding_id=shared_old_finding.id, scan_id=stale_tool_scan.id),
            Observation(finding_id=shared_current_finding.id, scan_id=current_scan.id),
            Observation(finding_id=retained_tool_finding.id, scan_id=stale_tool_scan.id),
            Observation(finding_id=sibling_finding.id, scan_id=sibling_scan.id),
            Observation(finding_id=notes_sibling_finding.id, scan_id=sibling_scan.id),
            SBOMObservation(
                vulnerability_id=old_only.id,
                sbom_document_id=old_document.id,
                package_id=old_package.id,
                key="description",
                description="legacytoken found in the old SBOM",
            ),
            SBOMObservation(
                vulnerability_id=old_only.id,
                sbom_document_id=old_document.id,
                package_id=original_supplier.id,
                key="description",
                description="Original supplier only",
            ),
            SBOMObservation(
                vulnerability_id=notes_only.id,
                sbom_document_id=old_document.id,
                key="recommendation",
                description="Scoped recommendation without an affected package",
            ),
        ])
        db.session.commit()
        variant_id = str(variant.id)
        project_id = str(project.id)

    current_response = client.get(f"/api/vulnerabilities?variant_id={variant_id}")
    assert current_response.status_code == 200
    current = {item["id"]: item for item in current_response.get_json()}
    retained_id = "CVE-OUTDATED-RETAINED-TOOL"
    assert set(current) == {"CVE-OUTDATED-SHARED-0001", retained_id}

    outdated_response = client.get(
        f"/api/vulnerabilities?variant_id={variant_id}&include_outdated=true"
    )
    assert outdated_response.status_code == 200
    outdated = {item["id"]: item for item in outdated_response.get_json()}
    assert set(outdated) == {
        "CVE-OUTDATED-ONLY-0001", "CVE-OUTDATED-SHARED-0001", "CVE-OUTDATED-NOTES", retained_id,
    }
    assert outdated[retained_id]["packages_status_by_variant"] == {variant_id: ["outdated-lib@2.0"]}
    assert outdated["CVE-OUTDATED-SHARED-0001"]["packages_current"] == [
        "outdated-lib@2.0",
    ]
    for field in ("packages_current", "packages_current_by_variant"):
        assert outdated["CVE-OUTDATED-SHARED-0001"][field] == current["CVE-OUTDATED-SHARED-0001"][field]
    assert outdated["CVE-OUTDATED-SHARED-0001"]["packages_current_by_variant"] == {
        variant_id: ["outdated-lib@2.0"],
    }
    assert outdated["CVE-OUTDATED-SHARED-0001"]["packages_status_by_variant"] == {
        variant_id: ["outdated-lib@1.0", "outdated-lib@2.0"],
    }
    assert outdated["CVE-OUTDATED-ONLY-0001"]["packages_status_by_variant"] == {
        variant_id: ["outdated-lib@1.0", "supplier-lib@1.0::Original", "tool-lib@1.0", "tool-lib@1.0::Documented"],
    }
    assert outdated["CVE-OUTDATED-ONLY-0001"]["packages"] == [
        "outdated-lib@1.0", "supplier-lib@1.0::Original", "tool-lib@1.0", "tool-lib@1.0::Documented",
    ]
    assert outdated["CVE-OUTDATED-NOTES"]["packages"] == []
    assert outdated["CVE-OUTDATED-NOTES"]["packages_status_by_variant"] == {}
    notes_details = client.get(
        f"/api/vulnerabilities/CVE-OUTDATED-NOTES?variant_id={variant_id}&include_outdated=true"
    )
    assert notes_details.status_code == 200
    notes = notes_details.get_json()
    assert notes["packages"] == notes["packages_current"] == []
    assert notes["packages_status_by_variant"] == notes["packages_current_by_variant"] == {}

    search_payload = {
        "vulnerability_ids": ["CVE-OUTDATED-ONLY-0001"],
        "terms": ["legacytoken"],
    }
    active_search = client.post(
        f"/api/vulnerabilities/search-descriptions?variant_id={variant_id}",
        json=search_payload,
    )
    assert active_search.get_json()["matches"]["legacytoken"] == []
    historical_search = client.post(
        f"/api/vulnerabilities/search-descriptions?variant_id={variant_id}&include_outdated=true",
        json=search_payload,
    )
    assert historical_search.get_json()["matches"]["legacytoken"] == [
        "CVE-OUTDATED-ONLY-0001",
    ]

    project_response = client.get(
        f"/api/vulnerabilities?project_id={project_id}&include_outdated=true"
    )
    assert project_response.status_code == 200
    project_ids = {item["id"] for item in project_response.get_json()}
    assert "CVE-OUTDATED-SIBLING-0001" in project_ids


def test_explorer_evidence_agrees_across_findings_packages_search_and_writes(app, client):
    from datetime import datetime, timezone
    from src.extensions import db
    from src.models import Finding, Observation, Package, Project, SBOMDocument, SBOMObservation, SBOMPackage
    from src.models import Scan, Variant, Vulnerability

    removed_id, retained_id = "CVE-SYNTH-REMOVED", "CVE-SYNTH-RETAINED"
    tool_old_id, tool_id = "CVE-SYNTH-TOOL-OLD", "CVE-SYNTH-TOOL"

    with app.app_context():
        project = Project.create("Shared evidence test")
        base = Variant.create("Board A", project.id)
        sibling = Variant.create("Board B", project.id)
        tool = Variant.create("Tool-only board", project.id)
        removed = Package.find_or_create("synthetic-removed", "1")
        retained = Package.find_or_create("synthetic-retained", "1")
        for vuln_id in (removed_id, retained_id, tool_old_id, tool_id):
            Vulnerability.create_record(vuln_id)
        removed_finding = Finding.get_or_create(removed.id, removed_id)
        retained_finding = Finding.get_or_create(retained.id, retained_id)
        tool_old_finding = Finding.get_or_create(removed.id, tool_old_id)
        tool_finding = Finding.get_or_create(removed.id, tool_id)

        def sbom(variant, day, packages, findings):
            scan = Scan(variant_id=variant.id, timestamp=datetime(2026, 1, day, tzinfo=timezone.utc))
            db.session.add(scan)
            db.session.flush()
            doc = SBOMDocument(scan_id=scan.id, path=f"/synthetic/{day}.json", source_name=f"{day}.json", format="cdx")
            db.session.add(doc)
            db.session.flush()
            for package in packages:
                db.session.add(SBOMPackage(sbom_document_id=doc.id, package_id=package.id))
            for finding in findings:
                db.session.add(Observation(scan_id=scan.id, finding_id=finding.id))
                db.session.add(SBOMObservation(
                    sbom_document_id=doc.id, vulnerability_id=finding.vulnerability_id, package_id=finding.package_id,
                    key="test description", description=f"synthetic evidence day {day}",
                ))

        sbom(base, 1, [removed, retained], [removed_finding, retained_finding])
        sbom(base, 2, [retained], [])
        sbom(sibling, 3, [retained], [retained_finding])
        for day, finding in ((1, tool_old_finding), (2, tool_finding)):
            tool_scan = Scan(
                variant_id=tool.id, timestamp=datetime(2026, 1, day, tzinfo=timezone.utc),
                scan_type="tool", scan_source="osv",
            )
            db.session.add(tool_scan)
            db.session.flush()
            db.session.add(Observation(scan_id=tool_scan.id, finding_id=finding.id))
        db.session.commit()
        project_id, base_id, sibling_id, tool_variant_id = map(str, (project.id, base.id, sibling.id, tool.id))

    def rows(path, query):
        response = client.get(f"/api/{path}?{query}")
        assert response.status_code == 200
        return {row["id"]: row for row in response.get_json()}

    current = f"project_id={project_id}"
    historical = f"{current}&include_outdated=true"
    assert set(rows("vulnerabilities", current)) == {retained_id, tool_id}
    history = rows("vulnerabilities", historical)
    assert set(history) == {removed_id, retained_id, tool_old_id, tool_id}
    shared = history[retained_id]
    assert shared["packages_current_by_variant"] == {sibling_id: ["synthetic-retained@1"]}
    assert shared["assessment_targets_by_variant"] == shared["packages_current_by_variant"]
    assert shared["packages_status_by_variant"] == {
        base_id: ["synthetic-retained@1"], sibling_id: ["synthetic-retained@1"],
    }
    assert history[removed_id]["assessment_targets_by_variant"] == {}
    assert history[tool_id]["packages_current_by_variant"] == {tool_variant_id: ["synthetic-removed@1"]}
    assert history[tool_old_id]["packages_current"] == []
    assert {removed_id, tool_old_id}.isdisjoint(rows("vulnerabilities", ""))
    assert {retained_id, tool_id}.issubset(rows("vulnerabilities", ""))

    for query, historical_view in ((current, False), (historical, True)):
        inventory = rows("packages", query)
        assert inventory["synthetic-retained@1"]["outdated"] is False
        assert inventory["synthetic-retained@1"]["inventory_variant_ids"] == sorted([base_id, sibling_id])
        assert ("synthetic-removed@1" in inventory) == historical_view
        if historical_view:
            assert inventory["synthetic-removed@1"]["inventory_variant_ids"] == [base_id]
            assert inventory["synthetic-removed@1"]["outdated"] is True
        detail = client.get(f"/api/vulnerabilities/{retained_id}?{query}").get_json()
        assert detail == {**rows("vulnerabilities", query)[retained_id], "description": detail["description"]}
        texts = {text["content"] for text in detail["texts"]}
        matches = client.post(f"/api/vulnerabilities/search-descriptions?{query}", json={
            "vulnerability_ids": [retained_id, removed_id], "terms": ["day 1", "day 3"],
        }).get_json()["matches"]
        assert ("synthetic evidence day 1" in texts) == historical_view
        assert "synthetic evidence day 3" in texts
        assert matches == {"day 1": sorted([removed_id, retained_id]) if historical_view else [], "day 3": [retained_id]}

    pair = f"variant_id={base_id}&compare_variant_id={sibling_id}"
    assert set(rows("vulnerabilities", pair)) == {retained_id}
    assert not rows("vulnerabilities", f"{pair}&include_outdated=true")
    multi = f"variant_ids={base_id},{sibling_id},{tool_variant_id}&operation=difference"
    assert not rows("vulnerabilities", multi)
    assert set(rows("vulnerabilities", f"{multi}&include_outdated=true")) == {removed_id}
    assert set(rows("packages", f"{multi}&include_outdated=true")) == {"synthetic-removed@1"}
    assert not rows("packages", f"variant_id={tool_variant_id}&include_outdated=true")

    editor = client.get(f"/api/vulnerabilities/{retained_id}/variant-active-packages?{current}").get_json()
    targets = {row["variant_id"]: row for row in editor}
    assert targets[base_id]["active_packages"] == []
    assert targets[base_id]["findings"][0]["outdated"] is True
    assert targets[sibling_id]["active_packages"] == ["synthetic-retained@1"]
    assert targets[sibling_id]["findings"][0]["outdated"] is False

    batch = {"assessments": [{
        "vuln_id": retained_id, "status": "fixed",
        "targets": [{"variant_id": base_id, "package": "synthetic-retained@1"}],
    }]}
    assert client.post("/api/assessments/batch", json={**batch, "current_only": True}).status_code == 400
    assert client.post("/api/assessments/batch", json=batch).status_code == 200


def test_outdated_comparison_recomputes_difference_union_and_intersection(app, client):
    from datetime import datetime, timezone

    from src.extensions import db
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.project import Project
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_observation import SBOMObservation
    from src.models.sbom_package import SBOMPackage
    from src.models.scan import Scan
    from src.models.time_estimate import TimeEstimate
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability

    with app.app_context():
        project = Project.create("OutdatedComparisonProject")
        base = Variant.create("OutdatedBase", project.id)
        compare = Variant.create("OutdatedCompare", project.id)
        third = Variant.create("OutdatedThird", project.id)
        sibling = Variant.create("OutdatedUnselected", project.id)
        outside = Variant.create("Outside", Project.create("OutsideComparisonProject").id)

        vulnerabilities = {
            key: Vulnerability.create_record(
                id=vuln_id, description=vuln_id, status="high",
            )
            for key, vuln_id in {
                "shared": "CVE-OUTDATED-COMPARE-SHARED",
                "compare": "CVE-OUTDATED-COMPARE-ONLY",
                "base": "CVE-OUTDATED-BASE-ONLY",
                "sibling": "CVE-OUTDATED-UNSELECTED",
                "outside": "CVE-OUTDATED-OUTSIDE",
            }.items()
        }
        db.session.commit()

        packages = {
            key: Package.find_or_create(name, version, [], [], "")
            for key, name, version in [
                ("shared", "comparison-shared", "1.0"),
                ("base_current", "base-current", "2.0"),
                ("compare_only", "compare-only", "1.0"),
                ("base_only", "base-only", "1.0"),
                ("sibling_only", "sibling-only", "1.0"),
                ("outside", "outside-only", "1.0"),
            ]
        }
        db.session.commit()

        scan_specs = [
            ("base_old", base, datetime(2024, 1, 1, tzinfo=timezone.utc),
             ["shared", "base_only"]),
            ("base_current", base, datetime(2024, 6, 1, tzinfo=timezone.utc),
             ["base_current"]),
            ("compare_current", compare, datetime(2024, 6, 1, tzinfo=timezone.utc),
             ["shared", "compare_only"]),
            ("third_current", third, datetime(2024, 6, 1, tzinfo=timezone.utc),
             ["shared"]),
            ("sibling_current", sibling, datetime(2024, 6, 1, tzinfo=timezone.utc),
             ["sibling_only"]),
            ("outside_current", outside, datetime(2024, 6, 1, tzinfo=timezone.utc),
             ["outside"]),
        ]
        scans = {}
        documents = {}
        for key, variant, timestamp, _package_keys in scan_specs:
            scan = Scan(
                variant_id=variant.id, scan_type="sbom", timestamp=timestamp,
            )
            db.session.add(scan)
            scans[key] = scan
        db.session.flush()
        for key, _variant, _timestamp, package_keys in scan_specs:
            document = SBOMDocument(
                path=f"/outdated-comparison/{key}.spdx.json",
                source_name=f"{key}.spdx.json",
                format="spdx",
                scan_id=scans[key].id,
            )
            db.session.add(document)
            documents[key] = document
        db.session.flush()
        for key, _variant, _timestamp, package_keys in scan_specs:
            for package_key in package_keys:
                db.session.add(SBOMPackage(
                    sbom_document_id=documents[key].id,
                    package_id=packages[package_key].id,
                ))

        third_tool = Scan(
            variant_id=third.id, scan_type="tool", scan_source="osv",
            timestamp=datetime(2024, 3, 1, tzinfo=timezone.utc),
        )
        db.session.add(third_tool)
        db.session.flush()
        scans["third_tool"] = third_tool
        observation_specs = [
            ("base_old", "shared", "shared"),
            ("base_old", "base_only", "base"),
            ("compare_current", "shared", "shared"),
            ("compare_current", "compare_only", "compare"),
            ("third_tool", "shared", "shared"),
            ("sibling_current", "sibling_only", "sibling"),
            ("sibling_current", "sibling_only", "shared"),
            ("outside_current", "outside", "shared"),
            ("outside_current", "outside", "base"),
            ("outside_current", "outside", "outside"),
        ]
        for scan_key, package_key, vulnerability_key in observation_specs:
            finding = Finding.get_or_create(
                packages[package_key].id, vulnerabilities[vulnerability_key].id,
            )
            db.session.add(Observation(
                finding_id=finding.id, scan_id=scans[scan_key].id,
            ))
        db.session.add_all([
            SBOMObservation(
                vulnerability_id=vulnerabilities["shared"].id,
                sbom_document_id=documents[scan_key].id,
                key="description",
                description=term,
            )
            for scan_key, term in [
                ("base_old", "basehistoricalterm"), ("sibling_current", "unselectedterm"),
                ("outside_current", "outsideprojectterm"),
            ]
        ])
        db.session.commit()
        foreign_finding = Finding.get_or_create(packages["outside"].id, vulnerabilities["base"].id)
        TimeEstimate.create(finding_id=foreign_finding.id, variant_id=outside.id, optimistic=1, likely=2, pessimistic=3)
        base_id, compare_id, third_id, project_id = map(
            str, (base.id, compare.id, third.id, project.id),
        )

    pair_base = f"/api/vulnerabilities?variant_id={base_id}&compare_variant_id={compare_id}"
    active_pair = client.get(pair_base)
    assert {item["id"] for item in active_pair.get_json()} == {
        "CVE-OUTDATED-COMPARE-SHARED", "CVE-OUTDATED-COMPARE-ONLY",
    }

    outdated_pair = client.get(f"{pair_base}&include_outdated=true")
    assert {item["id"] for item in outdated_pair.get_json()} == {
        "CVE-OUTDATED-COMPARE-ONLY",
    }
    outdated_pair_intersection = client.get(
        f"{pair_base}&operation=intersection&include_outdated=true"
    )
    assert {item["id"] for item in outdated_pair_intersection.get_json()} == {
        "CVE-OUTDATED-COMPARE-SHARED",
    }

    multi_base = f"/api/vulnerabilities?variant_ids={base_id},{compare_id},{third_id}"
    active_union = {
        row["id"]: row["effort_variant_ids"] for row in client.get(f"{multi_base}&operation=union").get_json()
    }
    assert active_union["CVE-OUTDATED-COMPARE-SHARED"] == [compare_id, third_id]
    multi_difference = client.get(
        f"{multi_base}&operation=difference&include_outdated=true"
    )
    assert {item["id"]: item["effort_variant_ids"] for item in multi_difference.get_json()} == {
        "CVE-OUTDATED-BASE-ONLY": [base_id],
    }
    multi_union = client.get(f"{multi_base}&operation=union&include_outdated=true")
    assert {item["id"]: item["effort_variant_ids"] for item in multi_union.get_json()} == {
        "CVE-OUTDATED-COMPARE-SHARED": [base_id, compare_id, third_id],
        "CVE-OUTDATED-COMPARE-ONLY": [compare_id],
        "CVE-OUTDATED-BASE-ONLY": [base_id],
    }
    multi_intersection = client.get(
        f"{multi_base}&operation=intersection&include_outdated=true"
    )
    assert {item["id"] for item in multi_intersection.get_json()} == {
        "CVE-OUTDATED-COMPARE-SHARED",
    }

    scope = f"project_id={project_id}&include_outdated=true"
    base_only_id = "CVE-OUTDATED-BASE-ONLY"
    project_rows = client.get(f"/api/vulnerabilities?{scope}").get_json()
    project_row = next(row for row in project_rows if row["id"] == base_only_id)
    project_details = client.get(f"/api/vulnerabilities/{base_only_id}?{scope}").get_json()
    assert project_row["effort"] == project_details["effort"] == dict.fromkeys(("optimistic", "likely", "pessimistic"))

    shared_id = "CVE-OUTDATED-COMPARE-SHARED"
    for historical in (False, True):
        project_scope = {"project_id": project_id, "include_outdated": str(historical).lower()}
        for filters, expected_count in [
            ({}, 4 if historical else 3),
            ({"variant_id": compare_id}, 2),
            ({"variant_ids": f"{base_id},{compare_id},{third_id}", "operation": "union"}, 3 if historical else 2),
        ]:
            params = {**project_scope, **filters}
            entries = client.get("/api/vulnerabilities", query_string=params).get_json()
            assert len(entries) == expected_count
            inventory = client.get("/api/packages", query_string=params).get_json()
            assert "outside-only@1.0" not in {item["id"] for item in inventory}
            shared_row = next(row for row in entries if row["id"] == shared_id)
            assert "outside-only@1.0" not in shared_row["packages"]
            detail = client.get(f"/api/vulnerabilities/{shared_id}", query_string=params).get_json()
            assert detail["packages"] == shared_row["packages"]
            assert all(text["content"] != "outsideprojectterm" for text in detail["texts"])
            matches = client.post(
                "/api/vulnerabilities/search-descriptions", query_string=params,
                json={"vulnerability_ids": [shared_id, "CVE-OUTDATED-OUTSIDE"],
                      "terms": ["outsideprojectterm", "CVE-OUTDATED-OUTSIDE"]},
            ).get_json()
            assert matches["matches"] == {"outsideprojectterm": [], "cve-outdated-outside": []}

    for scope, expected in (
        (f"variant_id={base_id}&compare_variant_id={compare_id}&operation=intersection", []),
        (f"project_id={project_id}&variant_ids={base_id},{compare_id},{third_id}&operation=union", []),
        (f"project_id={project_id}", [shared_id]),
    ):
        result = client.post(
            f"/api/vulnerabilities/search-descriptions?{scope}&include_outdated=true",
            json={
                "vulnerability_ids": [shared_id],
                "terms": ["basehistoricalterm", "unselectedterm"],
            },
        )
        assert result.status_code == 200
        assert result.get_json()["matches"] == {
            "basehistoricalterm": [shared_id],
            "unselectedterm": expected,
        }
        details = client.get(f"/api/vulnerabilities/{shared_id}?{scope}&include_outdated=true")
        assert details.status_code == 200
        detail = details.get_json()
        rows = client.get(f"/api/vulnerabilities?{scope}&include_outdated=true").get_json()
        scoped_row = next(row for row in rows if row["id"] == shared_id)
        for key in ("packages", "packages_status_by_variant", "packages_current", "packages_current_by_variant",
                    "assessment_targets_by_variant"):
            assert detail[key] == scoped_row[key]
        assert "outside-only@1.0" not in detail["packages"]
        text_contents = {text["content"] for text in detail["texts"]}
        assert "basehistoricalterm" in text_contents
        assert ("unselectedterm" in text_contents) == bool(expected)

    for scope in (f"variant_id={base_id}&compare_variant_id={compare_id}",
                  f"variant_ids={compare_id},{base_id},{third_id}&operation=difference"):
        details = client.get(f"/api/vulnerabilities/{shared_id}?{scope}&include_outdated=true")
        assert details.status_code == 200
        text_contents = {text["content"] for text in details.get_json()["texts"]}
        assert "basehistoricalterm" not in text_contents
        assert "unselectedterm" not in text_contents


def test_agent_vulnerability_detail_requires_one_variant_with_exact_current_targets(app, client):
    from src.models import Finding, Observation, Package, Project, Scan, Variant, Vulnerability

    vuln_id = "CVE-2099-12347"
    with app.app_context():
        project = Project.create("Agent detail fixture")
        base = Variant.create("base", project.id).id
        compared = Variant.create("compared", project.id).id
        scan = Scan.create("Synthetic observations", compared)
        Vulnerability.create_record(id=vuln_id, description="Synthetic observation")
        package = Package.find_or_create("agent-detail-fixture", "1")
        finding = Finding.get_or_create(package.id, vuln_id)
        Observation.create(finding.id, scan.id)

    route = f"/api/vulnerabilities/{vuln_id}"
    pair = f"variant_id={base}&compare_variant_id={compared}&operation=difference"
    exact = {str(compared): ["agent-detail-fixture@1"]}
    assert client.get(f"{route}?{pair}").get_json()["assessment_targets_by_variant"] == exact
    assert client.get(f"{route}?{pair}&agent_scoped=1").status_code == 400
    assert client.get(f"{route}?variant_ids={base},{compared}&agent_scoped=1").status_code == 400
    assert client.get(f"{route}?agent_scoped=1").status_code == 400
    assert client.get(f"{route}?variant_id={base}&agent_scoped=1").status_code == 404
    details = client.get(f"{route}?variant_id={compared}&include_outdated=true&agent_scoped=1")
    assert details.status_code == 200
    row = details.get_json()
    assert row["packages"] == row["packages_current"] == ["agent-detail-fixture@1"]
    assert row["assessment_targets_by_variant"] == row["packages_current_by_variant"] == exact
    assert "packages_status_by_variant" not in row


def test_get_vulnerability_by_id_with_variant_scope(app, client):
    """GET /api/vulnerabilities/<id>?variant_id=... applies scoped effort/CVSS."""
    from src.extensions import db
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.observation import Observation
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.metrics import Metrics
    from src.models.time_estimate import TimeEstimate
    from datetime import datetime, timezone
    import uuid as _uuid

    with app.app_context():
        project = Project.create("DetailScopeProject")
        variant = Variant.create("DetailScopeVariant", project.id)
        pkg = Package.find_or_create("detail-scope-pkg", "1.0.0", [], [], "")
        db.session.commit()
        vuln = Vulnerability.create_record(
            id="CVE-DETAIL-0001",
            description="Detail branch vuln",
            status="high",
        )
        db.session.commit()
        finding = Finding.get_or_create(pkg.id, vuln.id)

        scan = Scan(
            id=_uuid.uuid4(),
            variant_id=variant.id,
            timestamp=datetime(2024, 1, 3, tzinfo=timezone.utc),
        )
        db.session.add(scan)
        doc = SBOMDocument(
            id=_uuid.uuid4(),
            path="/demo/detail.spdx.json",
            source_name="detail.spdx.json",
            format="spdx",
            scan_id=scan.id,
        )
        db.session.add(doc)
        db.session.add(SBOMPackage(sbom_document_id=doc.id, package_id=pkg.id))
        db.session.add(Observation(finding_id=finding.id, scan_id=scan.id))

        Metrics.create(
            vulnerability_id=vuln.id,
            variant_id=None,
            version="3.1",
            score=5.0,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            author="scanner",
            origin="scanner",
        )
        Metrics.create(
            vulnerability_id=vuln.id,
            variant_id=variant.id,
            version="3.1",
            score=8.5,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            author="tester",
            origin="custom",
        )
        TimeEstimate.create(
            finding_id=finding.id,
            variant_id=None,
            optimistic=1,
            likely=2,
            pessimistic=3,
        )
        TimeEstimate.create(
            finding_id=finding.id,
            variant_id=variant.id,
            optimistic=4,
            likely=5,
            pessimistic=6,
        )
        db.session.commit()

        variant_id = str(variant.id)

    response = client.get(f"/api/vulnerabilities/CVE-DETAIL-0001?variant_id={variant_id}")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == "CVE-DETAIL-0001"
    assert data["effort"]["likely"] == "PT5H"
    assert any(cvss["origin"] == "custom" for cvss in data["severity"]["cvss"])


def test_get_vulnerability_scopes_severity_aggregates_by_project_and_variant(app, client):
    """The detail endpoint derives severity aggregates from its scoped metrics."""
    from src.extensions import db
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability
    from src.models.metrics import Metrics

    with app.app_context():
        vuln = Vulnerability.create_record(
            id="CVE-DETAIL-SCOPE-AGGREGATES",
            description="Scoped severity aggregate test",
            status="unknown",
        )
        db.session.commit()
        project_a = Project.create("SeverityAggregateProjectA")
        variant_a = Variant.create("SeverityAggregateVariantA", project_a.id)
        project_b = Project.create("SeverityAggregateProjectB")
        variant_b = Variant.create("SeverityAggregateVariantB", project_b.id)

        Metrics.create(
            vulnerability_id=vuln.id,
            version="3.1",
            score=5.0,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            author="scanner",
            origin="scanner",
        )
        Metrics.create(
            vulnerability_id=vuln.id,
            variant_id=variant_a.id,
            version="3.1",
            score=6.0,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
            author="project-a",
            origin="custom",
        )
        Metrics.create(
            vulnerability_id=vuln.id,
            variant_id=variant_b.id,
            version="3.1",
            score=9.8,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            author="project-b",
            origin="custom",
        )
        variant_a_id = str(variant_a.id)
        variant_b_id = str(variant_b.id)
        project_a_id = str(project_a.id)
        project_b_id = str(project_b.id)

    for query, expected_severity, expected_scores in (
        (f"variant_id={variant_a_id}", "medium", [5.0, 6.0]),
        (f"variant_id={variant_b_id}", "critical", [5.0, 9.8]),
        (f"project_id={project_a_id}", "medium", [5.0, 6.0]),
        (f"project_id={project_b_id}", "critical", [5.0, 9.8]),
    ):
        response = client.get(
            f"/api/vulnerabilities/CVE-DETAIL-SCOPE-AGGREGATES?{query}"
        )
        assert response.status_code == 200
        severity = response.get_json()["severity"]
        assert severity["severity"] == expected_severity
        assert severity["min_score"] == 5.0
        assert severity["max_score"] == max(expected_scores)
        assert sorted(metric["base_score"] for metric in severity["cvss"]) == expected_scores


# ---------------------------------------------------------------------------
# PATCH /api/vulnerabilities/<id> — invalid variant_id in effort (lines 280-281)
# ---------------------------------------------------------------------------

def test_patch_vulnerability_effort_invalid_variant_id(client):
    """PATCH vulnerability effort with invalid variant_id returns 400 (lines 280-281)."""
    response = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        "effort": {
            "optimistic": "PT1H",
            "likely": "PT4H",
            "pessimistic": "P1D",
        },
        "variant_id": "not-a-valid-uuid",
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "variant_id" in data["error"].lower() or "invalid" in data["error"].lower()


# ---------------------------------------------------------------------------
# PATCH /api/vulnerabilities/batch — invalid variant_id in effort (lines 354-355)
# ---------------------------------------------------------------------------

def test_patch_batch_vulnerability_effort_invalid_variant_id(client):
    """Batch PATCH effort with invalid variant_id appends error entry (lines 354-355)."""
    response = client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "effort": {
                "optimistic": "PT1H",
                "likely": "PT4H",
                "pessimistic": "P1D",
            },
            "variant_id": "not-a-valid-uuid",
        }]
    })
    data = json.loads(response.data)
    assert data["error_count"] >= 1
    assert any("variant_id" in str(e).lower() or "invalid" in str(e).lower()
               for e in data["errors"])


def test_apply_variant_scoped_overrides_skips_missing_vuln():
    """Missing vuln keys in the overrides map are ignored."""
    from src.routes.vulnerabilities import _apply_variant_scoped_overrides_to_vuln_dicts, _ScopedOverrides
    from src.models.metrics import Metrics
    from src.helpers.vuln_helpers import Effort

    vulns = {
        "keep": {"id": "keep", "severity": {"cvss": []}, "effort": None},
        "skip": {"id": "skip", "severity": {"cvss": []}, "effort": None},
    }
    override = _ScopedOverrides(
        cvss=[Metrics(vulnerability_id="keep", variant_id=None, version="3.1", score=7.0, vector="x", author="a")],
        effort=Effort(1, 2, 3),
    )

    _apply_variant_scoped_overrides_to_vuln_dicts(vulns, {"keep": override})

    assert vulns["keep"]["effort"]["likely"] == "PT2H"
    assert vulns["keep"]["severity"]["severity"] == "high"
    assert vulns["keep"]["severity"]["min_score"] == 7.0
    assert vulns["keep"]["severity"]["max_score"] == 7.0
    assert vulns["skip"]["effort"] is None


@pytest.mark.parametrize("scope", ["variant_id", "project_id"])
@pytest.mark.parametrize("detail", [False, True])
def test_scoped_severity_uses_only_selected_metrics(app, client, scope, detail):
    from src.extensions import db
    from src.models.metrics import Metrics
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability
    import uuid

    with app.app_context():
        vuln = db.session.get(Vulnerability, "CVE-2020-35492")
        vuln.status = "medium"
        for metric in list(vuln.metrics):
            db.session.delete(metric)
        other_project = Project.create("OtherMetricsProject")
        other_variant = Variant.create("OtherMetricsVariant", other_project.id)
        for score, variant_id in [
            (5.5, None),
            (7.8, uuid.UUID("22222222-2222-2222-2222-222222222222")),
            (9.8, other_variant.id),
        ]:
            db.session.add(Metrics(
                vulnerability_id=vuln.id, version="3.1", score=score,
                variant_id=variant_id,
            ))
        db.session.commit()

    scope_id = (
        "22222222-2222-2222-2222-222222222222" if scope == "variant_id"
        else "11111111-1111-1111-1111-111111111111"
    )
    path = "/api/vulnerabilities/CVE-2020-35492" if detail else "/api/vulnerabilities"
    response = client.get(f"{path}?{scope}={scope_id}")
    assert response.status_code == 200
    result = response.get_json()
    vuln = result if detail else next(v for v in result if v["id"] == "CVE-2020-35492")
    assert vuln["severity"]["severity"] == "high"
    assert vuln["severity"]["min_score"] == 5.5
    assert vuln["severity"]["max_score"] == 7.8
    assert sorted(m["base_score"] for m in vuln["severity"]["cvss"]) == [5.5, 7.8]


@pytest.mark.parametrize("operation", ["union", "intersection"])
@pytest.mark.parametrize("selected_score, expected_label, expected_scores", [
    (7.8, "high", [5.5, 6.5, 7.8]),
    (None, "medium", [5.5]),
])
def test_multi_variant_severity_excludes_unselected_metrics(
    app, client, operation, selected_score, expected_label, expected_scores
):
    import uuid
    from src.extensions import db
    from src.models import Finding, Metrics, Observation, Project, Scan, Variant, Vulnerability

    with app.app_context():
        vuln = db.session.get(Vulnerability, "CVE-2020-35492")
        vuln.status = "medium"
        for metric in list(vuln.metrics):
            db.session.delete(metric)
        first_variant_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
        second_variant = Variant.create(
            "SecondMetricsVariant", uuid.UUID("11111111-1111-1111-1111-111111111111")
        )
        second_variant_id = second_variant.id
        scan = Scan.create("Second variant scan", second_variant_id)
        finding = db.session.execute(
            db.select(Finding).where(Finding.vulnerability_id == vuln.id)
        ).scalar_one()
        Observation.create(finding_id=finding.id, scan_id=scan.id)
        other_project = Project.create("UnselectedMetricsProject")
        other_variant = Variant.create("UnselectedMetricsVariant", other_project.id)
        scores = [(5.5, None), (9.8, other_variant.id)]
        if selected_score is not None:
            scores.extend([(selected_score, first_variant_id), (6.5, second_variant_id)])
        for score, variant_id in scores:
            db.session.add(Metrics(
                vulnerability_id=vuln.id, version="3.1", score=score,
                variant_id=variant_id,
            ))
        db.session.commit()

    response = client.get(
        f"/api/vulnerabilities?variant_ids={first_variant_id},{second_variant_id}&operation={operation}"
    )
    assert response.status_code == 200
    result = response.get_json()
    assert [v["id"] for v in result] == ["CVE-2020-35492"]
    severity = result[0]["severity"]
    assert severity["severity"] == expected_label
    assert severity["min_score"] == min(expected_scores)
    assert severity["max_score"] == max(expected_scores)
    assert sorted(m["base_score"] for m in severity["cvss"]) == expected_scores


@pytest.mark.parametrize("scope", ["variant_id", "project_id"])
@pytest.mark.parametrize("detail", [False, True])
@pytest.mark.parametrize("scores, stored_label, expected_label, expected_score", [
    ([None], "high", "high", None),
    ([None, 7.8], "high", "high", 7.8),
    ([0.0], "none", "none", 0.0),
    ([None, 0.0], "high", "none", 0.0),
])
def test_scoped_severity_ignores_missing_scores(
    app, client, scope, detail, scores, stored_label, expected_label, expected_score
):
    from src.extensions import db
    from src.models import Metrics, Vulnerability

    with app.app_context():
        vuln = db.session.get(Vulnerability, "CVE-2020-35492")
        vuln.status = stored_label
        for metric in list(vuln.metrics):
            db.session.delete(metric)
        for score in scores:
            db.session.add(Metrics(vulnerability_id=vuln.id, version="3.1", score=score))
        db.session.commit()

    scope_id = (
        "22222222-2222-2222-2222-222222222222" if scope == "variant_id"
        else "11111111-1111-1111-1111-111111111111"
    )
    path = "/api/vulnerabilities/CVE-2020-35492" if detail else "/api/vulnerabilities"
    response = client.get(f"{path}?{scope}={scope_id}")
    assert response.status_code == 200
    result = response.get_json()
    vuln = result if detail else next(v for v in result if v["id"] == "CVE-2020-35492")
    severity = vuln["severity"]
    assert severity["severity"] == expected_label
    assert severity["min_score"] == expected_score
    assert severity["max_score"] == expected_score
    assert [m["base_score"] for m in severity["cvss"]] == scores


def test_populate_found_by_handles_non_string_doc_formats(monkeypatch):
    """Fallback skips non-string document formats and maps scan sources."""
    from src.routes.vulnerabilities import _populate_found_by

    class _Record:
        def __init__(self, vuln_id):
            self.id = vuln_id
            self.found_by = []

        def add_found_by(self, scanner):
            self.found_by.append(scanner)

    class _Result:
        def __init__(self, rows):
            self._rows = rows

        def all(self):
            return self._rows

    # The function runs separate queries for provenance, fallback observations,
    # and document formats to avoid multiplying observations by documents.
    fallback_rows = [
        ("v1", "scan-1", "nvd"),
        ("v2", "scan-2", None),
    ]
    format_rows = [("scan-1", None), ("scan-2", 12345)]
    calls = {"n": 0}

    def _fake_execute(*args, **kwargs):
        calls["n"] += 1
        rows = {1: [], 2: fallback_rows, 3: format_rows}[calls["n"]]
        return _Result(rows)

    monkeypatch.setattr(
        "src.routes.vulnerabilities.db.session.execute",
        _fake_execute,
    )

    records = [_Record("v1"), _Record("v2")]
    _populate_found_by(records)

    assert records[0].found_by == ["nvd_cpe"]
    assert records[1].found_by == []


# ---------------------------------------------------------------------------
# _populate_found_by: non-dedicated format (SPDX) and tool-source paths
# ---------------------------------------------------------------------------

def test_found_by_spdx_format(app, client):
    """An active SPDX SBOMDocument contributes 'spdx3' provenance."""
    from src.extensions import db
    from src.models.scan import Scan
    from src.models.sbom_document import SBOMDocument
    from src.models.observation import Observation
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.sbom_package import SBOMPackage
    from datetime import datetime, timezone

    with app.app_context():
        # Create an alternate package & vulnerability
        pkg = Package.find_or_create("spdx-test-pkg", "2.0.0", [], [], "")
        db.session.commit()
        vuln = Vulnerability.create_record(
            id="CVE-SPDX-0001",
            description="Test vuln for spdx found_by path",
            status="medium",
        )
        db.session.commit()
        finding = Finding.get_or_create(pkg.id, "CVE-SPDX-0001")

        # Create a scan with a SPDX SBOMDocument (non-dedicated format)
        import uuid as _uuid
        scan = Scan(
            id=_uuid.uuid4(),
            variant_id=_uuid.UUID("22222222-2222-2222-2222-222222222222"),
            timestamp=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )
        db.session.add(scan)
        spdx_doc = SBOMDocument(
            id=_uuid.uuid4(),
            path="/demo/spdx.spdx.json",
            source_name="spdx.spdx.json",
            format="spdx",
            scan_id=scan.id,
        )
        db.session.add(spdx_doc)
        db.session.add(SBOMPackage(sbom_document_id=spdx_doc.id, package_id=pkg.id))
        db.session.add(Observation(finding_id=finding.id, scan_id=scan.id))
        db.session.commit()

    # Query the vulnerability through the API
    response = client.get("/api/vulnerabilities")
    data = json.loads(response.data)
    spdx_vuln = next((v for v in data if v["id"] == "CVE-SPDX-0001"), None)
    assert spdx_vuln is not None
    assert "spdx3" in spdx_vuln["found_by"]


def test_found_by_tool_scan_nvd(app, client):
    """An active NVD tool scan in a variant without an SBOM contributes provenance."""
    from src.extensions import db
    from src.models.scan import Scan
    from src.models.observation import Observation
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.variant import Variant
    from datetime import datetime, timezone

    with app.app_context():
        pkg = Package.find_or_create("nvd-test-pkg", "3.0.0", [], [], "")
        db.session.commit()
        vuln = Vulnerability.create_record(
            id="CVE-NVD-0001",
            description="Test vuln for NVD tool scan path",
            status="low",
        )
        db.session.commit()
        finding = Finding.get_or_create(pkg.id, "CVE-NVD-0001")

        import uuid as _uuid
        existing_variant = db.session.get(Variant, _uuid.UUID("22222222-2222-2222-2222-222222222222"))
        tool_variant = Variant.create("NVD-only provenance", existing_variant.project_id)
        scan = Scan(
            id=_uuid.uuid4(),
            variant_id=tool_variant.id,
            scan_type="tool",
            scan_source="nvd",
            timestamp=datetime(2019, 1, 1, tzinfo=timezone.utc),
        )
        db.session.add(scan)
        db.session.add(Observation(finding_id=finding.id, scan_id=scan.id))
        db.session.commit()

    response = client.get("/api/vulnerabilities")
    data = json.loads(response.data)
    nvd_vuln = next((v for v in data if v["id"] == "CVE-NVD-0001"), None)
    assert nvd_vuln is not None
    assert "nvd_cpe" in nvd_vuln["found_by"]


def test_found_by_mixed_formats_reports_all(app, client):
    """When a scan has both spdx + grype docs (legacy rows without provenance
    markers), found_by reports all observed formats — the old preference
    heuristic was dropped."""
    from src.extensions import db
    from src.models.scan import Scan
    from src.models.sbom_document import SBOMDocument
    from src.models.observation import Observation
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.sbom_package import SBOMPackage
    from datetime import datetime, timezone

    with app.app_context():
        pkg = Package.find_or_create("mixed-test-pkg", "4.0.0", [], [], "")
        db.session.commit()
        vuln = Vulnerability.create_record(
            id="CVE-MIXED-0001",
            description="Test vuln for mixed format reporting",
            status="high",
        )
        db.session.commit()
        finding = Finding.get_or_create(pkg.id, "CVE-MIXED-0001")

        import uuid as _uuid
        scan = Scan(
            id=_uuid.uuid4(),
            variant_id=_uuid.UUID("22222222-2222-2222-2222-222222222222"),
            timestamp=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )
        db.session.add(scan)
        # Two docs in the same scan: spdx + grype
        spdx_doc = SBOMDocument(
            id=_uuid.uuid4(), path="/demo/spdx.json", source_name="spdx.json",
            format="spdx", scan_id=scan.id,
        )
        grype_doc = SBOMDocument(
            id=_uuid.uuid4(), path="/demo/grype.json", source_name="grype.json",
            format="grype", scan_id=scan.id,
        )
        db.session.add(spdx_doc)
        db.session.add(grype_doc)
        db.session.add(SBOMPackage(sbom_document_id=spdx_doc.id, package_id=pkg.id))
        db.session.add(SBOMPackage(sbom_document_id=grype_doc.id, package_id=pkg.id))
        db.session.add(Observation(finding_id=finding.id, scan_id=scan.id))
        db.session.commit()

    response = client.get("/api/vulnerabilities")
    data = json.loads(response.data)
    mixed_vuln = next((v for v in data if v["id"] == "CVE-MIXED-0001"), None)
    assert mixed_vuln is not None
    # No preference heuristic: both formats are reported.
    assert "spdx3" in mixed_vuln["found_by"]
    assert "grype" in mixed_vuln["found_by"]


def test_found_by_yocto_cve_check_mapping(app, client):
    """A vuln observed in a yocto_cve_check document maps found_by to
    'yocto_cve_check' via the observing-scan derivation."""
    from src.extensions import db
    from src.models.scan import Scan
    from src.models.sbom_document import SBOMDocument
    from src.models.observation import Observation
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.sbom_package import SBOMPackage
    from datetime import datetime, timezone

    with app.app_context():
        pkg = Package.find_or_create("yocto-test-pkg", "6.0.0", [], [], "")
        db.session.commit()
        Vulnerability.create_record(
            id="CVE-YOCTO-0001",
            description="Test vuln for yocto_cve_check mapping",
            status="medium",
        )
        db.session.commit()
        finding = Finding.get_or_create(pkg.id, "CVE-YOCTO-0001")

        import uuid as _uuid
        scan = Scan(
            id=_uuid.uuid4(),
            variant_id=_uuid.UUID("22222222-2222-2222-2222-222222222222"),
            timestamp=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )
        db.session.add(scan)
        yocto_doc = SBOMDocument(
            id=_uuid.uuid4(), path="/demo/yocto.json", source_name="yocto.json",
            format="yocto_cve_check", scan_id=scan.id,
        )
        db.session.add(yocto_doc)
        db.session.add(SBOMPackage(sbom_document_id=yocto_doc.id, package_id=pkg.id))
        db.session.add(Observation(finding_id=finding.id, scan_id=scan.id))
        db.session.commit()

    response = client.get("/api/vulnerabilities")
    data = json.loads(response.data)
    yocto_vuln = next((v for v in data if v["id"] == "CVE-YOCTO-0001"), None)
    assert yocto_vuln is not None
    assert "yocto_cve_check" in yocto_vuln["found_by"]


# ---------------------------------------------------------------------------
# GET /api/vulnerabilities — variant/project with no scans → empty list
# ---------------------------------------------------------------------------

def test_get_vulns_variant_no_scans(app, client):
    """GET with variant_id of a variant that has no scans returns []."""
    from src.extensions import db
    from src.models.project import Project
    from src.models.variant import Variant
    import uuid as _uuid

    with app.app_context():
        project = Project.create("NoScanProject")
        variant = Variant.create("noscan-variant", project.id)
        vid = str(variant.id)
    response = client.get(f"/api/vulnerabilities?variant_id={vid}")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data == []


def test_get_vulns_project_no_scans(app, client):
    """GET with project_id of a project that has no scans returns []."""
    from src.extensions import db
    from src.models.project import Project
    import uuid as _uuid

    with app.app_context():
        project = Project.create("NoScanProject2")
        pid = str(project.id)
    response = client.get(f"/api/vulnerabilities?project_id={pid}")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data == []


# ---------------------------------------------------------------------------
# GET /api/vulnerabilities?project_id=... (with data — covers bulk-load paths)
# ---------------------------------------------------------------------------

def test_get_vulns_by_project_id_with_data(app, client):
    """GET with a valid project_id that has scans returns vulns with metrics/packages/effort."""
    # The demo project "11111111..." has a scan with a CVE
    pid = "11111111-1111-1111-1111-111111111111"
    response = client.get(f"/api/vulnerabilities?project_id={pid}")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) >= 1
    vuln = data[0]
    assert "id" in vuln
    assert "packages" in vuln
    assert "severity" in vuln


# ---------------------------------------------------------------------------
# GET /api/vulnerabilities (no scope) — covers fallback scope
# ---------------------------------------------------------------------------

def test_get_vulns_global_no_scope(client):
    """GET without variant_id or project_id returns all vulns (fallback)."""
    response = client.get("/api/vulnerabilities")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) >= 1
    # Check enrichment fields
    vuln = data[0]
    assert "variants" in vuln
    assert "first_scan_date" in vuln


# ---------------------------------------------------------------------------
# GET /api/vulnerabilities/<id>/variant-snapshots — single batched call
# ---------------------------------------------------------------------------

def test_variant_snapshots_returns_effort_and_custom_cvss(app, client):
    """The batch endpoint returns per-variant effort and custom CVSS in one call."""
    from src.extensions import db
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.observation import Observation
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.metrics import Metrics
    from src.models.time_estimate import TimeEstimate
    from datetime import datetime, timezone
    import uuid as _uuid

    with app.app_context():
        project = Project.create("SnapshotProject")
        variant = Variant.create("snapshot-variant", project.id)
        pkg = Package.find_or_create("snapshot-pkg", "1.0.0", [], [], "")
        db.session.commit()
        Vulnerability.create_record(
            id="CVE-SNAP-0001",
            description="Test vuln for variant snapshots",
            status="high",
        )
        db.session.commit()
        finding = Finding.get_or_create(pkg.id, "CVE-SNAP-0001")

        scan = Scan(
            id=_uuid.uuid4(),
            variant_id=variant.id,
            timestamp=datetime(2021, 1, 1, tzinfo=timezone.utc),
        )
        db.session.add(scan)
        db.session.add(Observation(finding_id=finding.id, scan_id=scan.id))

        # Variant-scoped custom CVSS and time estimate
        Metrics.create(
            vulnerability_id="CVE-SNAP-0001",
            variant_id=variant.id,
            version="3.1",
            score=7.5,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            author="tester",
            origin="custom",
        )
        TimeEstimate.create(
            finding_id=finding.id,
            variant_id=variant.id,
            optimistic=1,
            likely=2,
            pessimistic=4,
        )
        db.session.commit()
        pid = str(project.id)
        vid = str(variant.id)

    response = client.get(f"/api/vulnerabilities/CVE-SNAP-0001/variant-snapshots?project_id={pid}")
    assert response.status_code == 200
    snapshots = json.loads(response.data)
    assert isinstance(snapshots, list)
    snap = next((s for s in snapshots if s["variant_id"] == vid), None)
    assert snap is not None
    assert snap["effort"]["optimistic"] is not None
    assert len(snap["custom_cvss"]) == 1
    assert snap["custom_cvss"][0]["origin"] == "custom"
    assert snap["custom_cvss"][0]["base_score"] == 7.5


def test_variant_snapshots_unknown_vuln_returns_404(client):
    """The batch endpoint returns 404 for an unknown vulnerability id."""
    response = client.get("/api/vulnerabilities/CVE-DOES-NOT-EXIST/variant-snapshots")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/vulnerabilities/<id>/variant-snapshots — invalid project_id
# ---------------------------------------------------------------------------

def test_variant_snapshots_invalid_project_id(client):
    """variant-snapshots with a malformed project_id returns 400."""
    response = client.get(
        "/api/vulnerabilities/CVE-2020-35492/variant-snapshots?project_id=not-a-uuid"
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# POST /api/vulnerabilities/<id>/nvd-refresh
# ---------------------------------------------------------------------------

def test_nvd_refresh_cve_not_found(client):
    """POST nvd-refresh for unknown CVE returns 404."""
    response = client.post("/api/vulnerabilities/CVE-9999-99999/nvd-refresh")
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["error"].lower()


def test_nvd_refresh_api_exception_returns_503(client):
    """POST nvd-refresh when NVD API raises an exception returns 503."""
    from unittest.mock import patch, MagicMock
    with patch("src.routes.vulnerabilities.NVD_DB") as mock_nvd_cls:
        mock_nvd_cls.return_value.api_get_cve.side_effect = Exception("Network error")
        response = client.post("/api/vulnerabilities/CVE-2020-35492/nvd-refresh",
                               json={"mode": "api"})
    assert response.status_code == 503
    data = json.loads(response.data)
    assert data["error_code"] == "unavailable"


def test_nvd_refresh_rate_limited_returns_429(client):
    """POST nvd-refresh when NVD API returns 429 passes it through."""
    from unittest.mock import patch
    with patch("src.routes.vulnerabilities.NVD_DB") as mock_nvd_cls:
        mock_nvd_cls.return_value.api_get_cve.return_value = (429, {})
        response = client.post("/api/vulnerabilities/CVE-2020-35492/nvd-refresh",
                               json={"mode": "api"})
    assert response.status_code == 429
    data = json.loads(response.data)
    assert data["error_code"] == "rate_limited"


def test_nvd_refresh_unauthorized_returns_401(client):
    """POST nvd-refresh when NVD API returns 401 passes it through."""
    from unittest.mock import patch
    with patch("src.routes.vulnerabilities.NVD_DB") as mock_nvd_cls:
        mock_nvd_cls.return_value.api_get_cve.return_value = (401, {})
        response = client.post("/api/vulnerabilities/CVE-2020-35492/nvd-refresh",
                               json={"mode": "api"})
    assert response.status_code == 401
    data = json.loads(response.data)
    assert data["error_code"] == "unauthorized"


def test_nvd_refresh_forbidden_returns_403(client):
    """POST nvd-refresh when NVD API returns 403 passes it through."""
    from unittest.mock import patch
    with patch("src.routes.vulnerabilities.NVD_DB") as mock_nvd_cls:
        mock_nvd_cls.return_value.api_get_cve.return_value = (403, {})
        response = client.post("/api/vulnerabilities/CVE-2020-35492/nvd-refresh",
                               json={"mode": "api"})
    assert response.status_code == 403
    data = json.loads(response.data)
    assert data["error_code"] == "unauthorized"


def test_nvd_refresh_no_data_returns_503(client):
    """POST nvd-refresh when NVD API returns 200 with empty vulnerabilities returns 503."""
    from unittest.mock import patch
    with patch("src.routes.vulnerabilities.NVD_DB") as mock_nvd_cls:
        mock_nvd_cls.return_value.api_get_cve.return_value = (200, {"vulnerabilities": []})
        response = client.post("/api/vulnerabilities/CVE-2020-35492/nvd-refresh",
                               json={"mode": "api"})
    assert response.status_code == 503
    data = json.loads(response.data)
    assert data["error_code"] == "unavailable"


def test_nvd_refresh_success_no_cvss(client):
    """POST nvd-refresh with valid response but no CVSS data returns 200."""
    from unittest.mock import patch, MagicMock
    fake_details = {
        "description": "Updated description",
        "base_score": None,
        "cvss_version": None,
        "cvss_vector": None,
    }
    cve_payload = {"id": "CVE-2020-35492", "descriptions": []}
    with patch("src.routes.vulnerabilities.NVD_DB") as mock_nvd_cls, \
         patch("src.routes.vulnerabilities.apply_nvd_update") as mock_apply:
        mock_nvd_cls.return_value.api_get_cve.return_value = (
            200,
            {"vulnerabilities": [{"cve": cve_payload}]},
        )
        mock_nvd_cls.extract_cve_details.return_value = fake_details
        response = client.post("/api/vulnerabilities/CVE-2020-35492/nvd-refresh",
                               json={"mode": "api"})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "vulnerabilities" in data
    assert data["vulnerabilities"][0]["id"] == "CVE-2020-35492"


def test_nvd_refresh_success_updates_existing_metric(app, client):
    """POST nvd-refresh with CVSS data updates an existing Metrics row."""
    from unittest.mock import patch
    from src.extensions import db
    from src.models.metrics import Metrics

    with app.app_context():
        existing_metric = db.session.execute(
            db.select(Metrics).where(
                Metrics.vulnerability_id == "CVE-2020-35492",
                Metrics.version == "3.1",
                Metrics.variant_id.is_(None),
            )
        ).scalar_one_or_none()
        if existing_metric is None:
            db.session.add(Metrics(
                vulnerability_id="CVE-2020-35492",
                version="3.1",
                score=7.8,
                vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                author="nvd",
            ))
            db.session.commit()

    fake_details = {
        "description": "Updated",
        "base_score": 8.0,
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
    cve_payload = {"id": "CVE-2020-35492"}
    with patch("src.routes.vulnerabilities.NVD_DB") as mock_nvd_cls, \
         patch("src.routes.vulnerabilities.apply_nvd_update"):
        mock_nvd_cls.return_value.api_get_cve.return_value = (
            200,
            {"vulnerabilities": [{"cve": cve_payload}]},
        )
        mock_nvd_cls.extract_cve_details.return_value = fake_details
        response = client.post("/api/vulnerabilities/CVE-2020-35492/nvd-refresh",
                               json={"mode": "api"})

    assert response.status_code == 200


def test_nvd_refresh_success_adds_new_metric(app, client):
    """POST nvd-refresh with CVSS for a new version adds a Metrics row."""
    from unittest.mock import patch

    fake_details = {
        "description": "Updated",
        "base_score": 6.5,
        "cvss_version": "4.0",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    }
    cve_payload = {"id": "CVE-2020-35492"}
    with patch("src.routes.vulnerabilities.NVD_DB") as mock_nvd_cls, \
         patch("src.routes.vulnerabilities.apply_nvd_update"):
        mock_nvd_cls.return_value.api_get_cve.return_value = (
            200,
            {"vulnerabilities": [{"cve": cve_payload}]},
        )
        mock_nvd_cls.extract_cve_details.return_value = fake_details
        response = client.post("/api/vulnerabilities/CVE-2020-35492/nvd-refresh",
                               json={"mode": "api"})

    assert response.status_code == 200


# ---------------------------------------------------------------------------
# POST /api/vulnerabilities/<id>/epss-refresh
# ---------------------------------------------------------------------------

def test_epss_refresh_cve_not_found(client):
    """POST epss-refresh for unknown CVE returns 404."""
    response = client.post("/api/vulnerabilities/CVE-9999-99999/epss-refresh")
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["error"].lower()


def test_epss_refresh_api_failure_gives_503(client):
    """POST epss-refresh gives 503 when the EPSS lookup fails."""
    from unittest.mock import patch
    with patch("src.routes.vulnerabilities.EPSS_DB") as mock_epss_cls:
        mock_epss_cls.return_value.api_get_epss.side_effect = OSError("offline")
        response = client.post("/api/vulnerabilities/CVE-2020-35492/epss-refresh")
    assert response.status_code == 503
    data = json.loads(response.data)
    assert "lookup failed" in data["error"].lower()


def test_epss_refresh_success(client):
    """POST epss-refresh with valid data returns 200 with updated vulnerability."""
    from unittest.mock import patch
    with patch("src.routes.vulnerabilities.EPSS_DB") as mock_epss_cls:
        mock_epss_cls.return_value.api_get_epss.return_value = {
            "score": "0.55000",
            "percentile": "0.85000",
        }
        response = client.post("/api/vulnerabilities/CVE-2020-35492/epss-refresh")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "vulnerabilities" in data
    vuln = data["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2020-35492"
    assert vuln["epss"]["score"] is not None


# ---------------------------------------------------------------------------
# POST /api/vulnerabilities/<id>/euvd-refresh
# ---------------------------------------------------------------------------

def _write_euvd_cache(cache_dir, mapping_rows, kev_entries):
    euvd_dir = cache_dir / "euvd"
    euvd_dir.mkdir(parents=True, exist_ok=True)
    (euvd_dir / "euvd_cve_mapping.csv").write_text(
        "euvd_id,cve_id\n" + "".join(f"{euvd},{cve}\n" for euvd, cve in mapping_rows)
    )
    (euvd_dir / "euvd_kev.json").write_text(json.dumps(kev_entries))


def test_euvd_refresh_rejects_non_cve_and_unknown_ids(client):
    assert client.post("/api/vulnerabilities/GHSA-1234-5678-9012/euvd-refresh").status_code == 400
    assert client.post("/api/vulnerabilities/CVE-2099-99999/euvd-refresh").status_code == 404


def test_euvd_refresh_sets_and_clears_eu_kev(client, tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(cache_dir))
    mapping = [("EUVD-2020-1234", "CVE-2020-35492")]
    _write_euvd_cache(cache_dir, mapping, [{
        "cveId": "CVE-2020-35492", "euvdId": "EUVD-2020-1234",
        "sources": ["CISA"], "dateAdded": "2026-11-01",
    }])

    response = client.post("/api/vulnerabilities/cve-2020-35492/euvd-refresh")
    assert response.status_code == 200
    vuln = response.get_json()["vulnerabilities"][0]
    assert vuln["euvd"] == {
        "id": "EUVD-2020-1234",
        "known_exploited": True,
        "sources": ["CISA"],
        "date_added": "2026-11-01",
        "url": "https://euvd.enisa.europa.eu/vulnerability/EUVD-2020-1234",
    }
    assert "EUVD-2020-1234" in vuln["aliases"]
    assert vuln["euvd_fetched_at"] is not None

    _write_euvd_cache(cache_dir, mapping, [{"cveId": "CVE-2000-0001", "euvdId": "EUVD-2000-0001"}])
    response = client.post("/api/vulnerabilities/CVE-2020-35492/euvd-refresh")
    assert response.status_code == 200
    euvd = response.get_json()["vulnerabilities"][0]["euvd"]
    assert euvd["id"] == "EUVD-2020-1234"
    assert euvd["known_exploited"] is False
    assert euvd["sources"] == []

    history = client.get(
        "/api/vulnerabilities/CVE-2020-35492/history?field=euvd_known_exploited"
    ).get_json()["history"]
    assert [(row["value"], row["source"]) for row in history][-2:] == [(True, "euvd"), (False, "euvd")]


@pytest.mark.parametrize("mapping_rows,kev_entries", [
    ([], [{"cveId": "CVE-2020-35492", "euvdId": "EUVD-2020-1234"}]),
    ([("EUVD-2020-1234", "CVE-2020-35492")], []),
])
def test_euvd_refresh_unavailable_data_returns_503(client, tmp_path, monkeypatch, mapping_rows, kev_entries):
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(cache_dir))
    _write_euvd_cache(cache_dir, mapping_rows, kev_entries)

    response = client.post("/api/vulnerabilities/CVE-2020-35492/euvd-refresh")
    assert response.status_code == 503
    assert "unavailable" in response.get_json()["error"]


# ---------------------------------------------------------------------------
# POST /api/vulnerabilities/<ghsa_id>/ghsa-refresh
# ---------------------------------------------------------------------------

def _ensure_ghsa_in_db(app, ghsa_id="GHSA-1234-5678-9012"):
    """Create a GHSA vulnerability in the test DB if it doesn't exist."""
    from src.extensions import db
    from src.models.vulnerability import Vulnerability
    with app.app_context():
        existing = db.session.get(Vulnerability, ghsa_id)
        if not existing:
            Vulnerability.create_record(id=ghsa_id, description="Test GHSA", status="medium")
            db.session.commit()


def test_ghsa_refresh_invalid_format_returns_400(client):
    """POST ghsa-refresh with a non-GHSA ID returns 400."""
    response = client.post("/api/vulnerabilities/CVE-2020-1234/ghsa-refresh")
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "GHSA" in data["error"]


def test_ghsa_refresh_invalid_segment_length_returns_400(client):
    """POST ghsa-refresh with wrong-length GHSA segments returns 400."""
    response = client.post("/api/vulnerabilities/GHSA-1234-5678-TOOLONG/ghsa-refresh")
    assert response.status_code == 400


def test_ghsa_refresh_not_in_db_returns_404(client):
    """POST ghsa-refresh for GHSA not in DB returns 404."""
    response = client.post("/api/vulnerabilities/GHSA-ZZZZ-ZZZZ-ZZZZ/ghsa-refresh")
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["error"].lower()


def test_ghsa_refresh_github_404_returns_404(app, client):
    """POST ghsa-refresh when GitHub returns 404 for the advisory returns 404."""
    import urllib.error
    from unittest.mock import patch
    _ensure_ghsa_in_db(app, "GHSA-ABCD-EFGH-1234")
    with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published") as mock_fetch:
        mock_fetch.side_effect = urllib.error.HTTPError(
            url="https://api.github.com", code=404, msg="Not Found", hdrs=None, fp=None
        )
        response = client.post("/api/vulnerabilities/GHSA-ABCD-EFGH-1234/ghsa-refresh")
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["error"].lower()


def test_ghsa_refresh_github_http_error_returns_502(app, client):
    """POST ghsa-refresh when GitHub returns a non-404 HTTP error returns 502."""
    import urllib.error
    from unittest.mock import patch
    _ensure_ghsa_in_db(app, "GHSA-ABCD-EFGH-5678")
    with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published") as mock_fetch:
        mock_fetch.side_effect = urllib.error.HTTPError(
            url="https://api.github.com", code=500, msg="Server Error", hdrs=None, fp=None
        )
        response = client.post("/api/vulnerabilities/GHSA-ABCD-EFGH-5678/ghsa-refresh")
    assert response.status_code == 502
    data = json.loads(response.data)
    assert "HTTP 500" in data["error"]


def test_ghsa_refresh_url_error_returns_503(app, client):
    """POST ghsa-refresh when GitHub is unreachable returns 503."""
    import urllib.error
    from unittest.mock import patch
    _ensure_ghsa_in_db(app, "GHSA-ABCD-EFGH-9012")
    with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published") as mock_fetch:
        mock_fetch.side_effect = urllib.error.URLError("Connection refused")
        response = client.post("/api/vulnerabilities/GHSA-ABCD-EFGH-9012/ghsa-refresh")
    assert response.status_code == 503
    data = json.loads(response.data)
    assert "Failed to reach" in data["error"]


def test_ghsa_refresh_none_published_at_returns_503(app, client):
    """POST ghsa-refresh when GitHub returns no published date returns 503."""
    from unittest.mock import patch
    _ensure_ghsa_in_db(app, "GHSA-ABCD-EFGH-3456")
    with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published") as mock_fetch:
        mock_fetch.return_value = None
        response = client.post("/api/vulnerabilities/GHSA-ABCD-EFGH-3456/ghsa-refresh")
    assert response.status_code == 503
    data = json.loads(response.data)
    assert "no published date" in data["error"].lower()


def test_ghsa_refresh_bad_date_format_returns_503(app, client):
    """POST ghsa-refresh when GitHub returns unparseable date returns 503."""
    from unittest.mock import patch
    _ensure_ghsa_in_db(app, "GHSA-ABCD-EFGH-7890")
    with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published") as mock_fetch:
        mock_fetch.return_value = "not-a-date"
        response = client.post("/api/vulnerabilities/GHSA-ABCD-EFGH-7890/ghsa-refresh")
    assert response.status_code == 503
    data = json.loads(response.data)
    assert "unparseable" in data["error"].lower()


def test_ghsa_refresh_success(app, client):
    """POST ghsa-refresh with valid published date returns 200."""
    from unittest.mock import patch
    _ensure_ghsa_in_db(app, "GHSA-BCDE-FGHI-2345")
    with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published") as mock_fetch:
        mock_fetch.return_value = "2024-03-15"
        response = client.post("/api/vulnerabilities/GHSA-BCDE-FGHI-2345/ghsa-refresh")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "vulnerabilities" in data
    assert data["vulnerabilities"][0]["id"] == "GHSA-BCDE-FGHI-2345"


def test_ghsa_refresh_success_updates_date(app, client):
    """POST ghsa-refresh with a new date updates publish_date and returns it."""
    from unittest.mock import patch
    from src.extensions import db
    from src.models.vulnerability import Vulnerability
    import datetime
    _ensure_ghsa_in_db(app, "GHSA-CDEF-GHIJ-3456")
    # Set an initial publish date that differs from what we'll return
    with app.app_context():
        rec = db.session.get(Vulnerability, "GHSA-CDEF-GHIJ-3456")
        if rec:
            rec.update_record(publish_date=datetime.date(2020, 1, 1), commit=True)

    with patch("src.routes.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published") as mock_fetch:
        mock_fetch.return_value = "2024-06-15"
        response = client.post("/api/vulnerabilities/GHSA-CDEF-GHIJ-3456/ghsa-refresh")

    assert response.status_code == 200


# ---------------------------------------------------------------------------
# GET /api/vulnerabilities — compare_variant_id difference with data
# ---------------------------------------------------------------------------

def test_get_vulnerabilities_compare_difference_with_base_ids(app, client):
    """Difference op returns only vulns in compare that are NOT in base."""
    from src.extensions import db
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.observation import Observation
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from datetime import datetime, timezone
    import uuid as _uuid

    with app.app_context():
        project = Project.create("DiffProject")
        base_v = Variant.create("diff-base", project.id)
        compare_v = Variant.create("diff-compare", project.id)
        pkg = Package.find_or_create("diff-pkg", "1.0.0", [], [], "")
        db.session.commit()

        # Shared vuln (in both)
        shared = Vulnerability.create_record(id="CVE-DIFF-SHARED-001", description="shared", status="low")
        # Only in compare
        compare_only = Vulnerability.create_record(id="CVE-DIFF-COMPARE-001", description="compare only", status="high")
        db.session.commit()

        finding_shared = Finding.get_or_create(pkg.id, shared.id)
        finding_compare = Finding.get_or_create(pkg.id, compare_only.id)

        base_scan = Scan(id=_uuid.uuid4(), variant_id=base_v.id,
                         timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc))
        compare_scan = Scan(id=_uuid.uuid4(), variant_id=compare_v.id,
                            timestamp=datetime(2024, 1, 2, tzinfo=timezone.utc))
        db.session.add_all([base_scan, compare_scan])

        base_doc = SBOMDocument(id=_uuid.uuid4(), path="/b.spdx.json",
                                source_name="b.spdx.json", format="spdx", scan_id=base_scan.id)
        compare_doc = SBOMDocument(id=_uuid.uuid4(), path="/c.spdx.json",
                                   source_name="c.spdx.json", format="spdx", scan_id=compare_scan.id)
        db.session.add_all([base_doc, compare_doc])
        db.session.add(SBOMPackage(sbom_document_id=base_doc.id, package_id=pkg.id))
        db.session.add(SBOMPackage(sbom_document_id=compare_doc.id, package_id=pkg.id))

        # Shared: in both
        db.session.add(Observation(finding_id=finding_shared.id, scan_id=base_scan.id))
        db.session.add(Observation(finding_id=finding_shared.id, scan_id=compare_scan.id))
        # compare-only: only in compare
        db.session.add(Observation(finding_id=finding_compare.id, scan_id=compare_scan.id))
        db.session.commit()

        base_id = str(base_v.id)
        compare_id = str(compare_v.id)

    response = client.get(
        f"/api/vulnerabilities?variant_id={base_id}&compare_variant_id={compare_id}&operation=difference"
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    ids = [v["id"] for v in data]
    # Only compare-only vuln should appear; shared one is excluded
    assert "CVE-DIFF-COMPARE-001" in ids
    assert "CVE-DIFF-SHARED-001" not in ids


def _large_payload():
    return [{"id": f"CVE-2020-{i:05d}", "summary": "x" * 64} for i in range(50)]


@pytest.mark.parametrize("accept_encoding", [
    "gzip",
    "GZip",
    "br, GZIP;q=0.5",
])
def test_compact_response_is_gzipped_when_the_client_accepts_it(accept_encoding):
    payload = _large_payload()

    with Flask(__name__).test_request_context(headers={"Accept-Encoding": accept_encoding}):
        response = _compact_json_response(payload)

    assert response.headers["Content-Encoding"] == "gzip"
    assert response.headers["Vary"] == "Accept-Encoding"
    assert json.loads(gzip.decompress(response.get_data())) == payload


def test_compact_response_stays_plain_without_gzip_support():
    payload = _large_payload()

    with Flask(__name__).test_request_context():
        response = _compact_json_response(payload)

    assert "Content-Encoding" not in response.headers
    assert json.loads(response.get_data()) == payload


def test_compact_response_stays_plain_when_gzip_is_rejected():
    payload = _large_payload()

    with Flask(__name__).test_request_context(headers={"Accept-Encoding": "gzip;q=0"}):
        response = _compact_json_response(payload)

    assert "Content-Encoding" not in response.headers
    assert json.loads(response.get_data()) == payload


def test_compact_response_leaves_small_payloads_uncompressed():
    with Flask(__name__).test_request_context(headers={"Accept-Encoding": "gzip"}):
        response = _compact_json_response([{"id": "CVE-2020-35492"}])

    assert "Content-Encoding" not in response.headers
    assert json.loads(response.get_data()) == [{"id": "CVE-2020-35492"}]


def test_compact_endpoint_serves_decodable_json_to_a_gzip_client(client):
    response = client.get(
        "/api/vulnerabilities?format=compact",
        headers={"Accept-Encoding": "gzip"},
    )

    assert response.status_code == 200
    body = response.data
    if response.headers.get("Content-Encoding") == "gzip":
        body = gzip.decompress(body)
    assert [v["id"] for v in json.loads(body)] == ["CVE-2020-35492"]

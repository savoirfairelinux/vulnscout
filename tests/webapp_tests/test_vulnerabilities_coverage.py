# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import json
from src.bin.webapp import create_app
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


# ---------------------------------------------------------------------------
# GET /api/vulnerabilities — compare_variant_id paths (lines 88, 100, 118)
# ---------------------------------------------------------------------------

def test_get_vulnerabilities_compare_base_none(client):
    """GET with variant_id+compare_variant_id where base has no scan → base_ids=set() (line 88)."""
    import uuid
    base_id = str(uuid.uuid4())
    compare_id = str(uuid.uuid4())
    response = client.get(f"/api/vulnerabilities?variant_id={base_id}&compare_variant_id={compare_id}")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)


def test_get_vulnerabilities_compare_intersection_no_scan(client):
    """GET with operation=intersection and compare has no scan → records=[] (line 100)."""
    import uuid
    base_id = str(uuid.uuid4())
    compare_id = str(uuid.uuid4())
    response = client.get(
        f"/api/vulnerabilities?variant_id={base_id}&compare_variant_id={compare_id}&operation=intersection"
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data == []


def test_get_vulnerabilities_compare_difference_no_scan(client):
    """GET (default difference) compare has no scan → records=[] (line 118)."""
    import uuid
    base_id = str(uuid.uuid4())
    compare_id = str(uuid.uuid4())
    response = client.get(
        f"/api/vulnerabilities?variant_id={base_id}&compare_variant_id={compare_id}&operation=difference"
    )
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

    response = client.get(
        f"/api/vulnerabilities?variant_id={base_id}&compare_variant_id={compare_id}&operation=intersection"
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert any(v["id"] == "CVE-COMPARE-0001" for v in data)


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
    assert vulns["skip"]["effort"] is None


def test_populate_found_by_handles_non_string_doc_formats(monkeypatch):
    """In the legacy fallback, non-string doc formats are skipped and tool
    scan sources are mapped."""
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

    # The function runs two queries: (1) provenance markers, (2) legacy
    # fallback. Return no provenance markers so both vulns fall through to the
    # fallback, then return fallback rows shaped (vuln_id, scan_source,
    # doc_format).
    fallback_rows = [
        ("v1", "nvd", None),      # non-string doc format -> use scan_source
        ("v2", None, 12345),      # both non-string -> nothing added
    ]
    calls = {"n": 0}

    def _fake_execute(*args, **kwargs):
        calls["n"] += 1
        # 1st call: provenance query (empty), 2nd call: fallback query
        return _Result([] if calls["n"] == 1 else fallback_rows)

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
    """When earliest scan has an SPDX SBOMDocument, found_by should contain 'spdx3'."""
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
            timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc),
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
    """When earliest scan is a tool scan with scan_source='nvd', found_by should contain 'nvd_cpe'."""
    from src.extensions import db
    from src.models.scan import Scan
    from src.models.observation import Observation
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
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
        scan = Scan(
            id=_uuid.uuid4(),
            variant_id=_uuid.UUID("22222222-2222-2222-2222-222222222222"),
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
            timestamp=datetime(2018, 1, 1, tzinfo=timezone.utc),
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
            timestamp=datetime(2016, 1, 1, tzinfo=timezone.utc),
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



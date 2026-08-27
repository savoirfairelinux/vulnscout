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
        with application.app_context():
            from src.extensions import db
            from src.models.finding import Finding
            from src.models.observation import Observation
            from src.models.package import Package
            from src.models.vulnerability import Vulnerability

            package = Package.get_by_string_id("cairo@1.16.0")
            assert package is not None
            Vulnerability.get_or_create("CVE-1999-12345")
            finding = Finding.get_or_create(package.id, "CVE-1999-12345")
            Observation.create(finding.id, "33333333-3333-3333-3333-333333333333", commit=False)
            db.session.commit()
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


@pytest.fixture()
def demo_ids(app):
    from src.extensions import db
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.scan import Scan
    from src.models.variant import Variant
    import uuid as uuid_module

    with app.app_context():
        vuln_id = "CVE-1999-12345"
        other_vuln_id = "CVE-1999-99999"
        for vid in (vuln_id, other_vuln_id):
            if Vulnerability.get_by_id(vid) is None:
                Vulnerability.create_record(id=vid)

        pkg_a = Package.find_or_create("cairo", "1.16.0")
        pkg_b = Package.find_or_create("libpng", "1.6.37")
        db.session.commit()

        variant_id = uuid_module.UUID("22222222-2222-2222-2222-222222222222")
        other_variant = Variant(
            id=uuid_module.uuid4(), name="other",
            project_id=uuid_module.UUID("11111111-1111-1111-1111-111111111111"))
        db.session.add(other_variant)
        db.session.commit()

        existing_scan_id = uuid_module.UUID("33333333-3333-3333-3333-333333333333")
        other_scan = Scan(id=uuid_module.uuid4(), variant_id=other_variant.id)
        db.session.add(other_scan)
        db.session.commit()

        for vid in (vuln_id, other_vuln_id):
            for pkg in (pkg_a, pkg_b):
                finding = Finding.get_or_create(pkg.id, vid)
                db.session.add(Observation(finding_id=finding.id, scan_id=existing_scan_id))
                db.session.add(Observation(finding_id=finding.id, scan_id=other_scan.id))
        db.session.commit()

        return {
            "vuln_id": vuln_id,
            "other_vuln_id": other_vuln_id,
            "variant_id": str(variant_id),
            "other_variant_id": str(other_variant.id),
            "two_packages": [pkg_a.string_id, pkg_b.string_id],
        }


def test_post_minimal_assessment(client):
    response = client.post("/api/vulnerabilities/CVE-1999-12345/assessments", json={
        'packages': ['cairo@1.16.0'],
        'status': 'exploitable',
        'workaround': 'Disable option X in configuration',
        'variant_id': '22222222-2222-2222-2222-222222222222',
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
        'packages': ['cairo@1.16.0'],
        'status': 'exploitable',
        'status_notes': 'Demonstration assessment',
        'responses': ['can_not_fix'],
        'impact_statement': 'This doesn\'t matter',
        'workaround': 'Disable option X in configuration',
        'workaround_timestamp': '2021-01-01T00:00:00Z',
        'timestamp': '2021-01-01T00:00:00Z',
        'last_updated': '2021-01-01T00:00:00Z',
        'variant_id': '22222222-2222-2222-2222-222222222222',
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


def test_post_assessment_missing_package_blocked(client):
    # A package that does not exist in the DB must not be auto-created; the
    # whole write is blocked with a 400 and no assessment is recorded.
    from src.models.package import Package

    before = client.get("/api/assessments?format=list")
    before_count = len(json.loads(before.data))

    response = client.post("/api/vulnerabilities/CVE-1999-12345/assessments", json={
        'packages': ['does-not-exist@9.9.9'],
        'status': 'exploitable',
        'variant_id': '22222222-2222-2222-2222-222222222222',
    })
    assert response.status_code == 400
    assert "does-not-exist@9.9.9" in response.get_data(as_text=True)

    # No package was created and no assessment was written.
    with client.application.app_context():
        assert Package.get_by_string_id("does-not-exist@9.9.9") is None
    after = client.get("/api/assessments?format=list")
    assert len(json.loads(after.data)) == before_count


def test_post_assessment_any_missing_package_blocks_all(client):
    # If ANY referenced package is missing, the whole request is rejected even
    # when other packages exist.
    from src.models.package import Package

    before = client.get("/api/assessments?format=list")
    before_count = len(json.loads(before.data))

    response = client.post("/api/vulnerabilities/CVE-1999-12345/assessments", json={
        'packages': ['cairo@1.16.0', 'missing@1.0.0'],
        'status': 'exploitable',
        'variant_id': '22222222-2222-2222-2222-222222222222',
    })
    assert response.status_code == 400
    assert "missing@1.0.0" in response.get_data(as_text=True)

    with client.application.app_context():
        assert Package.get_by_string_id("missing@1.0.0") is None
    after = client.get("/api/assessments?format=list")
    assert len(json.loads(after.data)) == before_count


def test_post_assessment_accepts_outdated_observed_finding(client):
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package

    with client.application.app_context():
        old_package = Package.find_or_create("cairo", "1.15.0")
        old_finding = Finding.get_or_create(old_package.id, "CVE-1999-12345")
        Observation.create(old_finding.id, "33333333-3333-3333-3333-333333333333", commit=False)
        db.session.commit()

    response = client.post("/api/vulnerabilities/CVE-1999-12345/assessments", json={
        'packages': ['cairo@1.15.0'],
        'status': 'exploitable',
        'variant_id': '22222222-2222-2222-2222-222222222222',
    })
    assert response.status_code == 200
    assert json.loads(response.data)["assessment"]["packages"] == ["cairo@1.15.0"]


def test_post_assessment_rejects_unobserved_finding(client):
    from src.models.package import Package

    with client.application.app_context():
        Package.find_or_create("cairo", "1.14.0")
        from src.extensions import db
        db.session.commit()

    response = client.post("/api/vulnerabilities/CVE-1999-12345/assessments", json={
        'packages': ['cairo@1.14.0'],
        'status': 'exploitable',
        'variant_id': '22222222-2222-2222-2222-222222222222',
    })
    assert response.status_code == 400
    assert "Invalid package version" in response.get_data(as_text=True)


def test_batch_missing_package_cancels_whole_batch(client):
    # A missing package cancels the complete user action, including valid items.
    from src.models.assessment import Assessment
    from src.models.package import Package

    with client.application.app_context():
        before = len(Assessment.get_by_vulnerability("CVE-1999-12345"))

    response = client.post("/api/assessments/batch", json={
        'assessments': [
            {
                'vuln_id': 'CVE-1999-12345',
                'packages': ['cairo@1.16.0'],
                'status': 'exploitable',
                'variant_id': '22222222-2222-2222-2222-222222222222',
            },
            {
                'vuln_id': 'CVE-1999-12345',
                'packages': ['ghost@0.0.1'],
                'status': 'exploitable',
                'variant_id': '22222222-2222-2222-2222-222222222222',
            },
        ]
    })
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["count"] == 0
    assert data["assessments"] == []
    assert data.get("error_count") == 1
    assert any("ghost@0.0.1" in e.get("error", "") for e in data["errors"])

    with client.application.app_context():
        assert Package.get_by_string_id("ghost@0.0.1") is None
        assert len(Assessment.get_by_vulnerability("CVE-1999-12345")) == before


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


def test_update_assessment(client):
    # First create an assessment
    response = client.post("/api/vulnerabilities/CVE-1999-12345/assessments", json={
        'packages': ['cairo@1.16.0'],
        'status': 'exploitable',
        'status_notes': 'Initial assessment',
        'workaround': 'No workaround available',
        'variant_id': '22222222-2222-2222-2222-222222222222',
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
        'packages': ['cairo@1.16.0'],
        'status': 'exploitable',
        'variant_id': '22222222-2222-2222-2222-222222222222',
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
        'packages': ['cairo@1.16.0'],
        'status': 'exploitable',
        'status_notes': 'Assessment to be deleted',
        'variant_id': '22222222-2222-2222-2222-222222222222',
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


def test_multi_package_assessment_creates_a_group_per_package(client, demo_ids):
    """Grouping is now storage, not inference: a multi-package write still
    creates one row per package (unmigrated in this phase), and each row is
    its own group — rows that merely arrived in the same request are no
    longer fused at read time."""
    response = client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "not_affected",
            "justification": "component_not_present",
            "packages": demo_ids["two_packages"],
            "variant_id": demo_ids["variant_id"],
        },
    )

    assert response.status_code == 200
    body = response.get_json()
    assert len(body["assessments"]) == 2
    group_ids = {a["group_id"] for a in body["assessments"]}
    assert None not in group_ids
    assert group_ids == {a["id"] for a in body["assessments"]}


def test_single_package_assessment_is_its_own_group(client, demo_ids):
    response = client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "not_affected",
            "justification": "component_not_present",
            "packages": [demo_ids["two_packages"][0]],
            "variant_id": demo_ids["variant_id"],
        },
    )

    assert response.status_code == 200
    row = response.get_json()["assessments"][0]
    assert row["group_id"] == row["id"]


def test_payload_group_id_no_longer_merges_writes_into_one_group(client, demo_ids):
    """Joining an existing group at write time is out of scope for this
    phase: a group only grows through reconcile, once it already holds real
    targets. The legacy ``group_id`` payload still validates the referenced
    group exists, but the new row remains its own, separate group."""
    first = client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "not_affected",
            "justification": "component_not_present",
            "packages": demo_ids["two_packages"],
            "variant_id": demo_ids["variant_id"],
        },
    ).get_json()
    group_id = first["assessments"][0]["group_id"]

    second = client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "not_affected",
            "justification": "component_not_present",
            "packages": [demo_ids["two_packages"][0]],
            "variant_id": demo_ids["other_variant_id"],
            "group_id": group_id,
        },
    )

    assert second.status_code == 200
    second_row = second.get_json()["assessments"][0]
    assert second_row["group_id"] == second_row["id"]
    assert second_row["group_id"] != group_id


def test_batch_creates_a_group_per_row_not_per_request(client, demo_ids):
    """A batch is one user action but grouping is per stored row now: rows
    that used to be fused by a shared invariant key are separate groups."""
    response = client.post("/api/assessments/batch", json={"assessments": [
        {
            "vuln_id": demo_ids["vuln_id"],
            "status": "not_affected",
            "justification": "component_not_present",
            "packages": demo_ids["two_packages"],
            "variant_id": demo_ids["variant_id"],
        },
        {
            "vuln_id": demo_ids["other_vuln_id"],
            "status": "not_affected",
            "justification": "component_not_present",
            "packages": demo_ids["two_packages"],
            "variant_id": demo_ids["variant_id"],
        },
    ]})

    assert response.status_code == 200
    rows = response.get_json()["assessments"]
    assert len(rows) == 4
    group_ids = {row["group_id"] for row in rows}
    assert None not in group_ids
    assert group_ids == {row["id"] for row in rows}


def test_batch_multi_variant_single_vuln_yields_two_groups(client, demo_ids):
    """Two rows created by one batch request, for the same vulnerability
    across two variants, remain two independent groups."""
    response = client.post("/api/assessments/batch", json={"assessments": [
        {
            "vuln_id": demo_ids["vuln_id"],
            "status": "fixed",
            "packages": [demo_ids["two_packages"][0]],
            "variant_id": demo_ids["variant_id"],
        },
        {
            "vuln_id": demo_ids["vuln_id"],
            "status": "fixed",
            "packages": [demo_ids["two_packages"][0]],
            "variant_id": demo_ids["other_variant_id"],
        },
    ]})

    assert response.status_code == 200
    rows = response.get_json()["assessments"]
    group_ids = {row["group_id"] for row in rows}
    assert len(group_ids) == 2
    assert group_ids == {row["id"] for row in rows}


def test_batch_single_row_vulnerability_is_its_own_group(client, demo_ids):
    response = client.post("/api/assessments/batch", json={"assessments": [{
        "vuln_id": demo_ids["vuln_id"],
        "status": "fixed",
        "packages": [demo_ids["two_packages"][0]],
        "variant_id": demo_ids["variant_id"],
    }]})

    assert response.status_code == 200
    row = response.get_json()["assessments"][0]
    assert row["group_id"] == row["id"]

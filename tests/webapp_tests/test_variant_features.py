# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
#
# Tests for variant-scoped assessment features introduced in commit b006e03:
#   - GET /api/variants                           list all variants
#   - GET /api/vulnerabilities/<vuln_id>/variants  variants linked to a CVE
#   - POST assessment with variant_id             scope assessment to a variant
#   - variant_id field in assessment serialisation

import pytest
import json
import uuid
from src.bin.webapp import create_app
from . import write_demo_files, setup_demo_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

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
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        setup_demo_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def app_with_variants(init_files):
    """App fixture with a full Project → Variant → Scan → Observation chain."""
    import os
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": init_files["status"],
            "OPENVEX_FILE": init_files["openvex"],
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        setup_demo_db(application)
        _setup_variant_chain(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


def _setup_variant_chain(app):
    """Add Project → Variant → Scan → Observation so the vuln-variants endpoint works."""
    from src.extensions import db
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.observation import Observation
    from src.models.finding import Finding

    with app.app_context():
        project = Project.get_or_create("test-project")
        variant_a = Variant.get_or_create("variant-a", project.id)
        variant_b = Variant.get_or_create("variant-b", project.id)
        db.session.commit()

        scan_a = Scan(description="scan a", variant_id=variant_a.id)
        scan_b = Scan(description="scan b", variant_id=variant_b.id)
        db.session.add_all([scan_a, scan_b])
        db.session.commit()

        # The existing finding for CVE-2020-35492 / cairo was created by setup_demo_db
        finding = db.session.execute(
            db.select(Finding).where(Finding.vulnerability_id == "CVE-2020-35492")
        ).scalar_one()

        obs_a = Observation(finding_id=finding.id, scan_id=scan_a.id)
        obs_b = Observation(finding_id=finding.id, scan_id=scan_b.id)
        db.session.add_all([obs_a, obs_b])
        db.session.commit()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def client_with_variants(app_with_variants):
    return app_with_variants.test_client()


# ---------------------------------------------------------------------------
# GET /api/variants
# ---------------------------------------------------------------------------

def test_list_all_variants_empty(client):
    """When no projects/variants exist the endpoint returns an empty list."""
    response = client.get("/api/variants")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)


def test_list_all_variants_returns_all(client_with_variants):
    """GET /api/variants returns every variant across all projects."""
    response = client_with_variants.get("/api/variants")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    names = [v["name"] for v in data]
    assert "variant-a" in names
    assert "variant-b" in names


def test_list_all_variants_fields(client_with_variants):
    """Each variant entry exposes id, name and project_id."""
    response = client_with_variants.get("/api/variants")
    data = json.loads(response.data)
    for variant in data:
        assert "id" in variant
        assert "name" in variant
        assert "project_id" in variant
        # id and project_id must be valid UUIDs
        uuid.UUID(variant["id"])
        uuid.UUID(variant["project_id"])


def test_list_all_variants_multiple_projects(app_with_variants, init_files):
    """Variants from different projects all appear in the flat list."""
    import os
    from src.extensions import db
    from src.models.project import Project
    from src.models.variant import Variant

    with app_with_variants.app_context():
        other_project = Project.get_or_create("other-project")
        Variant.get_or_create("other-variant", other_project.id)
        db.session.commit()

    client2 = app_with_variants.test_client()
    response = client2.get("/api/variants")
    data = json.loads(response.data)
    names = [v["name"] for v in data]
    assert "variant-a" in names
    assert "other-variant" in names


# ---------------------------------------------------------------------------
# GET /api/vulnerabilities/<vuln_id>/variants
# ---------------------------------------------------------------------------

def test_variants_by_vuln_no_observations(client):
    """CVE with a finding but no observations → no variants linked."""
    response = client.get("/api/vulnerabilities/CVE-2020-35492/variants")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data == []


def test_variants_by_vuln_returns_linked_variants(client_with_variants):
    """Both variants observed for CVE-2020-35492 are returned."""
    response = client_with_variants.get("/api/vulnerabilities/CVE-2020-35492/variants")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) == 2
    names = {v["name"] for v in data}
    assert names == {"variant-a", "variant-b"}


def test_variants_by_vuln_fields(client_with_variants):
    """Each variant entry has id, name and project_id."""
    response = client_with_variants.get("/api/vulnerabilities/CVE-2020-35492/variants")
    data = json.loads(response.data)
    for v in data:
        assert "id" in v
        assert "name" in v
        assert "project_id" in v
        uuid.UUID(v["id"])
        uuid.UUID(v["project_id"])


def test_variants_by_vuln_deduplication(app_with_variants):
    """Multiple scans on the same variant produce only one entry."""
    from src.extensions import db
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.observation import Observation
    from src.models.finding import Finding

    with app_with_variants.app_context():
        variant = db.session.execute(
            db.select(Variant).where(Variant.name == "variant-a")
        ).scalar_one()
        finding = db.session.execute(
            db.select(Finding).where(Finding.vulnerability_id == "CVE-2020-35492")
        ).scalar_one()

        # Add a second scan on variant-a with another observation
        extra_scan = Scan(description="extra scan", variant_id=variant.id)
        db.session.add(extra_scan)
        db.session.commit()
        db.session.add(Observation(finding_id=finding.id, scan_id=extra_scan.id))
        db.session.commit()

    client = app_with_variants.test_client()
    response = client.get("/api/vulnerabilities/CVE-2020-35492/variants")
    data = json.loads(response.data)
    names = [v["name"] for v in data]
    # variant-a must appear exactly once despite two observations
    assert names.count("variant-a") == 1


def test_variants_by_unknown_vuln(client):
    """Unknown CVE returns an empty list (not a 404)."""
    response = client.get("/api/vulnerabilities/CVE-9999-00000/variants")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data == []


# ---------------------------------------------------------------------------
# POST /api/vulnerabilities/<vuln_id>/assessments with variant_id
# ---------------------------------------------------------------------------

def test_post_assessment_with_variant_id(client_with_variants, app_with_variants):
    """Assessment posted with a variant_id stores and returns that variant_id."""
    with app_with_variants.app_context():
        from src.models.variant import Variant
        from src.extensions import db
        variant = db.session.execute(
            db.select(Variant).where(Variant.name == "variant-a")
        ).scalar_one()
        variant_id_str = str(variant.id)

    response = client_with_variants.post(
        "/api/vulnerabilities/CVE-2020-35492/assessments",
        json={
            "packages": ["cairo@1.16.0"],
            "status": "affected",
            "variant_id": variant_id_str,
        },
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "success"
    assert data["assessment"]["variant_id"] == variant_id_str


def test_post_assessment_without_variant_id_has_null(client):
    """When no variant_id is supplied the field is null in the response."""
    response = client.post(
        "/api/vulnerabilities/CVE-2020-35492/assessments",
        json={"packages": ["cairo@1.16.0"], "status": "affected"},
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["assessment"]["variant_id"] is None


def test_post_assessment_invalid_variant_id(client):
    """An unparseable variant_id is rejected with 400."""
    response = client.post(
        "/api/vulnerabilities/CVE-2020-35492/assessments",
        json={
            "packages": ["cairo@1.16.0"],
            "status": "affected",
            "variant_id": "not-a-uuid",
        },
    )
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "variant_id" in data["error"]


def test_post_assessment_variant_id_persisted(client_with_variants, app_with_variants):
    """The variant_id is readable back via GET /api/assessments/<id>."""
    with app_with_variants.app_context():
        from src.models.variant import Variant
        from src.extensions import db
        variant = db.session.execute(
            db.select(Variant).where(Variant.name == "variant-b")
        ).scalar_one()
        variant_id_str = str(variant.id)

    post_resp = client_with_variants.post(
        "/api/vulnerabilities/CVE-2020-35492/assessments",
        json={
            "packages": ["cairo@1.16.0"],
            "status": "fixed",
            "variant_id": variant_id_str,
        },
    )
    assert post_resp.status_code == 200
    assessment_id = json.loads(post_resp.data)["assessment"]["id"]

    get_resp = client_with_variants.get(f"/api/assessments/{assessment_id}")
    assert get_resp.status_code == 200
    fetched = json.loads(get_resp.data)
    assert fetched["variant_id"] == variant_id_str


# ---------------------------------------------------------------------------
# variant_id field in assessment serialisation (to_dict)
# ---------------------------------------------------------------------------

def test_assessment_to_dict_includes_variant_id_field(client):
    """The variant_id key is always present in a serialised assessment."""
    response = client.get("/api/assessments/da4d18f0-d89e-4d54-819d-86fc884cc737")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "variant_id" in data
    # Seed assessment has no variant → value should be None (or null)
    assert data["variant_id"] is None


def test_assessment_list_includes_variant_id_field(client):
    """All entries returned by GET /api/assessments have a variant_id key."""
    response = client.get("/api/assessments")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) > 0
    for entry in data:
        assert "variant_id" in entry


def test_assessment_variant_id_is_uuid_string_when_set(client_with_variants, app_with_variants):
    """When a variant_id is stored it is serialised as a UUID string."""
    with app_with_variants.app_context():
        from src.models.variant import Variant
        from src.extensions import db
        variant = db.session.execute(
            db.select(Variant).where(Variant.name == "variant-a")
        ).scalar_one()
        variant_id_str = str(variant.id)

    post_resp = client_with_variants.post(
        "/api/vulnerabilities/CVE-2020-35492/assessments",
        json={
            "packages": ["cairo@1.16.0"],
            "status": "affected",
            "variant_id": variant_id_str,
        },
    )
    assert post_resp.status_code == 200
    returned_id = json.loads(post_resp.data)["assessment"]["variant_id"]
    # Must be a valid UUID string
    uuid.UUID(returned_id)
    assert returned_id == variant_id_str


# ---------------------------------------------------------------------------
# GET /api/assessments filtered by variant_id
# ---------------------------------------------------------------------------

def test_filter_assessments_by_variant_id(client_with_variants, app_with_variants):
    """GET /api/assessments?variant_id=<id> returns only assessments for that variant."""
    with app_with_variants.app_context():
        from src.models.variant import Variant
        from src.extensions import db
        variant = db.session.execute(
            db.select(Variant).where(Variant.name == "variant-a")
        ).scalar_one()
        variant_id_str = str(variant.id)

    # Create one scoped and one unscoped assessment
    client_with_variants.post(
        "/api/vulnerabilities/CVE-2020-35492/assessments",
        json={"packages": ["cairo@1.16.0"], "status": "affected", "variant_id": variant_id_str},
    )
    client_with_variants.post(
        "/api/vulnerabilities/CVE-2020-35492/assessments",
        json={"packages": ["cairo@1.16.0"], "status": "fixed"},
    )

    response = client_with_variants.get(f"/api/assessments?variant_id={variant_id_str}")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert all(a["variant_id"] == variant_id_str for a in data)


def test_filter_assessments_by_invalid_variant_id(client):
    """GET /api/assessments?variant_id=bad returns 400."""
    response = client.get("/api/assessments?variant_id=not-a-uuid")
    assert response.status_code == 400

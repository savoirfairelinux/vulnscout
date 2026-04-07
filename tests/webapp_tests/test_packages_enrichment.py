# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Integration tests for the GET /api/packages vulnerability enrichment.

These tests cover the new fields added to the packages response:
  - ``vulnerabilities``: count of linked vulns per simplified_status
  - ``maxSeverity``:     highest CVSS severity per simplified_status group
"""

import uuid
import pytest
import json
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
def client(app):
    return app.test_client()


@pytest.fixture()
def app_with_obs(init_files):
    """App whose demo DB also includes an Observation linking the Finding to the Scan."""
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
        with application.app_context():
            from src.extensions import db
            from src.models.finding import Finding
            from src.models.observation import Observation
            from src.models.scan import Scan

            scan = db.session.execute(
                db.select(Scan).where(Scan.id == uuid.UUID("33333333-3333-3333-3333-333333333333"))
            ).scalar_one()
            finding = db.session.execute(
                db.select(Finding)
            ).scalars().first()
            Observation.create(finding_id=finding.id, scan_id=scan.id)

        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client_with_obs(app_with_obs):
    return app_with_obs.test_client()


@pytest.fixture()
def app_with_metrics(init_files):
    """App whose demo DB also includes a Metrics row (score=8.5, HIGH) and Observation."""
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
        with application.app_context():
            from src.extensions import db
            from src.models.finding import Finding
            from src.models.observation import Observation
            from src.models.scan import Scan
            from src.models.metrics import Metrics

            scan = db.session.execute(
                db.select(Scan).where(Scan.id == uuid.UUID("33333333-3333-3333-3333-333333333333"))
            ).scalar_one()
            finding = db.session.execute(db.select(Finding)).scalars().first()
            Observation.create(finding_id=finding.id, scan_id=scan.id)
            Metrics.create(
                vulnerability_id="CVE-2020-35492",
                version="3.1",
                score=8.5,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
            )

        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client_with_metrics(app_with_metrics):
    return app_with_metrics.test_client()


# ---------------------------------------------------------------------------
# Tests – keys are always present
# ---------------------------------------------------------------------------

def test_packages_response_contains_enrichment_keys(client):
    """GET /api/packages always includes 'vulnerabilities' and 'maxSeverity' keys."""
    response = client.get("/api/packages?format=list")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    pkg = data[0]
    assert "vulnerabilities" in pkg
    assert "maxSeverity" in pkg


# ---------------------------------------------------------------------------
# Tests – unfiltered (no variant_id / project_id)
# ---------------------------------------------------------------------------

def test_packages_vuln_count_no_filter(client):
    """Without variant filter all findings are counted; assessed vuln shows under 'Fixed'."""
    response = client.get("/api/packages?format=list")
    assert response.status_code == 200
    data = json.loads(response.data)
    pkg = data[0]
    # Assessment has status="fixed" → simplified_status="Fixed"
    assert pkg["vulnerabilities"].get("Fixed") == 1
    # maxSeverity is a dict (may be empty when no Metrics row exists)
    assert isinstance(pkg["maxSeverity"], dict)


def test_packages_max_severity_empty_when_no_metrics(client):
    """With no Metrics row (score=None → NONE) maxSeverity remains an empty dict.

    The aggregation only stores a severity entry when it strictly exceeds the
    NONE floor, so a package with only un-scored vulnerabilities ends up with
    an empty maxSeverity dict.
    """
    response = client.get("/api/packages?format=list")
    assert response.status_code == 200
    data = json.loads(response.data)
    pkg = data[0]
    assert pkg["maxSeverity"] == {}


def test_packages_max_severity_high_with_metric_score(client_with_metrics):
    """When a Metrics row with score=8.5 exists, maxSeverity should be 'HIGH'."""
    response = client_with_metrics.get("/api/packages?format=list")
    assert response.status_code == 200
    data = json.loads(response.data)
    pkg = data[0]
    assert pkg["maxSeverity"]["Fixed"]["label"] == "HIGH"


# ---------------------------------------------------------------------------
# Tests – variant-scoped filter requires Observation
# ---------------------------------------------------------------------------

VARIANT_ID = "22222222-2222-2222-2222-222222222222"


def test_packages_variant_filter_no_observation_empty_vulns(client):
    """With variant_id but no Observation the vulnerability counts must be empty."""
    response = client.get(f"/api/packages?format=list&variant_id={VARIANT_ID}")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    pkg = data[0]
    assert pkg["vulnerabilities"] == {}
    assert pkg["maxSeverity"] == {}


def test_packages_variant_filter_with_observation_counts_vuln(client_with_obs):
    """With variant_id and a proper Observation the vulnerability count is correct."""
    response = client_with_obs.get(f"/api/packages?format=list&variant_id={VARIANT_ID}")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    pkg = data[0]
    assert pkg["vulnerabilities"].get("Fixed") == 1


def test_packages_variant_filter_with_metrics_shows_severity(client_with_metrics):
    """With variant_id, Observation, and Metrics the correct severity is shown."""
    response = client_with_metrics.get(f"/api/packages?format=list&variant_id={VARIANT_ID}")
    assert response.status_code == 200
    data = json.loads(response.data)
    pkg = data[0]
    assert pkg["maxSeverity"]["Fixed"]["label"] == "HIGH"


# ---------------------------------------------------------------------------
# Tests – project-scoped filter
# ---------------------------------------------------------------------------

PROJECT_ID = "11111111-1111-1111-1111-111111111111"


def test_packages_project_filter_no_observation_empty_vulns(client):
    """With project_id but no Observation the vulnerability counts must be empty."""
    response = client.get(f"/api/packages?format=list&project_id={PROJECT_ID}")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    pkg = data[0]
    assert pkg["vulnerabilities"] == {}
    assert pkg["maxSeverity"] == {}


def test_packages_project_filter_with_observation_counts_vuln(client_with_obs):
    """With project_id and a proper Observation the vulnerability count is correct."""
    response = client_with_obs.get(f"/api/packages?format=list&project_id={PROJECT_ID}")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    pkg = data[0]
    assert pkg["vulnerabilities"].get("Fixed") == 1


# ---------------------------------------------------------------------------
# Tests – dict format still carries enrichment
# ---------------------------------------------------------------------------

def test_packages_dict_format_contains_enrichment_keys(client):
    """The dict response format also exposes the new enrichment fields."""
    response = client.get("/api/packages?format=dict")
    assert response.status_code == 200
    data = json.loads(response.data)
    pkg = data["cairo@1.16.0"]
    assert "vulnerabilities" in pkg
    assert "maxSeverity" in pkg
    assert pkg["vulnerabilities"].get("Fixed") == 1

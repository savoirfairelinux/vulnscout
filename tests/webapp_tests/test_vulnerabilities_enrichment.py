# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Integration tests for the assessment-enrichment logic added to GET /api/vulnerabilities.

Covers the three new fields added to every vulnerability dict in the response:
  - ``assessments``:        list of all assessment dicts for the vulnerability
  - ``status``:             status of the latest assessment (or "unknown")
  - ``simplified_status``:  human label of the latest assessment (or "Pending Assessment")
"""

import uuid
import pytest
import json
from datetime import datetime, timezone
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
def app_with_extra_vuln(init_files):
    """App whose demo DB contains an additional vulnerability with no assessment."""
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
            from src.models.vulnerability import Vulnerability

            unassessed = Vulnerability.create_record(
                id="CVE-2099-99999",
                description="Synthetic unassessed vulnerability for testing.",
                status="medium",
                epss_score=0.0,
                links=[],
            )
            db.session.commit()

        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client_extra(app_with_extra_vuln):
    return app_with_extra_vuln.test_client()


@pytest.fixture()
def app_multi_assess(init_files):
    """App whose demo DB has two assessments for CVE-2020-35492 (latest is 'affected')."""
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
            from src.models.assessment import Assessment

            finding = db.session.execute(db.select(Finding)).scalars().first()
            # Add a later assessment overriding the original "fixed" one
            later = Assessment(
                id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
                status="affected",
                timestamp=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
                status_notes="Re-opened",
                justification="",
                impact_statement="",
                responses=[],
                workaround="",
                finding_id=finding.id,
            )
            db.session.add(later)
            db.session.commit()

        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client_multi(app_multi_assess):
    return app_multi_assess.test_client()


# ---------------------------------------------------------------------------
# Tests – assessments field structure
# ---------------------------------------------------------------------------

def test_vulns_list_contains_assessments_key(client):
    """GET /api/vulnerabilities always includes an 'assessments' key per vuln."""
    response = client.get("/api/vulnerabilities?format=list")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert "assessments" in data[0]


def test_vulns_assessments_is_list(client):
    """`assessments` value is always a list."""
    response = client.get("/api/vulnerabilities?format=list")
    data = json.loads(response.data)
    assert isinstance(data[0]["assessments"], list)


def test_vulns_assessment_entry_fields(client):
    """Each assessment entry in the list includes all required fields."""
    response = client.get("/api/vulnerabilities?format=list")
    data = json.loads(response.data)
    vuln = data[0]
    assert len(vuln["assessments"]) == 1
    entry = vuln["assessments"][0]

    expected_keys = {
        "id", "vuln_id", "packages", "variant_id",
        "status", "simplified_status", "status_notes",
        "justification", "impact_statement", "responses",
        "workaround", "timestamp", "last_update",
    }
    assert expected_keys.issubset(entry.keys())


def test_vulns_assessment_entry_values(client):
    """Assessment entry values match the demo DB record."""
    response = client.get("/api/vulnerabilities?format=list")
    data = json.loads(response.data)
    entry = data[0]["assessments"][0]

    assert entry["id"] == "da4d18f0-d89e-4d54-819d-86fc884cc737"
    assert entry["vuln_id"] == "CVE-2020-35492"
    assert "cairo@1.16.0" in entry["packages"]
    assert entry["status"] == "fixed"
    assert entry["simplified_status"] == "Fixed"
    assert entry["impact_statement"] == "Yocto reported vulnerability as Patched"
    assert entry["responses"] == []
    assert entry["variant_id"] is None


def test_vulns_assessment_timestamp_is_iso8601(client):
    """Assessment timestamp is a non-empty ISO-8601 string."""
    response = client.get("/api/vulnerabilities?format=list")
    data = json.loads(response.data)
    ts = data[0]["assessments"][0]["timestamp"]
    assert isinstance(ts, str) and len(ts) > 0
    # Basic ISO-8601 sanity: contains a 'T' separator
    assert "T" in ts


# ---------------------------------------------------------------------------
# Tests – status / simplified_status enrichment on vuln dict
# ---------------------------------------------------------------------------

def test_vulns_status_enriched_from_assessment(client):
    """`status` and `simplified_status` on the vuln dict match the latest assessment."""
    response = client.get("/api/vulnerabilities?format=list")
    data = json.loads(response.data)
    vuln = data[0]
    assert vuln["status"] == "fixed"
    assert vuln["simplified_status"] == "Fixed"


def test_vulns_status_defaults_for_no_assessment(client_extra):
    """A vulnerability with no assessment gets status='unknown' and 'Pending Assessment'."""
    response = client_extra.get("/api/vulnerabilities?format=list")
    data = json.loads(response.data)
    unassessed = next(v for v in data if v["id"] == "CVE-2099-99999")
    assert unassessed["status"] == "unknown"
    assert unassessed["simplified_status"] == "Pending Assessment"
    assert unassessed["assessments"] == []


def test_vulns_status_from_latest_when_multiple_assessments(client_multi):
    """When multiple assessments exist, status reflects the chronologically latest one."""
    response = client_multi.get("/api/vulnerabilities?format=list")
    data = json.loads(response.data)
    vuln = next(v for v in data if v["id"] == "CVE-2020-35492")
    # The later record (2025-01-01) has status="affected" → "Exploitable"
    assert vuln["status"] == "affected"
    assert vuln["simplified_status"] == "Exploitable"
    # Both assessments are present in the list
    assert len(vuln["assessments"]) == 2


# ---------------------------------------------------------------------------
# Tests – dict format consistency
# ---------------------------------------------------------------------------

def test_vulns_dict_format_also_enriched(client):
    """The dict response format exposes the same enrichment fields."""
    response = client.get("/api/vulnerabilities?format=dict")
    data = json.loads(response.data)
    vuln = data["CVE-2020-35492"]
    assert vuln["status"] == "fixed"
    assert vuln["simplified_status"] == "Fixed"
    assert len(vuln["assessments"]) == 1

# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the new project, variant, config routes and variant/project-scoped
filtering on packages, vulnerabilities and assessments endpoints."""

import uuid
import json
import os
import pytest
from datetime import datetime, timezone

from src.bin.webapp import create_app
from . import write_demo_files


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def setup_db_with_project_variant(app):
    """Set up the in-memory DB with two projects/variants and scoped data.

    Layout
    ------
    ProjectA / VariantA  →  CairoScan  →  cairo@1.16.0 / CVE-2020-35492
    ProjectB / VariantB  →  BusyScan   →  busybox@1.35.0 (no vulnerability)

    The cairo finding has an Observation linked to CairoScan so that the
    variant/project-scoped queries return exactly the expected records.
    An Assessment for cairo's finding is attached to VariantA.

    Returns plain UUID strings (not ORM instances) so callers can safely use
    them outside the app context without triggering DetachedInstanceError.
    """
    from src.extensions import db
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.assessment import Assessment
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage

    with app.app_context():
        db.drop_all()
        db.create_all()

        # --- ProjectA / VariantA -----------------------------------------
        project_a = Project.create("ProjectA")
        variant_a = Variant.create("VariantA", project_a.id)
        scan_a = Scan.create("scan for VariantA", variant_a.id)

        # Package + vulnerability + finding
        cairo = Package.find_or_create(
            "cairo",
            "1.16.0",
            ["cpe:2.3:a:cairographics:cairo:1.16.0:*:*:*:*:*:*:*"],
            ["pkg:generic/cairo@1.16.0"],
            "",
        )
        db.session.commit()

        Vulnerability.create_record(
            id="CVE-2020-35492",
            description="Cairo heap buffer overflow",
            status="high",
        )
        db.session.commit()

        finding_cairo = Finding.get_or_create(cairo.id, "CVE-2020-35492")

        # Observation: links the finding to scan_a
        Observation.create(finding_cairo.id, scan_a.id)

        # SBOM document + package link for scan_a
        sbom_doc_a = SBOMDocument.create(
            path="/sbom/projectA.cdx.json",
            source_name="cdx",
            scan_id=scan_a.id,
        )
        SBOMPackage.create(sbom_doc_a.id, cairo.id)

        # Assessment scoped to VariantA
        assessment_a = Assessment(
            id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            status="fixed",
            timestamp=datetime(2024, 6, 7, 15, 0, 0, tzinfo=timezone.utc),
            status_notes="",
            justification="",
            impact_statement="Fixed in version 1.17.4",
            responses=[],
            workaround="",
            finding_id=finding_cairo.id,
            variant_id=variant_a.id,
        )
        db.session.add(assessment_a)
        db.session.commit()

        # --- ProjectB / VariantB -----------------------------------------
        project_b = Project.create("ProjectB")
        variant_b = Variant.create("VariantB", project_b.id)
        scan_b = Scan.create("scan for VariantB", variant_b.id)

        busybox = Package.find_or_create(
            "busybox",
            "1.35.0",
            [],
            ["pkg:generic/busybox@1.35.0"],
            "",
        )
        db.session.commit()

        sbom_doc_b = SBOMDocument.create(
            path="/sbom/projectB.cdx.json",
            source_name="cdx",
            scan_id=scan_b.id,
        )
        SBOMPackage.create(sbom_doc_b.id, busybox.id)
        # busybox has no vulnerability / finding / observation intentionally

        # Extract plain string IDs before the context closes to avoid
        # DetachedInstanceError when tests use these values outside the context.
        return {
            "project_a_id": str(project_a.id),
            "project_b_id": str(project_b.id),
            "variant_a_id": str(variant_a.id),
            "variant_b_id": str(variant_b.id),
        }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app_with_data():
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": "/dev/null",
        })
        # Bypass the "scan not finished" middleware (needs __END_OF_SCAN_SCRIPT__)
        application._INT_SCAN_FINISHED = True
        data = setup_db_with_project_variant(application)
        yield application, data
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)
        os.environ.pop("PROJECT_NAME", None)
        os.environ.pop("VARIANT_NAME", None)


@pytest.fixture()
def client(app_with_data):
    application, _ = app_with_data
    return application.test_client()


@pytest.fixture()
def client_and_data(app_with_data):
    application, data = app_with_data
    return application.test_client(), data


# ===========================================================================
# /api/projects
# ===========================================================================

class TestProjectsEndpoint:

    def test_list_projects_returns_all(self, client_and_data):
        client, data = client_and_data
        response = client.get("/api/projects")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert isinstance(body, list)
        names = [p["name"] for p in body]
        assert "ProjectA" in names
        assert "ProjectB" in names

    def test_list_projects_serialization(self, client_and_data):
        client, data = client_and_data
        response = client.get("/api/projects")
        assert response.status_code == 200
        body = json.loads(response.data)
        for item in body:
            assert "id" in item
            assert "name" in item
            # id should be a valid UUID string
            uuid.UUID(item["id"])

    def test_list_projects_empty(self):
        """When no projects exist the endpoint returns an empty list."""
        os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        try:
            from src.extensions import db
            application = create_app()
            application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
            application._INT_SCAN_FINISHED = True
            with application.app_context():
                db.drop_all()
                db.create_all()
            client = application.test_client()
            response = client.get("/api/projects")
            assert response.status_code == 200
            assert json.loads(response.data) == []
        finally:
            os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


# ===========================================================================
# /api/projects/<project_id>/variants
# ===========================================================================

class TestVariantsEndpoint:

    def test_list_variants_for_project(self, client_and_data):
        client, data = client_and_data
        project_id = data["project_a_id"]
        response = client.get(f"/api/projects/{project_id}/variants")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert isinstance(body, list)
        assert len(body) == 1
        assert body[0]["name"] == "VariantA"
        assert body[0]["project_id"] == project_id

    def test_list_variants_serialization(self, client_and_data):
        client, data = client_and_data
        project_id = data["project_a_id"]
        response = client.get(f"/api/projects/{project_id}/variants")
        body = json.loads(response.data)
        for item in body:
            assert "id" in item
            assert "name" in item
            assert "project_id" in item
            uuid.UUID(item["id"])

    def test_list_variants_not_found(self, client):
        fake_id = str(uuid.uuid4())
        response = client.get(f"/api/projects/{fake_id}/variants")
        assert response.status_code == 404

    def test_list_variants_different_projects_isolated(self, client_and_data):
        client, data = client_and_data
        project_b_id = data["project_b_id"]
        response = client.get(f"/api/projects/{project_b_id}/variants")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert len(body) == 1
        assert body[0]["name"] == "VariantB"


# ===========================================================================
# /api/config
# ===========================================================================

class TestConfigEndpoint:

    def test_config_no_env_vars(self, client):
        os.environ.pop("PROJECT_NAME", None)
        os.environ.pop("VARIANT_NAME", None)
        response = client.get("/api/config")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["project"] is None
        assert body["variant"] is None

    def test_config_with_matching_project_and_variant(self, app_with_data):
        application, _data = app_with_data
        os.environ["PROJECT_NAME"] = "ProjectA"
        os.environ["VARIANT_NAME"] = "VariantA"
        client = application.test_client()
        response = client.get("/api/config")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["project"] is not None
        assert body["project"]["name"] == "ProjectA"
        assert body["variant"] is not None
        assert body["variant"]["name"] == "VariantA"

    def test_config_with_project_no_variant_match(self, app_with_data):
        application, _data = app_with_data
        os.environ["PROJECT_NAME"] = "ProjectA"
        os.environ["VARIANT_NAME"] = "NonExistentVariant"
        client = application.test_client()
        response = client.get("/api/config")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["project"] is not None
        assert body["project"]["name"] == "ProjectA"
        assert body["variant"] is None

    def test_config_unknown_project(self, app_with_data):
        application, _data = app_with_data
        os.environ["PROJECT_NAME"] = "NonExistentProject"
        os.environ["VARIANT_NAME"] = "default"
        client = application.test_client()
        response = client.get("/api/config")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body["project"] is None
        assert body["variant"] is None


# ===========================================================================
# /api/packages  — variant / project filtering
# ===========================================================================

class TestPackagesFiltering:

    def test_packages_no_filter_returns_all(self, client_and_data):
        client, _ = client_and_data
        response = client.get("/api/packages?format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        names = [p["name"] for p in body]
        assert "cairo" in names
        assert "busybox" in names

    def test_packages_filter_by_variant_id(self, client_and_data):
        client, data = client_and_data
        variant_a_id = data["variant_a_id"]
        response = client.get(f"/api/packages?variant_id={variant_a_id}&format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        # Only cairo has an observation in VariantA's scan
        names = [p["name"] for p in body]
        assert "cairo" in names
        assert "busybox" not in names

    def test_packages_filter_by_project_id(self, client_and_data):
        client, data = client_and_data
        project_a_id = data["project_a_id"]
        response = client.get(f"/api/packages?project_id={project_a_id}&format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        names = [p["name"] for p in body]
        assert "cairo" in names
        assert "busybox" not in names

    def test_packages_filter_variant_b_returns_empty(self, client_and_data):
        """VariantB has no findings/observations so filtering returns empty."""
        client, data = client_and_data
        variant_b_id = data["variant_b_id"]
        response = client.get(f"/api/packages?variant_id={variant_b_id}&format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body == []

    def test_packages_invalid_variant_uuid(self, client):
        response = client.get("/api/packages?variant_id=not-a-uuid&format=list")
        assert response.status_code == 400

    def test_packages_invalid_project_uuid(self, client):
        response = client.get("/api/packages?project_id=not-a-uuid&format=list")
        assert response.status_code == 400

    def test_packages_dict_format_with_variant(self, client_and_data):
        client, data = client_and_data
        variant_a_id = data["variant_a_id"]
        response = client.get(f"/api/packages?variant_id={variant_a_id}&format=dict")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert isinstance(body, dict)
        assert "cairo@1.16.0" in body


# ===========================================================================
# /api/vulnerabilities  — variant / project filtering
# ===========================================================================

class TestVulnerabilitiesFiltering:

    def test_vulnerabilities_no_filter_returns_all(self, client_and_data):
        client, _ = client_and_data
        response = client.get("/api/vulnerabilities?format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        ids = [v["id"] for v in body]
        assert "CVE-2020-35492" in ids

    def test_vulnerabilities_filter_by_variant_id(self, client_and_data):
        client, data = client_and_data
        variant_a_id = data["variant_a_id"]
        response = client.get(f"/api/vulnerabilities?variant_id={variant_a_id}&format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        ids = [v["id"] for v in body]
        assert "CVE-2020-35492" in ids

    def test_vulnerabilities_filter_variant_b_empty(self, client_and_data):
        client, data = client_and_data
        variant_b_id = data["variant_b_id"]
        response = client.get(f"/api/vulnerabilities?variant_id={variant_b_id}&format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body == []

    def test_vulnerabilities_filter_by_project_id(self, client_and_data):
        client, data = client_and_data
        project_a_id = data["project_a_id"]
        response = client.get(f"/api/vulnerabilities?project_id={project_a_id}&format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        ids = [v["id"] for v in body]
        assert "CVE-2020-35492" in ids

    def test_vulnerabilities_filter_project_b_empty(self, client_and_data):
        client, data = client_and_data
        project_b_id = data["project_b_id"]
        response = client.get(f"/api/vulnerabilities?project_id={project_b_id}&format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body == []

    def test_vulnerabilities_invalid_variant_uuid(self, client):
        response = client.get("/api/vulnerabilities?variant_id=bad-uuid&format=list")
        assert response.status_code == 400

    def test_vulnerabilities_invalid_project_uuid(self, client):
        response = client.get("/api/vulnerabilities?project_id=bad-uuid&format=list")
        assert response.status_code == 400

    # Compare-filtering tests use the existing fixture:
    # VariantA has CVE-2020-35492, VariantB has no vulnerabilities.

    def test_vulnerabilities_compare_difference_returns_compare_unique_vulns(self, client_and_data):
        """difference(base=VB, compare=VA): vulns in VA but NOT in VB → CVE-2020-35492."""
        client, data = client_and_data
        variant_a_id = data["variant_a_id"]
        variant_b_id = data["variant_b_id"]
        url = (
            f"/api/vulnerabilities?format=list"
            f"&variant_id={variant_b_id}"
            f"&compare_variant_id={variant_a_id}"
            f"&operation=difference"
        )
        response = client.get(url)
        assert response.status_code == 200
        body = response.get_json()
        ids = [v["id"] for v in body]
        assert "CVE-2020-35492" in ids

    def test_vulnerabilities_compare_difference_empty_when_compare_has_no_unique(self, client_and_data):
        """difference(base=VA, compare=VB): vulns in VB but NOT in VA → empty (VB has none)."""
        client, data = client_and_data
        variant_a_id = data["variant_a_id"]
        variant_b_id = data["variant_b_id"]
        url = (
            f"/api/vulnerabilities?format=list"
            f"&variant_id={variant_a_id}"
            f"&compare_variant_id={variant_b_id}"
            f"&operation=difference"
        )
        response = client.get(url)
        assert response.status_code == 200
        body = response.get_json()
        assert body == []

    def test_vulnerabilities_compare_intersection_empty_when_no_common(self, client_and_data):
        """intersection(VA, VB): no common vulns → empty."""
        client, data = client_and_data
        variant_a_id = data["variant_a_id"]
        variant_b_id = data["variant_b_id"]
        url = (
            f"/api/vulnerabilities?format=list"
            f"&variant_id={variant_a_id}"
            f"&compare_variant_id={variant_b_id}"
            f"&operation=intersection"
        )
        response = client.get(url)
        assert response.status_code == 200
        body = response.get_json()
        assert body == []

    def test_vulnerabilities_compare_intersection_same_variant(self, client_and_data):
        """intersection(VA, VA): both sides identical → all of VA's vulns returned."""
        client, data = client_and_data
        variant_a_id = data["variant_a_id"]
        url = (
            f"/api/vulnerabilities?format=list"
            f"&variant_id={variant_a_id}"
            f"&compare_variant_id={variant_a_id}"
            f"&operation=intersection"
        )
        response = client.get(url)
        assert response.status_code == 200
        body = response.get_json()
        ids = [v["id"] for v in body]
        assert "CVE-2020-35492" in ids

    def test_vulnerabilities_compare_difference_same_variant_empty(self, client_and_data):
        """difference(VA, VA): base and compare identical → nothing unique to compare → empty."""
        client, data = client_and_data
        variant_a_id = data["variant_a_id"]
        url = (
            f"/api/vulnerabilities?format=list"
            f"&variant_id={variant_a_id}"
            f"&compare_variant_id={variant_a_id}"
            f"&operation=difference"
        )
        response = client.get(url)
        assert response.status_code == 200
        body = response.get_json()
        assert body == []

    def test_vulnerabilities_compare_default_operation_is_difference(self, client_and_data):
        """Omitting operation defaults to difference."""
        client, data = client_and_data
        variant_b_id = data["variant_b_id"]
        variant_a_id = data["variant_a_id"]
        url = (
            f"/api/vulnerabilities?format=list"
            f"&variant_id={variant_b_id}"
            f"&compare_variant_id={variant_a_id}"
        )
        response = client.get(url)
        assert response.status_code == 200
        body = response.get_json()
        ids = [v["id"] for v in body]
        assert "CVE-2020-35492" in ids

    def test_vulnerabilities_compare_unknown_operation_falls_back_to_difference(self, client_and_data):
        """An unrecognised operation value is treated as difference."""
        client, data = client_and_data
        variant_b_id = data["variant_b_id"]
        variant_a_id = data["variant_a_id"]
        url = (
            f"/api/vulnerabilities?format=list"
            f"&variant_id={variant_b_id}"
            f"&compare_variant_id={variant_a_id}"
            f"&operation=bogus"
        )
        response = client.get(url)
        assert response.status_code == 200
        body = response.get_json()
        ids = [v["id"] for v in body]
        assert "CVE-2020-35492" in ids

    def test_vulnerabilities_compare_invalid_variant_uuid(self, client_and_data):
        client, data = client_and_data
        variant_a_id = data["variant_a_id"]
        response = client.get(
            f"/api/vulnerabilities?format=list"
            f"&variant_id={variant_a_id}"
            f"&compare_variant_id=not-a-uuid"
        )
        assert response.status_code == 400

    def test_vulnerabilities_compare_invalid_base_uuid(self, client_and_data):
        client, data = client_and_data
        variant_a_id = data["variant_a_id"]
        response = client.get(
            f"/api/vulnerabilities?format=list"
            f"&variant_id=not-a-uuid"
            f"&compare_variant_id={variant_a_id}"
        )
        assert response.status_code == 400


# ===========================================================================
# /api/assessments  — variant / project filtering
# ===========================================================================

class TestAssessmentsFiltering:

    def test_assessments_no_filter_returns_all(self, client_and_data):
        client, _ = client_and_data
        response = client.get("/api/assessments?format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        ids = [a["id"] for a in body]
        assert "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in ids

    def test_assessments_filter_by_variant_id(self, client_and_data):
        client, data = client_and_data
        variant_a_id = data["variant_a_id"]
        response = client.get(f"/api/assessments?variant_id={variant_a_id}&format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert len(body) == 1
        assert body[0]["id"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

    def test_assessments_filter_variant_b_empty(self, client_and_data):
        client, data = client_and_data
        variant_b_id = data["variant_b_id"]
        response = client.get(f"/api/assessments?variant_id={variant_b_id}&format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body == []

    def test_assessments_filter_by_project_id(self, client_and_data):
        client, data = client_and_data
        project_a_id = data["project_a_id"]
        response = client.get(f"/api/assessments?project_id={project_a_id}&format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert len(body) == 1
        assert body[0]["id"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

    def test_assessments_filter_project_b_empty(self, client_and_data):
        client, data = client_and_data
        project_b_id = data["project_b_id"]
        response = client.get(f"/api/assessments?project_id={project_b_id}&format=list")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert body == []

    def test_assessments_invalid_variant_uuid(self, client):
        response = client.get("/api/assessments?variant_id=bad-uuid&format=list")
        assert response.status_code == 400

    def test_assessments_invalid_project_uuid(self, client):
        response = client.get("/api/assessments?project_id=bad-uuid&format=list")
        assert response.status_code == 400

    def test_assessments_dict_format_with_variant(self, client_and_data):
        client, data = client_and_data
        variant_a_id = data["variant_a_id"]
        response = client.get(f"/api/assessments?variant_id={variant_a_id}&format=dict")
        assert response.status_code == 200
        body = json.loads(response.data)
        assert isinstance(body, dict)
        assert "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in body

# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Supplementary coverage tests targeting remaining gaps toward ≥ 95 %."""

import uuid
import pytest

# ===========================================================================
# Finding — _resolve_package_id string paths (lines 53-65, 80)
# ===========================================================================

@pytest.fixture()
def app():
    import os
    from src.bin.webapp import create_app
    from src.extensions import db as _db
    # Override DB URI via env var BEFORE create_app reads config
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": "/dev/null",
        })
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def db_package(app):
    from src.models.package import Package
    return Package.create("supplementlib", "9.9.9")


@pytest.fixture()
def db_vuln(app):
    from src.models.vulnerability import Vulnerability
    return Vulnerability.create_record("CVE-2099-0001")


@pytest.fixture()
def db_finding(app, db_package, db_vuln):
    from src.models.finding import Finding
    return Finding.create(db_package.id, db_vuln.id)


class TestFindingStringResolution:
    """Cover Finding._resolve_package_id and get_by_id string paths."""

    def test_resolve_uuid_string(self, app, db_package, db_vuln):
        """Pass a valid UUID string — should convert and create successfully."""
        from src.models.finding import Finding
        f = Finding.create(str(db_package.id), db_vuln.id)
        assert f is not None
        assert f.package_id == db_package.id

    def test_resolve_name_at_version_string(self, app, db_package, db_vuln):
        """Pass a 'name@version' string — should look up the package by string_id."""
        from src.models.finding import Finding
        # Use a fresh vuln to avoid unique constraint
        from src.models.vulnerability import Vulnerability
        v2 = Vulnerability.create_record("CVE-2099-0002")
        f = Finding.create(db_package.string_id, v2.id)
        assert f is not None
        assert f.package_id == db_package.id

    def test_resolve_name_at_version_not_found(self, app, db_vuln):
        """Pass a 'name@version' that doesn't exist — should raise ValueError."""
        from src.models.finding import Finding
        with pytest.raises(ValueError, match="no matching package found"):
            Finding.create("doesnotexist@0.0.0", db_vuln.id)

    def test_resolve_invalid_type(self, app, db_vuln):
        """Pass a non-string, non-UUID type — should raise TypeError."""
        from src.models.finding import Finding
        with pytest.raises(TypeError):
            Finding._resolve_package_id(12345)  # int is not allowed

    def test_get_by_id_string(self, db_finding):
        """Pass a UUID string to get_by_id (covers line 80)."""
        from src.models.finding import Finding
        result = Finding.get_by_id(str(db_finding.id))
        assert result is not None
        assert result.id == db_finding.id

    def test_get_by_package_string(self, db_finding, db_package):
        """Pass a 'name@version' string to get_by_package."""
        from src.models.finding import Finding
        results = Finding.get_by_package(db_package.string_id)
        assert any(f.id == db_finding.id for f in results)


# ===========================================================================
# Vulnerability DB model — persist_from_transient update path (lines 568-569)
# ===========================================================================

class TestVulnerabilityPersistUpdate:
    def test_persist_from_transient_update_existing(self, app):
        """persist_from_transient when the record already exists (update path)."""
        from src.models.vulnerability import Vulnerability
        from src.models.cvss import CVSS

        # Create a DB record first
        Vulnerability.create_record(
            id="CVE-2099-UPDATE",
            description="Original description",
            status="unknown",
        )

        # Now build a transient DTO with updated data
        transient = Vulnerability("CVE-2099-UPDATE", ["scanner"], "https://nvd.nist.gov", "nvd")
        transient.add_text("Updated description", "description")
        transient.severity_without_cvss("high", 7.5)
        cvss = CVSS("3.1", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "NVD", 7.5, 3.9, 4.0)
        transient.register_cvss(cvss)

        record = Vulnerability.persist_from_transient(transient)
        assert record is not None
        assert record.id == "CVE-2099-UPDATE"

    def test_persist_from_transient_with_packages(self, app):
        """persist_from_transient creates Findings when packages are known in DB."""
        from src.models.vulnerability import Vulnerability
        from src.models.package import Package

        pkg = Package.create("patchlib", "1.2.3")
        transient = Vulnerability("CVE-2099-PKGS", ["scanner"], "ds", "ns")
        transient.add_package(pkg.string_id)
        transient.severity_without_cvss("medium", 5.0)

        record = Vulnerability.persist_from_transient(transient)
        assert record is not None
        assert record.id == "CVE-2099-PKGS"


# ===========================================================================
# Assessment controllers — _persist_assessment_to_db path (lines 20-25)
# ===========================================================================

class TestPersistAssessmentToDB:
    def test_persist_assessment_to_db_with_matching_package(self, app, db_package, db_vuln, db_finding):
        """
        _persist_assessment_to_db walks packages, finds the DB package,
        locates the Finding, and persists.
        Covers assessments.py lines 17-25.
        """
        from src.models.assessment import Assessment
        from src.controllers.assessments import _persist_assessment_to_db

        dto = Assessment.new_dto(db_vuln.id, [db_package.string_id])
        dto.set_status("under_investigation")
        _persist_assessment_to_db(dto)  # should not raise

    def test_persist_assessment_to_db_no_matching_package(self, app, db_vuln):
        """
        _persist_assessment_to_db silently skips packages not in the DB.
        Covers the 'db_pkg is None → continue' branch (line 21).
        """
        from src.models.assessment import Assessment
        from src.controllers.assessments import _persist_assessment_to_db

        dto = Assessment.new_dto(db_vuln.id, ["nonexistent@9.9.9"])
        dto.set_status("affected")
        _persist_assessment_to_db(dto)  # should not raise

    def test_persist_assessment_no_finding(self, app, db_package, db_vuln):
        """
        _persist_assessment_to_db skips when no Finding exists for the package+vuln.
        Covers the 'finding is None → continue' branch (line 23).
        """
        from src.models.assessment import Assessment
        from src.controllers.assessments import _persist_assessment_to_db

        # db_package exists but there's no Finding linking it to db_vuln
        dto = Assessment.new_dto(db_vuln.id, [db_package.string_id])
        dto.set_status("in_triage")
        _persist_assessment_to_db(dto)  # should not raise (finding is None → continue)

    def test_assessments_controller_to_dict_uses_db(self, app):
        """
        AssessmentsController.to_dict reads from the DB when available.
        Covers assessments.py line 113.
        """
        from src.controllers.packages import PackagesController
        from src.controllers.assessments import AssessmentsController
        from unittest.mock import MagicMock

        pkg_ctrl = PackagesController()
        mock_vuln_ctrl = MagicMock()
        assess_ctrl = AssessmentsController(pkg_ctrl, mock_vuln_ctrl)

        result = assess_ctrl.to_dict()
        assert isinstance(result, dict)

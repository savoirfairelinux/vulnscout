# -*- coding: utf-8 -*-
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Coverage tests for assessment_io.py targeting the lines missed by CI.

Lines covered: 321-322, 387, 547-548, 579,
               684, 698, 706, 710-714, 717-721, 734, 740,
               772-773, 784, 787, 810-814, 822,
               833-835, 844, 847, 850-854, 862-863, 871-875, 882.
"""

import json
import os
import uuid as _uuid
from unittest import mock

import pytest

from src.helpers.assessment_io import (
    build_variant_by_name_map,
    import_custom_data,
    import_statements,
    build_custom_data_export,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        from src.bin.webapp import create_app
        from src.extensions import db as _db
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def variant_and_project(app):
    from src.models.project import Project
    from src.models.variant import Variant
    proj = Project.create("io-cov-proj")
    var = Variant.create("io-cov-var", proj.id)
    return proj, var


# ===========================================================================
# import_statements — lines 321-322: except handler when DB.create fails
# ===========================================================================

class TestImportStatementsDbException:
    """Line 321-322: exception inside DBAssessment.create is caught."""

    def test_db_create_exception_appended_to_errors(self, app, variant_and_project):
        _, var = variant_and_project
        stmt = {
            "vulnerability": {"name": "CVE-2099-IOEX"},
            "status": "affected",
            "products": [{"@id": "some-pkg@1.0"}],
        }
        with app.app_context():
            with mock.patch("src.models.assessment.Assessment.create", side_effect=RuntimeError("db boom")):
                created, errors, skipped = import_statements([stmt], var.id)

        assert created == []
        assert len(errors) == 1
        assert errors[0]["vuln_id"] == "CVE-2099-IOEX"
        assert "db boom" in errors[0]["error"]


# ===========================================================================
# build_variant_by_name_map — line 387: with project_id (DB path)
# ===========================================================================

class TestBuildVariantByNameMapWithProjectId:
    """Line 387: project_id branch calls get_by_project on real DB."""

    def test_returns_only_variants_for_project(self, app, variant_and_project):
        proj, var = variant_and_project
        with app.app_context():
            result = build_variant_by_name_map(project_id=proj.id)

        assert "io-cov-var" in result
        assert result["io-cov-var"].id == var.id


# ===========================================================================
# build_custom_data_export — lines 547-548, 579
# ===========================================================================

class TestBuildCustomDataExport:
    """Lines 547-548 (variant_ids filter on TE query), 579 (variant_uuid_set branch)."""

    def test_variant_ids_filter_and_variant_name_resolved(self, app, variant_and_project):
        """Lines 547-548: variant_ids not None → TE query filtered.
        Line 579: variant_uuid_set non-empty → variant names resolved."""
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding
        from src.models.assessment import Assessment
        from src.extensions import db

        _, var = variant_and_project

        with app.app_context():
            pkg = Package.create("te-pkg", "1.0.0")
            vuln = Vulnerability.create_record("CVE-2099-TE01")
            finding = Finding.create(pkg.id, vuln.id)
            Assessment.create(
                status="not_affected",
                finding_id=finding.id,
                variant_id=var.id,
                origin="custom",
            )
            db.session.commit()

            result = build_custom_data_export(variant_ids=[var.id])

        assert result["version"] == 1
        assert len(result["assessments"]) == 1
        # variant name should be resolved on the exported assessment
        assert result["assessments"][0]["variant"] == "io-cov-var"

    def test_pending_ai_assessments_are_exported(self, app, variant_and_project):
        """Pending AI rows are emitted separately for the Review page AI tab."""
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding
        from src.models.assessment import Assessment

        _, var = variant_and_project

        with app.app_context():
            pkg = Package.create("ai-pkg", "1.0.0")
            vuln = Vulnerability.create_record("CVE-2099-AI01")
            finding = Finding.create(pkg.id, vuln.id)
            Assessment.create(
                status="under_investigation",
                finding_id=finding.id,
                variant_id=var.id,
                origin="ai",
            )

            result = build_custom_data_export(variant_ids=[var.id])

        assert result["assessments"] == []
        assert result["ai_assessments"] == [{
            "vuln_id": "CVE-2099-AI01",
            "status": "under_investigation",
            "simplified_status": "",
            "justification": None,
            "impact_statement": None,
            "status_notes": None,
            "workaround": None,
            "timestamp": result["ai_assessments"][0]["timestamp"],
            "packages": ["ai-pkg@1.0.0"],
            "variant_id": str(var.id),
            "variant": "io-cov-var",
        }]


# ===========================================================================
# import_custom_data — assessments section
# ===========================================================================

class TestImportCustomDataAssessments:
    """Lines 684, 698, 706, 710-714, 717-721, 734, 740."""

    def _base_result(self):
        return {
            "status": "success",
            "assessments_imported": 0,
            "assessments_skipped": 0,
            "cvss_imported": 0,
            "time_estimates_imported": 0,
            "errors": [],
        }

    def test_missing_vuln_id_appends_error(self, app, variant_and_project):
        """Line 698: missing vuln_id → error appended."""
        _, var = variant_and_project
        data = {"assessments": [{"status": "affected", "packages": ["p@1"]}]}
        with app.app_context():
            result = import_custom_data(data, {}, variant_id=var.id)
        assert any("Missing vuln_id" in e.get("error", "") for e in result["errors"])

    def test_missing_status_appends_error(self, app, variant_and_project):
        """Line 698: missing status → error appended."""
        _, var = variant_and_project
        data = {"assessments": [{"vuln_id": "CVE-2099-X", "packages": ["p@1"]}]}
        with app.app_context():
            result = import_custom_data(data, {}, variant_id=var.id)
        assert any("Missing vuln_id or status" in e.get("error", "") for e in result["errors"])

    def test_no_packages_appends_error(self, app, variant_and_project):
        """Line 706: no packages → error appended."""
        _, var = variant_and_project
        data = {"assessments": [{"vuln_id": "CVE-2099-NP", "status": "affected", "packages": []}]}
        with app.app_context():
            result = import_custom_data(data, {}, variant_id=var.id)
        assert any("No packages" in e.get("error", "") for e in result["errors"])

    def test_import_assessment_increments_counter(self, app, variant_and_project):
        """Lines 710-714, 740: successful import → assessments_imported += 1."""
        _, var = variant_and_project
        data = {
            "assessments": [{
                "vuln_id": "CVE-2099-IMP",
                "status": "not_affected",
                "packages": ["mylib@2.0"],
                "variant_id": str(var.id),
            }]
        }
        with app.app_context():
            result = import_custom_data(data, {var.name: var})
        assert result["assessments_imported"] == 1
        assert result["errors"] == []

    def test_package_with_supplier_separator(self, app, variant_and_project):
        """Lines 717-721: package string with '::' is split correctly."""
        _, var = variant_and_project
        data = {
            "assessments": [{
                "vuln_id": "CVE-2099-SUP",
                "status": "affected",
                "packages": ["mypkg@1.0::AcmeCorp"],
                "variant_id": str(var.id),
            }]
        }
        with app.app_context():
            result = import_custom_data(data, {var.name: var})
        assert result["assessments_imported"] == 1
        assert result["errors"] == []

    def test_duplicate_assessment_is_skipped(self, app, variant_and_project):
        """Line 734: importing same assessment twice → second is skipped."""
        _, var = variant_and_project
        data = {
            "assessments": [{
                "vuln_id": "CVE-2099-DUP",
                "status": "not_affected",
                "packages": ["duplib@1.0"],
                "variant_id": str(var.id),
            }]
        }
        with app.app_context():
            import_custom_data(data, {var.name: var})
            result = import_custom_data(data, {var.name: var})
        assert result["assessments_skipped"] == 1

    def test_variant_name_resolution_via_variant_by_name(self, app, variant_and_project):
        """Line 684: non-UUID variant token resolved via variant_by_name map."""
        _, var = variant_and_project
        variant_by_name = {"io-cov-var": var}
        data = {
            "assessments": [{
                "vuln_id": "CVE-2099-NAME",
                "status": "not_affected",
                "packages": ["namelib@1.0"],
                "variant_id": "io-cov-var",   # string name, not UUID
            }]
        }
        with app.app_context():
            result = import_custom_data(data, variant_by_name)
        assert result["assessments_imported"] == 1

    def test_import_ai_assessment_preserves_pending_origin(self, app, variant_and_project):
        """AI JSON rows return to the Review page as pending AI assessments."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        data = {
            "ai_assessments": [{
                "vuln_id": "CVE-2099-AI02",
                "status": "affected",
                "packages": ["ai-import@1.0"],
                "variant_id": str(var.id),
            }]
        }
        with app.app_context():
            result = import_custom_data(data, {var.name: var})
            imported = Assessment.get_by_origin([var.id], origin="ai")
            duplicate_result = import_custom_data(data, {var.name: var})

        assert result["ai_assessments_imported"] == 1
        assert result["assessments_imported"] == 0
        assert len(imported) == 1
        assert imported[0].vuln_id == "CVE-2099-AI02"
        assert duplicate_result["ai_assessments_skipped"] == 1


# ===========================================================================
# import_custom_data — CVSS section
# ===========================================================================

class TestImportCustomDataCvss:
    """Lines 772-773, 784, 787, 810-814, 822."""

    def test_cvss_vuln_not_found_appends_error(self, app, variant_and_project):
        """Lines 772-773: vuln not in DB → error appended."""
        _, var = variant_and_project
        data = {
            "cvss": [{
                "vuln_id": "CVE-2099-NOCVSS",
                "base_score": 7.5,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "version": "3.1",
            }]
        }
        with app.app_context():
            result = import_custom_data(data, {})
        assert any("not found" in e.get("error", "").lower() for e in result["errors"])

    def test_cvss_unknown_variant_name_appends_error(self, app, variant_and_project):
        """Line 784: variant token present but not resolvable → error."""
        from src.models.vulnerability import Vulnerability
        _, var = variant_and_project
        with app.app_context():
            Vulnerability.create_record("CVE-2099-CVSSVAR")
            data = {
                "cvss": [{
                    "vuln_id": "CVE-2099-CVSSVAR",
                    "variant_id": "no-such-variant",
                    "base_score": 7.5,
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "version": "3.1",
                }]
            }
            result = import_custom_data(data, {})
        assert any("not found" in e.get("error", "").lower() for e in result["errors"])

    def test_cvss_with_explicit_variant_id_imports(self, app, variant_and_project):
        """Lines 787, 810-814, 822: variant_id provided → CVSS imported."""
        from src.models.vulnerability import Vulnerability
        _, var = variant_and_project
        with app.app_context():
            Vulnerability.create_record("CVE-2099-CVSSOK")
            data = {
                "cvss": [{
                    "vuln_id": "CVE-2099-CVSSOK",
                    "variant_id": str(var.id),
                    "base_score": 7.5,
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "version": "3.1",
                }]
            }
            result = import_custom_data(data, {var.name: var})
        assert result["cvss_imported"] == 1


# ===========================================================================
# import_custom_data — time estimates section
# ===========================================================================

class TestImportCustomDataTimeEstimates:
    """Lines 833-835, 844, 847, 850-854, 862-863, 871-875, 882."""

    def test_te_vuln_not_found_appends_error(self, app, variant_and_project):
        """Lines 833-835: vuln not in DB → error appended."""
        _, var = variant_and_project
        data = {"time_estimates": [{"vuln_id": "CVE-2099-NOTD", "optimistic": "PT1H", "likely": "PT2H", "pessimistic": "PT4H"}]}
        with app.app_context():
            result = import_custom_data(data, {})
        assert any("not found" in e.get("error", "").lower() for e in result["errors"])

    def test_te_invalid_effort_appends_error(self, app, variant_and_project):
        """Line 844: validate_effort fails → error appended."""
        from src.models.vulnerability import Vulnerability
        _, var = variant_and_project
        with app.app_context():
            Vulnerability.create_record("CVE-2099-TEEFF")
            data = {"time_estimates": [{"vuln_id": "CVE-2099-TEEFF", "optimistic": "not-a-duration"}]}
            result = import_custom_data(data, {})
        assert any(e.get("vuln_id") == "CVE-2099-TEEFF" for e in result["errors"])

    def test_te_unknown_variant_name_appends_error(self, app, variant_and_project):
        """Lines 850-854: variant token present but not resolvable → error."""
        from src.models.vulnerability import Vulnerability
        _, var = variant_and_project
        with app.app_context():
            Vulnerability.create_record("CVE-2099-TEBADVAR")
            data = {
                "time_estimates": [{
                    "vuln_id": "CVE-2099-TEBADVAR",
                    "variant_id": "no-such-variant",
                    "optimistic": "PT1H",
                    "likely": "PT2H",
                    "pessimistic": "PT4H",
                }]
            }
            result = import_custom_data(data, {})
        assert any("not found" in e.get("error", "").lower() for e in result["errors"])

    def test_te_with_explicit_variant_id_imports(self, app, variant_and_project):
        """Lines 847, 862-863, 871-875: variant_id → apply_effort + increment."""
        from src.models.vulnerability import Vulnerability
        _, var = variant_and_project
        with app.app_context():
            Vulnerability.create_record("CVE-2099-TEOK")
            data = {
                "time_estimates": [{
                    "vuln_id": "CVE-2099-TEOK",
                    "variant_id": str(var.id),
                    "optimistic": "PT1H",
                    "likely": "PT2H",
                    "pessimistic": "PT4H",
                }]
            }
            result = import_custom_data(data, {var.name: var})
        assert result["time_estimates_imported"] == 1

    def test_final_status_error_when_only_errors(self, app, variant_and_project):
        """Line 882: status set to 'error' when nothing imported but errors exist."""
        _, var = variant_and_project
        data = {"assessments": [{"vuln_id": "CVE-X", "status": "affected", "packages": []}]}
        with app.app_context():
            result = import_custom_data(data, {})
        assert result["status"] == "error"
        assert result["errors"]

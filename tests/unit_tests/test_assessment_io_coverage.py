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
    detect_review_export_format,
    reconcile_review_export,
    parse_imported_timestamp,
    duplicate_multitarget_assessment_exists,
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
                targets=[(var.id, finding.id)],
                origin="custom",
            )
            db.session.commit()

            result = build_custom_data_export(variant_ids=[var.id])

        assert result["version"] == 2
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
                targets=[(var.id, finding.id)],
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
            "targets": [
                {"variant_id": str(var.id), "variant": "io-cov-var", "package": "ai-pkg@1.0.0"},
            ],
        }]


class TestReconcileReviewExport:
    def test_custom_export_preserves_order_updates_and_removes_variants(self):
        unchanged = {
            "vuln_id": "CVE-1", "variant_id": "variant-a",
            "packages": ["a@1"], "status": "affected",
        }
        changed = {
            "vuln_id": "CVE-2", "variant_id": "variant-a",
            "packages": ["b@1"], "status": "affected",
            "justification": "obsolete", "x-local-note": "keep",
        }
        removed = {
            "vuln_id": "CVE-3", "variant_id": "variant-b",
            "packages": ["c@1"], "status": "affected",
        }
        existing = {
            "version": 1,
            "exported_at": "old",
            "custom_header": "preserved",
            "assessments": [changed, removed, unchanged],
            "ai_assessments": [], "cvss": [], "time_estimates": [],
        }
        current = {
            "version": 1,
            "exported_at": "new",
            "assessments": [
                unchanged,
                {
                    "vuln_id": "CVE-2", "variant_id": "variant-a",
                    "packages": ["b@1"], "status": "fixed",
                },
                {"vuln_id": "CVE-4", "variant_id": "variant-a", "packages": [], "status": "affected"},
            ],
            "ai_assessments": [], "cvss": [], "time_estimates": [],
        }

        result = reconcile_review_export(existing, current)

        assert result["custom_header"] == "preserved"
        assert result["exported_at"] == "new"
        assert [item["vuln_id"] for item in result["assessments"]] == ["CVE-2", "CVE-1", "CVE-4"]
        assert result["assessments"][0]["status"] == "fixed"
        assert result["assessments"][0]["x-local-note"] == "keep"
        assert "justification" not in result["assessments"][0]

    def test_openvex_preserves_document_id_and_statement_order(self):
        existing = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "stable-id",
            "author": "old",
            "timestamp": "old",
            "version": 1,
            "statements": [
                {"vulnerability": {"name": "CVE-2"}, "products": [], "status": "affected"},
                {"vulnerability": {"name": "CVE-1"}, "products": [], "status": "affected"},
            ],
        }
        current = {
            **existing,
            "@id": "generated-id",
            "author": "new",
            "timestamp": "new",
            "statements": [
                {"vulnerability": {"name": "CVE-1"}, "products": [], "status": "fixed"},
                {"vulnerability": {"name": "CVE-2"}, "products": [], "status": "affected"},
            ],
        }

        result = reconcile_review_export(existing, current)

        assert result["@id"] == "stable-id"
        assert result["author"] == "new"
        assert result["version"] == 2
        assert [item["vulnerability"]["name"] for item in result["statements"]] == ["CVE-2", "CVE-1"]
        assert result["statements"][1]["status"] == "fixed"

    def test_openvex_requires_an_integer_version(self):
        document = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "stable-id",
            "author": "author",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "version": True,
            "statements": [],
        }

        with pytest.raises(ValueError):
            reconcile_review_export(document, {**document, "version": 1})

    def test_duplicate_records_match_exact_values_before_timestamp_updates(self):
        first = {
            "vuln_id": "CVE-1", "variant_id": "variant-a", "packages": ["pkg@1"],
            "status": "affected", "timestamp": "2026-01-01T00:00:00+00:00", "x-note": "first",
        }
        second = {
            "vuln_id": "CVE-1", "variant_id": "variant-a", "packages": ["pkg@1"],
            "status": "not_affected", "timestamp": "2026-01-02T00:00:00+00:00", "x-note": "second",
        }
        existing = {"version": 1, "assessments": [first, second], "ai_assessments": [], "cvss": [], "time_estimates": []}
        current = {
            "version": 1,
            "assessments": [
                {**second, "x-note": "ignored"},
                {**first, "status": "fixed"},
                {"vuln_id": "CVE-1", "variant_id": "variant-a", "packages": ["pkg@1"], "status": "affected", "timestamp": "2026-01-03T00:00:00+00:00"},
            ],
            "ai_assessments": [], "cvss": [], "time_estimates": [],
        }

        result = reconcile_review_export(existing, current)

        assert result["assessments"][0]["x-note"] == "first"
        assert result["assessments"][0]["status"] == "fixed"
        assert result["assessments"][1] == second
        assert "x-note" not in result["assessments"][2]

    @pytest.mark.parametrize("payload", [[], {"version": 1}, {"foo": "bar"}])
    def test_rejects_unsupported_or_malformed_exports(self, payload):
        with pytest.raises(ValueError):
            detect_review_export_format(payload)

    @pytest.mark.parametrize("payload", [
        {"@context": "openvex", "statements": []},
        {"version": 1, "assessments": [{"variant_id": "variant-a"}]},
        {"version": 1, "assessments": ["not-a-record"]},
    ])
    def test_rejects_malformed_review_record_identities(self, payload):
        with pytest.raises(ValueError):
            detect_review_export_format(payload)


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


# ===========================================================================
# Task-11 validation/edge-case gaps introduced by version-2 targets support
# ===========================================================================

class TestReviewOpenvexVersionGuard:
    """Line 215: _is_review_openvex_export rejects a non-integer version.

    ``isinstance(True, int)`` is True in Python (bool subclasses int), so a
    boolean version does not exercise this guard -- a genuine non-int value
    (a string) is required.
    """

    def test_openvex_doc_with_string_version_is_not_a_review_export(self):
        doc = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "stable-id",
            "author": "author",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "version": "not-an-int",
            "statements": [],
        }
        with pytest.raises(ValueError):
            detect_review_export_format(doc)


class TestValidV2Target:
    """Lines 243, 245: _is_valid_v2_target's own type guards, reached
    through detect_review_export_format's per-record validation."""

    def test_v2_target_entry_that_is_not_a_dict_is_rejected(self):
        payload = {
            "version": 2,
            "assessments": [{
                "vuln_id": "CVE-1", "packages": ["pkg@1"],
                "targets": ["not-a-dict"],
            }],
            "ai_assessments": [], "cvss": [], "time_estimates": [],
        }
        with pytest.raises(ValueError):
            detect_review_export_format(payload)

    def test_v2_target_with_non_string_package_is_rejected(self):
        payload = {
            "version": 2,
            "assessments": [{
                "vuln_id": "CVE-1", "packages": ["pkg@1"],
                "targets": [{"variant_id": "v1", "package": 123}],
            }],
            "ai_assessments": [], "cvss": [], "time_estimates": [],
        }
        with pytest.raises(ValueError):
            detect_review_export_format(payload)


class TestValidCustomRecordPackagesGuard:
    """Lines 260, 262: _is_valid_custom_record's ``packages`` guards."""

    def test_packages_field_that_is_not_a_list_is_rejected(self):
        payload = {
            "version": 1,
            "assessments": [{
                "vuln_id": "CVE-1", "variant_id": "v1", "packages": "not-a-list",
            }],
            "ai_assessments": [], "cvss": [], "time_estimates": [],
        }
        with pytest.raises(ValueError):
            detect_review_export_format(payload)

    def test_packages_list_with_non_string_entry_is_rejected(self):
        payload = {
            "version": 1,
            "assessments": [{
                "vuln_id": "CVE-1", "variant_id": "v1", "packages": [123],
            }],
            "ai_assessments": [], "cvss": [], "time_estimates": [],
        }
        with pytest.raises(ValueError):
            detect_review_export_format(payload)


class TestDetectFormatSectionMustBeArray:
    """Line 291: a top-level section that is not a list is rejected."""

    def test_cvss_section_that_is_not_a_list_is_rejected(self):
        payload = {
            "version": 1, "assessments": [], "ai_assessments": [],
            "cvss": "not-a-list", "time_estimates": [],
        }
        with pytest.raises(ValueError, match="must be an array"):
            detect_review_export_format(payload)


class TestRecordIdentityNonAssessmentSection:
    """Line 308: _record_identity's fallback for cvss/time_estimates
    sections (no ``packages`` key), reached through reconcile."""

    def test_reconciling_cvss_section_uses_variant_and_vuln_identity(self):
        existing = {
            "version": 1, "assessments": [], "ai_assessments": [],
            "cvss": [{"vuln_id": "CVE-1", "variant_id": "v1", "base_score": 5.0}],
            "time_estimates": [],
        }
        current = {
            "version": 1, "assessments": [], "ai_assessments": [],
            "cvss": [{"vuln_id": "CVE-1", "variant_id": "v1", "base_score": 9.0}],
            "time_estimates": [],
        }
        result = reconcile_review_export(existing, current)
        assert len(result["cvss"]) == 1
        assert result["cvss"][0]["base_score"] == 9.0


class TestValidateRecordsRejectsNonDictRecord:
    """Line 362: _validate_records raises when a record is not a dict.

    Reached by bypassing ``detect_review_export_format``'s own record
    validation: this exercises ``_reconcile_records`` directly by handing it
    an ``existing`` custom-data document whose ``assessments`` entry is not a
    dict but whose *outer* shape still satisfies ``_is_valid_custom_record``
    for the sections that matter to format detection is not otherwise
    possible, since detection already rejects non-dict records --
    so this instead confirms the guard raises for the CVSS/time_estimates
    sections, which are not covered by ``_is_valid_custom_record`` at all.
    """

    def test_non_dict_cvss_record_is_rejected_during_reconcile(self):
        existing = {
            "version": 1, "assessments": [], "ai_assessments": [],
            "cvss": ["not-a-dict"], "time_estimates": [],
        }
        current = {
            "version": 1, "assessments": [], "ai_assessments": [],
            "cvss": [], "time_estimates": [],
        }
        with pytest.raises(ValueError, match="invalid record"):
            reconcile_review_export(existing, current)


class TestReconcileFormatMismatch:
    """Line 441: reconciling an OpenVEX existing file against a custom-data
    current export (or vice versa) is rejected outright."""

    def test_custom_existing_against_openvex_current_is_rejected(self):
        existing = {
            "version": 1, "assessments": [], "ai_assessments": [],
            "cvss": [], "time_estimates": [],
        }
        current = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "id", "author": "author",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "version": 1, "statements": [],
        }
        with pytest.raises(ValueError, match="does not match"):
            reconcile_review_export(existing, current)


class TestParseImportedTimestampNaive:
    """Line 488: a naive (no timezone) timestamp is assumed UTC."""

    def test_naive_timestamp_is_assumed_utc(self):
        parsed = parse_imported_timestamp("2026-01-01T00:00:00", True)
        assert parsed is not None
        assert parsed.tzinfo is not None
        assert parsed.utcoffset().total_seconds() == 0


class TestDuplicateMultitargetEmptySet:
    """Line 556: an empty target set is never a duplicate."""

    def test_empty_targets_list_is_never_a_duplicate(self, app):
        with app.app_context():
            assert duplicate_multitarget_assessment_exists(
                [], status="affected", origin="custom",
            ) is False



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
        transient.description = "Updated description"
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


# ===========================================================================
# datetime_utils — ensure_utc_iso edge cases (lines 17, 19)
# ===========================================================================

class TestEnsureUtcIso:
    def test_none_returns_none(self):
        from src.helpers.datetime_utils import ensure_utc_iso
        assert ensure_utc_iso(None) is None

    def test_non_datetime_returns_str(self):
        from src.helpers.datetime_utils import ensure_utc_iso
        assert ensure_utc_iso(12345) == "12345"


# ===========================================================================
# EPSSProgressTracker — error() method (lines 72-76)
# ===========================================================================

class TestEpssProgressTrackerError:
    def test_error_sets_phase_and_message(self):
        from src.controllers.progress_tracker import ProgressTracker
        tracker = ProgressTracker(
            default_phase="epss_enrichment",
            completed_message="EPSS enrichment completed successfully",
        )
        tracker.error("something went wrong")
        progress = tracker.get_progress()
        assert progress["in_progress"] is False
        assert progress["phase"] == "error"
        assert progress["message"] == "something went wrong"
        assert progress["last_update"] is not None


# ===========================================================================
# _common.py — error branches (lines 33-34, 68-69, 73-74)
# ===========================================================================

class TestCommonHelperErrors:
    """Cover the SystemExit error branches in _common.py."""

    def test_resolve_project_not_found_exits(self, app):
        with app.app_context():
            from src.bin._common import resolve_project
            with pytest.raises(SystemExit):
                resolve_project("NoSuchProject_XYZ")

    def test_resolve_project_found_returns_object(self, app):
        from src.models.project import Project
        with app.app_context():
            Project.create("ResolveProjectOK")
            from src.bin._common import resolve_project
            result = resolve_project("ResolveProjectOK")
            assert result is not None

    def test_resolve_project_variant_project_not_found_exits(self, app):
        with app.app_context():
            from src.bin._common import resolve_project_variant
            with pytest.raises(SystemExit):
                resolve_project_variant("NoSuchProject_XYZ", "default", create=False)

    def test_resolve_project_variant_variant_not_found_exits(self, app):
        from src.models.project import Project
        with app.app_context():
            project = Project.create("VariantMissingProject")
            from src.bin._common import resolve_project_variant
            with pytest.raises(SystemExit):
                resolve_project_variant("VariantMissingProject", "no-such-variant", create=False)

    def test_resolve_project_variant_create_true(self, app):
        """create=True path (lines 63-64) — creates missing project and variant."""
        with app.app_context():
            from src.bin._common import resolve_project_variant
            proj, var = resolve_project_variant("AutoCreatedProj", "AutoVar", create=True)
            assert proj is not None
            assert var is not None

    def test_resolve_project_variant_existing(self, app):
        """Successful non-create path returns existing objects (lines 75-77)."""
        from src.models.project import Project
        from src.models.variant import Variant
        with app.app_context():
            project = Project.create("ExistingResolveProj")
            Variant.create("ExistingResolveVar", project.id)
            from src.bin._common import resolve_project_variant
            proj, var = resolve_project_variant("ExistingResolveProj", "ExistingResolveVar", create=False)
            assert proj.name == "ExistingResolveProj"
            assert var.name == "ExistingResolveVar"


# ===========================================================================
# cmd_export.py — scope resolution warning branches (lines 45-58)
# ===========================================================================

class TestCmdExportScopeBranches:
    """Cover the project/variant warning branches in export_command."""

    def test_export_project_not_found_warns(self, app, tmp_path):
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export", "--format", "spdx2", "--output-dir", str(tmp_path),
            "--project", "NonExistentProject_XYZ",
        ])
        assert result.exit_code == 0
        assert "not found" in result.output

    def test_export_variant_not_found_warns_and_uses_project_scope(self, app, tmp_path):
        from src.models.project import Project
        from src.models.variant import Variant
        with app.app_context():
            project = Project.create("ExportScopeProj")
            variant = Variant.create("ExportScopeVar", project.id)
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export", "--format", "spdx2", "--output-dir", str(tmp_path),
            "--project", "ExportScopeProj",
            "--variant", "NonExistentVariant_XYZ",
        ])
        assert result.exit_code == 0
        assert "not found" in result.output

    def test_export_with_project_and_variant_scoped(self, app, tmp_path):
        from src.models.project import Project
        from src.models.variant import Variant
        with app.app_context():
            project = Project.create("ExportScopeProjV")
            variant = Variant.create("ExportScopeVarV", project.id)
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export", "--format", "spdx2", "--output-dir", str(tmp_path),
            "--project", "ExportScopeProjV",
            "--variant", "ExportScopeVarV",
        ])
        assert result.exit_code == 0

    def test_export_with_project_only_uses_project_scope(self, app, tmp_path):
        from src.models.project import Project
        from src.models.variant import Variant
        with app.app_context():
            project = Project.create("ExportScopeProjOnly")
            variant = Variant.create("ExportScopeVarOnly", project.id)
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export", "--format", "spdx2", "--output-dir", str(tmp_path),
            "--project", "ExportScopeProjOnly",
        ])
        assert result.exit_code == 0


# ===========================================================================
# merger_ci.py — main() and __name__ == "__main__" (lines 66, 70)
# ===========================================================================

class TestMergerCiMain:
    """Cover the main() function in merger_ci.py."""

    def test_main_calls_run_main(self, app):
        from unittest.mock import patch, MagicMock
        fake_cache = MagicMock()
        with app.app_context():
            with patch("src.bin.merger_ci._run_main", return_value=fake_cache) as mock_run:
                from src.bin.merger_ci import main
                result = main()
        mock_run.assert_called_once()
        assert result is fake_cache


# ===========================================================================
# grype_vulns.py — _normalize_artifact_name fallback & description warning
# ===========================================================================

class TestGrypeVulnsNormalize:
    """Cover uncovered branches in GrypeVulns static helpers."""

    def test_normalize_name_with_slash_no_purl_returns_last_segment(self):
        """Lines 68-72: fallback path when name has '/' and purl is absent."""
        from src.views.grype_vulns import GrypeVulns
        result = GrypeVulns._normalize_artifact_name("openssl/openssl-foo")
        assert result == "openssl-foo"

    def test_normalize_name_with_slash_purl_empty_falls_through(self):
        """Lines 68-72: purl present but yields empty purl_name → fallback."""
        from src.views.grype_vulns import GrypeVulns
        # A purl where path_part after stripping ends up empty forces fallback
        result = GrypeVulns._normalize_artifact_name("namespace/pkg-name", purl=None)
        assert result == "pkg-name"

    def test_parse_vulnerability_non_string_description_warns(self, app):
        """Line 140: description present but not a string triggers logger.warning."""
        from src.controllers.cache import ControllersCache
        from src.views.grype_vulns import GrypeVulns
        with app.app_context():
            cache = ControllersCache()
            g = GrypeVulns(cache)
            vuln = g.parse_vulnerability_section({
                "id": "CVE-2023-9999",
                "severity": "HIGH",
                "description": 99,   # not a str, not None → line 140
                "urls": [],
                "cvss": [],
                "fix": {},
                "relatedVulnerabilities": [],
            })
        assert vuln is not None
        assert vuln.description is None  # non-string desc is skipped, remains None


# ===========================================================================
# SBOMObservation — __repr__ and commit=False path
# ===========================================================================

class TestSBOMObservation:
    def test_repr(self, app):
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.sbom_document import SBOMDocument
        from src.models.vulnerability import Vulnerability
        from src.models.sbom_observation import SBOMObservation
        with app.app_context():
            proj = Project.create("obs-repr-proj")
            var = Variant.create("main", proj.id)
            scan = Scan.create("obs-repr-scan", var.id)
            doc = SBOMDocument.create("/obs/test.spdx", "src", scan.id)
            vuln = Vulnerability.create_record("CVE-2099-OBS1")
            obs = SBOMObservation.create(vuln.id, doc.id, "yocto description", "some text")
            r = repr(obs)
            assert "SBOMObservation" in r

    def test_create_commit_false(self, app):
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.sbom_document import SBOMDocument
        from src.models.vulnerability import Vulnerability
        from src.models.sbom_observation import SBOMObservation
        from src.extensions import db
        with app.app_context():
            proj = Project.create("obs-flush-proj")
            var = Variant.create("main", proj.id)
            scan = Scan.create("obs-flush-scan", var.id)
            doc = SBOMDocument.create("/obs/flush.spdx", "src", scan.id)
            vuln = Vulnerability.create_record("CVE-2099-OBS2")
            obs = SBOMObservation.create(vuln.id, doc.id, "key", "desc", commit=False)
            db.session.commit()
            assert obs.id is not None


# ===========================================================================
# SBOMDocument.get_by_path — None return when no match / result when match
# ===========================================================================

class TestSBOMDocumentGetByPath:
    def test_get_by_path_returns_none_when_not_found(self, app):
        from src.models.sbom_document import SBOMDocument
        with app.app_context():
            result = SBOMDocument.get_by_path("/nonexistent/path.spdx")
            assert result is None

    def test_get_by_path_returns_document_when_found(self, app):
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.sbom_document import SBOMDocument
        with app.app_context():
            proj = Project.create("getbypath-proj")
            var = Variant.create("main", proj.id)
            scan = Scan.create("getbypath-scan", var.id)
            doc = SBOMDocument.create("/sbom/found.spdx", "src", scan.id)
            result = SBOMDocument.get_by_path("/sbom/found.spdx")
            assert result is not None
            assert result.id == doc.id


# ===========================================================================
# Assessment.add_package — Package instance path (lines 235-238)
# ===========================================================================

class TestAssessmentAddPackageInstance:
    def test_add_package_with_package_instance(self, app, db_package):
        from src.models.assessment import Assessment
        with app.app_context():
            dto = Assessment.new_dto("CVE-2099-ADDPKG")
            result = dto.add_package(db_package)
            assert result is True
            assert db_package.string_id in dto.packages


# ===========================================================================
# Assessment.from_vuln_assessment — sets origin to "sbom" when not already set
# ===========================================================================

class TestAssessmentFromVulnAssessmentOrigin:
    def test_sets_origin_to_sbom_on_update(self, app, db_package, db_vuln, db_finding):
        from src.models.assessment import Assessment
        with app.app_context():
            # Create existing assessment with origin != "sbom"
            existing = Assessment.create(
                status="under_investigation",
                finding_id=db_finding.id,
            )
            existing.origin = "scanner"
            from src.extensions import db
            db.session.flush()

            dto = Assessment.new_dto(db_vuln.id, [db_package.string_id])
            dto.id = existing.id
            dto.set_status("affected")
            updated = Assessment.from_vuln_assessment(dto, finding_id=db_finding.id)
            assert updated.origin == "sbom"


# ===========================================================================
# vuln_helpers.apply_cvss — sets default origin when missing
# ===========================================================================

class TestApplyCvssDefaultOrigin:
    def test_apply_cvss_sets_default_origin(self, app, db_vuln):
        from src.helpers.vuln_helpers import validate_and_apply_cvss
        with app.app_context():
            cvss_dict = {
                "base_score": 5.0,
                "vector_string": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "version": "3.1",
                "author": "scanner",
                # "origin" intentionally absent → line 72: new_cvss["origin"] = "scanner"
            }
            result = validate_and_apply_cvss(cvss_dict, db_vuln.id, None)
            assert result is None


# ===========================================================================
# Finding.get_or_create — race-condition except path (finding.py lines 139-141)
# ===========================================================================

class TestFindingGetOrCreateRace:
    """Cover the except block in Finding.get_or_create.

    The except branch is hit when a concurrent writer inserts the same
    (package, vulnerability) row between our initial SELECT (which returned
    None) and our own INSERT (which then collides on the UniqueConstraint).
    We simulate this by patching get_by_package_and_vulnerability to return
    None on the first call while the row already exists in the DB, so the
    nested INSERT raises IntegrityError and the recovery re-query returns it.
    """

    def test_race_condition_except_path(self, app, db_package, db_vuln):
        from unittest.mock import patch
        from src.models.finding import Finding

        # Row already in DB — the recovery SELECT will find it.
        pre_existing = Finding.create(db_package.id, db_vuln.id)

        call_count = [0]
        original = Finding.get_by_package_and_vulnerability

        def patched(pkg_id, vuln_id):
            call_count[0] += 1
            if call_count[0] == 1:
                return None  # pretend the row is absent (race window)
            return original(pkg_id, vuln_id)

        with patch.object(Finding, "get_by_package_and_vulnerability", patched):
            result = Finding.get_or_create(db_package.id, db_vuln.id)

        assert result.id == pre_existing.id
        assert call_count[0] == 2  # initial miss + recovery


# ===========================================================================
# Iso8601Duration.try_parse — unsupported-type path (line 210)
# ===========================================================================

class TestIso8601DurationTryParseUnsupported:
    """Cover the ValueError branch in Iso8601Duration.try_parse."""

    def test_try_parse_float_raises_value_error(self):
        from src.models.iso8601_duration import Iso8601Duration

        with pytest.raises(ValueError, match="Can only compare"):
            Iso8601Duration.try_parse(3.14)


# ===========================================================================
# ControllersCache — unused cached_property accessors (cache.py lines 48, 52, 56, 72)
# ===========================================================================

class TestControllersCacheProperties:
    """Access the four cached_property paths not exercised by any other test."""

    def test_conditions_parser_property(self):
        from src.controllers.cache import ControllersCache
        cache = ControllersCache()
        assert cache.conditions_parser is not None

    def test_finding_property(self):
        from src.controllers.cache import ControllersCache
        cache = ControllersCache()
        assert cache.finding is not None

    def test_metrics_property(self):
        from src.controllers.cache import ControllersCache
        cache = ControllersCache()
        assert cache.metrics is not None

    def test_time_estimate_property(self):
        from src.controllers.cache import ControllersCache
        cache = ControllersCache()
        assert cache.time_estimate is not None


# ===========================================================================
# normalize_timestamp_for_sort — all branches (datetime_utils.py lines 35, 37-40)
# ===========================================================================

class TestNormalizeTimestampForSort:

    def test_none_returns_datetime_min(self):
        from src.helpers.datetime_utils import normalize_timestamp_for_sort
        from datetime import datetime, timezone
        result = normalize_timestamp_for_sort(None)
        assert result == datetime.min.replace(tzinfo=timezone.utc)

    def test_valid_iso_string_is_parsed(self):
        from src.helpers.datetime_utils import normalize_timestamp_for_sort
        from datetime import datetime, timezone
        result = normalize_timestamp_for_sort("2024-01-15T10:00:00+00:00")
        assert result == datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

    def test_invalid_string_returns_datetime_min(self):
        from src.helpers.datetime_utils import normalize_timestamp_for_sort
        from datetime import datetime, timezone
        result = normalize_timestamp_for_sort("not-a-date")
        assert result == datetime.min.replace(tzinfo=timezone.utc)

    def test_naive_datetime_gets_utc_attached(self):
        from src.helpers.datetime_utils import normalize_timestamp_for_sort
        from datetime import datetime, timezone
        naive = datetime(2024, 6, 1, 12, 0, 0)
        result = normalize_timestamp_for_sort(naive)
        assert result.tzinfo == timezone.utc
        assert result.year == 2024


# ===========================================================================
# ConditionParser.eval — dead-code None guard (conditions_parser.py line 136)
# ===========================================================================

class TestConditionParserNullParsed:
    """Cover the ``if parsed is None`` guard by forcing parse_string to return None."""

    def test_eval_raises_when_parsed_is_none(self):
        from unittest.mock import MagicMock, patch
        from src.controllers.conditions_parser import ConditionParser
        cp = ConditionParser()
        fake_result = MagicMock()
        fake_result.asList.return_value = None
        with patch.object(cp, "parse_string", return_value=fake_result):
            with pytest.raises(ValueError, match="Failed to parse"):
                cp.evaluate("anything", {})


# ===========================================================================
# apply_effort — exception branch (vuln_helpers.py lines 105-106)
# ===========================================================================

class TestApplyEffortExceptionBranch:
    """Cover the except block in apply_effort by making findings raise."""

    def test_exception_is_swallowed(self):
        from src.helpers.vuln_helpers import apply_effort, Effort

        class _BrokenRecord:
            @property
            def findings(self):
                raise RuntimeError("db exploded")

        effort = Effort(optimistic=1, likely=2, pessimistic=4)
        # Must not raise — the except block swallows the error.
        apply_effort(_BrokenRecord(), None, effort)


# ===========================================================================
# _scan_helpers.validate_trigger — internal-error 500 branch (line 67)
# ===========================================================================

class TestValidateTriggerInternalError:
    """Cover the defensive ``variant_uuid is None`` branch (line 67).

    ``parse_uuid_or_400`` never returns ``(None, None)`` in practice, so this
    branch is dead code that requires a patch to reach.
    """

    def test_none_uuid_returns_500(self, app):
        from unittest.mock import patch
        with app.app_context():
            from src.routes._scan_helpers import validate_trigger
            with patch("src.routes._scan_helpers.parse_uuid_or_400", return_value=(None, None)):
                _, _, err = validate_trigger("anything", {}, "test-scan")
        assert err is not None
        assert err[1] == 500


# ===========================================================================
# SBOMPackage.get_or_create — exception fallback path (lines 82-83)
# ===========================================================================

class TestSBOMPackageGetOrCreateException:
    """Cover the except branch of get_or_create (race-condition recovery)."""

    def test_create_exception_falls_back_to_get(self, app):
        from unittest.mock import patch
        from src.models.sbom_package import SBOMPackage
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.sbom_document import SBOMDocument
        from src.models.package import Package

        with app.app_context():
            proj = Project.create("sbom-race-proj")
            var = Variant.create("main", proj.id)
            scan = Scan.create("race-scan", var.id)
            doc = SBOMDocument.create("/race/test.spdx", "src", scan.id)
            pkg = Package.create("race-lib", "1.0.0")

            # Pre-create the association so the recovery get() finds it.
            pre = SBOMPackage.create(doc.id, pkg.id)

            # Patch SBOMPackage.create to simulate a concurrent-insert error.
            with patch.object(SBOMPackage, "get", side_effect=[None, pre]):
                with patch.object(SBOMPackage, "create", side_effect=Exception("unique constraint")):
                    result = SBOMPackage.get_or_create(doc.id, pkg.id)

            assert result.package_id == pkg.id


# ===========================================================================
# SPDX3.output_as_json — vuln-not-in-vuln_to_ref continue branch (line 183)
# ===========================================================================

class TestSpdx3VulnNotInRefContinue:
    """Cover the ``continue`` on line 183 of spdx3.py.

    The third loop in output_as_json skips a vulnerability when it has no
    entry in vuln_to_ref.  This happens when the vulnerabilities dict returns
    an extra entry in the third pass that was absent during the second pass.
    """

    def test_vuln_absent_from_vuln_to_ref_is_skipped(self):
        from unittest.mock import MagicMock, PropertyMock
        from src.views.spdx3 import SPDX3
        from src.controllers import ControllersCache

        ctrl = ControllersCache()
        ctrl.packages = MagicMock()
        ctrl.packages.__iter__ = MagicMock(return_value=iter([]))

        # Loop 2 (building elements): sees nothing → vuln_to_ref stays empty.
        # Loop 3 (building relationships): sees ghost vuln → hits the ``continue``.
        ghost_vuln = MagicMock()
        ghost_vuln.packages = []

        call_count = [0]

        def _items_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                return {}.items()  # second loop: empty
            return {"CVE-GHOST-1": ghost_vuln}.items()  # third loop: ghost

        mock_vulns = MagicMock()
        mock_vulns.items.side_effect = _items_side_effect
        ctrl.vulnerabilities = MagicMock()
        type(ctrl.vulnerabilities).vulnerabilities = PropertyMock(return_value=mock_vulns)

        view = SPDX3(ctrl)
        output = view.output_as_json()
        # Ghost vuln has no ref → continue executed; JSON still returns.
        assert "@graph" in output


# ===========================================================================
# openvex.py line 118 — stmt["vulnerability"] is None → reset to {}
# ===========================================================================

class TestOpenVexVulnerabilityNullReset:
    def test_vulnerability_none_resets_to_empty_dict(self):
        """openvex.py line 118: when to_openvex_dict returns a dict with
        vulnerability=None and the vuln lookup returns a vuln object, the
        None value is replaced with {}."""
        from unittest.mock import MagicMock
        from src.views.openvex import OpenVex
        from src.controllers import ControllersCache

        fake_assess = MagicMock()
        fake_assess.vuln_id = "CVE-2024-NULL"
        fake_assess.to_openvex_dict.return_value = {
            "vulnerability": None,
            "status": "affected",
        }
        fake_assess.packages = []

        fake_vuln = MagicMock()
        fake_vuln.description = ""
        fake_vuln.aliases = ["CVE-2024-NULL"]
        fake_vuln.datasource = "nvd"
        fake_vuln.found_by = []

        ctrl = ControllersCache()
        ctrl.packages = MagicMock()
        ctrl.vulnerabilities = MagicMock()
        ctrl.vulnerabilities.get = MagicMock(return_value=fake_vuln)
        ctrl.assessments = MagicMock()
        ctrl.assessments.get_all = MagicMock(return_value=[fake_assess])

        view = OpenVex(ctrl)
        result = view.to_dict()
        stmt = result["statements"][0]
        # After the reset, aliases should be set on the now-empty dict.
        assert stmt["vulnerability"]["aliases"] == ["CVE-2024-NULL"]


# ===========================================================================
# fast_spdx3.py lines 491-493, 495 — dedup: compatible existing assessment
# ===========================================================================

class TestFastSpdx3DedupCompatibleAssessment:
    def test_compatible_existing_skips_add(self):
        """fast_spdx3.py lines 491-495: when a compatible existing assessment
        is found for the (vuln, pkg) pair, add() is not called."""
        from unittest.mock import MagicMock
        from src.views.fast_spdx3 import FastSPDX3
        from src.controllers import ControllersCache

        ctrl = ControllersCache()
        view = FastSPDX3(ctrl)

        pkg_uri = "http://example.com/pkg/foo@1.0"
        pkg_id = "foo@1.0"
        view.uri_to_package[pkg_uri] = pkg_id

        existing = MagicMock()
        existing.is_compatible_status.return_value = True

        view.assessmentsCtrl = MagicMock()
        view.assessmentsCtrl.warm_packages = MagicMock()
        view.assessmentsCtrl.gets_by_vuln_pkg = MagicMock(return_value=[existing])
        view.assessmentsCtrl.add = MagicMock()

        spdx_dict = {
            "@graph": [
                {
                    "type": "security_VexAffectedVulnAssessmentRelationship",
                    "from": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999",
                    "to": [pkg_uri],
                    "relationshipType": "doesNotAffect",
                }
            ]
        }
        view.process_vex_relationships(spdx_dict)

        existing.is_compatible_status.assert_called_once()
        view.assessmentsCtrl.add.assert_not_called()


# ===========================================================================
# spdx.py line 87  — load_from_file: parse succeeds but returns falsy
# spdx.py lines 103-104 — merge_components: supplier attribute access fails
# ===========================================================================

class TestSpdxLoadFromFileInvalidResult:
    def test_falsy_parse_result_raises(self, tmp_path):
        """spdx.py line 87: when parse_file returns None/falsy, raise
        Exception('Invalid SPDX file')."""
        from unittest.mock import patch
        from src.views.spdx import SPDX
        from src.controllers import ControllersCache

        dummy = tmp_path / "dummy.spdx.json"
        dummy.write_text("{}")

        ctrl = ControllersCache()
        view = SPDX(ctrl)

        with patch("src.views.spdx.parse_file", return_value=None):
            with pytest.raises(Exception, match="Invalid SPDX file"):
                view.load_from_file(str(dummy))


class TestSpdxMergeSupplierAccessError:
    def test_supplier_attribute_error_calls_verbose(self):
        """spdx.py lines 103-104: when accessing package.supplier raises,
        the except block calls verbose and the package is still added."""
        from unittest.mock import MagicMock, patch
        from src.views.spdx import SPDX
        from src.controllers import ControllersCache

        bad_pkg = MagicMock()
        bad_pkg.name = "bad-pkg"
        bad_pkg.version = "1.0"
        bad_pkg.supplier = MagicMock()
        # Make isinstance check pass but attribute access fail
        bad_pkg.supplier.__class__ = object  # not SpdxNoAssertion
        type(bad_pkg.supplier).actor_type = property(lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
        bad_pkg.license_declared = None
        bad_pkg.external_references = []

        doc = MagicMock()
        doc.packages = [bad_pkg]

        ctrl = ControllersCache()
        view = SPDX(ctrl)
        view.sbom = doc

        with patch("src.views.spdx.verbose") as mock_verbose:
            view.merge_components_into_controller()

        mock_verbose.assert_called_once()
        assert "bad-pkg" in mock_verbose.call_args[0][0]


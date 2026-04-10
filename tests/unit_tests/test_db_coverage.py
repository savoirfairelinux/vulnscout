# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""
Supplementary coverage tests to push coverage to ≥ 95 %.

Covers:
  - models.Observation            (CRUD)
  - models.SBOMPackage            (CRUD)
  - models.Package                (vendor-format, get_by_string_id, find_or_create update)
  - models.Vulnerability         (persist_from_transient create + update, full update kwargs)
  - models.Assessment             (from_vuln_assessment update path, full update kwargs)
  - views.TimeEstimates           (_iso_to_hours, _persist_db_estimate, load_from_dict DB fmt)
  - bin.merger_ci               (CLI 'merge' command)
  - routes.vulnerabilities        (_parse_effort_hours int/err, batch effort validation)
"""

import pytest
from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Shared app fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    import os
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
            _db.session.remove()
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def project(app):
    from src.models.project import Project
    return Project.create("CoverageProject")


@pytest.fixture()
def variant(app, project):
    from src.models.variant import Variant
    return Variant.create("CoverageVariant", project.id)


@pytest.fixture()
def scan(app, variant):
    from src.models.scan import Scan
    return Scan.create("coverage scan", variant.id)


@pytest.fixture()
def sbom_doc(app, scan):
    from src.models.sbom_document import SBOMDocument
    return SBOMDocument.create("/path/to/sbom.json", "coverage-source", scan.id)


@pytest.fixture()
def package(app):
    from src.models.package import Package
    return Package.create("libcov", "3.0.0")


@pytest.fixture()
def vuln_record(app):
    from src.models.vulnerability import Vulnerability
    return Vulnerability.create_record(
        id="CVE-2025-9999",
        description="Coverage test vuln",
        status="under_investigation",
        links=["https://example.com"],
    )


@pytest.fixture()
def finding(app, package, vuln_record):
    from src.models.finding import Finding
    return Finding.create(package.id, vuln_record.id)


# ===========================================================================
# Observation model
# ===========================================================================

class TestObservation:
    def test_create_and_get_by_id(self, app, finding, scan):
        from src.models.observation import Observation
        obs = Observation.create(finding_id=finding.id, scan_id=scan.id)
        found = Observation.get_by_id(obs.id)
        assert found is not None
        assert found.finding_id == finding.id
        assert found.scan_id == scan.id

    def test_get_by_id_string(self, app, finding, scan):
        from src.models.observation import Observation
        obs = Observation.create(finding_id=finding.id, scan_id=scan.id)
        found = Observation.get_by_id(str(obs.id))
        assert found is not None

    def test_get_by_scan(self, app, finding, scan):
        from src.models.observation import Observation
        obs = Observation.create(finding_id=finding.id, scan_id=scan.id)
        results = Observation.get_by_scan(scan.id)
        assert any(o.id == obs.id for o in results)

    def test_get_by_scan_string(self, app, finding, scan):
        from src.models.observation import Observation
        Observation.create(finding_id=finding.id, scan_id=scan.id)
        results = Observation.get_by_scan(str(scan.id))
        assert len(results) >= 1

    def test_get_by_finding(self, app, finding, scan):
        from src.models.observation import Observation
        obs = Observation.create(finding_id=finding.id, scan_id=scan.id)
        results = Observation.get_by_finding(finding.id)
        assert any(o.id == obs.id for o in results)

    def test_get_by_finding_string(self, app, finding, scan):
        from src.models.observation import Observation
        Observation.create(finding_id=finding.id, scan_id=scan.id)
        results = Observation.get_by_finding(str(finding.id))
        assert len(results) >= 1

    def test_delete(self, app, finding, scan):
        from src.models.observation import Observation
        obs = Observation.create(finding_id=finding.id, scan_id=scan.id)
        oid = obs.id
        obs.delete()
        assert Observation.get_by_id(oid) is None

    def test_repr(self, app, finding, scan):
        from src.models.observation import Observation
        obs = Observation.create(finding_id=finding.id, scan_id=scan.id)
        assert "Observation" in repr(obs)

    def test_create_with_none_ids_raises(self, app):
        from src.models.observation import Observation
        import sqlalchemy
        with pytest.raises((sqlalchemy.exc.IntegrityError, TypeError)):
            Observation.create(finding_id=None, scan_id=None)


# ===========================================================================
# SBOMPackage model
# ===========================================================================

class TestSBOMPackage:
    def test_create_and_get(self, app, sbom_doc, package):
        from src.models.sbom_package import SBOMPackage
        entry = SBOMPackage.create(sbom_doc.id, package.id)
        found = SBOMPackage.get(sbom_doc.id, package.id)
        assert found is not None
        assert found.sbom_document_id == sbom_doc.id
        assert found.package_id == package.id

    def test_create_with_strings(self, app, sbom_doc, package):
        from src.models.sbom_package import SBOMPackage
        from src.models.package import Package
        p2 = Package.create("libcov2", "2.0.0")
        entry = SBOMPackage.create(str(sbom_doc.id), str(p2.id))
        assert entry is not None

    def test_get_by_document(self, app, sbom_doc, package):
        from src.models.sbom_package import SBOMPackage
        SBOMPackage.create(sbom_doc.id, package.id)
        results = SBOMPackage.get_by_document(sbom_doc.id)
        assert len(results) >= 1

    def test_get_by_document_string(self, app, sbom_doc, package):
        from src.models.sbom_package import SBOMPackage
        SBOMPackage.create(sbom_doc.id, package.id)
        results = SBOMPackage.get_by_document(str(sbom_doc.id))
        assert len(results) >= 1

    def test_get_by_package(self, app, sbom_doc, package):
        from src.models.sbom_package import SBOMPackage
        SBOMPackage.create(sbom_doc.id, package.id)
        results = SBOMPackage.get_by_package(package.id)
        assert len(results) >= 1

    def test_get_by_package_string(self, app, sbom_doc, package):
        from src.models.sbom_package import SBOMPackage
        SBOMPackage.create(sbom_doc.id, package.id)
        results = SBOMPackage.get_by_package(str(package.id))
        assert len(results) >= 1

    def test_delete(self, app, sbom_doc, package):
        from src.models.sbom_package import SBOMPackage
        entry = SBOMPackage.create(sbom_doc.id, package.id)
        entry.delete()
        assert SBOMPackage.get(sbom_doc.id, package.id) is None

    def test_repr(self, app, sbom_doc, package):
        from src.models.sbom_package import SBOMPackage
        entry = SBOMPackage.create(sbom_doc.id, package.id)
        assert "SBOMPackage" in repr(entry)


# ===========================================================================
# Package extras
# ===========================================================================

class TestPackageExtras:
    def test_vendor_format_constructor(self, app):
        """Package("vendor:name", version) should split name and add CPE/PURL."""
        from src.models.package import Package
        p = Package("acme:libfoo", "1.0")
        assert p.name == "libfoo"
        assert any("acme" in c for c in (p.cpe or []))

    def test_get_by_string_id(self, app, package):
        from src.models.package import Package
        found = Package.get_by_string_id(package.string_id)
        assert found is not None
        assert found.id == package.id

    def test_find_or_create_updates_identifiers(self, app, package):
        """find_or_create should merge new CPE/PURL identifiers into an existing record."""
        from src.models.package import Package
        updated = Package.find_or_create(
            package.name,
            package.version,
            cpe=["cpe:2.3:a:test:libcov:3.0.0:*:*:*:*:*:*:*"],
            purl=["pkg:generic/libcov@3.0.0"],
        )
        assert updated.id == package.id
        assert "cpe:2.3:a:test:libcov:3.0.0:*:*:*:*:*:*:*" in (updated.cpe or [])

    def test_add_cpe_duplicate_ignored(self, app, package):
        """Adding the same CPE twice should not duplicate it."""
        from src.models.package import Package
        if not package.cpe:
            package.add_cpe("cpe:2.3:a:test:libcov:3.0.0:*:*:*:*:*:*:*")
        before = len(package.cpe)
        package.add_cpe(package.cpe[0])
        assert len(package.cpe) == before

    def test_merge_same_package(self, app):
        from src.models.package import Package
        p1 = Package("mergelib", "1.0", cpe=["cpe:2.3:*:*:mergelib:1.0:*:*:*:*:*:*:*"])
        p2 = Package("mergelib", "1.0", purl=["pkg:generic/mergelib@1.0"])
        result = p1.merge(p2)
        assert result is True
        assert "pkg:generic/mergelib@1.0" in (p1.purl or [])

    def test_merge_different_package_returns_false(self, app):
        from src.models.package import Package
        p1 = Package("libA", "1.0")
        p2 = Package("libB", "2.0")
        assert p1.merge(p2) is False


# ===========================================================================
# Vulnerability.persist_from_transient + full update
# ===========================================================================

class TestVulnerabilityPersistFromTransient:
    def _make_vuln(self, pkg_id="libcov@3.0.0"):
        """Create an in-memory Vulnerability DTO populated with test data."""
        from src.models.vulnerability import Vulnerability
        from src.models.cvss import CVSS
        v = Vulnerability("CVE-2025-1111", ["grype"], "https://nvd.nist.gov", "nvd:cpe")
        v.add_url("https://nvd.nist.gov/vuln/detail/CVE-2025-1111")
        v.add_text("A test vulnerability for coverage.", "description")
        v.add_alias("GHSA-test-1111")
        v.add_package(pkg_id)
        v.severity_label = "high"
        v.severity_max_score = 8.0
        v.severity_min_score = 7.5
        v.published = "2025-01-15"
        cvss = CVSS("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "NVD", 8.0, 3.9, 3.6)
        v.register_cvss(cvss)
        return v

    def test_persist_from_transient_create(self, app, package):
        """persist_from_transient should create a new Vulnerability + Finding + Metrics."""
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding
        v = self._make_vuln(pkg_id=package.string_id)
        rec = Vulnerability.persist_from_transient(v)
        assert rec is not None
        assert rec.id == "CVE-2025-1111"
        assert rec.description == "A test vulnerability for coverage."
        # finding should have been created
        findings = Finding.get_by_vulnerability("CVE-2025-1111")
        assert len(findings) >= 1

    def test_persist_from_transient_update(self, app, package):
        """Calling persist_from_transient twice should update the existing record."""
        from src.models.vulnerability import Vulnerability
        v = self._make_vuln(pkg_id=package.string_id)
        rec1 = Vulnerability.persist_from_transient(v)
        # mutate the vulnerability and call again
        v.add_url("https://new-link.example.com")
        v.severity_label = "critical"
        v.severity_max_score = 9.8
        v.epss = {"score": 0.95, "percentile": 0.99}
        rec2 = Vulnerability.persist_from_transient(v)
        assert rec2.id == rec1.id

    def test_vuln_record_full_update(self, app, vuln_record):
        """update_record() should handle every optional kwarg."""
        import datetime
        vuln_record.update_record(
            description="updated desc",
            status="fixed",
            publish_date=datetime.date(2025, 3, 1),
            attack_vector="AV:N",
            epss_score=0.98,
            links=["https://updated.example.com"],
        )
        assert vuln_record.description == "updated desc"
        assert vuln_record.status == "fixed"


# ===========================================================================
# Assessment.from_vuln_assessment update path + full update
# ===========================================================================

class TestAssessmentFromVulnAssessment:
    def test_from_vuln_assessment_create(self, app, finding):
        """from_vuln_assessment with no existing record should create a new one."""
        from src.models.assessment import Assessment
        va = Assessment.new_dto("CVE-2025-9999", ["libcov@3.0.0"])
        va.set_status("under_investigation")
        va.set_status_notes("first run", False)
        a = Assessment.from_vuln_assessment(va, finding_id=finding.id)
        assert a is not None
        assert a.status == "under_investigation"

    def test_from_vuln_assessment_update(self, app, finding):
        """from_vuln_assessment with an existing record should update it."""
        from src.models.assessment import Assessment
        # create first
        va1 = Assessment.new_dto("CVE-2025-9999", ["libcov@3.0.0"])
        va1.set_status("under_investigation")
        Assessment.from_vuln_assessment(va1, finding_id=finding.id)
        # update
        va2 = Assessment.new_dto("CVE-2025-9999", ["libcov@3.0.0"])
        va2.set_status("not_affected")
        va2.set_justification("vulnerable_code_not_present")
        va2.responses = ["no action needed"]
        a2 = Assessment.from_vuln_assessment(va2, finding_id=finding.id)
        assert a2.status == "not_affected"
        assert a2.justification == "vulnerable_code_not_present"
        assert a2.responses == ["no action needed"]

    def test_assessment_full_update(self, app, finding, variant):
        """update() should handle every optional kwarg."""
        from src.models.assessment import Assessment
        a = Assessment.create("under_investigation", finding_id=finding.id, variant_id=variant.id)
        a.update(
            source="grype",
            simplified_status="not_affected",
            status_notes="resolved",
            justification="vulnerable_code_not_present",
            impact_statement="no impact",
            workaround="upgrade to 2.0",
            responses=["patched"],
        )
        assert a.source == "grype"
        assert a.workaround == "upgrade to 2.0"

    def test_from_vuln_assessment_create_sets_simplified_status(self, app, finding):
        """from_vuln_assessment create path should populate simplified_status via STATUS_TO_SIMPLIFIED."""
        from src.models.assessment import Assessment, STATUS_TO_SIMPLIFIED
        va = Assessment.new_dto("CVE-2025-9999", ["libcov@3.0.0"])
        va.set_status("exploitable")
        a = Assessment.from_vuln_assessment(va, finding_id=finding.id)
        assert a.simplified_status == STATUS_TO_SIMPLIFIED["exploitable"]

    def test_from_vuln_assessment_update_sets_simplified_status(self, app, finding):
        """from_vuln_assessment update path should refresh simplified_status when status changes."""
        from src.models.assessment import Assessment, STATUS_TO_SIMPLIFIED
        va1 = Assessment.new_dto("CVE-2025-9999", ["libcov@3.0.0"])
        va1.set_status("under_investigation")
        Assessment.from_vuln_assessment(va1, finding_id=finding.id)

        va2 = Assessment.new_dto("CVE-2025-9999", ["libcov@3.0.0"])
        va2.set_status("fixed")
        a2 = Assessment.from_vuln_assessment(va2, finding_id=finding.id)
        assert a2.simplified_status == STATUS_TO_SIMPLIFIED["fixed"]

    def test_from_vuln_assessment_create_with_variant_id(self, app, finding, variant):
        """from_vuln_assessment create path should assign the supplied variant_id."""
        from src.models.assessment import Assessment
        va = Assessment.new_dto("CVE-2025-9999", ["libcov@3.0.0"])
        va.set_status("in_triage")
        a = Assessment.from_vuln_assessment(va, finding_id=finding.id, variant_id=variant.id)
        assert a.variant_id == variant.id

    def test_from_vuln_assessment_update_sets_variant_id_if_none(self, app, finding, variant):
        """from_vuln_assessment update path should set variant_id when the existing record has none."""
        from src.models.assessment import Assessment
        va1 = Assessment.new_dto("CVE-2025-9999", ["libcov@3.0.0"])
        va1.set_status("under_investigation")
        Assessment.from_vuln_assessment(va1, finding_id=finding.id)  # no variant_id

        va2 = Assessment.new_dto("CVE-2025-9999", ["libcov@3.0.0"])
        va2.set_status("fixed")
        a2 = Assessment.from_vuln_assessment(va2, finding_id=finding.id, variant_id=variant.id)
        assert a2.variant_id == variant.id

    def test_from_vuln_assessment_separate_record_per_variant(self, app, finding, variant, project):
        """Each variant must get its own assessment row for the same finding."""
        from src.models.assessment import Assessment
        from src.models.variant import Variant
        va1 = Assessment.new_dto("CVE-2025-9999", ["libcov@3.0.0"])
        va1.set_status("under_investigation")
        a1 = Assessment.from_vuln_assessment(va1, finding_id=finding.id, variant_id=variant.id)

        other_variant = Variant.create("OtherVariant", project.id)
        va2 = Assessment.new_dto("CVE-2025-9999", ["libcov@3.0.0"])
        va2.set_status("fixed")
        a2 = Assessment.from_vuln_assessment(va2, finding_id=finding.id, variant_id=other_variant.id)
        # Each variant should have its own assessment with its own variant_id
        assert a1.variant_id == variant.id
        assert a2.variant_id == other_variant.id
        assert a1.id != a2.id


# ===========================================================================
# TimeEstimates: DB integer format + _iso_to_hours
# ===========================================================================

class TestTimeEstimatesDB:
    def _make_controllers(self):
        from src.controllers.packages import PackagesController
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.assessments import AssessmentsController
        from unittest.mock import patch, MagicMock
        pkg = PackagesController()
        with patch("src.controllers.vulnerabilities.EPSS_DB") as mock_epss:
            mock_epss.return_value = MagicMock()
            vuln = VulnerabilitiesController(pkg)
        assess = AssessmentsController(pkg, vuln)
        return {"packages": pkg, "vulnerabilities": vuln, "assessments": assess}

    def test_iso_to_hours_valid(self, app):
        from src.views.time_estimates import TimeEstimates
        ctrls = self._make_controllers()
        te = TimeEstimates(ctrls)
        result = te._iso_to_hours("PT4H")
        assert result == 4

    def test_iso_to_hours_none(self, app):
        from src.views.time_estimates import TimeEstimates
        ctrls = self._make_controllers()
        te = TimeEstimates(ctrls)
        assert te._iso_to_hours(None) is None
        assert te._iso_to_hours("") is None

    def test_persist_db_estimate(self, app, finding, variant):
        """_persist_db_estimate should create a TimeEstimate row in the DB."""
        from src.views.time_estimates import TimeEstimates
        from src.models.time_estimate import TimeEstimate
        ctrls = self._make_controllers()
        te = TimeEstimates(ctrls)
        te._persist_db_estimate(
            str(finding.id),
            optimistic=1,
            likely=4,
            pessimistic=8,
            variant_id=str(variant.id),
        )
        results = TimeEstimate.get_by_finding(finding.id)
        assert len(results) >= 1
        assert results[0].optimistic == 1

    def test_persist_db_estimate_update(self, app, finding, variant):
        """Calling _persist_db_estimate twice with same ids should update."""
        from src.views.time_estimates import TimeEstimates
        from src.models.time_estimate import TimeEstimate
        ctrls = self._make_controllers()
        te = TimeEstimates(ctrls)
        te._persist_db_estimate(str(finding.id), 1, 4, 8, str(variant.id))
        te._persist_db_estimate(str(finding.id), 2, 6, 12, str(variant.id))
        results = TimeEstimate.get_by_finding(finding.id)
        assert results[0].optimistic == 2

    def test_load_from_dict_db_integer_format(self, app, finding):
        """load_from_dict should persist DB-format (int hours) tasks to the DB."""
        from src.views.time_estimates import TimeEstimates
        from src.models.time_estimate import TimeEstimate
        ctrls = self._make_controllers()
        te = TimeEstimates(ctrls)
        te.load_from_dict({
            "tasks": {
                str(finding.id): {
                    "optimistic": 2,
                    "likely": 5,
                    "pessimistic": 10,
                }
            }
        })
        results = TimeEstimate.get_by_finding(finding.id)
        assert len(results) >= 1
        assert results[0].likely == 5

    def test_load_from_dict_no_tasks_key(self, app):
        """load_from_dict should return early if 'tasks' key is absent."""
        from src.views.time_estimates import TimeEstimates
        ctrls = self._make_controllers()
        te = TimeEstimates(ctrls)
        te.load_from_dict({"version": 1})  # no tasks key, should not raise


# ===========================================================================
# merger_ci: merge CLI command
# ===========================================================================

class TestNewMergerCLI:
    def test_merge_command_creates_project_variant_scan(self, app, tmp_path):
        """The 'merge' CLI command should create project/variant/scan/sbom_doc entries."""
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan
        from src.models.sbom_document import SBOMDocument

        # Create a dummy SBOM file
        sbom = tmp_path / "test.spdx.json"
        sbom.write_text('{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"test"}')

        runner = app.test_cli_runner()
        result = runner.invoke(args=["merge", "--project", "CLIProject",
                                     "--variant", "CLIVariant", "--spdx", str(sbom)])
        assert result.exit_code == 0, result.output

        proj = Project.get_or_create("CLIProject")
        assert proj is not None
        variants = Variant.get_by_project(proj.id)
        assert len(variants) >= 1
        variant = variants[0]
        scans = Scan.get_by_variant_id(variant.id)
        assert len(scans) >= 1
        docs = SBOMDocument.get_by_scan(scans[0].id)
        assert len(docs) >= 1


# ===========================================================================
# routes/vulnerabilities: _parse_effort_hours coverage + batch effort errors
# ===========================================================================

class TestVulnRoutesEffort:
    """Tests that exercise previously uncovered route branches."""

    @pytest.fixture()
    def client(self, app):
        from src.models.vulnerability import Vulnerability
        from src.models.package import Package
        from src.models.finding import Finding
        # Mark scan as finished so the /api middleware does not block requests
        app._INT_SCAN_FINISHED = True
        with app.app_context():
            p = Package.find_or_create("routecov", "1.0")
            v = Vulnerability.create_record(
                id="CVE-2025-ROUTE", description="route coverage vuln", status="under_investigation"
            )
            Finding.create(p.id, v.id)
            _db.session.commit()
        return app.test_client()

    def test_patch_effort_with_integer_hours(self, client):
        """Sending integer hours should hit the _parse_effort_hours int branch (line 17)."""
        response = client.patch("/api/vulnerabilities/CVE-2025-ROUTE", json={
            "effort": {"optimistic": 1, "likely": 4, "pessimistic": 8}
        })
        assert response.status_code == 200

    def test_patch_effort_invalid_order(self, client):
        """optimistic > likely should return 400."""
        response = client.patch("/api/vulnerabilities/CVE-2025-ROUTE", json={
            "effort": {"optimistic": 10, "likely": 4, "pessimistic": 8}
        })
        assert response.status_code == 400

    def test_patch_effort_missing_key(self, client):
        """Effort dict missing a key should return 400."""
        response = client.patch("/api/vulnerabilities/CVE-2025-ROUTE", json={
            "effort": {"optimistic": 1, "likely": 4}
        })
        assert response.status_code == 400

    def test_patch_effort_invalid_type(self, client):
        """Non-iso, non-int effort value should return 400."""
        response = client.patch("/api/vulnerabilities/CVE-2025-ROUTE", json={
            "effort": {"optimistic": None, "likely": None, "pessimistic": None}
        })
        assert response.status_code == 400

    def test_batch_effort_missing_key(self, client):
        """Batch: effort dict missing a key should not crash and should report error."""
        response = client.patch("/api/vulnerabilities/batch", json={
            "vulnerabilities": [
                {"id": "CVE-2025-ROUTE", "effort": {"optimistic": 1, "likely": 2}}
            ]
        })
        import json as _json
        data = _json.loads(response.data)
        # Should report an error for this item
        assert "errors" in data

    def test_batch_effort_invalid_order(self, client):
        """Batch: opt > lik should append to errors."""
        response = client.patch("/api/vulnerabilities/batch", json={
            "vulnerabilities": [
                {"id": "CVE-2025-ROUTE", "effort": {"optimistic": 99, "likely": 2, "pessimistic": 3}}
            ]
        })
        import json as _json
        data = _json.loads(response.data)
        assert "errors" in data

    def test_batch_effort_invalid_type(self, client):
        """Batch: non-numeric effort should append to errors."""
        response = client.patch("/api/vulnerabilities/batch", json={
            "vulnerabilities": [
                {"id": "CVE-2025-ROUTE", "effort": {"optimistic": None, "likely": None, "pessimistic": None}}
            ]
        })
        import json as _json
        data = _json.loads(response.data)
        assert "errors" in data

    def test_batch_vuln_not_found(self, client):
        """Batch: unknown CVE id should append to errors."""
        response = client.patch("/api/vulnerabilities/batch", json={
            "vulnerabilities": [{"id": "CVE-9999-NOTEXIST"}]
        })
        import json as _json
        data = _json.loads(response.data)
        assert "errors" in data

    def test_batch_invalid_item_format(self, client):
        """Batch: item without 'id' should be reported as error."""
        response = client.patch("/api/vulnerabilities/batch", json={
            "vulnerabilities": [{"cvss": {}}]
        })
        import json as _json
        data = _json.loads(response.data)
        assert "errors" in data

    def test_batch_incomplete_cvss(self, client):
        """Batch: incomplete CVSS data should append to errors."""
        response = client.patch("/api/vulnerabilities/batch", json={
            "vulnerabilities": [
                {"id": "CVE-2025-ROUTE", "cvss": {"base_score": 8.0}}
            ]
        })
        import json as _json
        data = _json.loads(response.data)
        assert "errors" in data

    def test_get_nvd_progress(self, client, tmp_path, monkeypatch):
        """GET /api/nvd/progress should return 200 with progress data."""
        monkeypatch.setenv("NVD_DB_PATH", str(tmp_path / "nvd.db"))
        response = client.get("/api/nvd/progress")
        assert response.status_code == 200
        import json as _json
        data = _json.loads(response.data)
        assert "in_progress" in data

    def test_patch_effort_update_existing_time_estimate(self, client):
        """Sending effort when the finding already has a TimeEstimate hits the
        existing.update() path (line 66) instead of creating a new one."""
        import json as _json
        # First PATCH creates a TimeEstimate
        r1 = client.patch("/api/vulnerabilities/CVE-2025-ROUTE", json={
            "effort": {"optimistic": 1, "likely": 2, "pessimistic": 4}
        })
        assert r1.status_code == 200
        # Second PATCH should update the existing one (line 66)
        r2 = client.patch("/api/vulnerabilities/CVE-2025-ROUTE", json={
            "effort": {"optimistic": 2, "likely": 3, "pessimistic": 6}
        })
        assert r2.status_code == 200

    def test_batch_effort_update_existing_time_estimate(self, client):
        """Batch: sending effort when a TimeEstimate already exists hits line 127."""
        import json as _json
        # First create a TimeEstimate via single endpoint
        client.patch("/api/vulnerabilities/CVE-2025-ROUTE", json={
            "effort": {"optimistic": 1, "likely": 2, "pessimistic": 4}
        })
        # Second batch PATCH should update existing (line 127)
        r = client.patch("/api/vulnerabilities/batch", json={
            "vulnerabilities": [
                {"id": "CVE-2025-ROUTE", "effort": {"optimistic": 2, "likely": 3, "pessimistic": 6}}
            ]
        })
        assert r.status_code == 200

    def test_patch_cvss_metrics_exception(self, client):
        """PATCH /api/vulnerabilities/<id> with valid CVSS dict where Metrics.from_cvss
        raises covers the except block (lines 81-82)."""
        from unittest.mock import patch as mock_patch
        with mock_patch("src.routes.vulnerabilities.Metrics.from_cvss", side_effect=RuntimeError("db fail")):
            r = client.patch("/api/vulnerabilities/CVE-2025-ROUTE", json={
                "cvss": {
                    "base_score": 7.5,
                    "vector_string": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "version": "3.1",
                    "exploitability_score": 3.9,
                    "impact_score": 3.6,
                    "author": "NVD",
                }
            })
        # Should still return the vuln dict (exception is swallowed)
        assert r.status_code == 200

    def test_batch_cvss_metrics_exception(self, client):
        """Batch: valid CVSS but Metrics.from_cvss raises covers lines 143-144."""
        from unittest.mock import patch as mock_patch
        with mock_patch("src.routes.vulnerabilities.Metrics.from_cvss", side_effect=RuntimeError("db fail")):
            r = client.patch("/api/vulnerabilities/batch", json={
                "vulnerabilities": [{
                    "id": "CVE-2025-ROUTE",
                    "cvss": {
                        "base_score": 7.5,
                        "vector_string": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "version": "3.1",
                        "exploitability_score": 3.9,
                        "impact_score": 3.6,
                        "author": "NVD",
                    }
                }]
            })
        import json as _json
        data = _json.loads(r.data)
        assert "vulnerabilities" in data

    def test_patch_effort_with_valid_variant_id(self, client, app):
        """A valid UUID variant_id should be accepted and produce a 200 response."""
        from src.models.project import Project
        from src.models.variant import Variant
        with app.app_context():
            proj = Project.create("EffortProject")
            var = Variant.create("EffortVariant", proj.id)
            vid = str(var.id)
        response = client.patch("/api/vulnerabilities/CVE-2025-ROUTE", json={
            "effort": {"optimistic": 1, "likely": 4, "pessimistic": 8},
            "variant_id": vid,
        })
        assert response.status_code == 200

    def test_patch_effort_with_invalid_variant_id(self, client):
        """An unparseable variant_id string should return 400."""
        response = client.patch("/api/vulnerabilities/CVE-2025-ROUTE", json={
            "effort": {"optimistic": 1, "likely": 4, "pessimistic": 8},
            "variant_id": "not-a-valid-uuid",
        })
        assert response.status_code == 400

    def test_batch_effort_with_invalid_variant_id(self, client):
        """Batch: an invalid variant_id should append an error for that item."""
        import json as _json
        response = client.patch("/api/vulnerabilities/batch", json={
            "vulnerabilities": [{
                "id": "CVE-2025-ROUTE",
                "effort": {"optimistic": 1, "likely": 4, "pessimistic": 8},
                "variant_id": "not-a-valid-uuid",
            }]
        })
        data = _json.loads(response.data)
        assert "errors" in data
        assert any(e.get("id") == "CVE-2025-ROUTE" for e in data["errors"])

    def test_batch_effort_with_valid_variant_id(self, client, app):
        """Batch: a valid UUID variant_id is accepted and the item appears in results."""
        import json as _json
        from src.models.project import Project
        from src.models.variant import Variant
        with app.app_context():
            proj = Project.create("BatchEffortProject")
            var = Variant.create("BatchEffortVariant", proj.id)
            vid = str(var.id)
        response = client.patch("/api/vulnerabilities/batch", json={
            "vulnerabilities": [{
                "id": "CVE-2025-ROUTE",
                "effort": {"optimistic": 1, "likely": 4, "pessimistic": 8},
                "variant_id": vid,
            }]
        })
        assert response.status_code == 200
        data = _json.loads(response.data)
        assert "vulnerabilities" in data
        assert any(v["id"] == "CVE-2025-ROUTE" for v in data["vulnerabilities"])


# ===========================================================================
# PackagesController — coverage gaps
# ===========================================================================

class TestPackagesController:
    """Cover PackagesController branches not yet tested."""

    def test_from_dict_populates_controller(self, app):
        """from_dict() with valid data creates packages (lines 213-215)."""
        from src.controllers.packages import PackagesController
        data = {
            "libfoo@1.0": {"name": "libfoo", "version": "1.0", "cpe": [], "purl": [], "licences": ""},
            "libbar@2.0": {"name": "libbar", "version": "2.0"},
        }
        ctrl = PackagesController.from_dict(data)
        assert isinstance(ctrl, PackagesController)

    def test_contains_non_package_type_returns_false(self, app):
        """__contains__ with non-str/non-Package returns False (lines 228-229)."""
        from src.controllers.packages import PackagesController
        ctrl = PackagesController()
        assert (42 in ctrl) is False
        assert (None in ctrl) is False

    def test_remove_pkg_in_db(self, app):
        """remove() when the package exists in the DB triggers db_pkg.delete() (line 155)."""
        from src.controllers.packages import PackagesController
        from src.models.package import Package
        pkg = Package.create("remove-me", "1.0.0")
        ctrl = PackagesController()
        removed = ctrl.remove(pkg.string_id)
        assert removed is True

    def test_to_dict_db_fallback(self, app):
        """to_dict() when cache is empty queries the DB (lines 200-202)."""
        from src.controllers.packages import PackagesController
        from src.models.package import Package
        Package.create("pkgfallback", "3.0")
        ctrl = PackagesController()
        result = ctrl.to_dict()
        assert isinstance(result, dict)
        assert "pkgfallback@3.0" in result

    def test_preload_cache_exception_packages(self, app):
        """_preload_cache silently catches Package.get_all() exceptions (lines 48-49)."""
        from src.controllers.packages import PackagesController
        from unittest.mock import patch as mock_patch
        ctrl = PackagesController()
        with mock_patch("src.controllers.packages.Package.get_all", side_effect=RuntimeError("db down")):
            ctrl._preload_cache()  # should not raise
        assert ctrl._cache == {}

    def test_preload_cache_exception_findings(self, app):
        """_preload_cache silently catches Finding.get_all() exceptions (lines 54-55)."""
        from src.controllers.packages import PackagesController
        from unittest.mock import patch as mock_patch
        ctrl = PackagesController()
        with mock_patch("src.controllers.packages.Package.get_all", return_value=[]):
            with mock_patch("src.models.finding.Finding.get_all", side_effect=RuntimeError("db down")):
                ctrl._preload_cache()  # should not raise

    def test_get_populates_cache(self, app):
        """get() stores the result in _cache when found in DB (line 155)."""
        from src.controllers.packages import PackagesController
        from src.models.package import Package
        pkg = Package.create("getcache-test", "1.0")
        ctrl = PackagesController()
        result = ctrl.get(pkg.string_id)
        assert result is not None
        assert pkg.string_id in ctrl._cache

    def test_to_dict_db_exception(self, app):
        """to_dict() returns {} when DB raises (lines 171-173)."""
        from unittest.mock import patch as mock_patch
        from src.controllers.packages import PackagesController
        ctrl = PackagesController()
        with mock_patch("src.controllers.packages.Package.get_all", side_effect=RuntimeError("db fail")):
            result = ctrl.to_dict()
        assert result == {}

    def test_contains_db_exception(self, app):
        """__contains__ returns False when DB raises (lines 200-202)."""
        from unittest.mock import patch as mock_patch
        from src.controllers.packages import PackagesController
        ctrl = PackagesController()
        with mock_patch("src.controllers.packages.Package.get_by_string_id", side_effect=RuntimeError("db fail")):
            result = "nopkg@1.0" in ctrl
        assert result is False

    def test_len_db_exception(self, app):
        """__len__ returns 0 when DB raises (lines 213-215)."""
        from unittest.mock import patch as mock_patch
        from src.controllers.packages import PackagesController
        ctrl = PackagesController()
        with mock_patch("src.extensions.db.session") as mock_session:
            mock_session.query.side_effect = RuntimeError("fail")
            result = len(ctrl)
        assert result == 0

    def test_iter_db_exception(self, app):
        """__iter__ swallows DB exception (lines 228-229)."""
        from unittest.mock import patch as mock_patch
        from src.controllers.packages import PackagesController
        ctrl = PackagesController()
        with mock_patch("src.controllers.packages.Package.get_all", side_effect=RuntimeError("fail")):
            result = list(ctrl)
        assert result == []


# ===========================================================================
# AssessmentsController — coverage gaps
# ===========================================================================

class TestAssessmentsController:
    """Cover AssessmentsController branches not yet tested."""

    def test_remove_none_returns_false(self, app):
        """remove(None) should return False immediately (line 216)."""
        from src.controllers.packages import PackagesController
        from src.controllers.assessments import AssessmentsController
        from unittest.mock import MagicMock
        ctrl = AssessmentsController(PackagesController(), MagicMock())
        assert ctrl.remove(None) is False

    def test_remove_existing_assessment(self, app):
        """remove() on an assessment that is in the in-memory dict succeeds (lines 235-236)."""
        from src.controllers.packages import PackagesController
        from src.controllers.assessments import AssessmentsController
        from src.models.assessment import Assessment
        from unittest.mock import MagicMock
        ctrl = AssessmentsController(PackagesController(), MagicMock())
        a = Assessment.new_dto("CVE-2099-REM", ["pkg@1.0"])
        ctrl.add(a)
        removed = ctrl.remove(str(a.id))
        assert removed is True
        assert str(a.id) not in ctrl.assessments

    def test_contains_str(self, app):
        """__contains__ with a string key covers line 261."""
        from src.controllers.packages import PackagesController
        from src.controllers.assessments import AssessmentsController
        from unittest.mock import MagicMock
        ctrl = AssessmentsController(PackagesController(), MagicMock())
        assert ("nonexistent-uuid" in ctrl) is False

    def test_gets_by_pkg_db_path(self, app):
        """gets_by_pkg queries the DB when no in-memory match (lines 127-132 in assessments)."""
        from src.controllers.packages import PackagesController
        from src.controllers.assessments import AssessmentsController
        from unittest.mock import MagicMock
        ctrl = AssessmentsController(PackagesController(), MagicMock())
        result = ctrl.gets_by_pkg("pkg@1.0")
        assert isinstance(result, list)

    def test_gets_by_vuln_pkg_with_db_finding(self, app):
        """gets_by_vuln_pkg hits the DB finding+assessment path (lines 157-160)."""
        from src.models.vulnerability import Vulnerability
        from src.models.package import Package
        from src.models.finding import Finding
        from src.models.assessment import Assessment as DBAssessment
        from src.controllers.packages import PackagesController
        from src.controllers.assessments import AssessmentsController
        from unittest.mock import MagicMock

        v = Vulnerability.create_record("CVE-2099-VPAIR")
        p = Package.create("vpair-lib", "1.0")
        f = Finding.create(p.id, v.id)
        # Create a persisted assessment linked to the finding
        DBAssessment.create(status="affected", finding_id=f.id)

        ctrl = AssessmentsController(PackagesController(), MagicMock())
        result = ctrl.gets_by_vuln_pkg(v.id, p.string_id)
        assert len(result) >= 1

    def test_gets_by_pkg_db_hit_adds_to_results(self, app):
        """gets_by_pkg() DB path adds assessments to results (line 129 in assessments controller)."""
        from src.models.vulnerability import Vulnerability
        from src.models.package import Package
        from src.models.finding import Finding
        from src.models.assessment import Assessment as DBAssessment
        from src.controllers.packages import PackagesController
        from src.controllers.assessments import AssessmentsController
        from unittest.mock import MagicMock

        v = Vulnerability.create_record("CVE-2099-PKG2")
        p = Package.create("pkgctl2-test", "1.0")
        f = Finding.create(p.id, v.id)
        DBAssessment.create(status="affected", finding_id=f.id)

        ctrl = AssessmentsController(PackagesController(), MagicMock())
        result = ctrl.gets_by_pkg(p.string_id)
        assert len(result) >= 1

    def test_to_dict_db_fallback(self, app):
        """to_dict() falls back to DB when in-memory dict is empty."""
        from src.models.vulnerability import Vulnerability
        from src.models.package import Package
        from src.models.finding import Finding
        from src.models.assessment import Assessment as DBAssessment
        from src.controllers.packages import PackagesController
        from src.controllers.assessments import AssessmentsController
        from unittest.mock import MagicMock

        v = Vulnerability.create_record("CVE-2099-TODICT2")
        p = Package.create("todictpkg", "1.0")
        f = Finding.create(p.id, v.id)
        DBAssessment.create(status="not_affected", finding_id=f.id)

        ctrl = AssessmentsController(PackagesController(), MagicMock())
        # ctrl.assessments is empty (not pre-loaded from DB), so to_dict queries DB
        result = ctrl.to_dict()
        assert isinstance(result, dict)
        assert len(result) >= 1

    def test_to_dict_db_exception(self, app):
        """to_dict() returns {} when DB raises (lines 246-248)."""
        from unittest.mock import patch as mock_patch, MagicMock
        from src.controllers.packages import PackagesController
        from src.controllers.assessments import AssessmentsController

        ctrl = AssessmentsController(PackagesController(), MagicMock())
        with mock_patch("src.models.assessment.Assessment.get_all", side_effect=RuntimeError("fail")):
            result = ctrl.to_dict()
        assert result == {}

    def test_remove_byVuln_valueerror(self, app):
        """remove() recovers from ValueError when key not in _by_vuln list (lines 226-227)."""
        from src.controllers.packages import PackagesController
        from src.controllers.assessments import AssessmentsController
        from src.models.assessment import Assessment
        from unittest.mock import MagicMock

        ctrl = AssessmentsController(PackagesController(), MagicMock())
        a = Assessment.new_dto("CVE-2099-VUERR", ["pkg@1.0"])
        ctrl.add(a)
        key = str(a.id)
        # Manually empty the _by_vuln list to trigger ValueError in remove()
        ctrl._by_vuln["CVE-2099-VUERR"].clear()
        removed = ctrl.remove(key)
        assert removed is True

    def test_remove_byVulnPkg_valueerror(self, app):
        """remove() recovers from ValueError when key not in _by_vuln_pkg list (lines 233-234)."""
        from src.controllers.packages import PackagesController
        from src.controllers.assessments import AssessmentsController
        from src.models.assessment import Assessment
        from unittest.mock import MagicMock

        ctrl = AssessmentsController(PackagesController(), MagicMock())
        a = Assessment.new_dto("CVE-2099-VPERR", ["pkg@1.0"])
        ctrl.add(a)
        key = str(a.id)
        # Manually empty the _by_vuln_pkg list to trigger ValueError in remove()
        ctrl._by_vuln_pkg[("CVE-2099-VPERR", "pkg@1.0")].clear()
        removed = ctrl.remove(key)
        assert removed is True


# ===========================================================================
# VulnerabilitiesController — coverage gaps
# ===========================================================================

class TestVulnerabilitiesController:
    """Cover VulnerabilitiesController branches not yet tested."""

    def test_iter_db_fallback(self, app, monkeypatch):
        """__iter__ with empty in-memory dict queries the DB (lines 405-407)."""
        from unittest.mock import MagicMock
        from src.controllers.packages import PackagesController
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.models.vulnerability import Vulnerability

        monkeypatch.setattr("src.controllers.vulnerabilities.EPSS_DB", lambda: MagicMock())
        pkgctrl = PackagesController()
        ctrl = VulnerabilitiesController(pkgctrl)
        # Create the vuln AFTER init so it is not in the in-memory dict
        Vulnerability.create_record("CVE-2099-ITER")
        ctrl.vulnerabilities.clear()  # ensure cache is empty to force DB path
        results = list(ctrl)
        assert any(v.id == "CVE-2099-ITER" for v in results)

    def test_to_dict_db_fallback(self, app, monkeypatch):
        """to_dict() with empty in-memory dict queries the DB (lines 345-349)."""
        from unittest.mock import MagicMock
        from src.controllers.packages import PackagesController
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.models.vulnerability import Vulnerability

        monkeypatch.setattr("src.controllers.vulnerabilities.EPSS_DB", lambda: MagicMock())
        pkgctrl = PackagesController()
        ctrl = VulnerabilitiesController(pkgctrl)
        # Create the vuln AFTER init then clear memory so to_dict uses the DB
        Vulnerability.create_record("CVE-2099-TODICT")
        ctrl.vulnerabilities.clear()
        result = ctrl.to_dict()
        assert isinstance(result, dict)
        assert "CVE-2099-TODICT" in result

    def test_fetch_epss_scores_hit(self, app, monkeypatch):
        """fetch_epss_scores calls api_get_epss_batch, sets the in-memory score and persists to DB."""
        from src.controllers.packages import PackagesController
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.models.vulnerability import Vulnerability
        from unittest.mock import MagicMock

        monkeypatch.setattr("src.controllers.vulnerabilities.EPSS_DB", lambda: MagicMock())
        # Create the record in DB so the persist path is exercised
        Vulnerability.create_record("CVE-2099-EPSS")
        pkgctrl = PackagesController()
        ctrl = VulnerabilitiesController(pkgctrl)
        ctrl.epss_api = MagicMock()
        ctrl.epss_api.api_get_epss_batch.return_value = {
            "CVE-2099-EPSS": {"score": 0.05, "percentile": 50.0}
        }
        ctrl.fetch_epss_scores()
        # In-memory update
        assert ctrl.vulnerabilities["CVE-2099-EPSS"].epss["score"] == 0.05
        # DB update
        rec = Vulnerability.get_by_id("CVE-2099-EPSS")
        assert rec is not None
        assert float(rec.epss_score) == 0.05

    def test_fetch_epss_scores_persists_to_db(self, app, monkeypatch):
        """fetch_epss_scores writes the EPSS score to the database."""
        from src.controllers.packages import PackagesController
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.models.vulnerability import Vulnerability
        from unittest.mock import MagicMock

        Vulnerability.create_record("CVE-2099-EPSS-DB")
        pkgctrl = PackagesController()
        ctrl = VulnerabilitiesController(pkgctrl)
        ctrl.epss_api = MagicMock()
        ctrl.epss_api.api_get_epss_batch.return_value = {
            "CVE-2099-EPSS-DB": {"score": 0.42, "percentile": 95.0}
        }
        ctrl.fetch_epss_scores()
        rec = Vulnerability.get_by_id("CVE-2099-EPSS-DB")
        assert rec is not None
        assert float(rec.epss_score) == pytest.approx(0.42)

    def test_fetch_ghsa_published_success(self):
        """_fetch_ghsa_published returns the published_at value on success (lines 279-280)."""
        import json
        from unittest.mock import patch as mock_patch, MagicMock
        from src.controllers.vulnerabilities import VulnerabilitiesController

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"published_at": "2024-03-01T00:00:00Z"}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with mock_patch("urllib.request.urlopen", return_value=mock_resp):
            result = VulnerabilitiesController._fetch_ghsa_published("GHSA-xxxx-xxxx-xxxx")
        assert result == "2024-03-01T00:00:00Z"

    def test_fetch_ghsa_published_http_error(self):
        """_fetch_ghsa_published returns None on HTTPError (line 283)."""
        import urllib.error
        from unittest.mock import patch as mock_patch
        from src.controllers.vulnerabilities import VulnerabilitiesController

        err = urllib.error.HTTPError("url", 404, "Not Found", {}, None)
        with mock_patch("urllib.request.urlopen", side_effect=err):
            result = VulnerabilitiesController._fetch_ghsa_published("GHSA-xxxx")
        assert result is None

    def test_fetch_ghsa_published_url_error(self):
        """_fetch_ghsa_published returns None on URLError (line 285)."""
        import urllib.error
        from unittest.mock import patch as mock_patch
        from src.controllers.vulnerabilities import VulnerabilitiesController

        err = urllib.error.URLError("timeout")
        with mock_patch("urllib.request.urlopen", side_effect=err):
            result = VulnerabilitiesController._fetch_ghsa_published("GHSA-xxxx")
        assert result is None

    def test_fetch_ghsa_published_generic_error(self):
        """_fetch_ghsa_published returns None on generic Exception (line 286)."""
        from unittest.mock import patch as mock_patch
        from src.controllers.vulnerabilities import VulnerabilitiesController

        with mock_patch("urllib.request.urlopen", side_effect=OSError("socket")):
            result = VulnerabilitiesController._fetch_ghsa_published("GHSA-xxxx")
        assert result is None

    def test_fetch_nvd_data_ghsa(self, app, monkeypatch):
        """fetch_nvd_data processes a GHSA vuln and sets its published date."""
        import json
        from unittest.mock import patch as mock_patch, MagicMock
        from src.controllers.packages import PackagesController
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.models.vulnerability import Vulnerability

        monkeypatch.setattr("src.controllers.vulnerabilities.EPSS_DB", lambda: MagicMock())
        v = Vulnerability("GHSA-xxxx-test-0001", [], "", "github")
        pkgctrl = PackagesController()
        ctrl = VulnerabilitiesController(pkgctrl)
        ctrl.vulnerabilities["GHSA-xxxx-test-0001"] = v

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"published_at": "2024-06-01T00:00:00Z"}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with mock_patch("urllib.request.urlopen", return_value=mock_resp):
            ctrl.fetch_nvd_data()
        assert v.published == "2024-06-01T00:00:00Z"

    def test_get_vuln_db_fallback(self, app, monkeypatch):
        """get() falls back to the DB when vuln not in memory (lines 153-155)."""
        from unittest.mock import MagicMock
        from src.controllers.packages import PackagesController
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.models.vulnerability import Vulnerability

        monkeypatch.setattr("src.controllers.vulnerabilities.EPSS_DB", lambda: MagicMock())
        pkgctrl = PackagesController()
        ctrl = VulnerabilitiesController(pkgctrl)
        # Create the record AFTER init so _preload_cache did not pre-fill it
        Vulnerability.create_record("CVE-2099-DBGET")
        result = ctrl.get("CVE-2099-DBGET")
        assert result is not None
        assert result.id == "CVE-2099-DBGET"

    def test_published_populated_from_db_date(self, app):
        """Vulnerability loaded from DB with publish_date set exposes it via .published and to_dict()."""
        import datetime
        from src.models.vulnerability import Vulnerability

        rec = Vulnerability.create_record("CVE-2099-PUBDATE")
        rec.update_record(publish_date=datetime.date(2024, 3, 15))

        # Re-load from DB — simulates a fresh _preload_cache() after NVD enrichment
        fresh = Vulnerability.get_by_id("CVE-2099-PUBDATE")
        assert fresh is not None
        assert fresh.published == "2024-03-15", (
            "published transient should be initialised from publish_date on DB load"
        )
        assert fresh.to_dict()["published"] == "2024-03-15"


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
    application = create_app()
    application.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SCAN_FILE": "/dev/null",
    })
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


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
            workaround_timestamp="2025-01-01T00:00:00Z",
            responses=["patched"],
            last_update="2025-03-01T00:00:00Z",
        )
        assert a.source == "grype"
        assert a.workaround == "upgrade to 2.0"
        assert a.workaround_timestamp == "2025-01-01T00:00:00Z"
        assert a.last_update == "2025-03-01T00:00:00Z"


# ===========================================================================
# TimeEstimates: DB integer format + _iso_to_hours
# ===========================================================================

class TestTimeEstimatesDB:
    def _make_controllers(self):
        from src.controllers.packages import PackagesController
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.assessments import AssessmentsController
        pkg = PackagesController()
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
                                     "--variant", "CLIVariant", str(sbom)])
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

    def test_get_nvd_progress(self, client):
        """GET /api/nvd/progress should return 200 with progress data."""
        response = client.get("/api/nvd/progress")
        assert response.status_code == 200
        import json as _json
        data = _json.loads(response.data)
        assert "in_progress" in data

# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Integration tests for the 'Outdated' assessment flag.

Scenario: a custom assessment is written against firefox@1.0.  A new SBOM
scan then introduces firefox@2.0, which is also affected by the same CVE.
The old assessment should be flagged as outdated.
"""

import json
import os
import uuid
from datetime import datetime, timezone

import pytest

from src.bin.webapp import create_app
from src.extensions import db as _db
from src.models.assessment import Assessment
from src.models.finding import Finding
from src.models.metrics import Metrics
from src.models.observation import Observation
from src.models.package import Package
from src.models.project import Project
from src.models.sbom_document import SBOMDocument
from src.models.sbom_observation import SBOMObservation
from src.models.sbom_package import SBOMPackage
from src.models.scan import Scan
from src.models.time_estimate import TimeEstimate
from src.models.variant import Variant
from src.models.vulnerability import Vulnerability


# ------------------------------------------------------------------
# Shared UUIDs
# ------------------------------------------------------------------
PROJECT_ID = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
VARIANT_ID = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
SCAN_V1_ID = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
SCAN_V2_ID = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
TOOL_SCAN_V2_ID = uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")
CVE_ID = "CVE-2024-99999"


def _build_outdated_db(app, *, include_v2_finding: bool = True, include_v2_in_active: bool = True,
                       include_unchanged_second_pkg: bool = False):
    """Populate in-memory DB for outdated-assessment tests.

    ``include_v2_finding``  – when False the v2 package has no Finding, so
                               condition 4 fails (should NOT be outdated).
    ``include_v2_in_active``– when False scan_v2 is absent (package removed
                               entirely), so condition 2 fails.
    ``include_unchanged_second_pkg`` – when True, chrome@1.0 is added to both
                               the old and the active SBOM scan (i.e. it stays
                               current across the version bump).  Used to test
                               a multi-package assessment where only firefox is
                               superseded.
    """
    with app.app_context():
        _db.drop_all()
        _db.create_all()

        # --- Project / Variant ---
        project = Project(id=PROJECT_ID, name="test")
        _db.session.add(project)
        variant = Variant(id=VARIANT_ID, name="default", project_id=PROJECT_ID)
        _db.session.add(variant)

        # --- Vulnerability ---
        Vulnerability.create_record(id=CVE_ID, description="Test vuln", status="high")
        _db.session.commit()

        # --- Packages ---
        pkg_v1 = Package.find_or_create("firefox", "1.0", [], [], "")
        pkg_v2 = Package.find_or_create("firefox", "2.0", [], [], "")
        pkg_chrome = None
        if include_unchanged_second_pkg:
            pkg_chrome = Package.find_or_create("chrome", "1.0", [], [], "")
        _db.session.commit()

        # --- Findings ---
        finding_v1 = Finding.get_or_create(pkg_v1.id, CVE_ID)
        if pkg_chrome is not None:
            Finding.get_or_create(pkg_chrome.id, CVE_ID)
        _db.session.commit()

        finding_v2 = None
        if include_v2_finding:
            finding_v2 = Finding.get_or_create(pkg_v2.id, CVE_ID)
            _db.session.commit()

        # --- Scan v1 (older SBOM, firefox@1.0) ---
        scan_v1 = Scan(
            id=SCAN_V1_ID,
            variant_id=VARIANT_ID,
            scan_type="sbom",
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        _db.session.add(scan_v1)
        sbom_v1 = SBOMDocument(
            id=uuid.UUID("e1111111-1111-1111-1111-111111111111"),
            path="/scan/v1.spdx.json",
            source_name="v1.spdx.json",
            format="spdx",
            scan_id=SCAN_V1_ID,
        )
        _db.session.add(sbom_v1)
        _db.session.add(SBOMPackage(sbom_document_id=sbom_v1.id, package_id=pkg_v1.id))
        if pkg_chrome is not None:
            _db.session.add(SBOMPackage(sbom_document_id=sbom_v1.id, package_id=pkg_chrome.id))
        _db.session.add(Observation(finding_id=finding_v1.id, scan_id=SCAN_V1_ID))
        _db.session.commit()

        # --- Custom assessment on firefox@1.0 ---
        assess_id = uuid.UUID("f1111111-1111-1111-1111-111111111111")
        assessment = Assessment(
            id=assess_id,
            status="not_affected",
            simplified_status="Not affected",
            origin="custom",
            source="analyst",
            status_notes="No network access on this build",
            justification="vulnerable_code_not_in_execute_path",
            impact_statement="",
            responses=[],
            workaround="",
            finding_id=finding_v1.id,
            variant_id=VARIANT_ID,
            timestamp=datetime(2024, 1, 2, tzinfo=timezone.utc),
        )
        _db.session.add(assessment)
        _db.session.commit()

        if include_v2_in_active:
            # --- Scan v2 (newer SBOM, firefox@2.0) — this is the active scan ---
            scan_v2 = Scan(
                id=SCAN_V2_ID,
                variant_id=VARIANT_ID,
                scan_type="sbom",
                timestamp=datetime(2024, 6, 1, tzinfo=timezone.utc),
            )
            _db.session.add(scan_v2)
            sbom_v2 = SBOMDocument(
                id=uuid.UUID("e2222222-2222-2222-2222-222222222222"),
                path="/scan/v2.spdx.json",
                source_name="v2.spdx.json",
                format="spdx",
                scan_id=SCAN_V2_ID,
            )
            _db.session.add(sbom_v2)
            _db.session.add(SBOMPackage(sbom_document_id=sbom_v2.id, package_id=pkg_v2.id))
            if pkg_chrome is not None:
                _db.session.add(SBOMPackage(sbom_document_id=sbom_v2.id, package_id=pkg_chrome.id))
            if include_v2_finding and finding_v2 is not None:
                # A CVE finding for the new package version is observed in a
                # *tool* scan (nvd/osv/grype/scc), NOT the SBOM scan — this
                # mirrors the real ingestion pipeline.  The staleness helper
                # must look at the full active set (SBOM + tool scans) to see
                # it, so observing it here in a tool scan is the realistic case.
                tool_scan_v2 = Scan(
                    id=TOOL_SCAN_V2_ID,
                    variant_id=VARIANT_ID,
                    scan_type="tool",
                    scan_source="nvd",
                    timestamp=datetime(2024, 6, 2, tzinfo=timezone.utc),
                )
                _db.session.add(tool_scan_v2)
                _db.session.add(Observation(finding_id=finding_v2.id, scan_id=TOOL_SCAN_V2_ID))
            _db.session.commit()

        return assess_id


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture()
def _status_file(tmp_path):
    """Create a scan-status file that satisfies the scan-finished middleware."""
    f = tmp_path / "status.txt"
    f.write_text("__END_OF_SCAN_SCRIPT__")
    return f


@pytest.fixture()
def app_factory(_status_file):
    """Return a factory that creates a fresh test Flask app."""
    def _make():
        os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": _status_file,
        })
        return application
    yield _make
    os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

class TestOutdatedFlag:
    """Main scenario: assessment becomes outdated after version bump."""

    @pytest.fixture(autouse=True)
    def setup(self, app_factory):
        self.app = app_factory()
        self.assess_id = _build_outdated_db(self.app)
        self.client = self.app.test_client()

    def _delete_outdated_data(self):
        preview = self.client.get("/api/outdated-data")
        assert preview.status_code == 200
        return self.client.delete(
            "/api/outdated-data", json={"candidate_ids": json.loads(preview.data)["candidate_ids"]}
        )

    def _delete_empty_scans(self):
        preview = self.client.get("/api/empty-scans")
        assert preview.status_code == 200
        return self.client.delete(
            "/api/empty-scans",
            json={"scan_ids": [scan["id"] for scan in json.loads(preview.data)["scans"]]},
        )

    def _delete_orphaned_vulnerabilities(self):
        preview = self.client.get("/api/orphaned-vulnerabilities")
        assert preview.status_code == 200
        return self.client.delete(
            "/api/orphaned-vulnerabilities",
            json={"vulnerability_ids": [item["id"] for item in json.loads(preview.data)["vulnerabilities"]]},
        )

    def test_index_assess_variant_returns_outdated(self):
        """GET /api/assessments?variant_id=... marks the outdated assessment."""
        resp = self.client.get(f"/api/assessments?variant_id={VARIANT_ID}")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        custom = [a for a in data if a.get("origin") == "custom"]
        assert len(custom) == 1
        assert custom[0]["outdated"] is True
        assert custom[0]["superseded_by"] == ["firefox@2.0"]

    def test_index_assess_variant_reports_stale_package(self):
        """The response identifies the specific stale package and its replacement."""
        resp = self.client.get(f"/api/assessments?variant_id={VARIANT_ID}")
        data = json.loads(resp.data)
        custom = [a for a in data if a.get("origin") == "custom"]
        assert custom[0]["stale_packages"] == ["firefox@1.0"]
        assert custom[0]["superseded_map"] == {"firefox@1.0": ["firefox@2.0"]}

    def test_list_assess_by_vuln_returns_outdated(self):
        """GET /api/vulnerabilities/<id>/assessments marks the outdated assessment."""
        resp = self.client.get(f"/api/vulnerabilities/{CVE_ID}/assessments")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        custom = [a for a in data if a.get("origin") == "custom"]
        assert len(custom) == 1
        assert custom[0]["outdated"] is True
        assert custom[0]["superseded_by"] == ["firefox@2.0"]

    def test_list_assess_by_vuln_scopes_to_project(self):
        """Project-scoped history includes all of its variants, not other projects."""
        other_project_id = uuid.UUID("99999999-9999-9999-9999-999999999999")
        other_variant_id = uuid.UUID("88888888-8888-8888-8888-888888888888")
        other_assessment_id = uuid.UUID("77777777-7777-7777-7777-777777777777")
        with self.app.app_context():
            other_project = Project(id=other_project_id, name="other")
            other_variant = Variant(id=other_variant_id, name="other", project_id=other_project_id)
            finding = Finding.get_by_vulnerability(CVE_ID)[0]
            other_assessment = Assessment(
                id=other_assessment_id,
                status="affected",
                simplified_status="Exploitable",
                origin="custom",
                source="analyst",
                status_notes="",
                justification="",
                impact_statement="",
                responses=[],
                workaround="",
                finding_id=finding.id,
                variant_id=other_variant_id,
                timestamp=datetime(2024, 1, 3, tzinfo=timezone.utc),
            )
            _db.session.add_all([other_project, other_variant, other_assessment])
            _db.session.commit()

        resp = self.client.get(f"/api/vulnerabilities/{CVE_ID}/assessments?project_id={PROJECT_ID}")
        assert resp.status_code == 200
        assessment_ids = {item["id"] for item in json.loads(resp.data)}
        assert str(self.assess_id) in assessment_ids
        assert str(other_assessment_id) not in assessment_ids

    def test_outdated_flag_always_present(self):
        """Every assessment dict returned has the 'outdated' key."""
        resp = self.client.get(f"/api/assessments?variant_id={VARIANT_ID}")
        data = json.loads(resp.data)
        for item in data:
            assert "outdated" in item, f"Missing 'outdated' key in {item!r}"
            assert "superseded_by" in item
            assert "stale_packages" in item
            assert "superseded_map" in item

    def test_delete_outdated_data_removes_only_stale_records(self):
        """The cleanup endpoint removes the flagged package and assessment."""
        response = self._delete_outdated_data()

        assert response.status_code == 200
        summary = json.loads(response.data)
        assert summary["assessments_deleted"] == 1
        assert summary["observations_deleted"] == 1
        assert summary["findings_deleted"] == 1
        assert summary["vulnerabilities_deleted"] == 0
        assert summary["packages_deleted"] == 1

        with self.app.app_context():
            assert Package.get_by_string_id("firefox@1.0") is None
            assert Package.get_by_string_id("firefox@2.0") is not None
            assert _db.session.get(Assessment, self.assess_id) is None
            assert Vulnerability.get_by_id(CVE_ID) is not None

        package_response = self.client.get(
            f"/api/packages?variant_id={VARIANT_ID}&outdated_only=true"
        )
        assert package_response.status_code == 200
        assert json.loads(package_response.data) == []

    def test_outdated_data_preview_lists_the_records_to_delete(self):
        """The preview exposes the same stale package data and assessment."""
        response = self.client.get("/api/outdated-data")

        assert response.status_code == 200
        preview = json.loads(response.data)
        assert preview["candidate_ids"]["assessments"] == [str(self.assess_id)]
        assert len(preview["candidate_ids"]["observations"]) == 1
        assert preview["candidate_ids"]["package_pairs"] == [{
            "package_id": preview["candidate_ids"]["package_pairs"][0]["package_id"],
            "variant_id": str(VARIANT_ID),
        }]
        assert uuid.UUID(preview["candidate_ids"]["package_pairs"][0]["package_id"])
        assert {key: value for key, value in preview.items() if key != "candidate_ids"} == {
            "packages": [{
                "package": "firefox@1.0",
                "project": "test",
                "variant": "default",
                "vulnerabilities": [CVE_ID],
                "linked_data": {"observations": 1, "sbom_packages": 1, "sbom_observations": 0},
            }],
            "assessments": [{
                "project": "test",
                "vulnerability": CVE_ID,
                "package": "firefox@1.0",
                "variant": "default",
            }],
        }

    @pytest.mark.parametrize(
        "endpoint",
        ["/api/outdated-data", "/api/empty-scans", "/api/orphaned-vulnerabilities"],
    )
    def test_cleanup_delete_requires_confirmed_preview(self, endpoint):
        """HTTP cleanup rejects unconfirmed destructive requests."""
        response = self.client.delete(endpoint)

        assert response.status_code == 400

    def test_delete_outdated_data_removes_stale_sbom_only_package(self):
        """A package absent from the active SBOM is removed without a finding observation."""
        with self.app.app_context():
            obsolete_package = Package.find_or_create("legacy", "1.0", [], [], "")
            _db.session.add(SBOMPackage(
                sbom_document_id=uuid.UUID("e1111111-1111-1111-1111-111111111111"),
                package_id=obsolete_package.id,
            ))
            _db.session.commit()

        preview = self.client.get("/api/outdated-data")
        assert preview.status_code == 200
        packages = json.loads(preview.data)["packages"]
        assert any(package["package"] == "legacy@1.0" for package in packages)

        response = self._delete_outdated_data()

        assert response.status_code == 200
        assert json.loads(response.data)["packages_deleted"] == 2
        with self.app.app_context():
            assert Package.get_by_string_id("legacy@1.0") is None

    def test_delete_outdated_data_removes_orphaned_vulnerability_data(self):
        """A vulnerability exclusive to stale package evidence is removed with its metrics."""
        obsolete_cve = "CVE-2024-00001"
        with self.app.app_context():
            Vulnerability.create_record(id=obsolete_cve, description="Obsolete vuln", status="high")
            obsolete_package = Package.find_or_create("legacy", "1.0", [], [], "")
            obsolete_finding = Finding.get_or_create(obsolete_package.id, obsolete_cve)
            _db.session.add(SBOMPackage(
                sbom_document_id=uuid.UUID("e1111111-1111-1111-1111-111111111111"),
                package_id=obsolete_package.id,
            ))
            _db.session.add(Observation(finding_id=obsolete_finding.id, scan_id=SCAN_V1_ID))
            _db.session.add(Metrics(vulnerability_id=obsolete_cve, variant_id=VARIANT_ID))
            _db.session.commit()

        response = self._delete_outdated_data()

        assert response.status_code == 200
        assert json.loads(response.data)["vulnerabilities_deleted"] == 1
        with self.app.app_context():
            assert _db.session.get(Vulnerability, obsolete_cve) is None
            assert _db.session.execute(
                _db.select(Metrics).where(Metrics.vulnerability_id == obsolete_cve)
            ).scalar_one_or_none() is None
            assert _db.session.get(Vulnerability, CVE_ID) is not None

    def test_delete_outdated_data_removes_packageless_observations_from_superseded_sboms(self):
        """Package-less SBOM data from a prior import cannot retain a removed CVE."""
        obsolete_cve = "CVE-2001-1267"
        active_cve = "CVE-2024-00002"
        with self.app.app_context():
            Vulnerability.create_record(id=obsolete_cve, description="Obsolete vuln", status="high")
            Vulnerability.create_record(id=active_cve, description="Active vuln", status="high")
            SBOMObservation.create(
                vulnerability_id=obsolete_cve,
                sbom_document_id=uuid.UUID("e1111111-1111-1111-1111-111111111111"),
                key="Yocto VEX Description",
                description="Only present in the first SBOM",
                commit=False,
            )
            SBOMObservation.create(
                vulnerability_id=active_cve,
                sbom_document_id=uuid.UUID("e2222222-2222-2222-2222-222222222222"),
                key="Yocto VEX Description",
                description="Present in the active SBOM",
                commit=False,
            )
            _db.session.commit()

        response = self._delete_outdated_data()

        assert response.status_code == 200
        assert json.loads(response.data)["sbom_observations_deleted"] == 1
        with self.app.app_context():
            assert _db.session.execute(
                _db.select(SBOMObservation).where(SBOMObservation.vulnerability_id == obsolete_cve)
            ).scalar_one_or_none() is None
            assert _db.session.execute(
                _db.select(SBOMObservation).where(SBOMObservation.vulnerability_id == active_cve)
            ).scalar_one_or_none() is not None

        response = self._delete_orphaned_vulnerabilities()

        assert response.status_code == 200
        assert json.loads(response.data)["vulnerabilities_deleted"] == 1
        with self.app.app_context():
            assert _db.session.get(Vulnerability, obsolete_cve) is None
            assert _db.session.get(Vulnerability, active_cve) is not None

    def test_delete_outdated_cli_command(self):
        """The Flask command delegates to the same cleanup implementation."""
        runner = self.app.test_cli_runner()
        result = runner.invoke(args=["delete-outdated"])

        assert result.exit_code == 0
        assert "1 assessments" in result.output
        with self.app.app_context():
            assert Package.get_by_string_id("firefox@1.0") is None

    def test_delete_outdated_preserves_packages_active_in_other_variants(self):
        """Cleanup removes stale variant data without deleting shared active data."""
        second_variant_id = uuid.UUID("abababab-abab-abab-abab-abababababab")
        second_scan_id = uuid.UUID("cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd")
        with self.app.app_context():
            old_package = Package.get_by_string_id("firefox@1.0")
            assert old_package is not None
            old_finding = Finding.get_by_package_and_vulnerability(old_package.id, CVE_ID)
            assert old_finding is not None
            old_finding_id = old_finding.id
            _db.session.add(Variant(id=second_variant_id, name="other", project_id=PROJECT_ID))
            _db.session.add(Scan(
                id=second_scan_id,
                variant_id=second_variant_id,
                scan_type="sbom",
                timestamp=datetime(2024, 7, 1, tzinfo=timezone.utc),
            ))
            document = SBOMDocument(
                id=uuid.UUID("e3333333-3333-3333-3333-333333333333"),
                path="/scan/other.spdx.json",
                source_name="other.spdx.json",
                format="spdx",
                scan_id=second_scan_id,
            )
            _db.session.add(document)
            _db.session.add(SBOMPackage(
                sbom_document_id=document.id,
                package_id=old_package.id,
            ))
            _db.session.add(Observation(finding_id=old_finding.id, scan_id=second_scan_id))
            _db.session.commit()

        response = self._delete_outdated_data()

        assert response.status_code == 200
        assert json.loads(response.data)["packages_deleted"] == 0
        with self.app.app_context():
            old_package = Package.get_by_string_id("firefox@1.0")
            assert old_package is not None
            assert len(Observation.get_by_finding(old_finding_id)) == 1

    def test_delete_empty_scans_removes_only_redundant_non_initial_scans(self):
        """Empty scan cleanup uses the same complete diff shown in scan history."""
        duplicate_scan_id = uuid.UUID("12121212-1212-1212-1212-121212121212")
        with self.app.app_context():
            finding = Finding.get_by_package_and_vulnerability(
                Package.get_by_string_id("firefox@2.0").id, CVE_ID
            )
            _db.session.add(Scan(
                id=duplicate_scan_id,
                variant_id=VARIANT_ID,
                scan_type="tool",
                scan_source="nvd",
                timestamp=datetime(2024, 6, 3, tzinfo=timezone.utc),
            ))
            _db.session.add(Observation(finding_id=finding.id, scan_id=duplicate_scan_id))
            _db.session.commit()

        preview = self.client.get("/api/empty-scans")
        assert preview.status_code == 200
        assert [scan["id"] for scan in json.loads(preview.data)["scans"]] == [str(duplicate_scan_id)]

        response = self._delete_empty_scans()
        assert response.status_code == 200
        assert json.loads(response.data) == {"scans_deleted": 1}
        with self.app.app_context():
            assert _db.session.get(Scan, duplicate_scan_id) is None
            assert _db.session.get(Scan, SCAN_V1_ID) is not None
            assert _db.session.get(Scan, SCAN_V2_ID) is not None

    def test_empty_scan_cleanup_orders_equal_timestamps_by_id(self):
        """Equal-time scans have a deterministic predecessor regardless of insertion order."""
        earlier_id = uuid.UUID("11111111-2222-2222-2222-222222222222")
        redundant_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
        tied_timestamp = datetime(2024, 7, 1, tzinfo=timezone.utc)
        with self.app.app_context():
            _db.session.add(Scan(
                id=redundant_id,
                variant_id=VARIANT_ID,
                scan_type="tool",
                scan_source="nvd",
                timestamp=tied_timestamp,
            ))
            _db.session.add(Scan(
                id=earlier_id,
                variant_id=VARIANT_ID,
                scan_type="tool",
                scan_source="nvd",
                timestamp=tied_timestamp,
            ))
            _db.session.commit()

        preview = self.client.get("/api/empty-scans")
        assert preview.status_code == 200
        assert [scan["id"] for scan in json.loads(preview.data)["scans"]] == [
            str(earlier_id),
            str(redundant_id),
        ]

        response = self._delete_empty_scans()
        assert response.status_code == 200
        with self.app.app_context():
            assert _db.session.get(Scan, earlier_id) is None
            assert _db.session.get(Scan, redundant_id) is None
    def test_delete_orphaned_vulnerabilities_removes_assessments(self):
        """Assessment-only CVEs are not considered included in a project or variant."""
        orphaned_cve = "CVE-2024-00002"
        orphaned_assessment_id = uuid.UUID("13131313-1313-1313-1313-131313131313")
        with self.app.app_context():
            Vulnerability.create_record(id=orphaned_cve, description="Orphaned", status="low")
            package = Package.find_or_create("orphaned", "1.0", [], [], "")
            finding = Finding.get_or_create(package.id, orphaned_cve)
            _db.session.add(Assessment(
                id=orphaned_assessment_id,
                origin="custom",
                status="not_affected",
                finding_id=finding.id,
                variant_id=VARIANT_ID,
            ))
            _db.session.commit()

        preview = self.client.get("/api/orphaned-vulnerabilities")
        assert preview.status_code == 200
        assert json.loads(preview.data) == {
            "vulnerabilities": [{"id": orphaned_cve, "assessments": 1}]
        }

        response = self._delete_orphaned_vulnerabilities()
        assert response.status_code == 200
        assert json.loads(response.data) == {
            "vulnerabilities_deleted": 1,
            "assessments_deleted": 1,
            "findings_deleted": 1,
        }
        with self.app.app_context():
            assert _db.session.get(Vulnerability, orphaned_cve) is None
            assert _db.session.get(Assessment, orphaned_assessment_id) is None
            assert _db.session.get(Vulnerability, CVE_ID) is not None

    def test_orphaned_vulnerabilities_preserve_variant_owned_data(self):
        """Variant metrics and time estimates keep their CVEs out of cleanup."""
        metrics_cve = "CVE-2024-00003"
        estimate_cve = "CVE-2024-00004"
        estimate_id = uuid.UUID("14141414-1414-1414-1414-141414141414")
        with self.app.app_context():
            Vulnerability.create_record(id=metrics_cve, description="Custom metric", status="low")
            Vulnerability.create_record(id=estimate_cve, description="Estimated work", status="low")
            package = Package.find_or_create("estimated", "1.0", [], [], "")
            finding = Finding.get_or_create(package.id, estimate_cve)
            _db.session.add(Metrics(vulnerability_id=metrics_cve, variant_id=VARIANT_ID))
            _db.session.add(TimeEstimate(
                id=estimate_id,
                finding_id=finding.id,
                variant_id=VARIANT_ID,
                optimistic=1,
                likely=2,
                pessimistic=3,
            ))
            _db.session.commit()

        preview = self.client.get("/api/orphaned-vulnerabilities")
        assert preview.status_code == 200
        preview_ids = {item["id"] for item in json.loads(preview.data)["vulnerabilities"]}
        assert metrics_cve not in preview_ids
        assert estimate_cve not in preview_ids

        response = self._delete_orphaned_vulnerabilities()
        assert response.status_code == 200
        with self.app.app_context():
            assert _db.session.get(Vulnerability, metrics_cve) is not None
            assert _db.session.get(Vulnerability, estimate_cve) is not None
            assert _db.session.get(TimeEstimate, estimate_id) is not None

    def test_orphaned_vulnerability_cleanup_batches_large_candidate_sets(self):
        """Preview and deletion preserve exact counts across SQL parameter batches."""
        candidate_count = 401
        with self.app.app_context():
            package = Package.get_by_string_id("firefox@2.0")
            vulnerabilities = []
            findings = []
            assessments = []
            for index in range(candidate_count):
                vulnerability_id = f"CVE-2099-{index:05d}"
                finding_id = uuid.UUID(int=index + 1000)
                vulnerabilities.append(Vulnerability(
                    id=vulnerability_id,
                    description="Batched orphan",
                    status="low",
                ))
                findings.append(Finding(
                    id=finding_id,
                    package_id=package.id,
                    vulnerability_id=vulnerability_id,
                ))
                assessments.append(Assessment(
                    id=uuid.UUID(int=index + 2000),
                    origin="custom",
                    status="not_affected",
                    finding_id=finding_id,
                    variant_id=VARIANT_ID,
                ))
            _db.session.add_all(vulnerabilities)
            _db.session.add_all(findings)
            _db.session.add_all(assessments)
            _db.session.commit()

        preview = self.client.get("/api/orphaned-vulnerabilities")
        assert preview.status_code == 200
        candidates = json.loads(preview.data)["vulnerabilities"]
        assert len(candidates) == candidate_count
        assert all(candidate["assessments"] == 1 for candidate in candidates)

        response = self._delete_orphaned_vulnerabilities()
        assert response.status_code == 200
        assert json.loads(response.data) == {
            "vulnerabilities_deleted": candidate_count,
            "assessments_deleted": candidate_count,
            "findings_deleted": candidate_count,
        }

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            ("delete-empty-scans", "Deleted 0 empty scans"),
            ("delete-orphaned-vulnerabilities", "Deleted 0 orphaned vulnerabilities"),
        ],
    )
    def test_additional_cleanup_cli_commands(self, command, expected):
        result = self.app.test_cli_runner().invoke(args=[command])
        assert result.exit_code == 0
        assert expected in result.output

class TestNotOutdated_VersionStillActive:
    """Not outdated when the assessed package version is still in the active SBOM."""

    @pytest.fixture(autouse=True)
    def setup(self, app_factory):
        self.app = app_factory()
        # Build standard scenario but mark scan_v1 as the LATEST (no v2 scan).
        self.assess_id = _build_outdated_db(
            self.app,
            include_v2_finding=True,
            include_v2_in_active=False,  # no v2 scan → v1 is still active
        )
        self.client = self.app.test_client()

    def test_not_outdated_when_package_still_active(self):
        """Assessment is NOT outdated when firefox@1.0 is the current active package."""
        resp = self.client.get(f"/api/assessments?variant_id={VARIANT_ID}")
        data = json.loads(resp.data)
        custom = [a for a in data if a.get("origin") == "custom"]
        assert len(custom) == 1
        assert custom[0]["outdated"] is False
        assert custom[0]["superseded_by"] == []


class TestNotOutdated_NewVersionNotAffected:
    """Not outdated when the new package version does not have a finding for the CVE."""

    @pytest.fixture(autouse=True)
    def setup(self, app_factory):
        self.app = app_factory()
        self.assess_id = _build_outdated_db(
            self.app,
            include_v2_finding=False,  # v2 has no Finding → condition 4 fails
            include_v2_in_active=True,
        )
        self.client = self.app.test_client()

    def test_not_outdated_when_new_version_unaffected(self):
        """Assessment is NOT outdated when firefox@2.0 is not affected by the CVE."""
        resp = self.client.get(f"/api/assessments?variant_id={VARIANT_ID}")
        data = json.loads(resp.data)
        custom = [a for a in data if a.get("origin") == "custom"]
        assert len(custom) == 1
        assert custom[0]["outdated"] is False
        assert custom[0]["superseded_by"] == []


class TestNotOutdated_NonCustomOrigin:
    """Assessments with origin other than 'custom' are never flagged outdated."""

    @pytest.fixture(autouse=True)
    def setup(self, app_factory):
        self.app = app_factory()
        # Build the full outdated scenario, then flip origin to 'sbom'.
        _build_outdated_db(self.app)
        with self.app.app_context():
            assess = _db.session.get(
                Assessment, uuid.UUID("f1111111-1111-1111-1111-111111111111")
            )
            assert assess is not None
            assess.origin = "sbom"
            _db.session.commit()
        self.client = self.app.test_client()

    def test_non_custom_assessment_not_flagged(self):
        """SBOM-origin assessment is not marked outdated regardless of package changes."""
        resp = self.client.get(f"/api/assessments?variant_id={VARIANT_ID}")
        data = json.loads(resp.data)
        assert all(not a.get("outdated") for a in data)


class TestHelperEdgeCases:
    """Direct tests of annotate_assessments_outdated for inputs the routes can't produce."""

    @pytest.fixture(autouse=True)
    def setup(self, app_factory):
        self.app = app_factory()
        _build_outdated_db(self.app)

    def _annotate(self, dicts):
        from src.helpers.assessment_staleness import annotate_assessments_outdated
        with self.app.app_context():
            annotate_assessments_outdated(dicts)
        return dicts

    def _base_dict(self, **overrides):
        d = {
            "id": "x",
            "origin": "custom",
            "variant_id": str(VARIANT_ID),
            "vuln_id": CVE_ID,
            "packages": ["firefox@1.0"],
        }
        d.update(overrides)
        return d

    def test_versionless_package_reference_is_current(self):
        """A 'name'-only package reference matches any active version — never outdated."""
        dicts = [self._base_dict(packages=["firefox"])]
        self._annotate(dicts)
        assert dicts[0]["outdated"] is False
        assert dicts[0]["superseded_by"] == []

    def test_invalid_variant_id_is_skipped(self):
        """A malformed variant_id doesn't raise and leaves defaults."""
        dicts = [self._base_dict(variant_id="not-a-uuid")]
        self._annotate(dicts)
        assert dicts[0]["outdated"] is False

    def test_empty_packages_left_untouched(self):
        """An assessment with no packages keeps the defaults."""
        dicts = [self._base_dict(packages=[])]
        self._annotate(dicts)
        assert dicts[0]["outdated"] is False

    def test_mixed_current_and_stale_packages_is_current(self):
        """A name referenced at several versions stays current while any is active."""
        dicts = [self._base_dict(packages=["firefox@1.0", "firefox@2.0"])]
        self._annotate(dicts)
        assert dicts[0]["outdated"] is False

    def test_supplier_suffix_is_ignored_for_matching(self):
        """'name@version::supplier' matches the same way as 'name@version'."""
        dicts = [self._base_dict(packages=["firefox@1.0::Organization: Mozilla"])]
        self._annotate(dicts)
        assert dicts[0]["outdated"] is True
        assert dicts[0]["superseded_by"] == ["firefox@2.0"]


class TestOutdated_MultiPackageOneSuperseded:
    """A multi-package assessment is outdated when one package is superseded.

    Assessment covers firefox@1.0 AND chrome@1.0.  firefox is bumped to 2.0
    (still affected) while chrome@1.0 stays in the active SBOM.  The assessment
    must be flagged outdated because the firefox portion no longer applies,
    even though chrome@1.0 is unchanged.
    """

    @pytest.fixture(autouse=True)
    def setup(self, app_factory):
        self.app = app_factory()
        _build_outdated_db(self.app, include_unchanged_second_pkg=True)
        self.client = self.app.test_client()

    def _annotate(self, dicts):
        from src.helpers.assessment_staleness import annotate_assessments_outdated
        with self.app.app_context():
            annotate_assessments_outdated(dicts)
        return dicts

    def test_outdated_when_one_of_several_packages_superseded(self):
        """firefox@1.0 superseded by firefox@2.0 while chrome@1.0 stays current."""
        dicts = [{
            "id": "x",
            "origin": "custom",
            "variant_id": str(VARIANT_ID),
            "vuln_id": CVE_ID,
            "packages": ["firefox@1.0", "chrome@1.0"],
        }]
        self._annotate(dicts)
        assert dicts[0]["outdated"] is True
        assert dicts[0]["superseded_by"] == ["firefox@2.0"]
        # Only firefox@1.0 is flagged; chrome@1.0 stays current.
        assert dicts[0]["stale_packages"] == ["firefox@1.0"]
        assert dicts[0]["superseded_map"] == {"firefox@1.0": ["firefox@2.0"]}

    def test_current_when_all_packages_still_active(self):
        """No package superseded → assessment stays current."""
        dicts = [{
            "id": "x",
            "origin": "custom",
            "variant_id": str(VARIANT_ID),
            "vuln_id": CVE_ID,
            "packages": ["firefox@2.0", "chrome@1.0"],
        }]
        self._annotate(dicts)
        assert dicts[0]["outdated"] is False
        assert dicts[0]["superseded_by"] == []

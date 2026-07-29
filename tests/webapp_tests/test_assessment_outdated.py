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
from src.models.observation import Observation
from src.models.package import Package
from src.models.project import Project
from src.models.sbom_document import SBOMDocument
from src.models.sbom_package import SBOMPackage
from src.models.scan import Scan
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

    def test_outdated_flag_always_present(self):
        """Every assessment dict returned has the 'outdated' key."""
        resp = self.client.get(f"/api/assessments?variant_id={VARIANT_ID}")
        data = json.loads(resp.data)
        for item in data:
            assert "outdated" in item, f"Missing 'outdated' key in {item!r}"
            assert "superseded_by" in item
            assert "stale_packages" in item
            assert "superseded_map" in item


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

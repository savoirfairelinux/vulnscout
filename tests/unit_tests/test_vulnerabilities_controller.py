# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for src/controllers/vulnerabilities.py — DB-fallback paths
(lines 127-128, 161-162, 418-419)."""

import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# EPSS mock (autouse so no real /cache/vulnscout/epss.db is needed)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def mock_epss_db():
    mock = MagicMock()
    mock.get_score.return_value = None
    with patch("src.controllers.vulnerabilities.EPSS_DB", return_value=mock):
        yield mock


# ---------------------------------------------------------------------------
# DB app fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    import os
    from src.bin.webapp import create_app
    from src.extensions import db as _db

    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def db_vuln(app):
    from src.models.vulnerability import Vulnerability
    return Vulnerability.create_record("CVE-2099-CTRL")


@pytest.fixture()
def db_package(app):
    from src.models.package import Package
    return Package.create("ctrlpkg", "1.0.0")


@pytest.fixture()
def db_finding(app, db_package, db_vuln):
    from src.models.finding import Finding
    return Finding.create(db_package.id, db_vuln.id)


# ---------------------------------------------------------------------------
# get() — DB fallback when vuln is not in in-memory dict (lines 161-162)
# ---------------------------------------------------------------------------

class TestVulnerabilitiesControllerGet:
    def test_get_db_fallback(self, app, db_vuln):
        """get() fetches from DB when the in-memory dict is cleared (lines 161-162)."""
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController

        pkg_ctrl = PackagesController()
        vuln_ctrl = VulnerabilitiesController(pkg_ctrl)
        vuln_ctrl.vulnerabilities.clear()
        vuln_ctrl.alias_registered.clear()

        result = vuln_ctrl.get(db_vuln.id)
        assert result is not None
        assert result.id == db_vuln.id

    def test_get_returns_none_for_missing_vuln(self, app):
        """get() returns None when neither in-memory dict nor DB has the vuln."""
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController

        pkg_ctrl = PackagesController()
        vuln_ctrl = VulnerabilitiesController(pkg_ctrl)
        vuln_ctrl.vulnerabilities.clear()
        vuln_ctrl.alias_registered.clear()

        assert vuln_ctrl.get("CVE-9999-DOESNOTEXIST") is None


# ---------------------------------------------------------------------------
# __iter__ — DB iteration when in-memory dict is empty (lines 418-419)
# ---------------------------------------------------------------------------

class TestVulnerabilitiesControllerIter:
    def test_iter_uses_db_when_dict_is_empty(self, app, db_vuln):
        """__iter__ falls back to DB when the in-memory dict is cleared (lines 418-419)."""
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController

        pkg_ctrl = PackagesController()
        vuln_ctrl = VulnerabilitiesController(pkg_ctrl)
        vuln_ctrl.vulnerabilities.clear()

        vuln_ids = [v.id for v in vuln_ctrl]
        assert db_vuln.id in vuln_ids

# ---------------------------------------------------------------------------
# fetch_published_dates — NVD SQLite error (lines 328-329)
# ---------------------------------------------------------------------------

class TestFetchPublishedDates:
    def test_nvd_sqlite_error_is_silently_caught(self, app):
        """A connection error to the NVD SQLite DB is caught, not raised (lines 328-329)."""
        import sqlite3
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController
        from src.models.vulnerability import Vulnerability

        vuln = Vulnerability("CVE-2025-NVD", [], "ds", "ns")
        pkg_ctrl = PackagesController()
        vuln_ctrl = VulnerabilitiesController(pkg_ctrl)
        vuln_ctrl.vulnerabilities["CVE-2025-NVD"] = vuln

        with patch("sqlite3.connect", side_effect=sqlite3.OperationalError("no such file")):
            vuln_ctrl.fetch_published_dates()  # must not raise

    # ---------------------------------------------------------------------------
    # fetch_published_dates — GHSA thread-pool path (lines 346-359)
    # ---------------------------------------------------------------------------

    def test_ghsa_published_date_returned(self, app):
        """GHSA vulns use the ThreadPoolExecutor path; a mocked date is applied (lines 346-347)."""
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController
        from src.models.vulnerability import Vulnerability

        vuln = Vulnerability("GHSA-test-xxxx-0001", [], "ds", "ns")
        pkg_ctrl = PackagesController()
        vuln_ctrl = VulnerabilitiesController(pkg_ctrl)
        vuln_ctrl.vulnerabilities["GHSA-test-xxxx-0001"] = vuln

        with patch.object(
            VulnerabilitiesController,
            "_fetch_ghsa_published",
            return_value="2024-06-01T00:00:00Z",
        ):
            vuln_ctrl.fetch_published_dates()

        assert vuln.published == "2024-06-01T00:00:00Z"

    def test_ghsa_future_exception_is_caught(self, app):
        """An exception raised inside a GHSA future is caught, not re-raised (lines 357-359)."""
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController
        from src.models.vulnerability import Vulnerability

        vuln = Vulnerability("GHSA-test-xxxx-0002", [], "ds", "ns")
        pkg_ctrl = PackagesController()
        vuln_ctrl = VulnerabilitiesController(pkg_ctrl)
        vuln_ctrl.vulnerabilities["GHSA-test-xxxx-0002"] = vuln

        with patch.object(
            VulnerabilitiesController,
            "_fetch_ghsa_published",
            side_effect=RuntimeError("network error"),
        ):
            vuln_ctrl.fetch_published_dates()  # must not raise




# ---------------------------------------------------------------------------
# NOTE: Tests for parse_refresh_delay() and _should_refetch() have been
# removed as the caching system has been deprecated. All data fetches now
# attempt fresh data from remote sources (EPSS, NVD).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# _batch_commit — rollback on commit failure (lines 38-40)
# ---------------------------------------------------------------------------

class TestBatchCommitRollback:
    def test_rollback_called_on_commit_failure(self, app, monkeypatch):
        """Lines 38-40: on commit exception, rollback is called and no re-raise."""
        from src.controllers import vulnerabilities as vmod
        from unittest.mock import MagicMock

        rolled_back = []
        monkeypatch.setattr(vmod.db.session, "commit", MagicMock(side_effect=RuntimeError("boom")))
        monkeypatch.setattr(vmod.db.session, "rollback", lambda: rolled_back.append(True))

        vmod._batch_commit(1, 10, "TestLabel")  # must not raise
        assert rolled_back == [True]


# ---------------------------------------------------------------------------
# alias_registered — get() via alias (line 212)
# ---------------------------------------------------------------------------

class TestAliasGet:
    def test_get_via_alias_returns_canonical_vuln(self, app, db_vuln):
        """Line 212: alias_registered lookup returns the canonical vulnerability."""
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController
        from src.models.vulnerability import Vulnerability

        pkg_ctrl = PackagesController()
        vuln_ctrl = VulnerabilitiesController(pkg_ctrl)
        canonical = Vulnerability("CVE-2099-CANONICAL", [], "d", "n")
        vuln_ctrl.vulnerabilities["CVE-2099-CANONICAL"] = canonical
        vuln_ctrl.alias_registered["CVE-2099-ALIAS"] = "CVE-2099-CANONICAL"

        result = vuln_ctrl.get("CVE-2099-ALIAS")
        assert result is canonical


# ---------------------------------------------------------------------------
# _scope — get() returns None when scoped (lines 215-216)
# ---------------------------------------------------------------------------

class TestScopedGet:
    def test_get_returns_none_for_unknown_vuln_when_scoped(self, app):
        """Lines 215-216: when scope is set, get() does not fall back to DB."""
        import uuid
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController
        from src.helpers.export_scope import ExportScope

        scope = ExportScope(package_ids=set(), variant_ids=set())
        pkg_ctrl = PackagesController()
        vuln_ctrl = VulnerabilitiesController(pkg_ctrl, scope=scope)
        # The in-memory dict is empty, scope is set → must return None
        result = vuln_ctrl.get("CVE-NOTEXIST-9999")
        assert result is None


# ---------------------------------------------------------------------------
# _scope — __iter__ early return when scope set and dict empty (line 696)
# ---------------------------------------------------------------------------

class TestScopedIter:
    def test_iter_returns_empty_when_scope_and_no_loaded_vulns(self, app, db_vuln):
        """Line 696: when scope is active and vulnerabilities dict is empty,
        __iter__ does NOT fall back to DB."""
        import uuid
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController
        from src.helpers.export_scope import ExportScope

        scope = ExportScope(package_ids=set(), variant_ids=set())
        pkg_ctrl = PackagesController()
        vuln_ctrl = VulnerabilitiesController(pkg_ctrl, scope=scope)
        # Clear in-memory cache so the iteration hits the scope-guard branch
        vuln_ctrl.vulnerabilities.clear()

        results = list(vuln_ctrl)
        assert results == []


# ---------------------------------------------------------------------------
# _preload_cache — scoped filtering excludes out-of-scope findings (lines 152-159)
# ---------------------------------------------------------------------------

class TestPreloadCacheScoped:
    def test_scoped_preload_excludes_unscoped_vuln(self, app, db_package, db_vuln, db_finding):
        """Lines 152-159: when scope.package_ids does not include the package,
        the vulnerability is NOT loaded into the in-memory cache."""
        import uuid
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController
        from src.helpers.export_scope import ExportScope

        # Use an empty package_ids set — no package is in scope
        scope = ExportScope(package_ids=set(), variant_ids=set())
        pkg_ctrl = PackagesController()
        vuln_ctrl = VulnerabilitiesController(pkg_ctrl, scope=scope)

        assert db_vuln.id not in vuln_ctrl.vulnerabilities


# ---------------------------------------------------------------------------
# _preload_cache — metrics populated into MetricsModel._seen (lines 181-182)
# ---------------------------------------------------------------------------

class TestPreloadCacheMetrics:
    def test_existing_metrics_populate_seen_set(self, app, db_vuln):
        """Lines 181-182: metrics rows already in DB are added to MetricsModel._seen
        so that from_cvss skips the SELECT for existing entries."""
        from src.models.metrics import Metrics as MetricsModel
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController

        MetricsModel.create(
            vulnerability_id=db_vuln.id,
            version="3.1",
            score=7.5,
            vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )

        # Clear the seen set so we can verify it gets populated
        MetricsModel._seen.clear()

        pkg_ctrl = PackagesController()
        VulnerabilitiesController(pkg_ctrl)

        # Preload should have added the metric to _seen
        assert any(k[0] == db_vuln.id for k in MetricsModel._seen)


# ---------------------------------------------------------------------------
# record_sbom_observation (lines 622-631)
# ---------------------------------------------------------------------------

class TestRecordSbomObservation:
    def test_warning_logged_when_no_sbom_document(self, app, db_vuln):
        """Line 622-623: a warning is logged when current_sbom_document is None."""
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController
        from src.models.vulnerability import Vulnerability
        from unittest.mock import patch
        import logging

        pkg_ctrl = PackagesController()
        vuln_ctrl = VulnerabilitiesController(pkg_ctrl)
        transient = Vulnerability(db_vuln.id, [], "desc", "nvd")

        with patch.object(logging.getLogger("src.controllers.vulnerabilities"), "warning") as mock_warn:
            vuln_ctrl.record_sbom_observation(transient, "test-key", "test description")
        mock_warn.assert_called_once()

    def test_creates_observation_when_document_set(self, app, db_package, db_vuln):
        """Lines 624-631: SBOMObservation is created when current_sbom_document is set."""
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController
        from src.models.vulnerability import Vulnerability
        from src.models.scan import Scan
        from src.models.variant import Variant
        from src.models.project import Project
        from src.models.sbom_document import SBOMDocument
        from src.models.sbom_observation import SBOMObservation
        from src.extensions import db

        project = Project.create("ObsProj")
        variant = Variant.create("ObsVariant", project.id)
        scan = Scan.create("obs scan", variant.id, scan_type="sbom")
        doc = SBOMDocument.create("/obs/sbom.json", "spdx", scan.id)
        db.session.commit()

        pkg_ctrl = PackagesController()
        pkg_ctrl.current_sbom_document = doc
        vuln_ctrl = VulnerabilitiesController(pkg_ctrl)
        transient = Vulnerability(db_vuln.id, [], "desc", "nvd")

        vuln_ctrl.record_sbom_observation(transient, "obs-key", "observed", package=db_package)

        obs_rows = SBOMObservation.get_by_vuln(db_vuln.id)
        assert any(o.key == "obs-key" for o in obs_rows)


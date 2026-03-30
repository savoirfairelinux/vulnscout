# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for src/controllers/vulnerabilities.py — DB-fallback paths and
fetch_published_dates error/GHSA branches (lines 127-128, 161-162, 328-329,
346-347, 357-359, 418-419)."""

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

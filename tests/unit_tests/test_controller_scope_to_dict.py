# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for scope-aware ``to_dict()`` on the packages, vulnerabilities and
assessments controllers.

When an export/report scope is active the controllers must return ONLY the
pre-loaded in-scope data and never fall back to the global DB set, otherwise a
scoped report could leak another project's/variant's data.
"""

import os
import uuid
import pytest
from unittest.mock import MagicMock, patch

from src.bin.webapp import create_app
from src.extensions import db as _db
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from src.models.assessment import Assessment
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController
from src.helpers.export_scope import ExportScope


@pytest.fixture()
def app():
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


def _make_pkg(name="pkg-a", version="1.0"):
    return Package(name, version, [], [f"pkg:generic/{name}@{version}"])


# ---------------------------------------------------------------------------
# PackagesController.to_dict
# ---------------------------------------------------------------------------

class TestPackagesControllerScopeToDict:
    def test_unscoped_falls_back_to_db(self, app):
        ctrl = PackagesController()  # no scope
        pkg = _make_pkg("db-pkg")
        with patch.object(Package, "get_all", return_value=[pkg]):
            result = ctrl.to_dict()
        assert pkg.string_id in result

    def test_scoped_empty_cache_does_not_leak_db(self, app):
        scope = ExportScope(package_ids=set(), variant_ids=set())
        ctrl = PackagesController(scope=scope)
        with patch.object(Package, "get_all", return_value=[_make_pkg("db-pkg")]) as get_all:
            result = ctrl.to_dict()
        assert result == {}
        get_all.assert_not_called()

    def test_scoped_returns_only_cached(self, app):
        scope = ExportScope(package_ids={uuid.uuid4()}, variant_ids=set())
        ctrl = PackagesController(scope=scope)
        pkg = _make_pkg("scoped-pkg")
        ctrl._cache[pkg.string_id] = pkg
        with patch.object(Package, "get_all", return_value=[_make_pkg("db-pkg")]):
            result = ctrl.to_dict()
        assert list(result.keys()) == [pkg.string_id]


# ---------------------------------------------------------------------------
# VulnerabilitiesController.to_dict
# ---------------------------------------------------------------------------

class TestVulnerabilitiesControllerScopeToDict:
    @patch("src.controllers.vulnerabilities.EPSS_DB")
    def test_unscoped_falls_back_to_db(self, mock_epss, app):
        mock_epss.return_value = MagicMock()
        ctrl = VulnerabilitiesController(PackagesController())  # no scope
        v_db = Vulnerability("CVE-2024-0001", ["scanner"], "url", "unknown")
        with patch.object(Vulnerability, "get_all", return_value=[v_db]):
            result = ctrl.to_dict()
        assert "CVE-2024-0001" in result

    @patch("src.controllers.vulnerabilities.EPSS_DB")
    def test_scoped_empty_does_not_leak_db(self, mock_epss, app):
        mock_epss.return_value = MagicMock()
        scope = ExportScope(package_ids=set(), variant_ids=set())
        ctrl = VulnerabilitiesController(PackagesController(), scope=scope)
        v_db = Vulnerability("CVE-2024-0001", ["scanner"], "url", "unknown")
        with patch.object(Vulnerability, "get_all", return_value=[v_db]) as get_all:
            result = ctrl.to_dict()
        assert result == {}
        get_all.assert_not_called()

    @patch("src.controllers.vulnerabilities.EPSS_DB")
    def test_scoped_returns_only_inmemory(self, mock_epss, app):
        mock_epss.return_value = MagicMock()
        scope = ExportScope(package_ids=set(), variant_ids=set())
        ctrl = VulnerabilitiesController(PackagesController(), scope=scope)
        v = Vulnerability("CVE-IN-MEM", ["scanner"], "url", "unknown")
        ctrl.vulnerabilities[v.id] = v
        with patch.object(Vulnerability, "get_all", return_value=[
            Vulnerability("CVE-DB-ONLY", ["scanner"], "url", "unknown")
        ]):
            result = ctrl.to_dict()
        assert list(result.keys()) == ["CVE-IN-MEM"]


# ---------------------------------------------------------------------------
# AssessmentsController.to_dict
# ---------------------------------------------------------------------------

class TestAssessmentsControllerScopeToDict:
    def test_unscoped_falls_back_to_db(self, app):
        ctrl = AssessmentsController(MagicMock())  # no scope
        a_db = Assessment.new_dto("CVE-DB", ["pkg@1.0"])
        with patch.object(Assessment, "get_all", return_value=[a_db]):
            result = ctrl.to_dict()
        assert any(d["vuln_id"] == "CVE-DB" for d in result.values())

    def test_scoped_filters_by_variant(self, app):
        v1 = uuid.uuid4()
        v2 = uuid.uuid4()
        a1 = Assessment.new_dto("CVE-IN-SCOPE", ["pkg@1.0"])
        a1.variant_id = v1
        a2 = Assessment.new_dto("CVE-OUT-OF-SCOPE", ["pkg@1.0"])
        a2.variant_id = v2

        scope = ExportScope(package_ids=set(), variant_ids={v1})
        ctrl = AssessmentsController(MagicMock(), scope=scope)
        ctrl.assessments = {str(a1.id): a1, str(a2.id): a2}

        with patch.object(Assessment, "get_all", return_value=[]):
            result = ctrl.to_dict()

        vuln_ids = {d["vuln_id"] for d in result.values()}
        assert vuln_ids == {"CVE-IN-SCOPE"}

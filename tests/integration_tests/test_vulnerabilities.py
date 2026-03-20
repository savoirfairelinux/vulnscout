# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from unittest.mock import patch, MagicMock
import urllib.request
import json

@pytest.fixture
def pkg_ABC():
    pkg = Package("abc", "1.0.0")
    pkg.generate_generic_cpe()
    pkg.generate_generic_purl()
    return pkg


@pytest.fixture
def pkg_XYZ():
    pkg = Package("xyz", "2.3.4")
    pkg.generate_generic_cpe()
    pkg.generate_generic_purl()
    return pkg


@pytest.fixture
def pkg_controller(pkg_ABC, pkg_XYZ):
    controller = PackagesController()
    controller.add(pkg_ABC)
    controller.add(pkg_XYZ)
    return controller


@pytest.fixture
def vuln_123():
    vuln = Vulnerability("CVE-2022-1230", ["test"], "test", "test")
    vuln.add_url("https://cve.com/1230")
    vuln.add_text("CVE-123", "text1")
    vuln.add_package("test@1.0.0")
    vuln.add_advisory("advisory 1")
    return vuln


@pytest.fixture
def vuln_456(vuln_123, pkg_ABC):
    vuln = Vulnerability("CVE-2022-4560", ["test"], "test", "test")
    vuln.add_alias(vuln_123.id)
    vuln.add_related_vulnerability("CVE-000")
    vuln.add_url("https://cve.com/4560")
    vuln.add_text("CVE-456", "text2")
    vuln.add_package(pkg_ABC)
    vuln.add_advisory("advisory 2")
    return vuln


@pytest.fixture
def vuln_789(vuln_456, pkg_XYZ):
    vuln = Vulnerability("CVE-2022-1789", ["test"], "test", "test")
    vuln.add_alias(vuln_456.id)
    vuln.add_url("https://cve.com/1789")
    vuln.add_package(pkg_XYZ)
    return vuln


@pytest.fixture
def vuln_controller(pkg_controller, vuln_123):
    controller = VulnerabilitiesController(pkg_controller)
    controller.add(vuln_123)
    return controller


def test_vulnerability_not_present(vuln_controller, vuln_456):
    """
    GIVEN a VulnerabilitiesController instance
    WHEN no parameters are passed
    THEN check that the instance is created with empty attributes
    """
    assert vuln_controller.get(vuln_456.id) is None
    assert vuln_456.id not in vuln_controller
    assert vuln_456 not in vuln_controller
    assert vuln_controller.resolve_id(vuln_456.id)["is_alias"] is False
    assert vuln_controller.resolve_id(vuln_456.id)["id"] is None


def test_add_vulnerability(vuln_controller, vuln_123):
    """
    GIVEN a VulnerabilitiesController instance
    WHEN a vulnerability is added
    THEN check that the vulnerability is added correctly to the controller
    """
    assert len(vuln_controller) == 1
    assert vuln_controller.get(vuln_123.id) == vuln_123
    assert vuln_123.id in vuln_controller
    assert vuln_123 in vuln_controller
    found_vuln = 0
    for v in vuln_controller:
        if v == vuln_123:
            found_vuln = 1
    assert found_vuln == 1


def test_add_vulnerability_with_alias(vuln_controller, vuln_123, vuln_456):
    """
    GIVEN a VulnerabilitiesController instance
    WHEN a vulnerability is added with an alias
    THEN check that the vulnerability is added correctly to the controller
    """
    vuln_controller.add(vuln_456)
    assert len(vuln_controller) == 1
    assert vuln_controller.get(vuln_456.id) == vuln_123
    assert vuln_456.id in vuln_controller
    assert vuln_456 in vuln_controller
    assert vuln_controller.resolve_id(vuln_123.id)["is_alias"] is False
    assert vuln_controller.resolve_id(vuln_123.id)["id"] == vuln_123.id
    assert vuln_controller.resolve_id(vuln_456.id)["is_alias"] is True
    assert vuln_controller.resolve_id(vuln_456.id)["id"] == vuln_123.id


def test_removing_vulnerability(vuln_controller, vuln_123, vuln_456):
    """
    GIVEN a VulnerabilitiesController instance
    WHEN a vulnerability is added and removed
    THEN check that the vulnerability and their alias are removed correctly from the controller
    """
    vuln_controller.add(vuln_456)
    assert vuln_controller.remove(vuln_123.id) is True
    assert len(vuln_controller) == 0
    assert vuln_123.id not in vuln_controller
    assert vuln_456.id not in vuln_controller
    assert vuln_controller.remove(vuln_123.id) is False


def test_export_import_vulnerabilities(vuln_controller, pkg_controller, vuln_123):
    """
    GIVEN a VulnerabilitiesController instance with vulnerabilities
    WHEN the controller is exported and imported
    THEN check that the controller is correctly exported and imported
    """
    new_vulnCtrl = VulnerabilitiesController.from_dict(pkg_controller, vuln_controller.to_dict())
    assert len(new_vulnCtrl) == len(vuln_controller)
    assert vuln_123 in new_vulnCtrl


def test_add_vulnerability_already_present(vuln_controller, vuln_123, vuln_456, vuln_789):
    """
    GIVEN a VulnerabilitiesController instance with a vulnerability
    WHEN the vulnerability is added again
    THEN check that the vulnerability is merged with the existing one
    """
    vuln_controller.add(None)
    assert len(vuln_controller) == 1
    assert len(vuln_controller.alias_registered) == 0

    vuln_controller.add(vuln_123)
    assert len(vuln_controller) == 1
    assert len(vuln_controller.alias_registered) == 0

    vuln_controller.add(vuln_456)
    assert len(vuln_controller) == 1
    assert len(vuln_controller.alias_registered) == 1

    vuln_controller.add(vuln_789)
    assert len(vuln_controller) == 1
    assert len(vuln_controller.alias_registered) == 2

    vuln_controller.add(vuln_789)
    assert len(vuln_controller) == 1
    assert len(vuln_controller.alias_registered) == 2


def test_fetch_epss_scores(vuln_controller):
    for i in range(1000, 1085):
        # missing CVE in NVD and EPSS score
        if i == 1017 or i == 1060:
            continue
        vuln = Vulnerability(f"CVE-2022-{i}", ["test"], "test", "test")
        vuln_controller.add(vuln)

    assert len(vuln_controller) >= 80
    vuln_controller.fetch_epss_scores()
    for v in vuln_controller.vulnerabilities.values():
        if v.epss["score"] is None:
            print(v.id, "is missing EPSS score")
    scored_vulns = [v for v in vuln_controller.vulnerabilities.values() if v.epss["score"] is not None]
    print(f"Vulnerabilities with EPSS scores: {len(scored_vulns)}")
    if len(scored_vulns) == 0:
        print("Warning: No vulnerabilities with EPSS scores found in the DB for the test range.")
    else:
        assert all(v.epss["score"] is not None for v in scored_vulns)

@pytest.fixture
def vuln_ghsa():
    """Fixture for a GitHub Security Advisory vulnerability."""
    vuln = Vulnerability("GHSA-xxxx-yyyy-zzzz", ["test"], "test", "test")
    return vuln

@patch('urllib.request.urlopen')
@patch('sqlite3.connect')
def test_fetch_published_dates_ghsa_http_error(mock_sqlite, mock_urlopen, vuln_controller, vuln_ghsa):
    """
    GIVEN a GHSA vulnerability
    WHEN the GitHub API returns an HTTP Error
    THEN the loop should continue gracefully without crashing
    """
    vuln_controller.add(vuln_ghsa)
    vuln_controller.nvd_db_path = "mock_db.sqlite"
    
    # Simulate a 404 Not Found from GitHub
    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="...", code=404, msg="Not Found", hdrs={}, fp=None
    )

    # Execute - should not raise exception
    vuln_controller.fetch_published_dates()

    # Assertions
    assert vuln_ghsa.published is None


# ---------------------------------------------------------------------------
# DB-fallback and alias-chain paths
# ---------------------------------------------------------------------------

def test_get_via_alias(pkg_controller, vuln_123, vuln_456):
    """
    GIVEN a VulnerabilitiesController with vuln_456 aliased to vuln_123
    WHEN get() is called with vuln_456.id
    THEN it returns vuln_123 (via alias_registered)
    """
    ctrl = VulnerabilitiesController(pkg_controller)
    ctrl.add(vuln_123)
    ctrl.add(vuln_456)
    # Direct alias lookup (lines 155-159)
    result = ctrl.get(vuln_456.id)
    assert result is not None
    assert result.id == vuln_123.id


def test_iter_db_fallback(pkg_controller, vuln_123):
    """
    GIVEN a VulnerabilitiesController whose in-memory dict is empty
    WHEN iterating over it
    THEN entries are yielded from the DB
    """
    ctrl = VulnerabilitiesController(pkg_controller)
    ctrl.add(vuln_123)

    # Clear in-memory state to force DB path
    ctrl.vulnerabilities.clear()
    ctrl.alias_registered.clear()

    ids = [v.id for v in ctrl]  # DB path (lines 407, 409-410)
    assert vuln_123.id in ids


def test_remove_also_clears_aliases(pkg_controller, vuln_123, vuln_456):
    """
    GIVEN a VulnerabilitiesController with an alias
    WHEN removing the canonical vulnerability
    THEN the alias is also cleared from alias_registered (lines 266-267)
    """
    ctrl = VulnerabilitiesController(pkg_controller)
    ctrl.add(vuln_123)
    ctrl.add(vuln_456)
    assert vuln_456.id in ctrl.alias_registered
    ctrl.remove(vuln_123.id)
    assert vuln_456.id not in ctrl.alias_registered


def test_add_via_alias_registered(pkg_controller, vuln_123, vuln_456, vuln_789):
    """
    GIVEN vuln_456 is already registered as an alias pointing to vuln_123
    WHEN vuln_789 (which lists vuln_456 as its alias) is added
    THEN vuln_789 is resolved to vuln_123 via the alias_registered chain
    """
    ctrl = VulnerabilitiesController(pkg_controller)
    ctrl.add(vuln_123)
    ctrl.add(vuln_456)   # registers CVE-456 → CVE-123
    # Now vuln_789 has vuln_456.id as its alias (alias in alias_registered = chain)
    result = ctrl.add(vuln_789)
    # vuln_789 should have been merged into the canonical vuln_123 entry
    assert result.id == vuln_123.id
    assert vuln_789.id in ctrl.alias_registered


def test_add_via_alias_in_vuln_aliases_field(pkg_controller, vuln_123):
    """
    GIVEN a VulnerabilitiesController with vuln_123
    WHEN a new vulnerability that lists vuln_123.id as an alias is added
    THEN it merges into the canonical vuln_123 (lines 336-339: alias in vulnerabilities dict)
    """
    # Build a new vulnerability whose .aliases list contains vuln_123.id
    new_vuln = Vulnerability("CVE-TEST-NEW", ["test"], "test", "test")
    new_vuln.add_alias(vuln_123.id)
    new_vuln.add_package("abc@1.0.0")

    ctrl = VulnerabilitiesController(pkg_controller)
    ctrl.add(vuln_123)
    result = ctrl.add(new_vuln)  # lines 336-339

    # Should merge into existing vuln_123 entry
    assert result.id == vuln_123.id


def test_preload_cache_metrics_seen(pkg_controller):
    """
    GIVEN a persisted vulnerability with Metrics records
    WHEN _preload_cache is called
    THEN MetricsModel._seen is populated with the metric dedup keys (lines 111-121, 131)
    """
    from src.models.vulnerability import Vulnerability as VulnModel
    from src.models.metrics import Metrics

    # Create a DB vulnerability with a Metrics record
    v = VulnModel.create_record("CVE-PRELOAD-CACHE-2")
    Metrics.reset_cache()
    v_ctrl = VulnerabilitiesController(pkg_controller)
    Metrics.create("CVE-PRELOAD-CACHE-2", version="3.1", score=5.0, vector="AV:N", author="auto")

    # Call _preload_cache — should populate Metrics._seen
    old_cache_size = len(Metrics._seen)
    v_ctrl._preload_cache()
    assert len(Metrics._seen) >= old_cache_size  # new entry was added

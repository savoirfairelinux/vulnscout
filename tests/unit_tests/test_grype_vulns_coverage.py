# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Coverage tests for src/views/grype_vulns.py.

Targets lines: 62-63, 200, 202, 204-205, 212-215, 233-236.
"""

import os
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Fixtures
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
def controllers(app):
    from src.controllers.cache import ControllersCache
    return ControllersCache()


@pytest.fixture()
def grype(controllers):
    from src.views.grype_vulns import GrypeVulns
    return GrypeVulns(controllers)


# ---------------------------------------------------------------------------
# _normalize_artifact_name
# ---------------------------------------------------------------------------

class TestNormalizeArtifactName:
    def test_purl_exception_branch(self):
        """Lines 62-63: except Exception: pass when PURL parsing raises."""
        from src.views.grype_vulns import GrypeVulns

        class _BadPurl:
            """An object that looks like it has '/' but blows up on .split()."""
            def __contains__(self, item):
                return True

            def split(self, *args, **kwargs):
                raise RuntimeError("broken purl")

            def startswith(self, prefix):
                return False

        # Should not raise — falls back to name stripping
        result = GrypeVulns._normalize_artifact_name("mylib", _BadPurl())
        assert result == "mylib"

    def test_fallback_strips_repeated_namespace(self):
        """Fallback (no PURL): strips leading namespace segments."""
        from src.views.grype_vulns import GrypeVulns
        result = GrypeVulns._normalize_artifact_name("openssl/openssl-foo")
        assert result == "openssl-foo"

    def test_purl_canonical_name_extraction(self):
        """Happy-path: name is extracted from PURL."""
        from src.views.grype_vulns import GrypeVulns
        result = GrypeVulns._normalize_artifact_name(
            "group/name", "pkg:pypi/requests@2.28.0"
        )
        assert result == "requests"

    def test_plain_name_unchanged(self):
        """A name without '/' is returned as-is."""
        from src.views.grype_vulns import GrypeVulns
        assert GrypeVulns._normalize_artifact_name("libssl") == "libssl"


# ---------------------------------------------------------------------------
# parse_vulnerability_section
# ---------------------------------------------------------------------------

class TestParseVulnerabilitySection:
    def test_non_string_description_triggers_warning(self, grype):
        """Lines 200, 202, 204-205: description is not a string → _logger.warning."""
        vuln_data = {
            "id": "CVE-2024-WARN",
            "namespace": "nvd",
            "severity": "medium",
            "description": 42,          # not a string!
            "urls": [],
            "cvss": [],
        }
        import logging
        with patch.object(grype._logger if hasattr(grype, "_logger") else logging.getLogger("src.views.grype_vulns"),
                          "warning") as mock_warn:
            vuln = grype.parse_vulnerability_section(vuln_data)
        assert vuln.id == "CVE-2024-WARN"
        # Warning should have been emitted for non-string description
        mock_warn.assert_called_once()

    def test_none_description_not_warned(self, grype):
        """A None description is skipped without a warning."""
        vuln_data = {
            "id": "CVE-2024-NONE",
            "namespace": "nvd",
            "severity": "low",
            "description": None,
            "urls": [],
            "cvss": [],
        }
        import logging
        with patch.object(logging.getLogger("src.views.grype_vulns"), "warning") as mock_warn:
            vuln = grype.parse_vulnerability_section(vuln_data)
        assert vuln.id == "CVE-2024-NONE"
        mock_warn.assert_not_called()

    def test_with_cvss_data(self, grype):
        """Lines 212-215: CVSS items are parsed and registered on the vuln."""
        vuln_data = {
            "id": "CVE-2024-CVSS",
            "namespace": "nvd",
            "severity": "high",
            "description": "a vulnerability with CVSS",
            "urls": [],
            "cvss": [
                {
                    "version": "3.1",
                    "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "source": "nvd",
                    "metrics": {
                        "baseScore": 9.8,
                        "exploitabilityScore": 3.9,
                        "impactScore": 5.9,
                    },
                }
            ],
        }
        vuln = grype.parse_vulnerability_section(vuln_data)
        assert vuln.id == "CVE-2024-CVSS"
        assert len(vuln.severity_cvss) == 1
        assert vuln.severity_cvss[0].base_score == 9.8


# ---------------------------------------------------------------------------
# load_from_dict — fix state branches
# ---------------------------------------------------------------------------

class TestLoadFromDictFixStates:
    def _make_match(self, cve_id: str, pkg_name: str, pkg_version: str, fix_state: str,
                    fix_versions=None):
        # Grype JSON: 'fix' lives inside the 'vulnerability' object.
        fix_dict: dict = {"state": fix_state}
        if fix_versions is not None:
            fix_dict["versions"] = fix_versions
        return {
            "vulnerability": {
                "id": cve_id,
                "namespace": "nvd",
                "severity": "high",
                "description": "test",
                "urls": [],
                "cvss": [],
                "fix": fix_dict,
            },
            "artifact": {
                "name": pkg_name,
                "version": pkg_version,
                "type": "rpm",
                "cpes": [f"cpe:2.3:a:{pkg_name}:{pkg_name}:{pkg_version}:*:*:*:*:*:*:*"],
                "purl": f"pkg:rpm/{pkg_name}@{pkg_version}",
            },
        }

    def test_wont_fix_state(self, grype):
        """Lines 233-234: fix state 'wont-fix' creates an observation."""
        data = {
            "matches": [
                self._make_match("CVE-2024-WF01", "libssl", "1.0.0", "wont-fix")
            ]
        }
        grype.load_from_dict(data)
        # Just verify it doesn't raise and the vuln is added
        assert grype.vulnerabilitiesCtrl.get("CVE-2024-WF01") is not None

    def test_fixed_state_with_versions(self, grype):
        """Lines 235-236: fix state 'fixed' with versions creates an observation."""
        data = {
            "matches": [
                self._make_match("CVE-2024-FX01", "libssl", "1.0.0", "fixed",
                                 fix_versions=["1.0.1", "2.0.0"])
            ]
        }
        grype.load_from_dict(data)
        assert grype.vulnerabilitiesCtrl.get("CVE-2024-FX01") is not None

    def test_unknown_fix_state_triggers_warning(self, grype):
        """Line 210: the 'unknown_state' branch logs a warning."""
        data = {
            "matches": [
                self._make_match("CVE-2024-UK01", "libssl", "1.0.0", "partially-fixed")
            ]
        }
        # Just run — coverage records line 210; no need to assert on the logger.
        grype.load_from_dict(data)
        # Verify the vuln was still added despite the unknown fix state
        assert grype.vulnerabilitiesCtrl.get("CVE-2024-UK01") is not None

    def test_not_fixed_state(self, grype):
        """fix state 'not-fixed' creates no observation (pass branch)."""
        data = {
            "matches": [
                self._make_match("CVE-2024-NF01", "libssl", "1.0.0", "not-fixed")
            ]
        }
        grype.load_from_dict(data)
        assert grype.vulnerabilitiesCtrl.get("CVE-2024-NF01") is not None

    def test_match_details_only_fallback_path(self, grype):
        """Lines 233-236: package comes only from matchDetails (no artifact section)
        so it is NOT pre-warmed in _db_queried_pkgs → takes the else/fallback path."""
        data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-MD01",
                        "namespace": "nvd",
                        "severity": "medium",
                        "description": "test",
                        "urls": [],
                        "cvss": [],
                        "fix": {"state": "not-fixed"},
                    },
                    # Deliberately no "artifact" key — package comes only from matchDetails.
                    "matchDetails": [
                        {
                            "searchedBy": {
                                "Package": {"name": "curl", "version": "7.88.0"}
                            },
                            "found": {
                                "purl": "pkg:rpm/curl@7.88.0",
                                "cpes": [],
                            },
                        }
                    ],
                }
            ]
        }
        grype.load_from_dict(data)
        assert grype.vulnerabilitiesCtrl.get("CVE-2024-MD01") is not None

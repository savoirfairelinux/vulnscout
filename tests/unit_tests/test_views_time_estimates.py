# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Unit tests for src/views/time_estimates.py – no DB required."""

import uuid
from unittest.mock import MagicMock, patch
import pytest

from src.views.time_estimates import TimeEstimates


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_controllers(vulns=None):
    """Return a minimal controllers dict with a mock vulnerabilities controller."""
    vuln_ctrl = MagicMock()
    vuln_ctrl.vulnerabilities = vulns or {}
    pkg_ctrl = MagicMock()
    assess_ctrl = MagicMock()
    return {"packages": pkg_ctrl, "vulnerabilities": vuln_ctrl, "assessments": assess_ctrl}


def _make_vuln(opt=None, like=None, pess=None):
    vuln = MagicMock()
    vuln.id = str(uuid.uuid4())
    vuln.effort = {"optimistic": opt, "likely": like, "pessimistic": pess}
    return vuln


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:
    def test_controllers_assigned(self):
        controllers = _make_controllers()
        te = TimeEstimates(controllers)
        assert te.packagesCtrl is controllers["packages"]
        assert te.vulnerabilitiesCtrl is controllers["vulnerabilities"]
        assert te.assessmentsCtrl is controllers["assessments"]


# ---------------------------------------------------------------------------
# _iso_to_hours
# ---------------------------------------------------------------------------

class TestIsoToHours:
    def test_none_returns_none(self):
        assert TimeEstimates._iso_to_hours(None) is None

    def test_empty_string_returns_none(self):
        assert TimeEstimates._iso_to_hours("") is None

    def test_four_hours(self):
        result = TimeEstimates._iso_to_hours("PT4H")
        assert result == 4

    def test_one_day(self):
        result = TimeEstimates._iso_to_hours("PT24H")
        assert result == 24

    def test_invalid_raises_returns_none(self):
        result = TimeEstimates._iso_to_hours("NOT_VALID")
        assert result is None


# ---------------------------------------------------------------------------
# _persist_db_estimate
# ---------------------------------------------------------------------------

class TestPersistDbEstimate:
    def test_creates_when_no_existing(self):
        fid = str(uuid.uuid4())
        vid = str(uuid.uuid4())
        with patch("src.views.time_estimates.TimeEstimate") as MockTE:
            MockTE.get_by_finding_and_variant.return_value = None
            TimeEstimates._persist_db_estimate(fid, 1, 2, 3, vid)
            MockTE.create.assert_called_once()

    def test_updates_when_existing(self):
        fid = str(uuid.uuid4())
        vid = str(uuid.uuid4())
        existing = MagicMock()
        with patch("src.views.time_estimates.TimeEstimate") as MockTE:
            MockTE.get_by_finding_and_variant.return_value = existing
            TimeEstimates._persist_db_estimate(fid, 1, 2, 3, vid)
            existing.update.assert_called_once_with(optimistic=1, likely=2, pessimistic=3)

    def test_creates_when_no_variant(self):
        fid = str(uuid.uuid4())
        with patch("src.views.time_estimates.TimeEstimate") as MockTE:
            TimeEstimates._persist_db_estimate(fid, 1, 2, 3)
            MockTE.create.assert_called_once()
            MockTE.get_by_finding_and_variant.assert_not_called()

    def test_silently_skips_on_exception(self):
        """Should not raise even if import or DB call fails."""
        fid = str(uuid.uuid4())
        with patch("src.views.time_estimates.TimeEstimates._persist_db_estimate",
                   side_effect=Exception("DB down")):
            pass  # just verify the real method wraps in try/except by calling it directly
        # Call real method – it should not raise
        TimeEstimates._persist_db_estimate(fid, 1, 2, 3, None)


# ---------------------------------------------------------------------------
# load_from_dict
# ---------------------------------------------------------------------------

class TestLoadFromDict:
    def test_no_tasks_key_is_noop(self):
        ctrl = _make_controllers()
        te = TimeEstimates(ctrl)
        te.load_from_dict({})  # must not raise

    def test_db_format_calls_persist(self):
        ctrl = _make_controllers()
        te = TimeEstimates(ctrl)
        fid = str(uuid.uuid4())
        vid = str(uuid.uuid4())
        with patch.object(te, "_persist_db_estimate") as mock_persist:
            te.load_from_dict({"tasks": {fid: {"optimistic": 1, "likely": 2, "pessimistic": 3, "variant_id": vid}}})
            mock_persist.assert_called_once_with(fid, 1, 2, 3, vid)

    def test_db_format_no_variant(self):
        ctrl = _make_controllers()
        te = TimeEstimates(ctrl)
        fid = str(uuid.uuid4())
        with patch.object(te, "_persist_db_estimate") as mock_persist:
            te.load_from_dict({"tasks": {fid: {"optimistic": 2, "likely": 4, "pessimistic": 8}}})
            mock_persist.assert_called_once_with(fid, 2, 4, 8, None)

    def test_legacy_format_sets_effort(self):
        vuln = _make_vuln()
        ctrl = _make_controllers()
        ctrl["vulnerabilities"].get.return_value = vuln
        te = TimeEstimates(ctrl)
        with patch.object(te, "_persist_db_estimate"):
            te.load_from_dict({"tasks": {"CVE-2099-1": {
                "optimistic": "PT1H", "likely": "PT2H", "pessimistic": "PT3H"
            }}})
        vuln.set_effort.assert_called_once_with("PT1H", "PT2H", "PT3H")
        ctrl["vulnerabilities"].add.assert_called_once_with(vuln)

    def test_legacy_format_vuln_not_found_skipped(self):
        ctrl = _make_controllers()
        ctrl["vulnerabilities"].get.return_value = None
        te = TimeEstimates(ctrl)
        # Must not raise
        te.load_from_dict({"tasks": {"UNKNOWN-CVE": {"optimistic": "PT1H", "likely": "PT2H", "pessimistic": "PT3H"}}})

    def test_legacy_format_persists_to_db_via_findings(self):
        """When ISO hours can be converted and Finding.get_by_vulnerability works, persist is called."""
        vuln = _make_vuln()
        ctrl = _make_controllers()
        ctrl["vulnerabilities"].get.return_value = vuln
        te = TimeEstimates(ctrl)
        finding = MagicMock()
        finding.id = uuid.uuid4()
        with patch("src.models.finding.Finding.get_by_vulnerability", return_value=[finding]):
            with patch.object(te, "_persist_db_estimate") as mock_persist:
                te.load_from_dict({"tasks": {"CVE-2099-1": {
                    "optimistic": "PT1H", "likely": "PT2H", "pessimistic": "PT3H"
                }}})
                mock_persist.assert_called_once_with(str(finding.id), 1, 2, 3)

    def test_legacy_format_missing_hours_skips_persist(self):
        """If ISO conversion fails for any field, persist is NOT called."""
        vuln = _make_vuln()
        ctrl = _make_controllers()
        ctrl["vulnerabilities"].get.return_value = vuln
        te = TimeEstimates(ctrl)
        with patch.object(te, "_persist_db_estimate") as mock_persist:
            te.load_from_dict({"tasks": {"CVE-2099-1": {
                "optimistic": None, "likely": None, "pessimistic": None
            }}})
            mock_persist.assert_not_called()


# ---------------------------------------------------------------------------
# to_dict
# ---------------------------------------------------------------------------

class TestToDict:
    def test_empty_vulnerabilities(self):
        ctrl = _make_controllers()
        te = TimeEstimates(ctrl)
        result = te.to_dict()
        assert result["version"] == 1
        assert result["author"] == "Savoir-faire Linux"
        assert result["tasks"] == {}

    def test_vulns_with_complete_effort(self):
        from src.models.iso8601_duration import Iso8601Duration
        vuln = _make_vuln(
            opt=Iso8601Duration("PT1H"),
            like=Iso8601Duration("PT2H"),
            pess=Iso8601Duration("PT4H"),
        )
        ctrl = _make_controllers(vulns={"CVE-2099-1": vuln})
        te = TimeEstimates(ctrl)
        result = te.to_dict()
        assert "CVE-2099-1" in result["tasks"]
        assert result["tasks"]["CVE-2099-1"]["optimistic"] == "PT1H"
        assert result["tasks"]["CVE-2099-1"]["likely"] == "PT2H"
        assert result["tasks"]["CVE-2099-1"]["pessimistic"] == "PT4H"

    def test_vulns_with_partial_effort_excluded(self):
        vuln = _make_vuln(opt=None, like=None, pess=None)
        ctrl = _make_controllers(vulns={"CVE-2099-2": vuln})
        te = TimeEstimates(ctrl)
        result = te.to_dict()
        assert "CVE-2099-2" not in result["tasks"]

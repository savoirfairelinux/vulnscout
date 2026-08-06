# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import datetime
import pytest

from src.controllers.nvd_apply import apply_nvd_update


NOW = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)


class FakeVuln:
    """Minimal stand-in for a Vulnerability record."""

    def __init__(self, **kwargs):
        self.description = kwargs.get("description", "old description")
        self.status = kwargs.get("status", "low")
        self.attack_vector = kwargs.get("attack_vector", None)
        self.links = kwargs.get("links", [])
        self.weaknesses = kwargs.get("weaknesses", [])
        self.cpes = kwargs.get("cpes", [])
        self.publish_date = kwargs.get("publish_date", None)
        self.nvd_last_modified = kwargs.get("nvd_last_modified", None)
        self.nvd_fetched_at = None
        self.nvd_data_updated_at = None
        self._updates: dict = {}

    def update_record(self, commit=True, **kwargs):
        self._updates.update(kwargs)
        self._updates["commit"] = commit
        for key, value in kwargs.items():
            setattr(self, key, value)


def test_apply_nvd_update_changes_fields_and_returns_true():
    vuln = FakeVuln(description="old")
    details = {"description": "new description", "status": None}
    changed = apply_nvd_update(vuln, details, NOW)

    assert changed is True
    assert vuln.description == "new description"
    assert vuln.nvd_fetched_at == NOW
    assert vuln.nvd_data_updated_at == NOW


def test_apply_nvd_update_no_changes_returns_false_stamps_fetched_at():
    vuln = FakeVuln(description="same", status="high")
    details = {"description": "same", "status": "high"}
    changed = apply_nvd_update(vuln, details, NOW)

    assert changed is False
    assert vuln.nvd_fetched_at == NOW
    assert vuln.nvd_data_updated_at is None  # not updated when no change


def test_apply_nvd_update_none_values_do_not_overwrite():
    vuln = FakeVuln(description="existing")
    details = {"description": None}
    changed = apply_nvd_update(vuln, details, NOW)

    assert changed is False
    assert vuln.description == "existing"


def test_apply_nvd_update_partial_fields():
    vuln = FakeVuln(description="old", status="low", attack_vector="LOCAL")
    details = {
        "description": "new",
        "status": "low",  # unchanged
        "attack_vector": "NETWORK",  # changed
    }
    changed = apply_nvd_update(vuln, details, NOW)

    assert changed is True
    assert vuln.description == "new"
    assert vuln.attack_vector == "NETWORK"
    assert vuln.status == "low"  # unchanged
    assert vuln.nvd_data_updated_at == NOW


def test_apply_nvd_update_persists_affected_cpes():
    vuln = FakeVuln(cpes=["cpe:2.3:a:example:old:*:*:*:*:*:*:*"])
    details = {"cpes": ["cpe:2.3:a:example:new:*:*:*:*:*:*:*"]}

    changed = apply_nvd_update(vuln, details, NOW)

    assert changed is True
    assert vuln.cpes == ["cpe:2.3:a:example:new:*:*:*:*:*:*:*"]


def test_apply_nvd_update_empty_details():
    vuln = FakeVuln(description="existing")
    changed = apply_nvd_update(vuln, {}, NOW)

    assert changed is False
    assert vuln.nvd_fetched_at == NOW
    assert vuln.nvd_data_updated_at is None


def test_apply_nvd_update_commit_false_passed():
    """update_record must be called with commit=False."""
    vuln = FakeVuln(description="old")
    details = {"description": "new"}
    apply_nvd_update(vuln, details, NOW)

    assert vuln._updates.get("commit") is False

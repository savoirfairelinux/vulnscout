# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import datetime
import uuid
from unittest.mock import MagicMock, patch, call
import pytest

from src.controllers.nvd_refresh import (
    build_cpe_map,
    apply_nvd_update,
)


# ---------------------------------------------------------------------------
# build_cpe_map
# ---------------------------------------------------------------------------

def test_build_cpe_map_groups_cves_by_cpe():
    """Multiple CVEs sharing a CPE are all mapped to that CPE."""
    packages = [
        MagicMock(id=uuid.uuid4(), cpe=["cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*"]),
        MagicMock(id=uuid.uuid4(), cpe=["cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*"]),
    ]
    findings = [
        MagicMock(vulnerability_id="CVE-2024-0001", package_id=packages[0].id),
        MagicMock(vulnerability_id="CVE-2024-0002", package_id=packages[1].id),
    ]
    result = build_cpe_map(
        {"CVE-2024-0001", "CVE-2024-0002"},
        findings,
        {p.id: p for p in packages},
    )
    assert "cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*" in result
    assert result["cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*"] == {"CVE-2024-0001", "CVE-2024-0002"}


def test_build_cpe_map_skips_wildcard_vendor():
    """CPEs with wildcard in the vendor (parts[3]) position are excluded from batch map."""
    pkg = MagicMock(id=uuid.uuid4(), cpe=["cpe:2.3:a:*:lib:1.0:*:*:*:*:*:*:*"])
    finding = MagicMock(vulnerability_id="CVE-2024-9999", package_id=pkg.id)
    result = build_cpe_map(
        {"CVE-2024-9999"},
        [finding],
        {pkg.id: pkg},
    )
    assert result == {}


def test_build_cpe_map_skips_packages_without_cpe():
    pkg = MagicMock(id=uuid.uuid4(), cpe=None)
    finding = MagicMock(vulnerability_id="CVE-2024-1111", package_id=pkg.id)
    result = build_cpe_map({"CVE-2024-1111"}, [finding], {pkg.id: pkg})
    assert result == {}


# ---------------------------------------------------------------------------
# apply_nvd_update
# ---------------------------------------------------------------------------

def _make_vuln(description="old desc", status="medium", links=None,
               weaknesses=None, publish_date=None, attack_vector="NETWORK",
               nvd_last_modified="2024-01-01T00:00:00.000"):
    v = MagicMock()
    v.description = description
    v.status = status
    v.links = links or ["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"]
    v.weaknesses = weaknesses or ["CWE-79"]
    v.publish_date = publish_date or datetime.date(2024, 1, 1)
    v.attack_vector = attack_vector
    v.nvd_last_modified = nvd_last_modified
    v.update_record = MagicMock(return_value=v)
    return v


def test_apply_nvd_update_sets_nvd_data_updated_at_when_field_changes():
    vuln = _make_vuln(description="old")
    now = datetime.datetime.now(datetime.timezone.utc)
    details = {
        "description": "new description",
        "status": "medium",
        "links": vuln.links,
        "weaknesses": vuln.weaknesses,
        "publish_date": vuln.publish_date,
        "attack_vector": vuln.attack_vector,
        "nvd_last_modified": vuln.nvd_last_modified,
    }
    changed = apply_nvd_update(vuln, details, now)
    assert changed is True
    vuln.update_record.assert_called_once()
    call_kwargs = vuln.update_record.call_args[1]
    assert call_kwargs["description"] == "new description"
    assert call_kwargs["nvd_data_updated_at"] == now
    assert call_kwargs["nvd_fetched_at"] == now


def test_apply_nvd_update_does_not_set_nvd_data_updated_at_when_nothing_changes():
    vuln = _make_vuln()
    now = datetime.datetime.now(datetime.timezone.utc)
    details = {
        "description": vuln.description,
        "status": vuln.status,
        "links": vuln.links,
        "weaknesses": vuln.weaknesses,
        "publish_date": vuln.publish_date,
        "attack_vector": vuln.attack_vector,
        "nvd_last_modified": vuln.nvd_last_modified,
    }
    changed = apply_nvd_update(vuln, details, now)
    assert changed is False
    vuln.update_record.assert_not_called()


def test_apply_nvd_update_always_sets_nvd_fetched_at_on_change():
    vuln = _make_vuln(status="low")
    now = datetime.datetime.now(datetime.timezone.utc)
    details = {
        "description": vuln.description,
        "status": "critical",   # changed
        "links": vuln.links,
        "weaknesses": vuln.weaknesses,
        "publish_date": vuln.publish_date,
        "attack_vector": vuln.attack_vector,
        "nvd_last_modified": vuln.nvd_last_modified,
    }
    changed = apply_nvd_update(vuln, details, now)
    assert changed is True
    kwargs = vuln.update_record.call_args[1]
    assert kwargs["nvd_fetched_at"] == now
    assert kwargs["nvd_data_updated_at"] == now


def test_apply_nvd_update_handles_none_details_fields_gracefully():
    """None values in details do not overwrite existing data."""
    vuln = _make_vuln(description="keep me")
    now = datetime.datetime.now(datetime.timezone.utc)
    details = {
        "description": None,
        "status": None,
        "links": None,
        "weaknesses": None,
        "publish_date": None,
        "attack_vector": None,
        "nvd_last_modified": None,
    }
    changed = apply_nvd_update(vuln, details, now)
    assert changed is False
    vuln.update_record.assert_not_called()

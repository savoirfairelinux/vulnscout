# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Unit tests for group-reconcile payload parsing (no DB access)."""

import uuid

from src.routes._assessment_group import parse_reconcile_payload

VARIANT = "22222222-2222-2222-2222-222222222222"


def _payload(**overrides):
    base = {
        "vuln_id": "CVE-2020-35492",
        "packages": ["cairo@1.16.0"],
        "variant_ids": [VARIANT],
        "existing_ids": [],
        "status": "affected",
    }
    base.update(overrides)
    return base


def test_valid_payload_parses():
    req, err = parse_reconcile_payload(_payload())
    assert err is None
    assert req is not None
    assert req.vuln_id == "CVE-2020-35492"
    assert req.variant_ids == [uuid.UUID(VARIANT)]
    assert req.packages == ["cairo@1.16.0"]
    assert req.existing_ids == []
    assert req.update_timestamp is True


def test_missing_vuln_id_is_rejected():
    req, err = parse_reconcile_payload(_payload(vuln_id=""))
    assert req is None
    assert err == {"error": "vuln_id is required"}


def test_empty_packages_is_rejected():
    req, err = parse_reconcile_payload(_payload(packages=[]))
    assert req is None
    assert err is not None
    assert "packages" in err["error"]


def test_empty_variant_ids_is_rejected():
    req, err = parse_reconcile_payload(_payload(variant_ids=[]))
    assert req is None
    assert err is not None
    assert "variant_ids" in err["error"]


def test_non_uuid_variant_id_is_rejected():
    req, err = parse_reconcile_payload(_payload(variant_ids=["not-a-uuid"]))
    assert req is None
    assert err == {"error": "Invalid variant_id: not-a-uuid"}


def test_non_uuid_existing_id_is_rejected():
    req, err = parse_reconcile_payload(_payload(existing_ids=["nope"]))
    assert req is None
    assert err == {"error": "Invalid assessment id: nope"}


def test_invalid_status_is_rejected():
    req, err = parse_reconcile_payload(_payload(status="banana"))
    assert req is None
    assert err == {"error": "Invalid status"}


def test_not_affected_requires_justification():
    req, err = parse_reconcile_payload(_payload(status="not_affected"))
    assert req is None
    assert err == {"error": "Justification required"}


def test_non_boolean_update_timestamp_is_rejected():
    req, err = parse_reconcile_payload(_payload(update_timestamp="yes"))
    assert req is None
    assert err == {"error": "update_timestamp must be a boolean"}


def test_invalid_timestamp_is_rejected():
    req, err = parse_reconcile_payload(_payload(timestamp="not-a-date"))
    assert req is None
    assert err == {"error": "Invalid timestamp"}


def test_omitted_responses_is_flagged_absent():
    req, err = parse_reconcile_payload(_payload())
    assert err is None
    assert req is not None
    assert req.has_responses is False


def test_explicit_responses_is_flagged_present():
    req, err = parse_reconcile_payload(_payload(responses=["rollback"]))
    assert err is None
    assert req is not None
    assert req.has_responses is True
    assert list(req.dto.responses) == ["rollback"]


def test_empty_justification_clears_it():
    """An empty justification means "clear", as the per-row PUT always read it."""
    req, err = parse_reconcile_payload(_payload(status="fixed", justification=""))
    assert err is None
    assert req is not None
    assert not req.dto.justification


def test_empty_justification_still_refused_when_required():
    req, err = parse_reconcile_payload(_payload(status="not_affected", justification=""))
    assert req is None
    assert err == {"error": "Justification required"}


def test_unknown_justification_is_still_rejected():
    req, err = parse_reconcile_payload(_payload(status="fixed", justification="made_up"))
    assert req is None
    assert err == {"error": "Invalid justification"}

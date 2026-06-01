# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared validation and persistence helpers for vulnerability CVSS scores
and time-estimate (effort) values.

Used by both ``routes/vulnerabilities.py`` (batch PATCH) and
``helpers/assessment_io.py`` (custom-data import).
"""

from __future__ import annotations

from ..models import Metrics, CVSS, Iso8601Duration
from ..helpers.verbose import verbose


def _parse_effort_hours(value) -> int:
    """Parse an effort value (ISO 8601 duration string or integer hours) to whole hours."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(Iso8601Duration(value).total_seconds // 3600)
    raise ValueError(f"Invalid effort value: {value!r}")


def _validate_effort(eff: dict):
    """Validate and parse effort dict with optimistic/likely/pessimistic keys.

    Returns ``(opt, lik, pes, None)`` on success or ``(None, None, None, error_string)``
    on failure.
    """
    if not all(k in eff for k in ("optimistic", "likely", "pessimistic")):
        return None, None, None, "Invalid effort values"
    try:
        opt = _parse_effort_hours(eff["optimistic"])
        lik = _parse_effort_hours(eff["likely"])
        pes = _parse_effort_hours(eff["pessimistic"])
    except (ValueError, TypeError):
        return None, None, None, "Invalid effort values"
    if not (opt <= lik <= pes):
        return None, None, None, "Invalid effort values"
    return opt, lik, pes, None


def _validate_and_apply_cvss(
    new_cvss: dict,
    record_id: str,
    variant_id,
    log_prefix: str = "",
):
    """Validate CVSS payload and persist to Metrics.

    Returns an error string on validation failure, ``None`` on success.
    """
    required_keys = {"base_score", "vector_string", "version"}
    if not required_keys.issubset(new_cvss.keys()):
        return "Invalid CVSS data"
    if not new_cvss.get("author"):
        new_cvss["author"] = "unknown"
    if not new_cvss.get("origin"):
        new_cvss["origin"] = "scanner"
    cvss_obj = CVSS.from_dict(new_cvss)
    try:
        Metrics.from_cvss(cvss_obj, record_id, variant_id)
    except Exception as e:
        verbose(f"[{log_prefix} cvss] {e}")
    return None


def _apply_effort(record, variant_id, opt, lik, pes, log_prefix: str = ""):
    """Persist effort values to the first finding's TimeEstimate."""
    try:
        from ..models.time_estimate import TimeEstimate
        for finding in (record.findings or []):
            if variant_id is not None:
                existing = TimeEstimate.get_by_finding_and_variant(finding.id, variant_id)
            else:
                existing = finding.time_estimate
            if existing is not None:
                existing.update(optimistic=opt, likely=lik, pessimistic=pes)
            else:
                TimeEstimate.create(
                    finding_id=finding.id, variant_id=variant_id,
                    optimistic=opt, likely=lik, pessimistic=pes
                )
            break
    except Exception as e:
        verbose(f"[{log_prefix} effort] {e}")

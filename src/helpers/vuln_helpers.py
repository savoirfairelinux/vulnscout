# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared validation and persistence helpers for vulnerability CVSS scores
and time-estimate (effort) values.

Used by both ``routes/vulnerabilities.py`` (batch PATCH) and
``helpers/assessment_io.py`` (custom-data import).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from ..models.vulnerability import Vulnerability as _Vulnerability

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql.selectable import Exists

from ..extensions import batch_session, db
from ..models import CVSS, Finding, Iso8601Duration, Metrics, Observation, Scan, TimeEstimate
from ..helpers.verbose import verbose


class Effort(NamedTuple):
    optimistic: int | None
    likely: int | None
    pessimistic: int | None


def _parse_effort_hours(value: int | str | None) -> int:
    """Parse an effort value (ISO 8601 duration string or integer hours) to whole hours."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(Iso8601Duration(value).total_seconds // 3600)
    raise ValueError(f"Invalid effort value: {value!r}")


def validate_effort(eff: object) -> tuple[Effort, None] | tuple[None, str]:
    """Validate and parse effort dict with optimistic/likely/pessimistic keys.

    Returns ``(effort, None)`` on success or ``(None, error_string) on failure.
    """
    if not isinstance(eff, dict) or not all(k in eff for k in ("optimistic", "likely", "pessimistic")):
        return None, "Invalid effort values"
    try:
        opt = _parse_effort_hours(eff["optimistic"])
        lik = _parse_effort_hours(eff["likely"])
        pes = _parse_effort_hours(eff["pessimistic"])
    except (ValueError, TypeError):
        return None, "Invalid effort values"
    if not (opt <= lik <= pes):
        return None, "Invalid effort values"
    return Effort(opt, lik, pes), None


def validate_and_apply_cvss(
    new_cvss: dict[str, str | float],
    record_id: str,
    variant_id: uuid.UUID | None,
    log_prefix: str = "",
) -> str | None:
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


class _MissingEffortTarget(ValueError):
    pass


def estimate_has_variant_observation() -> Exists:
    """Match an estimate's finding to an observation in its own variant."""
    return db.select(Observation.finding_id).join(Scan, Scan.id == Observation.scan_id).where(
        Observation.finding_id == TimeEstimate.finding_id,
        Scan.variant_id == TimeEstimate.variant_id,
    ).exists()


def apply_effort(
    record: "_Vulnerability", variant_ids: Sequence[uuid.UUID | None],
    effort: Effort,
    log_prefix: str = "",
    *,
    require_observation: bool = False,
) -> str | None:
    """Persist one estimate per requested variant, or report why none were saved."""
    try:
        with batch_session():
            for variant_id in variant_ids:
                scope = db.select(Finding.id).where(Finding.vulnerability_id == record.id)
                scoped = require_observation and variant_id is not None
                if scoped:
                    scope = scope.join(Observation, Observation.finding_id == Finding.id).join(
                        Scan, Scan.id == Observation.scan_id,
                    ).where(Scan.variant_id == variant_id)
                finding_id = db.session.scalar(scope.order_by(Finding.id).limit(1))
                if finding_id is None:
                    raise _MissingEffortTarget("No finding for the requested time estimate")

                estimates = (
                    db.select(TimeEstimate).join(Finding, Finding.id == TimeEstimate.finding_id)
                    .where(Finding.vulnerability_id == record.id, TimeEstimate.variant_id == variant_id)
                )
                # Prefer an estimate we can update in place before repairing a legacy association.
                if variant_id is not None:
                    estimates = estimates.order_by(estimate_has_variant_observation().desc())
                existing = db.session.scalar(estimates.order_by(TimeEstimate.id).limit(1))
                if existing is not None:
                    if scoped and existing.finding_id != finding_id:
                        observed = db.session.scalar(scope.where(Finding.id == existing.finding_id).exists().select())
                        if not observed:
                            existing.finding_id = finding_id
                    existing.update(*effort)
                else:
                    TimeEstimate.create(
                        finding_id=finding_id, variant_id=variant_id,
                        optimistic=effort.optimistic, likely=effort.likely, pessimistic=effort.pessimistic,
                    )
    except _MissingEffortTarget as e:
        return str(e)
    except SQLAlchemyError as e:
        verbose(f"[{log_prefix} effort] {e}")
        return "Failed to save time estimate"
    return None

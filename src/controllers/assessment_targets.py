# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Renders assessments with per-target staleness for the read endpoints.

Single source of truth for how an assessment's targets are annotated and
ordered, so the front-ends stop reimplementing it and drifting apart.
"""

from ..helpers.assessment_staleness import annotate_assessments_outdated
from ..models.assessment import Assessment


def annotate_targets(assessments: list[Assessment]) -> list[dict]:
    """Render assessments as dicts, newest first, with per-target staleness.

    Each dict is ``Assessment.to_dict()`` with its ``targets`` entries
    enriched with an ``outdated`` flag and sorted.
    """
    if not assessments:
        return []

    dicts = [a.to_dict() for a in assessments]
    annotate_assessments_outdated(dicts)
    # Keyed on the (variant, package name) pair, not on the package alone:
    # ``stale_packages`` unions every variant the assessment targets, so it
    # would mark a target outdated because its package went stale in some
    # *other* variant.  ``stale_targets`` is the annotation that keeps the
    # variant dimension.  Its ``package_name`` is the bare name, so it pairs
    # with ``package.name`` rather than with ``string_id``.
    stale_by_assessment = {
        d["id"]: {
            (target["variant_id"], target["package_name"])
            for target in d.get("stale_targets") or []
        }
        for d in dicts
    }

    for assessment, d in zip(assessments, dicts):
        stale = stale_by_assessment.get(d["id"], set())
        targets = [
            {
                "variant_id": str(row.variant_id),
                "package": row.finding.package.string_id,
                "outdated": (
                    str(row.variant_id), row.finding.package.name) in stale,
            }
            for row in assessment.target_rows
        ]
        d["targets"] = sorted(
            targets, key=lambda t: (t["variant_id"] or "", t["package"]))

    return sorted(dicts, key=lambda d: d["timestamp"] or "", reverse=True)

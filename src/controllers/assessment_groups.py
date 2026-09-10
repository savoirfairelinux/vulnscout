# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Builds assessment groups for the read endpoints.

Single source of truth for how assessments are grouped.  It exists so the
front-ends stop reimplementing grouping and drifting apart.

Task 15 fuses writers: every write path now creates exactly one assessment
row per requested set of ``(variant, package)`` pairs, so a "group" is just
that one assessment and its target rows -- there is no longer a separate
membership table to join through (``assessment_group_member`` was dropped in
Task 14).
"""

import uuid

from ..extensions import db
from ..helpers.assessment_staleness import annotate_assessments_outdated
from ..helpers.datetime_utils import ensure_utc_iso
from ..models.assessment import Assessment

CONTENT_FIELDS = (
    "status", "simplified_status", "status_notes", "justification",
    "impact_statement", "workaround", "origin",
)


def load_group(group_id: uuid.UUID) -> list[Assessment]:
    """Return the assessment behind this group id; empty when unknown.

    A group is now an assessment, so this is a primary-key lookup wrapped in
    a list to keep the callers' shape.
    """
    assessment = db.session.get(Assessment, group_id)
    return [assessment] if assessment is not None else []


def build_groups(assessments: list[Assessment]) -> list[dict]:
    """Render assessments as group dicts, newest first.

    Each assessment is one group, keyed by its own id, with one entry in
    ``targets`` per stored target row. Nothing is bucketed: rows that merely
    look alike are distinct assessments and stay distinct.
    """
    if not assessments:
        return []

    member_dicts = [a.to_dict() for a in assessments]
    annotate_assessments_outdated(member_dicts)
    # Keyed on the (variant, package name) pair, not on the package alone:
    # ``stale_packages`` unions every variant the assessment targets, so it
    # would mark a target outdated because its package went stale in some
    # *other* variant. ``stale_targets`` is the annotation that keeps the
    # variant dimension. Its ``package_name`` is the bare name, so it pairs
    # with ``package.name`` rather than with ``string_id``.
    stale_by_assessment = {
        d["id"]: {
            (target["variant_id"], target["package_name"])
            for target in d.get("stale_targets") or []
        }
        for d in member_dicts
    }

    groups = []
    for assessment in assessments:
        stale = stale_by_assessment.get(str(assessment.id), set())
        targets = [
            {
                "variant_id": str(row.variant_id),
                "package": row.finding.package.string_id,
                "outdated": (str(row.variant_id), row.finding.package.name) in stale,
                "assessment_id": str(assessment.id),
            }
            for row in assessment.target_rows
        ]
        groups.append({
            "group_id": str(assessment.id),
            "vuln_id": assessment.vuln_id,
            **{field: getattr(assessment, field) or "" for field in CONTENT_FIELDS},
            "responses": list(assessment.responses or []),
            "timestamp": ensure_utc_iso(assessment.timestamp),
            "targets": sorted(
                targets, key=lambda t: (t["variant_id"] or "", t["package"])),
            "assessment_ids": [str(assessment.id)],
        })

    return sorted(groups, key=lambda g: g["timestamp"] or "", reverse=True)

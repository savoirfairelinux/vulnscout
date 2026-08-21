# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Builds assessment groups for the read endpoints.

Single source of truth for how assessments are grouped.  It exists so the
front-ends stop reimplementing grouping and drifting apart.
"""

import uuid

from sqlalchemy import select

from ..extensions import db
from ..helpers.assessment_staleness import annotate_assessments_outdated
from ..helpers.datetime_utils import ensure_utc_iso
from ..models.assessment import Assessment
from ..models.assessment_group_member import AssessmentGroupMember

CONTENT_FIELDS = (
    "status", "simplified_status", "status_notes", "justification",
    "impact_statement", "workaround", "origin",
)


def load_group(group_id: uuid.UUID) -> list[Assessment]:
    """Return every assessment in the group; empty when the group is unknown."""
    return list(db.session.execute(
        select(Assessment)
        .join(AssessmentGroupMember,
              AssessmentGroupMember.assessment_id == Assessment.id)
        .where(AssessmentGroupMember.group_id == group_id)
    ).scalars())


def build_groups(assessments: list[Assessment]) -> list[dict]:
    """Collapse assessments into group dicts, newest first.

    Grouped rows collapse into one entry keyed by their stored group id.  An
    ungrouped assessment yields the same shape with ``group_id`` None and a
    single target, so callers never branch on whether a group exists.
    """
    if not assessments:
        return []

    memberships: dict[uuid.UUID, uuid.UUID] = {
        row.assessment_id: row.group_id
        for row in db.session.execute(
            select(AssessmentGroupMember.assessment_id, AssessmentGroupMember.group_id)
            .where(AssessmentGroupMember.assessment_id.in_([a.id for a in assessments]))
        ).all()
    }

    # One call for the whole page: three queries total, not three per group.
    member_dicts = [a.to_dict() for a in assessments]
    annotate_assessments_outdated(member_dicts)
    stale_by_assessment = {
        d["id"]: set(d.get("stale_packages") or []) for d in member_dicts
    }

    buckets: dict[str, list[Assessment]] = {}
    for assessment in assessments:
        group_id = memberships.get(assessment.id)
        key = str(group_id) if group_id else f"ungrouped::{assessment.id}"
        buckets.setdefault(key, []).append(assessment)

    groups = []
    for key, members in buckets.items():
        head = members[0]
        targets = [
            {
                "variant_id": str(m.variant_id) if m.variant_id else None,
                "package": pkg,
                "outdated": pkg in stale_by_assessment.get(str(m.id), set()),
                "assessment_id": str(m.id),
            }
            for m in members for pkg in m.packages
        ]
        groups.append({
            "group_id": None if key.startswith("ungrouped::") else key,
            "vuln_id": head.vuln_id,
            **{field: getattr(head, field) or "" for field in CONTENT_FIELDS},
            "responses": list(head.responses or []),
            "timestamp": ensure_utc_iso(head.timestamp),
            "targets": sorted(
                targets, key=lambda t: (t["variant_id"] or "", t["package"])),
            "assessment_ids": [str(m.id) for m in members],
        })

    return sorted(groups, key=lambda g: g["timestamp"] or "", reverse=True)

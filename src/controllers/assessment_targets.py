# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Renders assessments with per-target staleness for the read endpoints.

Single source of truth for how an assessment's targets are annotated and
ordered, so the front-ends stop reimplementing it and drifting apart.
"""

from uuid import UUID

from ..extensions import db
from ..helpers.active_scans import active_scan_ids_for_variants
from ..helpers.assessment_risk_links import RiskModelIndex
from ..helpers.assessment_staleness import annotate_assessments_outdated
from ..helpers.finding_evidence import finding_packages_for_scans
from ..models.assessment import Assessment
from ..models.observation import Observation
from ..models.scan import Scan


def annotate_targets(assessments: list[Assessment], link_scope: set[UUID] | None = None) -> list[dict]:
    """Render assessments as dicts, newest first, with per-target staleness.

    Each dict is ``Assessment.to_dict()`` with its ``targets`` entries
    enriched with an ``outdated`` flag and sorted.
    """
    if not assessments:
        return []

    indexes: dict[UUID, RiskModelIndex] = {}
    dicts = [a.to_dict(link_scope=link_scope, link_indexes=indexes) for a in assessments]
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
        outdated = {
            (str(row.variant_id), row.finding.package.string_id):
                (str(row.variant_id), row.finding.package.name) in stale
            for row in assessment.target_rows
        }
        targets = [{**t, "outdated": outdated[t["variant_id"], t["package"]]} for t in d["targets"]]
        d["targets"] = sorted(
            targets, key=lambda t: (t["variant_id"] or "", t["package"]))

    return sorted(dicts, key=lambda d: d["timestamp"] or "", reverse=True)


def annotate_review_evidence(assessments: list[Assessment], payload: list[dict]) -> None:
    """Mark previously observed custom targets absent from current published evidence."""
    custom = {str(row.id): row for row in assessments if row.origin == "custom"}
    targets = [target for row in custom.values() for target in row.target_rows]
    if not targets:
        return
    variants = {target.variant_id for target in targets}
    published = set(db.session.execute(
        db.select(Scan.variant_id, Observation.finding_id)
        .join(Observation, Observation.scan_id == Scan.id)
        .where(Scan.in_progress.is_(False), Scan.variant_id.in_(variants),
               Observation.finding_id.in_({target.finding_id for target in targets}))
        .distinct()
    ).tuples())
    current = finding_packages_for_scans(
        active_scan_ids_for_variants(variants), {row.vuln_id for row in custom.values() if row.vuln_id},
        collect_writable_targets=True,
    ).writable_targets
    outdated = published - current

    for entry in payload:
        if (row := custom.get(entry["id"])) is None:
            continue
        missing = {
            (str(target.variant_id), target.finding.package.string_id)
            for target in row.target_rows
            if (target.variant_id, target.finding_id) in outdated
        }
        for target in entry["targets"]:
            target["outdated"] = (target["variant_id"], target["package"]) in missing
        entry["outdated"] = bool(missing)

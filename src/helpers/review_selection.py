# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Resolve custom assessments and their per-target review state for ``ai-review``."""
from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from ..models.assessment import Assessment
from ..models.assessment_review import AssessmentReview, ReviewState, fingerprint_assessment, review_state


@dataclass(frozen=True)
class ReviewTarget:
    assessment_id: UUID
    vuln_id: str
    variant_id: UUID
    variant: str
    project_id: UUID
    package: str
    finding_id: UUID
    review_state: ReviewState


@dataclass
class ReviewSelection:
    assessment_id: UUID
    vuln_id: str
    fingerprint: str
    targets: list[ReviewTarget]
    excluded_targets: int = 0


def _selection(assessment: Assessment, variant_ids: set[UUID]) -> ReviewSelection:
    reviews = {(r.variant_id, r.finding_id): r
               for r in AssessmentReview.get_all_for_assessment(assessment.id)}
    targets: list[ReviewTarget] = []
    excluded = 0
    for row in assessment.target_rows:
        if row.variant_id not in variant_ids:
            excluded += 1
            continue
        targets.append(ReviewTarget(
            assessment.id, assessment.vuln_id, row.variant_id, row.variant.name,
            row.variant.project_id, row.finding.package.string_id, row.finding_id,
            review_state(reviews.get((row.variant_id, row.finding_id)))))
    targets.sort(key=lambda t: (t.variant, t.package))
    return ReviewSelection(assessment.id, assessment.vuln_id,
                           fingerprint_assessment(assessment) or "", targets, excluded)


def select_by_ids(ids: list[UUID], variant_ids: set[UUID], scope_label: str
                  ) -> tuple[list[ReviewSelection], list[str]]:
    """Each listed custom assessment, restricted to its targets in ``variant_ids`` (the -p project)."""
    selections: list[ReviewSelection] = []
    errors: list[str] = []
    for aid in dict.fromkeys(ids):
        assessment = Assessment.get_by_id(aid)
        if assessment is None:
            errors.append(f"Assessment {aid} not found.")
            continue
        if assessment.origin != "custom":
            errors.append(f"Assessment {aid} has origin '{assessment.origin}'; "
                          "only custom assessments can be reviewed.")
            continue
        selection = _selection(assessment, variant_ids)
        if selection.targets:
            selections.append(selection)
        else:
            errors.append(f"Assessment {aid} has no target in {scope_label}.")
    return selections, errors


def select_by_cve(cve_ids: list[str], variant_ids: set[UUID], scope_label: str
                  ) -> tuple[list[ReviewSelection], int, list[str]]:
    """Every custom assessment of each CVE with at least one target in ``variant_ids``.

    Unpaginated on purpose: the CLI must never silently truncate. ``ignored`` counts the
    non-custom assessments of the CVEs that have a target in ``variant_ids``.
    """
    selections: list[ReviewSelection] = []
    ignored = 0
    errors: list[str] = []
    for cve in dict.fromkeys(c.upper() for c in cve_ids):
        found = others = 0
        for assessment in Assessment.get_by_vulnerability(cve):
            if assessment.origin != "custom":
                in_scope = any(row.variant_id in variant_ids for row in assessment.target_rows)
                ignored += in_scope
                others += in_scope
                continue
            selection = _selection(assessment, variant_ids)
            if selection.targets:
                selections.append(selection)
                found += 1
        if not found:
            reason = (f"Its {others} assessment(s) there come from SBOM scans or pending AI suggestions, "
                      "which are never reviewed; only custom (user) assessments can be." if others
                      else "This CVE has no assessment there; create a custom assessment first.")
            errors.append(f"{cve}: no custom assessment to review in {scope_label}. {reason}")
    return selections, ignored, errors

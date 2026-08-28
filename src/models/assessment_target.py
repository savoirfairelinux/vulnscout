# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Records which (variant, finding) pairs one assessment applies to.

Assessment content is stored once on the assessment row; this table records
every place that judgement lands.  A target is a *pair* — an analyst may assess
variant A's openssl and variant B's zlib without asserting anything about
A/zlib — so two independent collections would wrongly imply the cross-product.
"""

import uuid

from sqlalchemy import ForeignKey, select
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db, Base


class GroupInvariantError(ValueError):
    """Raised when a set of targets may not share one assessment.

    An assessment stays inside one project and addresses one vulnerability;
    members cannot disagree about text, since assessment content lives in
    exactly one place — the assessment row itself.
    """


class AssessmentTarget(Base):
    """Links one :class:`Assessment` to one ``(variant, finding)`` pair."""

    __tablename__ = "assessment_targets"

    # The whole triple is the key: an assessment may repeat neither a variant
    # nor a finding within itself, but may reuse either across the pair.
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), primary_key=True
    )
    variant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("variants.id"), primary_key=True, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id"), primary_key=True, index=True
    )

    assessment: Mapped["Assessment"] = relationship(back_populates="target_rows")  # noqa: F821
    finding: Mapped["Finding"] = relationship(  # noqa: F821
        back_populates="assessment_targets", lazy="selectin",
    )
    variant: Mapped["Variant"] = relationship()  # noqa: F821

    def __repr__(self) -> str:
        return (
            f"<AssessmentTarget assessment_id={self.assessment_id}"
            f" variant_id={self.variant_id} finding_id={self.finding_id}>"
        )


def validate_targets(pairs: "list[tuple[uuid.UUID, uuid.UUID]]") -> None:
    """Raise :class:`GroupInvariantError` unless these targets may share an assessment.

    ``pairs`` are ``(variant_id, finding_id)``.  Resolution is a single query —
    project through the variant, vulnerability through the finding — so
    validating a whole target set costs one round trip rather than one per
    target.
    """
    from .finding import Finding
    from .variant import Variant

    if not pairs:
        return

    variant_ids = {variant_id for variant_id, _ in pairs}
    finding_ids = {finding_id for _, finding_id in pairs}

    projects = dict(db.session.execute(
        select(Variant.id, Variant.project_id).where(Variant.id.in_(variant_ids))
    ).all())
    vulns = dict(db.session.execute(
        select(Finding.id, Finding.vulnerability_id).where(Finding.id.in_(finding_ids))
    ).all())

    missing = [
        f"({variant_id}, {finding_id})"
        for variant_id, finding_id in pairs
        if variant_id not in projects or finding_id not in vulns
    ]
    if missing:
        raise GroupInvariantError("Unknown target: " + ", ".join(sorted(missing)))

    distinct_projects = {projects[variant_id] for variant_id, _ in pairs}
    distinct_vulns = {(vulns[finding_id] or "").upper() for _, finding_id in pairs}

    if len(distinct_projects) > 1:
        raise GroupInvariantError(
            "Targets cannot share an assessment: they belong to different projects"
        )
    if len(distinct_vulns) > 1:
        raise GroupInvariantError(
            "Targets cannot share an assessment: they address different vulnerabilities"
        )

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Records which (variant, finding) pairs one assessment applies to.

Assessment content is stored once on the assessment row; this table records
every place that judgement lands.  A target is a *pair* — an analyst may assess
variant A's openssl and variant B's zlib without asserting anything about
A/zlib — so two independent collections would wrongly imply the cross-product.
"""

import uuid
from typing import TYPE_CHECKING, cast

from sqlalchemy import ForeignKey, Table, select
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db, Base

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection
    from sqlalchemy.sql.elements import ColumnElement

    from .assessment import Assessment
    from .finding import Finding
    from .variant import Variant


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

    assessment: Mapped["Assessment"] = relationship(back_populates="target_rows")
    finding: Mapped["Finding"] = relationship(
        back_populates="assessment_targets", lazy="selectin",
    )
    variant: Mapped["Variant"] = relationship()

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

    projects: dict[uuid.UUID, uuid.UUID] = {
        row[0]: row[1]
        for row in db.session.execute(
            select(Variant.id, Variant.project_id).where(Variant.id.in_(variant_ids))
        ).all()
    }
    vulns: dict[uuid.UUID, str] = {
        row[0]: row[1]
        for row in db.session.execute(
            select(Finding.id, Finding.vulnerability_id).where(Finding.id.in_(finding_ids))
        ).all()
    }

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


def reap_targets(connection: "Connection", criterion: "ColumnElement[bool]") -> None:
    """Delete the target rows matching *criterion*, and any assessment left empty.

    Neither ``assessment_targets.variant_id`` nor ``.finding_id`` carries an
    ``ondelete`` clause, and this application keeps sqlite's ``foreign_keys``
    pragma off, so nothing removes these rows on its own.  Worse, both are part
    of the primary key, so the ORM's default "blank out the foreign key" for a
    deleted parent raises instead of cleaning up.  Mapper events on the parents
    call this before the parent row goes.

    An assessment left with no targets at all goes with them: it is reachable
    only through its targets (``Assessment.create`` refuses an empty target
    set), so it would be an invisible orphan.  An assessment that another
    target still reaches keeps it and survives.
    """
    # Core statements against the mapped tables, not raw SQL: the listener gets
    # a Connection rather than a Session, and only the mapped columns know how
    # to bind a UUID for the active driver.
    from .assessment import Assessment

    # ``__table__`` is typed as FromClause; these are real Tables, and only
    # Table carries .delete().
    targets = cast(Table, AssessmentTarget.__table__)
    assessments = cast(Table, Assessment.__table__)

    affected = {
        row[0] for row in connection.execute(
            select(targets.c.assessment_id).where(criterion)
        )
    }
    connection.execute(targets.delete().where(criterion))
    if not affected:
        return

    still_reachable = {
        row[0] for row in connection.execute(
            select(targets.c.assessment_id).where(targets.c.assessment_id.in_(affected))
        )
    }
    orphans = affected - still_reachable
    if orphans:
        connection.execute(assessments.delete().where(assessments.c.id.in_(orphans)))

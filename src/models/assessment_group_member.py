# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Records which assessments were written by a single user action.

Membership is *sparse*: a row exists only when one action produced more than
one assessment for one vulnerability.  A single-target assessment has no group
and is referenced by its own assessment id.
"""

import uuid

from sqlalchemy import ForeignKey, select
from sqlalchemy.orm import Mapped, mapped_column

from ..extensions import db, Base


class AssessmentGroupMember(Base):
    """Links one :class:`Assessment` to the group it was created with."""

    __tablename__ = "assessment_group_members"

    # Primary key on assessment_id enforces "one group per assessment".
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), primary_key=True
    )
    group_id: Mapped[uuid.UUID] = mapped_column(index=True, nullable=False)

    def __repr__(self) -> str:
        return (
            f"<AssessmentGroupMember assessment_id={self.assessment_id}"
            f" group_id={self.group_id}>"
        )

    @staticmethod
    def create_group(
        assessment_ids: "list[uuid.UUID]",
        group_id: "uuid.UUID | None" = None,
        commit: bool = True,
    ) -> uuid.UUID:
        """Put every assessment in ``assessment_ids`` into one group.

        Args:
            assessment_ids: rows to link.  May be a single id when joining a
                group that an earlier request already created.
            group_id: join this existing group instead of starting a new one.
            commit: False for bulk operations inside ``batch_session()``.

        Returns:
            The group id the assessments now belong to.
        """
        resolved = group_id or uuid.uuid4()
        for assessment_id in assessment_ids:
            db.session.add(
                AssessmentGroupMember(assessment_id=assessment_id, group_id=resolved)
            )
        if commit:
            db.session.commit()
        else:
            db.session.flush()
        return resolved

    @staticmethod
    def get_assessment_ids(group_id: uuid.UUID) -> "list[uuid.UUID]":
        """Return every assessment id in the group, empty when unknown."""
        return list(db.session.execute(
            select(AssessmentGroupMember.assessment_id)
            .where(AssessmentGroupMember.group_id == group_id)
        ).scalars())

    @staticmethod
    def get_group_id(assessment_id: uuid.UUID) -> "uuid.UUID | None":
        """Return the assessment's group id, or None when it is ungrouped."""
        return db.session.execute(
            select(AssessmentGroupMember.group_id)
            .where(AssessmentGroupMember.assessment_id == assessment_id)
        ).scalar_one_or_none()
